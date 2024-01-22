#!/usr/bin/env python

# Copyright Andreas Misje 2023, 2022 Aurora Networks Managed Services 
# See https://github.com/misje/wazuh-opencti for documentation
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

import sys
import os
from socket import socket, AF_UNIX, SOCK_DGRAM
from datetime import date, datetime, timedelta
import time
import requests
from requests.exceptions import ConnectionError
import json
import ipaddress
import re
import traceback

# Maximum number of alerts to create for indicators found per query:
max_ind_alerts = 3
# Maximum number of alerts to create for observables found per query:
max_obs_alerts = 3
# Debug can be enabled by setting the internal configuration setting
# integration.debug to 1 or higher:
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
url = ''
# Match SHA256:
regex_file_hash = re.compile('[A-Fa-f0-9]{64}')
# Match sysmon_eventX, sysmon_event_XX, systemon_eidX(X)_detections, and sysmon_process-anomalies:
sha256_sysmon_event_regex = re.compile('sysmon_(?:(?:event_?|eid)(?:1|6|7|15|23|24|25)|process-anomalies)')
# Match sysmon_event3 and sysmon_eid3_detections:
sysmon_event3_regex = re.compile('sysmon_(?:event|eid)3')
# Match sysmon_event_22 and sysmon_eid22_detections:
sysmon_event22_regex = re.compile('sysmon_(?:event_|eid)22')
# Location of source events file:
log_file = '{0}/logs/integrations.log'.format(pwd)
# UNIX socket to send detections events to:
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
# Find ";"-separated entries that are not prefixed with "type: X ". In order to
# avoid non-fixed-width look-behind, match against the unwanted prefix, but
# only group the match we care about, and filter out the empty strings later:
dns_results_regex = re.compile(r'type:\s*\d+\s*[^;]+|([^\s;]+)')

def main(args):
    global url
    debug('# Starting')
    alert_path = args[1]
    # Documentation says to do args[2].split(':')[1], but this is incorrect:
    token = args[2]
    url = args[3]

    debug('# API key: {}'.format(token))
    debug('# Alert file location: {}'.format(alert_path))

    with open(alert_path, errors='ignore') as alert_file:
        alert = json.load(alert_file)

    debug('# Processing alert:')
    debug(alert)

    for new_alert in query_opencti(alert, url, token):
        send_event(new_alert, alert['agent'])

def debug(msg, do_log = False):
    do_log |= debug_enabled
    if not do_log:
        return

    now = time.strftime('%a %b %d %H:%M:%S %Z %Y')
    msg = '{0}: {1}\n'.format(now, msg)
    f = open(log_file,'a')
    f.write(msg)
    f.close()

def log(msg):
    debug(msg, do_log=True)

# Recursively remove all empty nulls, strings, empty arrays and empty dicts
# from a dict:
def remove_empties(value):
    # Keep booleans, but remove '', [] and {}:
    def empty(value):
        return False if isinstance(value, bool) else not bool(value)
    if isinstance(value, list):
        return [x for x in (remove_empties(x) for x in value) if not empty(x)]
    elif isinstance(value, dict):
        return {key: val for key, val in ((key, remove_empties(val)) for key, val in value.items()) if not empty(val)}
    else:
        return value

# Given an object 'output' with a list of objects (edges and nodes) at key
# 'listKey', create a new list at key 'newKey' with just values from the
# original list's objects at key 'valueKey'. Example: 
# {'objectLabel': {'edges': [{'node': {'value': 'cryptbot'}}, {'node': {'value': 'exe'}}]}}
# →
# {'labels:': ['cryptbot', 'exe']}
def simplify_objectlist(output, listKey, valueKey, newKey):
    edges = output[listKey]['edges']
    output[newKey] = [key[valueKey] for edge in edges for _, key in edge.items()]
    if newKey != listKey:
        # Delete objectLabels (array of objects) now that we have just the names:
        del output[listKey]

# Take a string, like
# "type:  5 youtube-ui.l.google.com;::ffff:142.250.74.174;::ffff:216.58.207.206;::ffff:172.217.21.174;::ffff:142.250.74.46;::ffff:142.250.74.110;::ffff:142.250.74.78;::ffff:216.58.207.238;::ffff:142.250.74.142;",
# discard records other than A/AAAA, ignore non-global addresses, and convert
# IPv4-mapped IPv6 to IPv4:
def format_dns_results(results):
    def unmap_ipv6(addr):
        if type(addr) is ipaddress.IPv4Address:
            return addr

        v4 = addr.ipv4_mapped
        return v4 if v4 else addr

    try:
        # Extract only A/AAAA records (and discard the empty strings):
        results = list(filter(len, dns_results_regex.findall(results)))
        # Convert IPv4-mapped IPv6 to IPv4:
        results = list(map(lambda x: unmap_ipv6(ipaddress.ip_address(x)).exploded, results))
        # Keep only global addresses:
        return list(filter(lambda x: ipaddress.ip_address(x).is_global, results))
    except ValueError:
        return []

# Determine whether alert contains a packetbeat DNS query:
def packetbeat_dns(alert):
    return all(key in alert['data'] for key in ('method', 'dns')) and alert['data']['method'] == 'QUERY'

# For every object in dns.answers, retrieve "data", but only if "type" is
# A/AAAA and the resulting address is a global IP address:
def filter_packetbeat_dns(results):
    return [r['data'] for r in results if (r['type'] == 'A' or r['type'] == 'AAAA') and ipaddress.ip_address(r['data']).is_global]

# Sort indicators based on
#  - Whether it is not revoked
#  - Whether the indicator has "detection"
#  - Score (the higher the better)
#  - Confidence (the higher the better)
#  - valid_until is before now():
def indicator_sort_func(x):
    return (x['revoked'], not x['x_opencti_detection'], -x['x_opencti_score'], -x['confidence'], datetime.strptime(x['valid_until'], '%Y-%m-%dT%H:%M:%S.%fZ') <= datetime.now())

def sort_indicators(indicators):
    # In case there are several indicators, and since we will only extract
    # one, sort them based on !revoked, detection, score, confidence and
    # lastly expiry:
    return sorted(indicators, key=indicator_sort_func)

# Modify the indicator object so that it is more fit for opensearch (simplify
# deeply-nested lists etc.):
def modify_indicator(indicator):
    if indicator:
        # Simplify object lists for indicator labels and kill chain phases:
        simplify_objectlist(indicator, listKey = 'objectLabel', valueKey = 'value', newKey = 'labels')
        simplify_objectlist(indicator, listKey = 'killChainPhases', valueKey = 'kill_chain_name', newKey = 'killChainPhases')
        if 'externalReferences' in indicator:
            # Extract URIs from external references:
            simplify_objectlist(indicator, listKey = 'externalReferences', valueKey = 'url', newKey = 'externalReferences')

    return indicator

def indicator_link(indicator):
    return url.removesuffix('graphql') + 'dashboard/observations/indicators/{0}'.format(indicator['id'])

# Modify the observable object so that it is more fit for opensearch (simplify
# deeply-nested lists etc.):
def modify_observable(observable, indicators):
    # Generate a link to the observable:
    observable['observable_link'] = url.removesuffix('graphql') + 'dashboard/observations/observables/{0}'.format(observable['id'])

    # Extract URIs from external references:
    simplify_objectlist(observable, listKey = 'externalReferences', valueKey = 'url', newKey = 'externalReferences')
    # Convert list of file objects to list of file names:
    #simplify_objectlist(observable, listKey = 'importFiles', valueKey = 'name', newKey = 'importFiles')
    # Convert list of label objects to list of label names:
    simplify_objectlist(observable, listKey = 'objectLabel', valueKey = 'value', newKey = 'labels')

    # Grab the first indicator (already sorted to get the most relevant one):
    observable['indicator'] = next(iter(indicators), None)
    # Indicate in the alert that there were multiple indicators:
    observable['multipleIndicators'] = len(indicators) > 1
    # Generate a link to the indicator:
    if observable['indicator']:
        observable['indicator_link'] = indicator_link(observable['indicator'])

    modify_indicator(observable['indicator'])
    # Remove the original list of objects:
    del observable['indicators']
    # Remove the original list of relationships:
    del observable['stixCoreRelationships']

# Domain name–IP address releationships are not always up to date in a CTI
# database (naturally). If a DNS enrichment connector is used to create
# "resolves-to" relationship (or "related-to"), it may be worth looking up
# relationships to the observable, and if these objects have indicators, create
# an alert:
def relationship_with_indicators(node):
    related = []
    try:
        for relationship in node['stixCoreRelationships']['edges']:
            if relationship['node']['related']['indicators']['edges']:
                related.append(dict(
                    id=relationship['node']['related']['id'],
                    type=relationship['node']['type'],
                    value=relationship['node']['related']['value'],
                    # Create a list of the individual node objects in indicator edges:
                    indicator = modify_indicator(next(iter(sort_indicators(list(map(lambda x:x['node'], relationship['node']['related']['indicators']['edges'])))), None)),
                    multipleIndicators = len(relationship['node']['related']['indicators']['edges']) > 1,
                    ))
                if related[-1]['indicator']:
                    related[-1]['indicator_link'] = indicator_link(related[-1]['indicator'])
    except KeyError:
        pass

    return next(iter(sorted(related, key=lambda x:indicator_sort_func(x['indicator']))), None)

def add_context(source_event, event):
    # Add source information to the original alert (naming convention
    # from official VirusTotal integration):
    event['opencti']['source'] = {}
    event['opencti']['source']['alert_id'] = source_event['id']
    if 'syscheck' in source_event:
        event['opencti']['source']['file'] = source_event['syscheck']['path']
        event['opencti']['source']['md5'] = source_event['syscheck']['md5_after']
        event['opencti']['source']['sha1'] = source_event['syscheck']['sha1_after']
        event['opencti']['source']['sha256'] = source_event['syscheck']['sha256_after']
    if 'data' in source_event:
        for key in ['in_iface', 'src_ip', 'src_mac', 'src_port', 'dest_ip', 'dst_mac', 'dest_port', 'proto', 'app_proto']:
            if key in source_event['data']:
                event['opencti']['source'][key] = source_event['data'][key]
        if packetbeat_dns(source_event):
            event['opencti']['source']['queryName'] = source_event['data']['dns']['question']['name']
            if 'answers' in source_event['data']['dns']:
                event['opencti']['source']['queryResults'] = ';'.join(map(lambda x:x['data'], source_event['data']['dns']['answers']))
        if 'alert' in source_event['data']:
            event['opencti']['source']['source_event'] = {}
            for key in ['action', 'category', 'signature', 'signature_id']:
                if key in source_event['data']['alert']:
                    event['opencti']['source']['alert'][key] = source_event['data']['alert'][key]
        if 'win' in source_event['data']:
            if 'eventdata' in source_event['data']['win']:
                for key in ['queryName', 'queryResults', 'image']:
                    if key in source_event['data']['win']['eventdata']:
                        event['opencti']['source'][key] = source_event['data']['win']['eventdata'][key]

def send_event(msg, agent = None):
    if not agent or agent['id'] == '000':
        string = '1:opencti:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->opencti:{3}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any', json.dumps(msg))

    debug('# Event:')
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

def send_error_event(msg, agent = None):
    send_event({'integration': 'opencti', 'opencti': {
        'error': msg,
        'event_type': 'error',
        }}, agent)

# Construct a stix pattern for a single IP address, either IPv4 or IPv6:
def ind_ip_pattern(string):
    if ipaddress.ip_address(string).version == 6:
        return f"[ipv6-addr:value = '{string}']"
    else:
        return f"[ipv4-addr:value = '{string}']"

def query_opencti(alert, url, token):
    # The OpenCTI graphql query is filtering on a key and a list of values. By
    # default, this key is "value", unless set to "hashes.SHA256":
    filter_key='value'
    groups = alert['rule']['groups']

    # TODO: Look up registry keys/values? No such observables in OpenCTI yet from any sources

    # In case a key or index lookup fails, catch this and gracefully exit. Wrap
    # logic in a try–catch:
    try:
        # For any sysmon event that provides a sha256 hash (matches the group
        # name regex):
        if any(True for _ in filter(sha256_sysmon_event_regex.match, groups)):
            filter_key='hashes.SHA256'
            # It is not a 100 % guaranteed that there is a (valid) sha256 hash
            # present in the metadata. Quit if no hash is found:
            match = regex_file_hash.search(alert['data']['win']['eventdata']['hashes'])
            if match:
                filter_values = [match.group(0)]
                ind_filter = [f"[file:hashes.'SHA-256' = '{match.group(0)}']"]
            else:
                sys.exit()
        # Sysmon event 3 contains IP addresses, which will be queried:
        elif any(True for _ in filter(sysmon_event3_regex.match, groups)):
            filter_values = [alert['data']['win']['eventdata']['destinationIp']]
            ind_filter = [ind_ip_pattern(filter_values[0])]
            if not ipaddress.ip_address(filter_values[0]).is_global:
                sys.exit()
        # Group 'ids' may contain IP addresses.
        # This may be tailored for suricata, but we'll match against the "ids"
        # group. These keys are probably used by other decoders as well:
        elif 'ids' in groups:
            # If data contains dns, it may contain a DNS query from packetbeat:
            if packetbeat_dns(alert):
                addrs = filter_packetbeat_dns(alert['data']['dns']['answers']) if 'answers' in alert['data']['dns'] else []
                filter_values = [alert['data']['dns']['question']['name']] + addrs
                ind_filter = [f"[domain-name:value = '{filter_values[0]}']"] + list(map(lambda a: ind_ip_pattern(a), addrs))
            else:
                # Look up either dest or source IP, whichever is public:
                filter_values = [next(filter(lambda x: ipaddress.ip_address(x).is_global, [alert['data']['dest_ip'], alert['data']['src_ip']]), None)]
                ind_filter = [ind_ip_pattern(filter_values[0])] if filter_values else None
            if not filter_values:
                sys.exit()
        # Look up domain names in DNS queries (sysmon event 22), along with the
        # results (if they're IPv4/IPv6 addresses (A/AAAA records)):
        elif any(True for _ in filter(sysmon_event22_regex.match, groups)):
            query = alert['data']['win']['eventdata']['queryName']
            results = format_dns_results(alert['data']['win']['eventdata']['queryResults'])
            filter_values = [query] + results
            ind_filter = [f"[domain-name:value = '{filter_values[0]}']"] + list(map(lambda a: ind_ip_pattern(a), results))
        # Look up sha256 hashes for files added to the system or files that have been modified:
        elif 'syscheck_file' in groups and any(x in groups for x in ['syscheck_entry_added', 'syscheck_entry_modified']):
            filter_key = 'hashes.SHA256'
            filter_values = [alert['syscheck']['sha256_after']]
            ind_filter = [f"[file:hashes.'SHA-256' = '{filter_values[0]}']"]
        # Look up sha256 hashes in columns of any osqueries:
        # Currently, only osquery_file is defined in wazuh_manager.conf, but add 'osquery' for future use(?):
        elif any(x in groups for x in ['osquery', 'osquery_file']):
            filter_key = 'hashes.SHA256'
            filter_values = [alert['data']['osquery']['columns']['sha256']]
            ind_filter = [f"[file:hashes.'SHA-256' = '{filter_values[0]}']"]
        # Nothing to do:
        else:
            sys.exit()

    # Don't treat a non-existent index or key as an error. If they don't exist,
    # there is certainly no alert to make. Just quit:
    except IndexError:
        sys.exit()
    except KeyError:
        sys.exit()

    query_headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}',
        'Accept': '*/*'
    }
    # Look for hashes, addresses and domain names is as many places as
    # possible, and return as much information as possible.
    api_json_body={'query':
            '''
            fragment Labels on StixCoreObject {
              objectLabel {
                edges {
                  node {
                    value
                  }
                }
              }
            }

            fragment Object on StixCoreObject {
              id
              created_at
              updated_at
              createdBy {
                ... on Identity {
                  id
                  standard_id
                  identity_class
                  name
                }
                ... on Organization {
                  x_opencti_organization_type
                  x_opencti_reliability
                }
                ... on Individual {
                  x_opencti_firstname
                  x_opencti_lastname
                }
              }
              ...Labels
              externalReferences {
                edges {
                  node {
                    source_name
                    url
                  }
                }
              }
            }

            fragment IndShort on Indicator {
              id
              name
              valid_until
              revoked
              confidence
              x_opencti_score
              x_opencti_detection
              indicator_types
              x_mitre_platforms
              pattern_type
              pattern
              ...Labels
              killChainPhases {
                edges {
                  node {
                    kill_chain_name
                  }
                }
              }
            }

            fragment IndLong on Indicator {
              ...Object
              ...IndShort
            }

            fragment Indicators on StixCyberObservable {
              indicators {
                edges {
                  node {
                    ...IndShort
                  }
                }
              }
            }

            fragment PageInfo on PageInfo {
              startCursor
              endCursor
              hasNextPage
              hasPreviousPage
              globalCount
            }

            query IoCs($obs: FilterGroup, $ind: FilterGroup) {
              indicators(filters: $ind, first: 10) {
                edges {
                  node {
                    ...IndLong
                  }
                }
                pageInfo {
                  ...PageInfo
                }
              }

              stixCyberObservables(filters: $obs, first: 10) {
                edges {
                  node {
                    ...Object
                    entity_type
                    observable_value
                    x_opencti_description
                    x_opencti_score
                    ...Indicators
                    ... on DomainName {
                      value
                      stixCoreRelationships(toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name"]) {
                        edges {
                          node {
                            type: toType
                            related: to {
                              ... on IPv4Addr {
                                id
                                value
                                ...Indicators
                              }
                              ... on IPv6Addr {
                                id
                                value
                                ...Indicators
                              }
                              ... on DomainName {
                                id
                                value
                                ...Indicators
                              }
                            }
                          }
                        }
                      }
                    }
                    ... on IPv4Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name"]) {
                        edges {
                          node {
                            type: fromType
                            related: from {
                              ... on DomainName {
                                id
                                value
                                ...Indicators
                              }
                            }
                          }
                        }
                      }
                    }
                    ... on IPv6Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name"]) {
                        edges {
                          node {
                            type: fromType
                            related: from {
                              ... on DomainName {
                                id
                                value
                                ...Indicators
                              }
                            }
                          }
                        }
                      }
                    }
                    ... on Hostname {
                      value
                    }
                    ... on StixFile {
                      extensions
                      size
                      name
                      x_opencti_additional_names
                    }
                  }
                }
                pageInfo {
                  ...PageInfo
                }
              }
            }
            ''' , 'variables': {
                    'obs': {
                        "mode": "or",
                        "filterGroups": [],
                        "filters": [{"key": filter_key, "values": filter_values}]
                    },
                    'ind': {
                        "mode": "and",
                        "filterGroups": [],
                        "filters": [
                            {"key": "pattern_type", "values": ["stix"]},
                            {"mode": "or", "key": "pattern", "values": ind_filter},
                        ]
                    }
                    }}
    #debug('# Query:')
    #debug(api_json_body)

    new_alerts = []
    try:
        response = requests.post(url, headers=query_headers, json=api_json_body)
    # Create an alert if the OpenCTI service cannot be reached:
    except ConnectionError:
        log('Failed to connect to {}'.format(url))
        send_error_event('Failed to connect to the OpenCTI API', alert['agent'])
        sys.exit(1)

    try:
        response = response.json()
    except json.decoder.JSONDecodeError:
        # If the API returns data, but not valid JSON, it is typically an error
        # code.
        log('# Failed to parse response from API')
        send_error_event('Failed to parse response from OpenCTI API', alert['agent'])
        sys.exit(1)

    debug('# Response:')
    debug(response)

    # Sort indicators based on a number of factors in order to prioritise them
    # in case many are returned:
    direct_indicators = sorted(
            # Extract the indicator objects (nodes) from the indicator list in
            # the response:
            list(map(lambda x:x['node'], response['data']['indicators']['edges'])),
            key=indicator_sort_func)
    # As opposed to indicators for observables, create an alert for every
    # indicator (limited by max_ind_alerts and the fixed limit in the query
    # (see "first: X")):
    for indicator in direct_indicators[:max_ind_alerts]:
        new_alert = {'integration': 'opencti', 'opencti': {
            'indicator': modify_indicator(indicator),
            'indicator_link': indicator_link(indicator),
            'query_key': filter_key,
            'query_values': ';'.join(ind_filter),
            'event_type': 'indicator_pattern_match' if indicator['pattern'] == ind_filter else 'indicator_partial_pattern_match',
            }}
        add_context(alert, new_alert)
        new_alerts.append(remove_empties(new_alert))

    for edge in response['data']['stixCyberObservables']['edges']:
        node = edge['node']

        # Create a list of the individual node objects in indicator edges:
        indicators = sort_indicators(list(map(lambda x:x['node'], node['indicators']['edges'])))
        # Get related obsverables (typically between IP addresses and domain
        # names) if they have indicators (retrieve only one indicator):
        related_obs_w_ind = relationship_with_indicators(node)

        # Remove indicators already found directly in the indicator query:
        if indicators:
            indicators = [i for i in indicators if i['id'] not in [di['id'] for di in direct_indicators]]
        if related_obs_w_ind and related_obs_w_ind['indicator']['id'] in [di['id'] for di in direct_indicators]:
            related_obs_w_ind = None

        # If the observable has no indicators, ignore it:
        if not indicators and not related_obs_w_ind:
            # TODO: Create event for this?
            debug(f'# Observable found ({node["id"]}), but it has no indicators')
            continue

        new_alert = {'integration': 'opencti', 'opencti': edge['node']}
        new_alert['opencti']['related'] = related_obs_w_ind
        new_alert['opencti']['query_key'] = filter_key
        new_alert['opencti']['query_values'] = ';'.join(filter_values)
        new_alert['opencti']['event_type'] = 'observable_with_indicator' if indicators else 'observable_with_related_indicator'

        modify_observable(new_alert['opencti'], indicators)

        add_context(alert, new_alert)
        # Remove all nulls, empty lists and objects, and empty strings:
        new_alerts.append(remove_empties(new_alert))

    return new_alerts

if __name__ == '__main__':
    try:
        if len(sys.argv) >= 4:
            debug('{0} {1} {2} {3}'.format(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ''), do_log = True)
        else:
            log('Incorrect arguments: {0}'.format(' '.join(sys.argv)))
            sys.exit(1)

        debug_enabled = len(sys.argv) > 4 and sys.argv[4] == 'debug'

        main(sys.argv)
    except Exception as e:
        debug(str(e), do_log = True)
        debug(traceback.format_exc(), do_log = True)
        raise
