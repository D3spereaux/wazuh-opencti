#!/usr/bin/env python

# Copyright Andreas Misje 2024, 2022 Aurora Networks Managed Services
# See https://github.com/misje/wazuh-opencti for documentation
# Modified by Brian Dao
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
import logging

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
log_file = '/var/ossec/logs/debug-custom-opencti.log'
# UNIX socket to send detections events to:
socket_addr = '/var/ossec/queue/sockets/queue'
# Find ";"-separated entries that are not prefixed with "type: X ". In order to
# avoid non-fixed-width look-behind, match against the unwanted prefix, but
# only group the match we care about, and filter out the empty strings later:
dns_results_regex = re.compile(r'type:\s*\d+\s*[^;]+|([^\s;]+)')

# Set up logging with debug level
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,  # Changed to DEBUG for detailed logging
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

def main(args):
    global url
    logger.debug('# Starting')
    alert_path = args[1]
    # Documentation says to do args[2].split(':')[1], but this is incorrect:
    token = args[2]
    url = args[3]

#    logger.debug('# API key: {}'.format(token))
#    logger.debug('# Alert file location: {}'.format(alert_path))

    with open(alert_path, errors='ignore') as alert_file:
        alert = json.load(alert_file)

    logger.debug('# Processing alert:')
    logger.debug(alert)

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
# {'objectLabel': [{'value': 'cryptbot'}, {'value': 'exe'}]}
# →
# {'labels:': ['cryptbot', 'exe']}
def simplify_objectlist(output, listKey, valueKey, newKey):
    if 'edges' in output[listKey]:
        edges = output[listKey]['edges']
        output[newKey] = [key[valueKey] for edge in edges for _, key in edge.items()]
    else:
        output[newKey] = [key[valueKey] for key in output[listKey]]

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
    """
    Modify the observable object so that it is more fit for opensearch (simplify
    deeply-nested lists etc.).

    This function takes an observable object and a list of indicator objects as
    input. It will generate a link to the observable, simplify the labels and
    external references, grab the most relevant indicator (using the
    indicator_sort_func), and generate a link to the indicator. Additionally, it
    will indicate in the alert that there were multiple indicators.

    :param observable: The observable object to modify
    :param indicators: A list of indicator objects to pick from
    :return: The modified observable object
    """
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
    """
    Analyzes the relationships of a given node to identify related indicators
    and enriches them with additional information.

    Parameters:
    node (dict): A dictionary containing a node with its STIX core relationships.

    Returns:
    dict or None: A dictionary containing the most relevant related indicator
    with its ID, type, relationship, value, a modified indicator object, and
    a link to the indicator if available. Returns None if no such indicator is found.

    The function processes the 'stixCoreRelationships' in the node, extracting
    indicators from related nodes. It modifies these indicators to include
    additional information relevant for alert generation. The indicators are
    sorted based on relevance criteria, and the most relevant one is returned.
    """

    related = []
    try:
        for relationship in node['stixCoreRelationships']['edges']:
            if relationship['node']['related']['indicators']['edges']:
                related.append(dict(
                    id=relationship['node']['related']['id'],
                    type=relationship['node']['type'],
                    relationship=relationship['node']['relationship_type'],
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
    """
    Add context to an event based on a source event. The source event is
    expected to be a JSON object with keys 'id', 'rule', 'syscheck', 'data',
    and optionally 'alert' and 'win'. The function extracts relevant
    information from the source event and adds it to the event as a nested
    dictionary under the 'opencti' key.

    The information extracted from the source event includes the alert_id and
    rule_id, syscheck information (file, md5, sha1, sha256), data from the
    source event (in_iface, srcintf, src_ip, srcip, src_mac, srcmac, src_port,
    srcport, dest_ip, dstip, dest_mac, dstmac, dest_port, dstport, dstintf,
    proto, app_proto), DNS data (queryName, queryResults), alert data
    (action, category, signature, signature_id), Windows event data
    (queryName, queryResults, image), and audit execve data (success, key,
    uid, gid, euid, egid, exe, exit, pid).

    If the source event does not contain the expected keys, the function will
    not add any context to the event. If the source event contains invalid
    data, the function will log a warning.

    :param source_event: A JSON object containing the source event
    :param event: The event to add context to
    :return: The modified event with added context
    """
    logger.debug(f'Source Event: {source_event}')
    logger.debug(f'Event: {event}')
    try:
        # Initialize opencti and source dictionaries if not present
        if 'opencti' not in event:
            event['opencti'] = {}
        if 'source' not in event['opencti']:
            event['opencti']['source'] = {}

        # Add basic source information
        event['opencti']['source']['alert_id'] = source_event['id']
        event['opencti']['source']['rule_id'] = source_event['rule']['id']

        # Add syscheck information if present
        if 'syscheck' in source_event:
            event['opencti']['source']['file'] = source_event['syscheck']['path']
            event['opencti']['source']['md5'] = source_event['syscheck']['md5_after']
            event['opencti']['source']['sha1'] = source_event['syscheck']['sha1_after']
            event['opencti']['source']['sha256'] = source_event['syscheck']['sha256_after']

        # Process data field if present
        if 'data' in source_event:
            for key in ['in_iface', 'srcintf', 'src_ip', 'srcip', 'src_mac', 'srcmac', 'src_port', 'srcport', 
                        'dest_ip', 'dstip', 'dst_mac', 'dstmac', 'dest_port', 'dstport', 'dstintf', 'proto', 'app_proto']:
                if key in source_event['data']:
                    event['opencti']['source'][key] = source_event['data'][key]

            # Process DNS data if present
            if packetbeat_dns(source_event):
                event['opencti']['source']['queryName'] = source_event['data']['dns']['question']['name']
                if 'answers' in source_event['data']['dns']:
                    event['opencti']['source']['queryResults'] = ';'.join(map(lambda x: x['data'], source_event['data']['dns']['answers']))

            # Process alert data if present and valid
            if 'alert' in source_event['data'] and isinstance(source_event['data']['alert'], dict):
                event['opencti']['source']['alert'] = {}  # Initialize alert dictionary
                for key in ['action', 'category', 'signature', 'signature_id']:
                    if key in source_event['data']['alert']:
                        event['opencti']['source']['alert'][key] = source_event['data']['alert'][key]
                logger.debug("Added alert context for alert_id %s: %s", source_event['id'], event['opencti']['source']['alert'])
            elif 'alert' in source_event['data']:
                logger.warning("Invalid 'alert' data in source_event['data'] for alert_id %s: %s", 
                               source_event['id'], source_event['data']['alert'])
            else:
                logger.debug("No 'alert' key in source_event['data'] for alert_id %s", source_event['id'])

            # Process Windows event data if present
            if 'win' in source_event['data'] and 'eventdata' in source_event['data']['win']:
                for key in ['queryName', 'queryResults', 'image']:
                    if key in source_event['data']['win']['eventdata']:
                        event['opencti']['source'][key] = source_event['data']['win']['eventdata'][key]

            # Process audit execve data if present
            if 'audit' in source_event['data'] and 'execve' in source_event['data']['audit']:
                event['opencti']['source']['execve'] = ' '.join(source_event['data']['audit']['execve'][key] for key in sorted(source_event['data']['audit']['execve'].keys()))
                for key in ['success', 'key', 'uid', 'gid', 'euid', 'egid', 'exe', 'exit', 'pid']:
                    if key in source_event['data']['audit']:
                        event['opencti']['source'][key] = source_event['data']['audit'][key]

        logger.debug("Successfully added context for alert_id: %s", source_event['id'])
    except Exception as e:
        logger.error("Error adding context for alert_id %s: %s", source_event.get('id', 'unknown'), str(e))

def send_event(msg, agent = None):
    """Send an event to the Wazuh Manager."""
    try:
        if not agent or agent['id'] == '000':
            string = '1:opencti:{0}'.format(json.dumps(msg))
        else:
            string = '1:[{0}] ({1}) {2}->opencti:{3}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any', json.dumps(msg))
        logger.debug(f"Sending Event: {string}")
        with socket(AF_UNIX, SOCK_DGRAM) as sock:
            sock.connect(socket_addr)
            sock.send(string.encode())
    except Exception as e:
        logger.debug(f"Error sending event: {e}")

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

# Return the value of the first key argument that exists in within:
def oneof(*keys, within):
    return next((within[key] for key in keys if key in within), None)

def query_opencti(alert, url, token):
    """
    Construct a query to the OpenCTI API and return a list of alerts based on the
    response. The query is constructed based on the group names in the alert.
    Currently, the following group names are processed:

    - ids: Look up either dest or source IP, whichever is public
    - sysmon_event3: Look up either dest or source IP, whichever is public
    - sysmon_event22: Look up domain names in DNS queries, along with the results
    - syscheck_file: Look up sha256 hashes for files added to the system or files
      that have been modified
    - osquery_file: Look up sha256 hashes in columns of any osqueries
    - audit_command: Extract any command line arguments that looks vaguely like a
      URL (starts with 'http')

    :param alert: The alert to process
    :param url: The URL of the OpenCTI API
    :param token: The API token for the OpenCTI API
    :return: A list of alerts based on the response from the OpenCTI API
    """
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
            # Check if DNS data exists in the alert
            if 'dns' in alert['data'] and 'query' in alert['data']['dns'] and alert['data']['dns']['query']:
                # Extract rrname from DNS query
                rrname = alert['data']['dns']['query'][0].get('rrname', '')
                logger.debug(f'Extract rrname to check: {rrname}')
                # Look up either dest or source IP, whichever is public
                public_ip = next(filter(lambda x: x and ipaddress.ip_address(x).is_global, [
                    oneof('dest_ip', 'dstip', within=alert['data']),
                    oneof('src_ip', 'srcip', within=alert['data'])
                ]), None)
                filter_values = [public_ip, rrname] if public_ip else [rrname]
                ind_filter = []
                if public_ip:
                    ind_filter.append(ind_ip_pattern(public_ip))
                    logger.debug(f'Extract public IP to check: {public_ip}')
                    logger.debug(f'New Indicator Filter: {ind_filter}')
                if rrname:
                    ind_filter.extend([
                        f"[domain-name:value = '{rrname}']",
                        f"[hostname:value = '{rrname}']"
                    ])
                    logger.debug(f'New Indicator Filter: {ind_filter}')
            else:
                # No DNS data, fall back to IP only
                public_ip = next(filter(lambda x: x and ipaddress.ip_address(x).is_global, [
                    oneof('dest_ip', 'dstip', within=alert['data']),
                    oneof('src_ip', 'srcip', within=alert['data'])
                ]), None)
                filter_values = [public_ip]
                ind_filter = [ind_ip_pattern(public_ip)] if public_ip else None
                logger.debug(f'Extract public IP to check: {public_ip}')
                logger.debug(f'New Indicator Filter: {ind_filter}')
            if not all(v for v in filter_values if v):
                sys.exit()

            # If data contains dns, it may contain a DNS query from packetbeat:
            if packetbeat_dns(alert):
                addrs = filter_packetbeat_dns(alert['data']['dns']['answers']) if 'answers' in alert['data']['dns'] else []
                filter_values = [alert['data']['dns']['question']['name']] + addrs
                ind_filter = [f"[domain-name:value = '{filter_values[0]}']", f"[hostname:value = '{filter_values[0]}']"] + list(map(lambda a: ind_ip_pattern(a), addrs))
            else:
                # Look up either dest or source IP, whichever is public:
                filter_values = [next(filter(lambda x: x and ipaddress.ip_address(x).is_global, [oneof('dest_ip', 'dstip', within=alert['data']), oneof('src_ip', 'srcip', within=alert['data'])]), None)]
                ind_filter = [ind_ip_pattern(filter_values[0])] if filter_values else None
            if not all(filter_values):
                sys.exit()

        # Look up domain names in DNS queries (sysmon event 22), along with the
        # results (if they're IPv4/IPv6 addresses (A/AAAA records)):
        elif any(True for _ in filter(sysmon_event22_regex.match, groups)):
            query = alert['data']['win']['eventdata']['queryName']
            results = format_dns_results(alert['data']['win']['eventdata']['queryResults'])
            filter_values = [query] + results
            ind_filter = [f"[domain-name:value = '{filter_values[0]}']", f"[hostname:value = '{filter_values[0]}']"] + list(map(lambda a: ind_ip_pattern(a), results))
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
        elif 'audit_command' in groups:
            # Extract any command line arguments that looks vaguely like a URL (starts with 'http'):
            filter_values = [val for val in alert['data']['audit']['execve'].values() if val.startswith('http')]
            ind_filter = list(map(lambda x: f"[url:value = 'x']", filter_values))
            if not filter_values:
                sys.exit()
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
                value
              }
            }

            fragment Object on StixCoreObject {
              id
              type: entity_type
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
                kill_chain_name
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

            fragment NameRelation on StixObjectOrStixRelationshipOrCreator {
              ... on DomainName {
                id
                value
                ...Indicators
              }
              ... on Hostname {
                id
                value
                ...Indicators
              }
            }

            fragment AddrRelation on StixObjectOrStixRelationshipOrCreator {
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
                    observable_value
                    x_opencti_description
                    x_opencti_score
                    ...Indicators
                    ... on DomainName {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on Hostname {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on Url {
                      value
                      stixCoreRelationships(
                        toTypes: ["IPv4-Addr", "IPv6-Addr", "Domain-Name", "Hostname"]
                      ) {
                        edges {
                          node {
                            type: toType
                            relationship_type
                            related: to {
                              ...AddrRelation
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on IPv4Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: fromType
                            relationship_type
                            related: from {
                              ...NameRelation
                            }
                          }
                        }
                      }
                    }
                    ... on IPv6Addr {
                      value
                      stixCoreRelationships(fromTypes: ["Domain-Name", "Hostname"]) {
                        edges {
                          node {
                            type: fromType
                            relationship_type
                            related: from {
                              ...NameRelation
                            }
                          }
                        }
                      }
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
    debug('# Query:')
    debug(api_json_body)

    new_alerts = []
    try:
        response = requests.post(url, headers=query_headers, json=api_json_body)
    # Create an alert if the OpenCTI service cannot be reached:
    except ConnectionError:
        logger.debug('Failed to connect to {}'.format(url))
        send_error_event('Failed to connect to the OpenCTI API', alert['agent'])
        sys.exit(1)

    try:
        response = response.json()
    except json.decoder.JSONDecodeError:
        # If the API returns data, but not valid JSON, it is typically an error
        # code.
        logger.debug('# Failed to parse response from API')
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
            'event_type': 'indicator_pattern_match' if indicator['pattern'] in ind_filter else 'indicator_partial_pattern_match',
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
            logger.debug(f'# Observable found ({node["id"]}), but it has no indicators')
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
            logger.debug('{0} {1} {2} {3}'.format(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else ''))
        else:
            logger.debug('Incorrect arguments: {0}'.format(' '.join(sys.argv)))
            sys.exit(1)

        debug_enabled = len(sys.argv) > 4 and sys.argv[4] == 'debug'

        main(sys.argv)
    except Exception as e:
        debug(str(e), do_log = True)
        debug(traceback.format_exc(), do_log = True)
        raise
