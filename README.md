# Wazuh OpenCTI integration

## Intro

wazuh-opencti is a [Wazuh
integration](https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html)
that looks up alert metadata in an
[OpenCTI](https://www.filigran.io/en/products/opencti) threat intel database.
If the metadata is found in any STIX indicator, the integration will create a
Wazuh alert with plenty of metadata from the OpenCTI
[observable](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_p49j1fwoxldc)
and
[indicator](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_muftrcpnf89v).

wazuh-opencti operates on
- SHA256 hashes (typically from files)
- IP addresses (IPv4/IPv6)
- Domain names (like DNS queries)
- Hostnames (like DNS queries)

and inspects events from sysmon, syscheck, suricata and osquery. The script can
easily be extended to match other types of events as well.

The integration will only inspect events whose *rule.groups* matches
- sysmon events 1, 3, 6, 7, 15, 22, 23, 24, 25
- ids
- syscheck\_file
- osquery
- osquery\_file

The logic is as follows:

- The value to look up is queried against observables (stixCyberObservables)
  and indicators (indicators)
- For every indicator that matches (the indicator has to have pattern\_type
  "stix", and it has to be a single-value (simple) pattern, like
  *[file:hashes.'SHA-256' =
  '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'* or
  *[domain-name:value = 'example.org'*), an alert of type
  *indicator_pattern_match* is created. A maximum of three alerts are created
  (configurable by modifying the *max_ind_alerts* variable), and a maximum of 10
  indicators are returned by the query for processing and filtering. Indicators
  are sorted by !revoked, detection, score, confidence and valid\_until. If the
  indicator only matches partially, the event type will be
  *indicator_partial_pattern_match*.
- For every observable that matches (either by *value* or *hashes_SHA256*,
  depending on the type of observable), an alert is created if the
  observable has an indicator related to it. Only one indicator is included,
  and they are sorted like mentioned above before picking the first one. The
  alert\_type is *observable_with_indicator*. A maximum of two alerts are created
  (configurable by modifying the *max_obs_alerts* variable), and a maximum of
  10 observables are returned by the query.
- If the observable is related to other observables (IP addresses and domain
  names), and those observables have indicators, the related indicator is
  included in the event. If the observable only has related indicators, the
  event\_type is *observable_with_related_indicator*.

## Requirements

* An OpenCTI instance (version 5.12.24 or higher) up and running
  * Older versions are supported, but you need to revert the changes in #13/#11
    and/or #15 in order to support the older graphql filter syntax.
* A read-only OpenCTI API token suitable for querying data (*Access knowledge*
  \+ *Access exploration*(?))

## Installation

Copy the two *custom-opencti* files into your Wazuh manager integrations
directory, */var/ossec/integrations*. If you're using docker, this will be the
root directory in the *wazuh_integrations* volume.

## Configuration

Modify your manager configuration file, */var/ossec/etc/ossec.conf*. If you're
using docker, this will be the file *config/wazuh_cluster/wazuh_manager.conf*.
Add an entry like the following to an `<ossec_config>` block:

```xml
  <integration>
     <name>custom-opencti</name>
     <group>sysmon_eid1_detections,sysmon_eid3_detections,sysmon_eid7_detections,sysmon_eid22_detections,syscheck_file,osquery_file,ids,sysmon_process-anomalies</group>
     <alert_format>json</alert_format>
     <api_key>REPLACE-ME-WITH-A-VALID-TOKEN</api_key>
     <hook_url>https://my.opencti.location/graphql</hook_url>
  </integration>
```

Be sure to replace **api_key** and **hook_url**. You should also modify
**group** to match entries in events' *rule.groups* that you want to inspect.
You may use `<rule_id>` instead of `<group>` to match individual rules instead,
but note that **you cannot mix both!** If you use `<rule_id>`, `<group>` will
be ignored.

wazuh-opencti looks at events' *rule.groups* before querying OpenCTI.
Currently, it only cares about events related to sysmon, syscheck (file),
suricata/packetbeat and osquery. If you look at the configuration example
above, you'll notice that **sysmon_eidX_detections** is used instead of
**sysmon_eventX**.  This is because Wazuh (at least as of 4.3.9) doesn't
produce any sysmon\_eventX events. – Only specific *detections* events. Also
note that 4.3.9 doesn't even have basic rules that cover all of the sysmon
events. You may need to add rules for sysmon event 16–25. Event 22–25 is used
by this integration.

All monitored directories and files through syscheck will be inspected without
further configuration (as long as "syscheck" is part of *<group>* as described
earlier), but DNS queries will have to be manually configured to be logged and
subsequently look up by this integration. If you do not already have a rule
that logs DNS queries, use the following examples as guidance:

On Windows (sysmon):
```xml
<group name="sysmon,sysmon_eid22_detections,windows,">
   <rule id="100140" level="3">
      <if_sid>61650</if_sid>
      <description>DNS query for $(win.eventdata.queryName)</description>
   </rule>
</group>
```

On Linux (using packetbeat):
```xml
<group name="packetbeat,ids">
   <rule id="101000" level="0">
      <decoded_as>json</decoded_as>
      <field name="@source">packetbeat</field>
      <options>no_full_log</options>
      <description>packetbeat messages grouped</description>
   </rule>

   <rule id="101001" level="3">
      <if_sid>101000</if_sid>
      <field name="method">QUERY</field>
      <mitre>
         <id>T1071</id>
      </mitre>
      <description>DNS query for $(dns.question.name)</description>
      <options>no_full_log</options>
   </rule>
</group>
```

In order for Wazuh to create alerts when an IoC is found, a rule is needed.
Rules for when the integration fails to operate are also highly recommended.
Here is an example rule set (be sure to replace the rule IDs to avoid conflicts
in your setup):

```xml
<group name="threat_intel,">
   <rule id="100210" level="10">
      <field name="integration">opencti</field>
      <description>OpenCTI</description>
      <group>opencti,</group>
   </rule>

   <rule id="100211" level="5">
      <if_sid>100210</if_sid>
      <field name="opencti.error">\.+</field>
      <description>OpenCTI: Failed to connect to API</description>
      <options>no_full_log</options>
      <group>opencti,opencti_error,</group>
   </rule>

   <rule id="100212" level="12">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">indicator_pattern_match</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100213" level="12">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">observable_with_indicator</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.indicator.observable_value)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100214" level="10">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">observable_with_related_indicator</field>
      <description>OpenCTI: IoC possibly found in threat intel (related): $(opencti.related.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>

   <rule id="100215" level="10">
      <if_sid>100210</if_sid>
      <field name="opencti.event_type">indicator_partial_pattern_match</field>
      <description>OpenCTI: IoC possibly found in threat intel: $(opencti.indicator.name)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
</group>
```

This integration looks up observables with indicators that are related to an
observable. For instance, if a domain name has no indicators, but the IPv4
address it resolves to (if such a relationship exists in OpenCTI) has an
indicator, an alert with *event_type* **observable_with_related_indicator** is
created. This may produce noise depending on your database, so you may want to
have a different level on this alert, as in the example above. A connector like
[google-dns](https://github.com/OpenCTI-Platform/connectors/tree/master/internal-enrichment/google-dns)
can be enabled to create automatic relationships between addresses and domain
name objects.

In order to test that the integration works, create an observable in OpenCTI
with a SHA256 hash that matches a file you will later create or move in Windows
or Linux. Then create an indicator (wazuh-opencti only creates alerts if an
observable has an indicator tied to it). Depending om your syscheck setup, put
the file with the matching hash in a monitored directory and wait for the alert
to be created. If you don't have a real-time syscheck setup yet, consider
setting one up for *C:\\Users\\\*\Downloads*.

During testing and development, it may be very useful to enable debug output
from the integration. Debug output may be enabled in [internal
options](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html#integrator).
If you're using docker, add `integrator.debug = 1` to
*local_internal_options.conf* in the *wazuh_etc* volume.  The log is found in
*/var/ossec/logs/integrations.log*. If you're using docker docker, run
`docker-compose exec wazuh.manager tail -f /var/ossec/logs/integrations.log`.
If the log is empty, check the Wazuh manager log and ensure that the
integration doesn't fail and return an exit value of 1.

### Event types / rule groups used to trigger OpenCTI API calls

| group name | metadata |
| ---------- | -------- |
 sysmon\_event1, sysmon\_eid1\_detections | win.eventdata.hashes |
 sysmon\_event6, sysmon\_eid6\_detections | win.eventdata.hashes |
 sysmon\_event7, sysmon\_eid7\_detections | win.eventdata.hashes |
 sysmon\_event\_15, sysmon\_eid15\_detections | win.eventdata.hashes |
 sysmon\_event\_22, sysmon\_eid22\_detections | win.eventdata.queryName, win.eventdata.queryResults |
 sysmon\_event\_23, sysmon\_eid23\_detections | win.eventdata.hashes |
 sysmon\_event\_24, sysmon\_eid24\_detections | win.eventdata.hashes |
 sysmon\_event\_25, sysmon\_eid25\_detections | win.eventdata.hashes |
 sysmon\_process-anomalies | win.eventdata.hashes |
 ids | dest\_ip, destip, src\_ip, srcip, dns.question.name, dns.question.answers |
 osquery, osquery\_file | osquery.columns.sha256 |
 
## Customisation

Feel free to modify custom-opencty.py to suit your needs. It was designed to
cover my own needs, but I am sure that there are other events and groups this
integration could inspect. I would greatly appreciate if you could provide a
pull request to enhance the script if you think others may benefit from your
modifications.

## Examples

Here are some examples of how the events produced are. The data is just for
demonstration.

### DNS query with an IP addresse matching an indicator pattern

| Key | Value |
| --- | ----- |
| @timestamp | 2023-08-31T10:34:33.222Z |
| \_id | REDACTED |
| agent.id | REDACTED |
| agent.ip | REDACTED |
| agent.name | REDACTED |
| data.integration | opencti |
| data.opencti.event\_type | indicator\_pattern\_match |
| data.opencti.indicator.confidence | 70 |
| data.opencti.indicator.createdBy.id | b975431a-59a9-4982-b75c-cff659801f15 |
| data.opencti.indicator.createdBy.identity\_class | organization |
| data.opencti.indicator.createdBy.name | ThreatFox Abuse.ch |
| data.opencti.indicator.createdBy.standard\_id | identity--15d97c2e-9367-521e-9306-03a9c99c538d |
| data.opencti.indicator.created\_at | 2023-08-30T13:39:42.959Z |
| data.opencti.indicator.externalReferences | https://attack.mitre.org/software/S0154/ |
| data.opencti.indicator.id | 4c14daab-d133-43b6-88ef-e82ec0fd337a |
| data.opencti.indicator.indicator\_types | malicious-activity |
| data.opencti.indicator.labels | malicious-activity |
| data.opencti.indicator.name | Cobalt Strike |
| data.opencti.indicator.pattern | \[ipv4-addr:value = '116.163.24.195'\] |
| data.opencti.indicator.pattern\_type | stix |
| data.opencti.indicator.revoked | false |
| data.opencti.indicator.updated\_at | 2023-08-30T13:39:42.985Z |
| data.opencti.indicator.valid\_until | 2023-09-29T12:17:03.000Z |
| data.opencti.indicator.x\_opencti\_detection | false |
| data.opencti.indicator.x\_opencti\_score | 50 |
| data.opencti.indicator\_link | https://REDACTED/dashboard/observations/indicators/4c14daab-d133-43b6-88ef-e82ec0fd337a |
| data.opencti.query\_key | value |
| data.opencti.query\_values | \[domain-name:value = 'cdn.bootcss.com'\];\[ipv4-addr:value = '116.172.148.7'\];\[ipv4-addr:value = '119.188.86.194'\];\[ipv4-addr:value = '116.153.64.158'\];\[ipv4-addr:value = '1.62.64.68'\];\[ipv4-addr:value = '116.163.24.195'\];\[ipv4-addr:value = '36.248.54.138'\];\[ipv4-addr:value = '119.167.229.212'\];\[ipv4-addr:value = '218.12.86.80'\];\[ipv4-addr:value = '1.62.64.108'\] |
| data.opencti.source.alert\_id | 1693478062.194800757 |
| data.opencti.source.image | C:\\\\Program Files\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe |
| data.opencti.source.queryName | cdn.bootcss.com |
| data.opencti.source.queryResults | type: 5 cdn.bootcss.com.cdn.dnsv1.com.cn;type: 5 rpljaw8p.slt.sched.tdnsv8.com;::ffff:116.172.148.7;::ffff:119.188.86.194;::ffff:116.153.64.158;::ffff:1.62.64.68;::ffff:116.163.24.195;::ffff:36.248.54.138;::ffff:119.167.229.212;::ffff:218.12.86.80;::ffff:1.62.64.108; |
| decoder.name | json |
| id | 1693478073.195158709 |
| input.type | log |
| location | opencti |
| manager.name | wazuh.manager |
| rule.description | OpenCTI: IoC found in threat intel: Cobalt Strike |
| rule.firedtimes | 3 |
| rule.groups | threat\_intel, opencti, opencti\_alert |
| rule.id | 100212 |
| rule.level | 12 |
| rule.mail | true |
| timestamp | 2023-08-31T10:34:33.222+0000 |

### DNS query with domain name matching an observable with an indicator

The following is an event where the domain name queried matches against an
observable with an indicator, and a related observable also with an indicator
is included.

| Key | Value |
| --- | ----- |
| @timestamp | 2023-08-09T16:40:02.889Z |
| \_id | REDACTED |
| agent.id | REDACTED |
| agent.ip | REDACTED |
| agent.name | REDACTED |
| data.integration | opencti |
| data.opencti.created\_at | 2023-08-09T06:22:27.177Z |
| data.opencti.entity\_type | Domain-Name |
| data.opencti.event\_type | observable\_with\_indicator |
| data.opencti.id | efcd09cc-8f0d-41f5-8fb2-c197b5459623 |
| data.opencti.indicator.confidence | 15 |
| data.opencti.indicator.id | 959feeae-2f16-4521-baca-af58a374c845 |
| data.opencti.indicator.labels | deleteme |
| data.opencti.indicator.name | test3.example.org |
| data.opencti.indicator.pattern | \[domain-name:value = 'test3.example.org'\] |
| data.opencti.indicator.pattern\_type | stix |
| data.opencti.indicator.revoked | false |
| data.opencti.indicator.valid\_until | 2024-08-08T06:22:27.380Z |
| data.opencti.indicator.x\_opencti\_detection | false |
| data.opencti.indicator.x\_opencti\_score | 50 |
| data.opencti.indicator\_link | https://REDACTED/dashboard/observations/indicators/959feeae-2f16-4521-baca-af58a374c845 |
| data.opencti.labels | deleteme |
| data.opencti.multipleIndicators | false |
| data.opencti.observable\_link | https://REDACTED/dashboard/observations/observables/efcd09cc-8f0d-41f5-8fb2-c197b5459623 |
| data.opencti.observable\_value | test3.example.org |
| data.opencti.query\_key | value |
| data.opencti.query\_values | test3.example.org |
| data.opencti.related.id | 7a9f6847-12b1-41f7-bb4a-b41f94808547 |
| data.opencti.related.indicator.confidence | 15 |
| data.opencti.related.indicator.id | 17384027-a7ff-4802-8576-7af336d4833f |
| data.opencti.related.indicator.labels | deleteme |
| data.opencti.related.indicator.name | 9dd2:b4b0:ab1d:7c8d:6c26:32c2:af75:93af |
| data.opencti.related.indicator.pattern | \[ipv6-addr:value = '9dd2:b4b0:ab1d:7c8d:6c26:32c2:af75:93af'\] |
| data.opencti.related.indicator.pattern\_type | stix |
| data.opencti.related.indicator.revoked | false |
| data.opencti.related.indicator.valid\_until | 2023-10-08T13:27:48.365Z |
| data.opencti.related.indicator.x\_opencti\_detection | false |
| data.opencti.related.indicator.x\_opencti\_score | 50 |
| data.opencti.related.indicator\_link | https://REDACTED/dashboard/observations/indicators/17384027-a7ff-4802-8576-7af336d4833f |
| data.opencti.related.multipleIndicators | false |
| data.opencti.related.type | IPv6-Addr |
| data.opencti.related.value | 9dd2:b4b0:ab1d:7c8d:6c26:32c2:af75:93af |
| data.opencti.source.alert\_id | 1691599198.370628528 |
| data.opencti.source.queryName | test3.example.org |
| data.opencti.updated\_at | 2023-08-09T06:22:27.246Z |
| data.opencti.value | test3.example.org |
| data.opencti.x\_opencti\_description | TEST |
| data.opencti.x\_opencti\_score | 50 |
| decoder.name | json |
| id | 1691599202.370639246 |
| input.type | log |
| location | opencti |
| manager.name | wazuh.manager |
| rule.description | OpenCTI: IoC found in threat intel: test3.example.org |
| rule.firedtimes | 1 |
| rule.groups | threat\_intel, opencti, opencti\_alert |
| rule.id | 100214 |
| rule.level | 12 |
| rule.mail | true |
| timestamp | 2023-08-09T16:40:02.889+0000 |
