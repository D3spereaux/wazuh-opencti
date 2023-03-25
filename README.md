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

and inspects events from sysmon, syscheck, suricata and osquery. The script can
easily be extended to match other types of events as well.

The integration will only inspect events whose *rule.groups* matches
- sysmon events 1, 3, 6, 7, 15, 22, 23, 24, 25
- ids
- syscheck\_file
- osquery
- osquery\_file

## Requirements

* An OpenCTI instance up and running
* A read-only OpenCTI API token suitable for querying data

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
     <group>sysmon_eid1_detections,sysmon_eid3_detections,sysmon_eid7_detections,syscheck_file,osquery_file,ids,sysmon_process-anomalies</group>
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
suricata and osquery. If you look at the configuration example above, you'll
notice that **sysmon_eidX_detections** is used instead of **sysmon_eventX**.
This is because Wazuh (at least as of 4.3.9) doesn't produce any sysmon\_eventX
events. – Only specific *detections* events. Also note that 4.3.9 doesn't even
have basic rules that cover all of the sysmon events. You may need to add rules
for sysmon event 16–25. Event 23–25 is used by this integration.

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
      <field name="opencti.id">\.+</field>
      <description>OpenCTI: IoC found in threat intel: $(opencti.x_opencti_description)</description>
      <options>no_full_log</options>
      <group>opencti,opencti_alert,</group>
   </rule>
</group>
```

In order to test that the integration works, create an observable in OpenCTI
with a SHA256 hash that matches a file you will later create or move in Windows
or Linux.  Then create an indicator (wazuh-opencti only creates alerts if an
observable has an indicator tied to it). Depending om your syscheck setup, put
the file with the matching hash in a monitored directory and wait for the alert
to be created. If you don't have a real-time syscheck setup yet, consider
setting one up for *C:\\Users\\\*\Downloads*.

During testing and development, it may be very useful to enable debug output
from the integration. Debug output may be enabled in [internal
options](https://documentation.wazuh.com/current/user-manual/reference/internal-options.html#integrator).
If you're using docker, add `integrator.debug = 1`to
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
 sysmon\_event\_22, sysmon\_eid22\_detections | win.eventdata.queryName |
 sysmon\_event\_23, sysmon\_eid23\_detections | win.eventdata.hashes |
 sysmon\_event\_24, sysmon\_eid24\_detections | win.eventdata.hashes |
 sysmon\_event\_25, sysmon\_eid25\_detections | win.eventdata.hashes |
 sysmon\_process-anomalies | win.eventdata.hashes |
 ids | dest\_ip, src\_ip |
 osquery, osquery\_file | osquery.columns.sha256 |
 
 ### Customisation

 Feel free to modify custom-opencty.py to suit your needs. It was designed to
 cover my own needs, but I am sure that there are other events and groups this
 integration could inspect. I would greatly appreciate if you could provide a
 pull request to enhance the script if you think others may benefit from your
 modifications.
