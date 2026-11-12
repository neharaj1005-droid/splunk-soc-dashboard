# Splunk SOC Dashboard

A Security Operations Center (SOC) dashboard built in Splunk Dashboard Studio. It searches Windows authentication logs and Cisco firewall logs, groups the results into detections, and maps each detection to a MITRE ATT&CK technique.

**Data source:** Sample Windows authentication and Cisco firewall logs loaded in a Splunk Enterprise test instance.

## Data Sources

| Sourcetype | Matching rule |
|---|---|
| `winauthentication_security` | Failed logons, EventCode 4625 |
| `cisco_firewall` | Events containing "Connection Lost" |
| `linux_secure` | Events containing "Failed password". These queries are included but were not tested, because no Linux data was loaded. |

## Detections

| Detection | Logic | Severity | MITRE ATT&CK |
|---|---|---|---|
| Privileged account failures | Failed logins where the target user is `root` or `Administrator` | CRITICAL | T1078 (Valid Accounts) |
| Standard endpoint brute force | Failed logins for any other user | HIGH | T1110 (Brute Force) |
| Connection Lost events | Events containing "Connection Lost" on Cisco firewall logs | MEDIUM | T1133 (External Remote Services) |

The MITRE mapping is a rule-based classification. It labels events by these rules and does not confirm that an attack occurred.

## Dashboard Panels

1. **Brute Force Alerts:** count of failed authentication events.
2. **Top Targeted User Accounts:** the five accounts with the most failed logins.
3. **Abrupt VPN Drops:** count of "Connection Lost" events on Cisco firewall logs.
4. **MITRE ATT&CK Framework Mapping:** event counts grouped by attack type, severity, and MITRE ID.
5. **Multi IP Search:** for each target user with more than one distinct source IP, the count of distinct IPs and the list of those IPs.

## Repository Structure

- `splunk-soc-dashboard/dashboard_source.json`: Splunk Dashboard Studio source, containing the five searches and the layout.
- `splunk-soc-dashboard/dashboard_top.png` and `splunk-soc-dashboard/dashboard_bottom.png`: screenshots of the dashboard.

## Testing

The dashboard was loaded into a Splunk Enterprise instance with 503,288 events across 8 sourcetypes, including 10,210 `winauthentication_security` events and 517 `cisco_firewall` events. The panels have not yet been checked one by one. No `linux_secure` data was loaded, so Linux-dependent results were not tested.

## Limitations

- The dashboard runs on static sample data, not live log ingestion.
- "Connection Lost" matches any Cisco firewall event containing that text. It is not confirmed to be VPN-specific.
- The privileged account rule fires on any single failed login for `root` or `Administrator`. It does not count attempts.
- The Multi IP and MITRE panels depend on fields such as `user` and `ip` being present in the Windows events. This has not been verified.
