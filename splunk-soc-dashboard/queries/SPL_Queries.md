# Production Search Processing Language (SPL) Catalog

This documentation details the raw, performance-tuned SPL logic and regex token extraction structures built into the 5-tab SOC Log Analyzer Dashboard.

---

### 1. Top Targeted User Accounts (Tab 1 — Bar Chart)
* **Objective:** Extracts `User=` from Windows raw logs and `for <user> from` from Linux logs to rank the top 5 most targeted accounts.

```spl
index=* ((sourcetype=linux_secure "Failed password") OR (sourcetype=winauthentication_security EventCode=4625))
| rex field=_raw "for (?<linux_user\(>\S+\)) from"
| rex field=_raw "User=(?<win_user\(>\S+\))"
| eval target_user=coalesce(win_user, linux_user)
| stats count by target_user
| sort - count
| head 5
```

---

### 2. Brute Force Alerts Badge (Tab 2 — Single Value)
* **Objective:** Aggregates all failed authentication events across Linux (`linux_secure`) and Windows Active Directory (`EventCode=4625`).

```spl
index=* ((sourcetype=linux_secure "Failed password") OR (sourcetype=winauthentication_security EventCode=4625))
| stats count as "Brute Force Alerts"
```

---

### 3. Abrupt Boundary VPN Drops (Tab 3 — Single Value)
* **Objective:** Tracks unexpected remote workforce VPN disconnections (`Connection Lost`) at the Cisco perimeter firewall.

```spl
index=* sourcetype=cisco_firewall "Connection Lost"
| stats count as "Abrupt VPN Drops"
```

---

### 4. MITRE ATT&CK Framework Mapping Matrix (Tab 4 — Table)
* **Objective:** Dynamically classifies multi-source logs into severity tiers (**CRITICAL**, **HIGH**, **MEDIUM**) and maps them to MITRE ATT&CK technique IDs.

```spl
index=* ((sourcetype=linux_secure "Failed password") OR (sourcetype=winauthentication_security EventCode=4625) OR (sourcetype=cisco_firewall "Connection Lost"))
| rex field=_raw "for (?<linux_user\(>\S+\)) from"
| rex field=_raw "User=(?<win_user\(>\S+\))"
| eval target_user=coalesce(win_user, linux_user)
| eval Attack_Type=case(
    target_user=="root" OR target_user=="Administrator", "Privileged Account Brute Force", 
    sourcetype=="cisco_firewall", "Abrupt Boundary Session Drop", 
    1=1, "Standard Endpoint Brute Force")
| eval MITRE_ID=case(
    Attack_Type=="Privileged Account Brute Force", "T1078 (Valid Accounts)", 
    Attack_Type=="Abrupt Boundary Session Drop", "T1133 (External Remote Services)", 
    Attack_Type=="Standard Endpoint Brute Force", "T1110 (Brute Force)")
| eval Severity=case(
    Attack_Type=="Privileged Account Brute Force", "CRITICAL", 
    Attack_Type=="Abrupt Boundary Session Drop", "MEDIUM", 
    Attack_Type=="Standard Endpoint Brute Force", "HIGH")
| stats count by Attack_Type, Severity, MITRE_ID
| rename count as "Event Count"
| sort - "Event Count"
```

---

### 5. Multi-IP Behavioral Hunting Table (Tab 5 — Table)
* **Objective:** Identifies distributed brute-force attacks where multiple distinct IPs target a single user account, flattening the IP list to keep the dashboard compact.

```spl
index=* ((sourcetype=linux_secure "Failed password") OR (sourcetype=winauthentication_security EventCode=4625))
| rex field=_raw "(?<extracted_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
| rex field=_raw "for (?<linux_user\(>\S+\)) from"
| rex field=_raw "User=(?<win_user\(>\S+\))"
| eval target_user=coalesce(win_user, linux_user)
| where isnotnull(target_user) AND isnotnull(extracted_ip)
| stats dc(extracted_ip) as unique_ips values(extracted_ip) as attacking_sources by target_user
| where unique_ips > 1
| eval top_ips=mvindex(attacking_sources, 0, 4)
| eval "Attacking IP List"=mvjoin(top_ips, ", ") . if(unique_ips>5, " ... (and " . (unique_ips-5) . " more)", "")
| rename unique_ips as "Distinct Attacking IPs", target_user as "Compromised Target User"
| table "Compromised Target User", "Distinct Attacking IPs", "Attacking IP List"
| sort - "Distinct Attacking IPs"
```
