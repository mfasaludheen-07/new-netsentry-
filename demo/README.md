# NetSentry Demonstration Datasets

This directory contains defensive threat hunting and incident response test datasets formatted for NetSentry ingestion.

> **CRITICAL NOTICE:** All IP addresses and domains in these datasets are safe, reserved test indicators (RFC 1918 private subnets, RFC 5737 `203.0.113.0/24` documentation IP space, and `*.example` reserved domain names). They are intended solely for authorized security laboratory training, validation, and forensic analysis.

---

## 1. Fictional Threat Hunting Narrative

This telemetry sequence models a classic multi-stage cyber incident on an enterprise subnet:

| Timestamp (UTC) | Phase | Description | Observed Telemetry |
| :--- | :--- | :--- | :--- |
| `10:19:55 - 10:20:30` | **Initial Beacon & C2 Lookup** | Compromised internal workstation `PC-07` queries suspicious DNS infrastructure. | High-frequency DNS requests for `*.suspicious.example` (Triggers `RULE-007: DNS Burst`). |
| `10:20:00 - 10:22:00` | **C2 Communication** | `PC-07` establishes regular periodic TCP connections to an external server. | Repeated connection pattern to documentation IP `203.0.113.20:443` (Triggers `RULE-004: Unusual External` & `RULE-008: Beaconing`). |
| `10:23:01 - 10:23:12` | **Reconnaissance & Port Scan** | `PC-07` probes 12 distinct TCP ports against internal server `10.0.0.5`. | Ports 21, 22, 23, 25, 80, 135, 139, 443, 445, 1433, 3389, 8080 (Triggers `RULE-001: Port Scan`). |
| `10:25:01 - 10:25:08` | **Host Sweep** | `PC-07` attempts SMB connections across the internal subnet. | Connections to `192.168.1.11` through `.20` and `10.0.0.5` through `.6` (Triggers `RULE-002: Host Sweep`). |
| `10:28:15 - 10:31:00` | **Lateral Movement & Remote Access** | `PC-07` connects to administrative and remote management ports on `SERVER-01`. | Connections to SMB (445), RDP (3389), and SSH (22) (Triggers `RULE-005: Suspicious Remote Services`). |
| `10:35:00` | **Data Exfiltration** | Internal endpoint transmits an abnormally large payload to the external destination. | 14.7 MB egress to `203.0.113.20` (Triggers `RULE-006: Large Outbound Transfer`). |

The simultaneous triggering of multiple high-severity heuristics on `PC-07` automatically activates `RULE-009: Multiple Detection Combination`, elevating the asset's investigation priority.

---

## 2. Included Demo Files

- **`demo-network.csv`**: Generic network traffic log containing all stages of the incident sequence.
- **`demo-dns.json`**: JSON-formatted DNS query logs capturing high-frequency C2 resolution bursts.

---

## 3. How to Ingest and Hunt

1. **Log In:** Navigate to `http://localhost/netsentry` and log in as `analyst@netsentry.local` (`Password123!`).
2. **Upload Telemetry:**
   - Go to **Traffic Logs** > **Upload Telemetry**.
   - Select `demo/demo-network.csv`.
   - Set **Source Name** to `Corporate Perimeter Firewall`.
   - Select **Source Type** as `Generic Network Log (CSV)`.
   - Click **Upload & Parse Telemetry**.
3. **Execute Detections:**
   - Once imported, navigate to **Alerts** or click **Run Detection Rules** from the Dashboard.
   - NetSentry will identify the port scan, host sweep, remote service usage, and data exfiltration.
4. **Create an Investigation:**
   - Open any generated alert (e.g. *Potential Port Scan* or *Large Outbound Transfer*).
   - Click **Escalate to Investigation** or **Create Case**.
   - Link related alerts and IOCs.
5. **Analyze the Attack Path:**
   - Under the Case, open the **Attack Path** tab to mark the observed stages (*Network Discovery*, *Internal Scanning*, *Remote Services*, *Lateral Movement*, *Exfiltration*).
   - In the **MITRE ATT&CK** tab, link techniques `T1046`, `T1021`, `T1071`, `T1041`.
6. **Generate Investigation Report:**
   - In the **Report** tab, click **Generate Comprehensive Final Report** to generate a 16-section incident summary.
