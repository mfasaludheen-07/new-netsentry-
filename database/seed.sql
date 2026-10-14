-- database/seed.sql
-- NetSentry: Initial Data & Demo Lab Seed
USE netsentry;

SET FOREIGN_KEY_CHECKS = 0;

-- 1. Insert Roles
INSERT INTO roles (id, name, description, permissions) VALUES
(1, 'ADMIN', 'System Administrator with full management and audit privileges', '["all"]'),
(2, 'ANALYST', 'Security Analyst with access to logs, alerts, cases, findings, and evidence', '["logs:view","logs:upload","alerts:manage","cases:manage","iocs:manage","evidence:manage","reports:generate"]'),
(3, 'VIEWER', 'Read-only observer with permission to view permitted investigations and telemetry', '["logs:view","alerts:view","cases:view","reports:view"]')
ON DUPLICATE KEY UPDATE name=VALUES(name);

-- 2. Insert Users (Password is: Password123!)
-- Hash: $2y$10$i5VEeX8ctb0tcft0cWEVbexzd9cRwd0SChWKXDsRrimfEmJBQB1k2
INSERT INTO users (id, username, email, password_hash, role_id, status) VALUES
(1, 'admin', 'admin@netsentry.local', '$2y$10$i5VEeX8ctb0tcft0cWEVbexzd9cRwd0SChWKXDsRrimfEmJBQB1k2', 1, 'active'),
(2, 'analyst', 'analyst@netsentry.local', '$2y$10$i5VEeX8ctb0tcft0cWEVbexzd9cRwd0SChWKXDsRrimfEmJBQB1k2', 2, 'active'),
(3, 'viewer', 'viewer@netsentry.local', '$2y$10$i5VEeX8ctb0tcft0cWEVbexzd9cRwd0SChWKXDsRrimfEmJBQB1k2', 3, 'active')
ON DUPLICATE KEY UPDATE username=VALUES(username);

-- 3. System Settings
INSERT INTO settings (setting_key, setting_value, description) VALUES
('app_title', 'NetSentry', 'Application Display Title'),
('session_timeout', '3600', 'Inactivity session timeout in seconds'),
('max_upload_mb', '20', 'Maximum log and evidence file upload size in MB'),
('port_scan_threshold', '6', 'Number of distinct ports contacted within window to trigger RULE-001'),
('port_scan_window', '180', 'Window in seconds for port scanning detection'),
('host_sweep_threshold', '3', 'Number of internal destination IPs contacted to trigger RULE-002'),
('failed_conn_threshold', '4', 'Threshold of failed/denied connection attempts for RULE-003'),
('large_transfer_threshold', '10485760', 'Outbound bytes threshold (10 MB) for RULE-006'),
('dns_burst_threshold', '10', 'Number of DNS queries within 60s for RULE-007'),
('beacon_interval_tolerance', '10', 'Periodic connection threshold for RULE-008'),
('soc_contact_email', 'soc@netsentry.local', 'Default SOC escalation contact email')
ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value);

-- 4. Detection Rules (All 9 specified rules)
INSERT INTO detection_rules (id, name, description, enabled, severity, threshold, time_window_seconds, rule_type, mitre_technique_id) VALUES
('RULE-001', 'Potential Port Scan', 'One source IP connects to multiple distinct destination ports on a target host within a configured time window.', 1, 'HIGH', 6, 180, 'PORT_SCAN', 'T1046'),
('RULE-002', 'Potential Host Sweep', 'One source IP contacts multiple internal subnet hosts within a short period, indicating discovery activity.', 1, 'HIGH', 3, 300, 'HOST_SWEEP', 'T1018'),
('RULE-003', 'Repeated Failed Connections', 'Multiple denied or failed connection events originating from the same source IP.', 1, 'MEDIUM', 4, 300, 'FAILED_CONNS', 'T1046'),
('RULE-004', 'Unusual External Communication', 'Internal host repeatedly communicates with an external IP address not previously observed in baseline.', 1, 'MEDIUM', 3, 600, 'UNUSUAL_EXTERNAL', 'T1071'),
('RULE-005', 'Suspicious Remote-Service Activity', 'Repeated connections to administrative/remote service ports (SSH 22, RDP 3389, SMB 445, WinRM 5985/5986).', 1, 'HIGH', 2, 300, 'REMOTE_SERVICES', 'T1021'),
('RULE-006', 'Large Outbound Transfer', 'Unusually large outbound byte volume from an internal host to an external destination, indicating possible data exfiltration.', 1, 'CRITICAL', 10485760, 600, 'LARGE_TRANSFER', 'T1041'),
('RULE-007', 'DNS Burst', 'An unusually high frequency of DNS requests originating from a single endpoint within a short duration.', 1, 'MEDIUM', 10, 60, 'DNS_BURST', 'T1071'),
('RULE-008', 'Repeated Connection Pattern', 'Regular repeated connections to the same external host at consistent intervals, indicating potential beaconing/C2 activity.', 1, 'HIGH', 4, 300, 'BEACON_PATTERN', 'T1071'),
('RULE-009', 'Multiple Detection Combination', 'A single internal endpoint triggers two or more distinct detection alerts within 15 minutes, escalating incident priority.', 1, 'CRITICAL', 2, 900, 'MULTI_DETECTION', 'T1078')
ON DUPLICATE KEY UPDATE name=VALUES(name);

-- 5. MITRE ATT&CK Catalog
INSERT INTO mitre_techniques (id, name, tactic, description) VALUES
('T1046', 'Network Service Discovery', 'Discovery', 'Adversaries may attempt to get a listing of services running on hosts over a network, commonly via port scanning.'),
('T1021', 'Remote Services', 'Lateral Movement', 'Adversaries may use Valid Accounts to log into remote services such as SSH, VNC, or RDP to expand footprint.'),
('T1078', 'Valid Accounts', 'Defense Evasion, Persistence, Initial Access', 'Adversaries may obtain and abuse credentials of existing accounts to gain unauthorized access.'),
('T1018', 'Remote System Discovery', 'Discovery', 'Adversaries may attempt to discover other systems on the network through host sweeps or ping probes.'),
('T1049', 'System Network Connections Discovery', 'Discovery', 'Adversaries may attempt to get a listing of network connections to or from the compromised system.'),
('T1071', 'Application Layer Protocol', 'Command and Control', 'Adversaries may communicate using application layer protocols (HTTP, HTTPS, DNS) to blend in with normal network traffic.'),
('T1041', 'Exfiltration Over C2 Channel', 'Exfiltration', 'Adversaries may steal data by transferring it over an existing command and control channel.')
ON DUPLICATE KEY UPDATE name=VALUES(name);

-- 6. Log Source & Upload Seed
INSERT INTO log_sources (id, name, source_type, description, timezone, created_by) VALUES
(1, 'Primary Boundary Firewall & Flow Collector', 'Firewall', 'Core perimeter traffic and internal segmentation flow telemetry', 'UTC', 1)
ON DUPLICATE KEY UPDATE name=VALUES(name);

INSERT INTO log_uploads (id, source_id, original_filename, stored_filename, file_size, mime_type, hash_sha256, status, total_rows, imported_rows, skipped_rows, error_count, uploaded_by) VALUES
(1, 1, 'demo-network.csv', 'seed_demo_network_log.csv', 4096, 'text/csv', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'COMPLETED', 14, 14, 0, 0, 2)
ON DUPLICATE KEY UPDATE original_filename=VALUES(original_filename);

-- 7. Network Events (Safe fictional demo dataset reflecting Section 35 story)
INSERT INTO network_events (id, upload_id, timestamp, source_ip, destination_ip, source_port, destination_port, protocol, hostname, username, domain, bytes_sent, bytes_received, dns_query, event_type, action, source_type, raw_event) VALUES
(1, 1, '2026-10-06 10:20:00', '192.168.1.10', '192.168.1.1', 54101, 53, 'UDP', 'PC-07', 'alice.m', 'suspicious.example', 120, 280, 'suspicious.example', 'dns_query', 'ALLOW', 'DNS', '2026-10-06 10:20:00 PC-07 192.168.1.10:54101 -> 192.168.1.1:53 DNS query suspicious.example'),
(2, 1, '2026-10-06 10:20:30', '192.168.1.10', '203.0.113.20', 54102, 443, 'TCP', 'PC-07', 'alice.m', 'suspicious.example', 850, 4200, NULL, 'connection', 'ALLOW', 'Firewall', '2026-10-06 10:20:30 PC-07 192.168.1.10:54102 -> 203.0.113.20:443 TCP ALLOW bytes_out=850'),
(3, 1, '2026-10-06 10:21:00', '192.168.1.10', '203.0.113.20', 54103, 443, 'TCP', 'PC-07', 'alice.m', 'suspicious.example', 540, 1200, NULL, 'connection', 'ALLOW', 'Firewall', '2026-10-06 10:21:00 PC-07 192.168.1.10:54103 -> 203.0.113.20:443 TCP ALLOW bytes_out=540'),
(4, 1, '2026-10-06 10:21:30', '192.168.1.10', '203.0.113.20', 54104, 443, 'TCP', 'PC-07', 'alice.m', 'suspicious.example', 610, 1340, NULL, 'connection', 'ALLOW', 'Firewall', '2026-10-06 10:21:30 PC-07 192.168.1.10:54104 -> 203.0.113.20:443 TCP ALLOW bytes_out=610'),
(5, 1, '2026-10-06 10:22:00', '192.168.1.10', '203.0.113.20', 54105, 443, 'TCP', 'PC-07', 'alice.m', 'suspicious.example', 590, 1100, NULL, 'connection', 'ALLOW', 'Firewall', '2026-10-06 10:22:00 PC-07 192.168.1.10:54105 -> 203.0.113.20:443 TCP ALLOW bytes_out=590'),
(6, 1, '2026-10-06 10:23:01', '192.168.1.10', '10.0.0.5', 49201, 21, 'TCP', 'PC-07', 'alice.m', NULL, 64, 0, NULL, 'connection', 'DENY', 'Firewall', '2026-10-06 10:23:01 PC-07 192.168.1.10:49201 -> 10.0.0.5:21 TCP DENY syn_sent'),
(7, 1, '2026-10-06 10:23:03', '192.168.1.10', '10.0.0.5', 49202, 22, 'TCP', 'PC-07', 'alice.m', NULL, 64, 0, NULL, 'connection', 'DENY', 'Firewall', '2026-10-06 10:23:03 PC-07 192.168.1.10:49202 -> 10.0.0.5:22 TCP DENY syn_sent'),
(8, 1, '2026-10-06 10:23:05', '192.168.1.10', '10.0.0.5', 49203, 80, 'TCP', 'PC-07', 'alice.m', NULL, 64, 0, NULL, 'connection', 'DENY', 'Firewall', '2026-10-06 10:23:05 PC-07 192.168.1.10:49203 -> 10.0.0.5:80 TCP DENY syn_sent'),
(9, 1, '2026-10-06 10:23:07', '192.168.1.10', '10.0.0.5', 49204, 135, 'TCP', 'PC-07', 'alice.m', NULL, 64, 0, NULL, 'connection', 'DENY', 'Firewall', '2026-10-06 10:23:07 PC-07 192.168.1.10:49204 -> 10.0.0.5:135 TCP DENY syn_sent'),
(10, 1, '2026-10-06 10:23:09', '192.168.1.10', '10.0.0.5', 49205, 445, 'TCP', 'PC-07', 'alice.m', NULL, 128, 160, NULL, 'connection', 'ALLOW', 'Firewall', '2026-10-06 10:23:09 PC-07 192.168.1.10:49205 -> 10.0.0.5:445 TCP ALLOW smb_init'),
(11, 1, '2026-10-06 10:23:12', '192.168.1.10', '10.0.0.5', 49206, 3389, 'TCP', 'PC-07', 'alice.m', NULL, 64, 0, NULL, 'connection', 'DENY', 'Firewall', '2026-10-06 10:23:12 PC-07 192.168.1.10:49206 -> 10.0.0.5:3389 TCP DENY syn_sent'),
(12, 1, '2026-10-06 10:25:10', '192.168.1.10', '192.168.1.20', 49301, 445, 'TCP', 'PC-07', 'alice.m', NULL, 64, 0, NULL, 'connection', 'DENY', 'Firewall', '2026-10-06 10:25:10 PC-07 192.168.1.10:49301 -> 192.168.1.20:445 TCP DENY'),
(13, 1, '2026-10-06 10:25:20', '192.168.1.10', '10.0.0.8', 49302, 445, 'TCP', 'PC-07', 'alice.m', NULL, 64, 0, NULL, 'connection', 'DENY', 'Firewall', '2026-10-06 10:25:20 PC-07 192.168.1.10:49302 -> 10.0.0.8:445 TCP DENY'),
(14, 1, '2026-10-06 10:25:35', '192.168.1.10', '10.0.0.12', 49303, 445, 'TCP', 'PC-07', 'alice.m', NULL, 64, 0, NULL, 'connection', 'DENY', 'Firewall', '2026-10-06 10:25:35 PC-07 192.168.1.10:49303 -> 10.0.0.12:445 TCP DENY'),
(15, 1, '2026-10-06 10:30:00', '192.168.1.10', '10.0.0.5', 49400, 445, 'TCP', 'PC-07', 'alice.m', NULL, 48200, 62100, NULL, 'connection', 'ALLOW', 'Firewall', '2026-10-06 10:30:00 PC-07 192.168.1.10:49400 -> 10.0.0.5:445 TCP ALLOW session_established'),
(16, 1, '2026-10-06 10:35:10', '192.168.1.10', '203.0.113.20', 54200, 443, 'TCP', 'PC-07', 'alice.m', 'suspicious.example', 15482900, 42000, NULL, 'connection', 'ALLOW', 'Firewall', '2026-10-06 10:35:10 PC-07 192.168.1.10:54200 -> 203.0.113.20:443 TCP ALLOW bytes_out=15482900')
ON DUPLICATE KEY UPDATE id=VALUES(id);

-- 8. Endpoints
INSERT INTO endpoints (id, hostname, ip_address, os_info, criticality, owner_description, first_seen, last_seen, alert_count, case_count) VALUES
(1, 'PC-07', '192.168.1.10', 'Windows 11 Enterprise', 'HIGH', 'Workstation - Alice Mitchell (Finance)', '2026-10-06 10:20:00', '2026-10-06 10:35:10', 4, 1),
(2, 'SERVER-01', '10.0.0.5', 'Ubuntu 22.04 LTS', 'CRITICAL', 'Core Internal Database & File Server', '2026-10-06 10:23:01', '2026-10-06 10:30:00', 1, 1),
(3, 'WS-DEV-02', '192.168.1.20', 'Windows 10 Pro', 'MEDIUM', 'Engineering Workstation', '2026-10-06 10:25:10', '2026-10-06 10:25:10', 0, 0)
ON DUPLICATE KEY UPDATE hostname=VALUES(hostname);

-- 9. Alerts
INSERT INTO alerts (id, rule_id, title, description, severity, source_ip, destination_ip, endpoint, first_seen, last_seen, event_count, status, confidence) VALUES
('ALT-2026-000001', 'RULE-001', 'Potential Port Scan against SERVER-01', 'Source 192.168.1.10 probed 6 distinct destination ports (21, 22, 80, 135, 445, 3389) on internal host 10.0.0.5 within 180s window.', 'HIGH', '192.168.1.10', '10.0.0.5', 'PC-07', '2026-10-06 10:23:01', '2026-10-06 10:23:12', 6, 'INVESTIGATING', 'HIGH'),
('ALT-2026-000002', 'RULE-002', 'Potential Internal Host Sweep', 'Source 192.168.1.10 contacted 3 distinct internal subnet hosts (192.168.1.20, 10.0.0.8, 10.0.0.12) on SMB port 445 in short succession.', 'HIGH', '192.168.1.10', '10.0.0.0/24', 'PC-07', '2026-10-06 10:25:10', '2026-10-06 10:25:35', 3, 'INVESTIGATING', 'HIGH'),
('ALT-2026-000003', 'RULE-008', 'Repeated Periodic Connection Pattern', 'Host 192.168.1.10 exhibited regular interval outbound connections (every 30s) to external IP 203.0.113.20.', 'HIGH', '192.168.1.10', '203.0.113.20', 'PC-07', '2026-10-06 10:20:30', '2026-10-06 10:22:00', 4, 'INVESTIGATING', 'MEDIUM'),
('ALT-2026-000004', 'RULE-006', 'Large Outbound Data Transfer Exceeding Threshold', 'Host 192.168.1.10 transmitted 14.76 MB (15,482,900 bytes) in a single TCP session to external IP 203.0.113.20.', 'CRITICAL', '192.168.1.10', '203.0.113.20', 'PC-07', '2026-10-06 10:35:10', '2026-10-06 10:35:10', 1, 'INVESTIGATING', 'HIGH')
ON DUPLICATE KEY UPDATE title=VALUES(title);

-- Associate alert events
INSERT INTO alert_events (alert_id, event_id) VALUES
('ALT-2026-000001', 6), ('ALT-2026-000001', 7), ('ALT-2026-000001', 8), ('ALT-2026-000001', 9), ('ALT-2026-000001', 10), ('ALT-2026-000001', 11),
('ALT-2026-000002', 12), ('ALT-2026-000002', 13), ('ALT-2026-000002', 14),
('ALT-2026-000003', 2), ('ALT-2026-000003', 3), ('ALT-2026-000003', 4), ('ALT-2026-000003', 5),
('ALT-2026-000004', 16)
ON DUPLICATE KEY UPDATE alert_id=VALUES(alert_id);

-- 10. Investigation Case: NET-DEMO-001
INSERT INTO cases (id, title, description, severity, priority, status, assigned_to, created_by, created_at) VALUES
('NET-DEMO-001', 'Suspected Lateral Movement and Data Staging from PC-07', 'Analyst triage initiated following correlated high-severity detection alerts originating from internal finance workstation PC-07. Observed initial DNS query to suspicious.example, followed by beacon-like cadence to 203.0.113.20, multi-port sweep against core internal database SERVER-01, and subsequent 14.7MB egress spike.', 'HIGH', 'HIGH', 'INVESTIGATING', 2, 2, '2026-10-06 10:40:00')
ON DUPLICATE KEY UPDATE title=VALUES(title);

-- Case Alerts association
INSERT INTO case_alerts (case_id, alert_id) VALUES
('NET-DEMO-001', 'ALT-2026-000001'),
('NET-DEMO-001', 'ALT-2026-000002'),
('NET-DEMO-001', 'ALT-2026-000003'),
('NET-DEMO-001', 'ALT-2026-000004')
ON DUPLICATE KEY UPDATE case_id=VALUES(case_id);

-- Case Events association
INSERT INTO case_events (case_id, event_id) VALUES
('NET-DEMO-001', 1), ('NET-DEMO-001', 2), ('NET-DEMO-001', 3), ('NET-DEMO-001', 4),
('NET-DEMO-001', 5), ('NET-DEMO-001', 6), ('NET-DEMO-001', 7), ('NET-DEMO-001', 8),
('NET-DEMO-001', 9), ('NET-DEMO-001', 10), ('NET-DEMO-001', 11), ('NET-DEMO-001', 12),
('NET-DEMO-001', 13), ('NET-DEMO-001', 14), ('NET-DEMO-001', 15), ('NET-DEMO-001', 16)
ON DUPLICATE KEY UPDATE case_id=VALUES(case_id);

-- 11. IOCs
INSERT INTO iocs (id, value, type, confidence, status, first_seen, last_seen, notes) VALUES
(1, '203.0.113.20', 'IP', 'HIGH', 'SUSPICIOUS', '2026-10-06 10:20:30', '2026-10-06 10:35:10', 'External documentation IP observed receiving regular beacon traffic and large egress transfer.'),
(2, 'suspicious.example', 'DOMAIN', 'HIGH', 'SUSPICIOUS', '2026-10-06 10:20:00', '2026-10-06 10:35:10', 'Reserved example domain resolved immediately prior to external communication initiation.'),
(3, '198.51.100.25', 'IP', 'LOW', 'OBSERVED', '2026-10-06 09:15:00', '2026-10-06 09:15:00', 'Passive DNS associated external documentation address.'),
(4, 'PC-07', 'HOSTNAME', 'HIGH', 'OBSERVED', '2026-10-06 10:20:00', '2026-10-06 10:35:10', 'Internal origin endpoint for suspicious activity sequence.')
ON DUPLICATE KEY UPDATE value=VALUES(value);

-- Case IOCs association
INSERT INTO case_iocs (case_id, ioc_id) VALUES
('NET-DEMO-001', 1),
('NET-DEMO-001', 2),
('NET-DEMO-001', 4)
ON DUPLICATE KEY UPDATE case_id=VALUES(case_id);

-- 12. Attack Stages (Analyst-assisted Attack Path Reconstruction)
INSERT INTO attack_stages (case_id, stage_order, stage_name, status, confidence, evidence_summary, related_events_count, analyst_comment, updated_by) VALUES
('NET-DEMO-001', 1, 'External Communication', 'OBSERVED', 'HIGH', 'DNS query to suspicious.example followed by repeated HTTPS sessions to 203.0.113.20.', 5, 'Cadence of 30-second intervals indicates possible automated beaconing mechanism.', 2),
('NET-DEMO-001', 2, 'Network Discovery', 'OBSERVED', 'HIGH', 'Targeted TCP probing from PC-07 against internal subnet destinations.', 3, 'Probes focused on standard Windows management ports (445).', 2),
('NET-DEMO-001', 3, 'Internal Scanning', 'OBSERVED', 'HIGH', 'Sequential connection attempts against 6 ports on SERVER-01 (10.0.0.5).', 6, 'Ports scanned include 21, 22, 80, 135, 445, 3389.', 2),
('NET-DEMO-001', 4, 'Remote Service Activity', 'SUSPECTED', 'MEDIUM', 'Subsequent established SMB session on port 445 between PC-07 and SERVER-01.', 2, 'Legitimate credentials potentially abused; validating authentication logs.', 2),
('NET-DEMO-001', 5, 'Potential Lateral Movement', 'SUSPECTED', 'MEDIUM', 'Multiple denied SMB probes across engineering workstations and internal file hosts.', 3, 'Likely reconnaissance prior to settling on SERVER-01 target.', 2),
('NET-DEMO-001', 6, 'Large Outbound Transfer', 'CONFIRMED', 'HIGH', '15.48 MB transmission from PC-07 to 203.0.113.20.', 1, 'Volume is 30x the typical daily outbound egress for this workstation role.', 2)
ON DUPLICATE KEY UPDATE stage_name=VALUES(stage_name);

-- 13. Case MITRE Mapping
INSERT INTO case_mitre (case_id, technique_id, status, notes, supporting_evidence, updated_by) VALUES
('NET-DEMO-001', 'T1071', 'OBSERVED', 'Outbound C2 over HTTPS (port 443) to 203.0.113.20 with periodic beacon intervals.', 'Events #2-5, Alert ALT-2026-000003', 2),
('NET-DEMO-001', 'T1046', 'OBSERVED', 'Multi-port probing on SERVER-01 (10.0.0.5) observed within 12 seconds.', 'Events #6-11, Alert ALT-2026-000001', 2),
('NET-DEMO-001', 'T1018', 'OBSERVED', 'Sweep across multiple internal IP targets on port 445.', 'Events #12-14, Alert ALT-2026-000002', 2),
('NET-DEMO-001', 'T1021', 'SUSPECTED', 'SMB connection established to file server following reconnaissance.', 'Event #15', 2),
('NET-DEMO-001', 'T1041', 'SUSPECTED', '15.48 MB transfer to external destination matching C2 endpoint.', 'Event #16, Alert ALT-2026-000004', 2)
ON DUPLICATE KEY UPDATE status=VALUES(status);

-- 14. Forensic Timeline Events
INSERT INTO timeline_events (case_id, event_time, event_type, source, destination, protocol, severity, description, reference_type, reference_id) VALUES
('NET-DEMO-001', '2026-10-06 10:20:00', 'DNS_QUERY', '192.168.1.10 (PC-07)', '192.168.1.1 (DNS)', 'UDP:53', 'INFO', 'PC-07 resolved domain suspicious.example', 'EVENT', '1'),
('NET-DEMO-001', '2026-10-06 10:20:30', 'EXTERNAL_CONN', '192.168.1.10 (PC-07)', '203.0.113.20', 'TCP:443', 'MEDIUM', 'First connection observed to external C2 candidate', 'EVENT', '2'),
('NET-DEMO-001', '2026-10-06 10:22:00', 'ALERT_TRIGGERED', '192.168.1.10 (PC-07)', '203.0.113.20', 'TCP:443', 'HIGH', 'Detection Alert ALT-2026-000003: Repeated Periodic Connection Pattern (Beaconing)', 'ALERT', 'ALT-2026-000003'),
('NET-DEMO-001', '2026-10-06 10:23:01', 'PORT_SCAN', '192.168.1.10 (PC-07)', '10.0.0.5 (SERVER-01)', 'TCP', 'HIGH', 'Detection Alert ALT-2026-000001: Potential Port Scan against SERVER-01', 'ALERT', 'ALT-2026-000001'),
('NET-DEMO-001', '2026-10-06 10:25:10', 'HOST_SWEEP', '192.168.1.10 (PC-07)', '10.0.0.0/24 subnet', 'TCP:445', 'HIGH', 'Detection Alert ALT-2026-000002: Potential Internal Host Sweep', 'ALERT', 'ALT-2026-000002'),
('NET-DEMO-001', '2026-10-06 10:30:00', 'SMB_SESSION', '192.168.1.10 (PC-07)', '10.0.0.5 (SERVER-01)', 'TCP:445', 'MEDIUM', 'Established SMB session transferring 110 KB', 'EVENT', '15'),
('NET-DEMO-001', '2026-10-06 10:35:10', 'DATA_EGRESS', '192.168.1.10 (PC-07)', '203.0.113.20', 'TCP:443', 'CRITICAL', 'Detection Alert ALT-2026-000004: Large Outbound Data Transfer (14.76 MB)', 'ALERT', 'ALT-2026-000004'),
('NET-DEMO-001', '2026-10-06 10:40:00', 'CASE_CREATED', 'System', 'Analyst', 'INTERNAL', 'INFO', 'Case NET-DEMO-001 opened and assigned to analyst', 'CASE_STATUS', 'NET-DEMO-001')
ON DUPLICATE KEY UPDATE description=VALUES(description);

-- 15. Analyst Findings
INSERT INTO findings (case_id, title, description, evidence, confidence, status, created_by, created_at) VALUES
('NET-DEMO-001', 'Outbound Command and Control Channel Established', 'Telemetric analysis reveals regular 30-second interval HTTPS beacons from PC-07 to documentation external IP 203.0.113.20, preceded by query for suspicious.example.', 'Flow logs #1-#5, Alert ALT-2026-000003', 'HIGH', 'CONFIRMED', 2, '2026-10-06 10:45:00'),
('NET-DEMO-001', 'Internal Reconnaissance against Sensitive Server Assets', 'Host PC-07 engaged in automated port discovery against core database server 10.0.0.5, followed by subnet sweep for open SMB listeners.', 'Network Events #6-#14, Alerts ALT-2026-000001, ALT-2026-000002', 'HIGH', 'CONFIRMED', 2, '2026-10-06 10:48:00'),
('NET-DEMO-001', 'Exfiltration of Staged Internal Telemetry', '14.76 MB egress burst occurred at 10:35:10 directed to 203.0.113.20 immediately after SMB interaction with SERVER-01.', 'Network Event #16, Alert ALT-2026-000004', 'HIGH', 'CONFIRMED', 2, '2026-10-06 10:52:00')
ON DUPLICATE KEY UPDATE title=VALUES(title);

-- 16. Analyst Notes
INSERT INTO analyst_notes (case_id, user_id, note, created_at) VALUES
('NET-DEMO-001', 2, '10:42 AM: Opened investigation based on combined severity of Port Scan, Beaconing, and Large Transfer detections from workstation PC-07.', '2026-10-06 10:42:00'),
('NET-DEMO-001', 2, '10:55 AM: Contacted network operations to isolate endpoint PC-07 (192.168.1.10) at switch level. IP 203.0.113.20 added to perimeter drop list.', '2026-10-06 10:55:00'),
('NET-DEMO-001', 2, '11:10 AM: Verified destination IP 203.0.113.20 is not a legitimate corporate SaaS partner. Initiating memory triage on PC-07.', '2026-10-06 11:10:00')
ON DUPLICATE KEY UPDATE note=VALUES(note);

-- 17. Seed Evidence & Chain of Custody
INSERT INTO evidence (id, case_id, original_filename, stored_filename, mime_type, size, hash_sha256, description, uploaded_by, uploaded_at) VALUES
(1, 'NET-DEMO-001', 'pc07_flow_capture_filtered.csv', 'ev_pc07_flow_capture_20261006.csv', 'text/csv', 4096, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'Filtered packet and flow logs extracted from perimeter switch for PC-07 IP 192.168.1.10', 2, '2026-10-06 10:43:00')
ON DUPLICATE KEY UPDATE original_filename=VALUES(original_filename);

INSERT INTO evidence_chain (evidence_id, user_id, action, action_timestamp, ip_address, current_hash) VALUES
(1, 2, 'UPLOADED', '2026-10-06 10:43:00', '127.0.0.1', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
(1, 2, 'VIEWED', '2026-10-06 10:44:00', '127.0.0.1', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
ON DUPLICATE KEY UPDATE action=VALUES(action);

-- 18. Audit Logs
INSERT INTO audit_logs (user_id, action, entity_type, entity_id, details, ip_address, user_agent, timestamp) VALUES
(1, 'SYSTEM_INIT', 'SYSTEM', '1', 'NetSentry system initialized with baseline rules and security schemas', '127.0.0.1', 'NetSentry System Installer', '2026-10-06 09:00:00'),
(2, 'LOGIN_SUCCESS', 'USER', '2', 'Analyst logged into NetSentry SOC portal', '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '2026-10-06 10:15:00'),
(2, 'LOG_UPLOADED', 'LOG_UPLOAD', '1', 'Uploaded demo-network.csv (14 events processed)', '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '2026-10-06 10:20:00'),
(2, 'ALERT_CREATED', 'ALERT', 'ALT-2026-000001', 'Generated Port Scan alert for PC-07 against SERVER-01', '127.0.0.1', 'Detection Engine', '2026-10-06 10:24:00'),
(2, 'CASE_CREATED', 'CASE', 'NET-DEMO-001', 'Created investigation case NET-DEMO-001 for PC-07 activity', '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '2026-10-06 10:40:00'),
(2, 'EVIDENCE_UPLOADED', 'EVIDENCE', '1', 'Uploaded evidence pc07_flow_capture_filtered.csv with SHA-256 validation', '127.0.0.1', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', '2026-10-06 10:43:00')
ON DUPLICATE KEY UPDATE action=VALUES(action);

SET FOREIGN_KEY_CHECKS = 1;
