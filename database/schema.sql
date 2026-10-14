-- database/schema.sql
-- NetSentry: Network Threat Hunting & Attack Reconstruction Platform
-- Database Schema (MySQL 8+ / MariaDB 10.4+)

CREATE DATABASE IF NOT EXISTS netsentry CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE netsentry;

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS analyst_notes;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS evidence_chain;
DROP TABLE IF EXISTS evidence;
DROP TABLE IF EXISTS case_mitre;
DROP TABLE IF EXISTS mitre_techniques;
DROP TABLE IF EXISTS attack_stages;
DROP TABLE IF EXISTS timeline_events;
DROP TABLE IF EXISTS event_correlations;
DROP TABLE IF EXISTS endpoint_events;
DROP TABLE IF EXISTS endpoints;
DROP TABLE IF EXISTS case_iocs;
DROP TABLE IF EXISTS iocs;
DROP TABLE IF EXISTS case_events;
DROP TABLE IF EXISTS case_alerts;
DROP TABLE IF EXISTS cases;
DROP TABLE IF EXISTS alert_events;
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS detection_rules;
DROP TABLE IF EXISTS network_events;
DROP TABLE IF EXISTS log_uploads;
DROP TABLE IF EXISTS log_sources;
DROP TABLE IF EXISTS settings;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;

SET FOREIGN_KEY_CHECKS = 1;

-- 1. Roles
CREATE TABLE roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description VARCHAR(255) NULL,
    permissions JSON NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Users
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    status ENUM('active', 'disabled') DEFAULT 'active',
    failed_logins INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Settings
CREATE TABLE settings (
    setting_key VARCHAR(100) PRIMARY KEY,
    setting_value TEXT NULL,
    description VARCHAR(255) NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Log Sources
CREATE TABLE log_sources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    source_type VARCHAR(50) NOT NULL DEFAULT 'Generic Network Log',
    description TEXT NULL,
    timezone VARCHAR(50) DEFAULT 'UTC',
    created_by INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 5. Log Uploads
CREATE TABLE log_uploads (
    id INT AUTO_INCREMENT PRIMARY KEY,
    source_id INT NULL,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL,
    file_size INT NOT NULL,
    mime_type VARCHAR(100) NOT NULL DEFAULT 'text/plain',
    hash_sha256 VARCHAR(64) NOT NULL DEFAULT '',
    status ENUM('PENDING', 'PROCESSING', 'COMPLETED', 'FAILED', 'UPLOADED') DEFAULT 'PENDING',
    total_rows INT DEFAULT 0,
    imported_rows INT DEFAULT 0,
    skipped_rows INT DEFAULT 0,
    error_count INT DEFAULT 0,
    parsing_errors TEXT NULL,
    uploaded_by INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (source_id) REFERENCES log_sources(id) ON DELETE SET NULL,
    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 6. Network Events (Canonical Normalized Event Model)
CREATE TABLE network_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    upload_id INT NULL,
    timestamp DATETIME NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    destination_ip VARCHAR(45) NOT NULL,
    source_port INT NULL,
    destination_port INT NULL,
    protocol VARCHAR(20) DEFAULT 'TCP',
    hostname VARCHAR(255) NULL,
    username VARCHAR(100) NULL,
    domain VARCHAR(255) NULL,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    dns_query VARCHAR(255) NULL,
    event_type VARCHAR(100) DEFAULT 'connection',
    action VARCHAR(50) DEFAULT 'ALLOW',
    source_type VARCHAR(50) DEFAULT 'generic',
    raw_event TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_src_ip (source_ip),
    INDEX idx_dst_ip (destination_ip),
    INDEX idx_dst_port (destination_port),
    INDEX idx_proto (protocol),
    INDEX idx_hostname (hostname),
    INDEX idx_domain (domain),
    FOREIGN KEY (upload_id) REFERENCES log_uploads(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 7. Detection Rules
CREATE TABLE detection_rules (
    id VARCHAR(50) PRIMARY KEY, -- e.g. RULE-001
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    enabled TINYINT(1) DEFAULT 1,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
    threshold INT DEFAULT 5,
    time_window_seconds INT DEFAULT 300,
    rule_type VARCHAR(100) NOT NULL,
    mitre_technique_id VARCHAR(50) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 8. Alerts
CREATE TABLE alerts (
    id VARCHAR(50) PRIMARY KEY, -- e.g. ALT-2026-000001
    rule_id VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
    source_ip VARCHAR(45) NULL,
    destination_ip VARCHAR(45) NULL,
    endpoint VARCHAR(255) NULL,
    first_seen DATETIME NOT NULL,
    last_seen DATETIME NOT NULL,
    event_count INT DEFAULT 1,
    status ENUM('NEW', 'TRIAGED', 'INVESTIGATING', 'FALSE_POSITIVE', 'RESOLVED') DEFAULT 'NEW',
    confidence ENUM('LOW', 'MEDIUM', 'HIGH') DEFAULT 'MEDIUM',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_alert_status (status),
    INDEX idx_alert_severity (severity),
    INDEX idx_alert_src (source_ip),
    FOREIGN KEY (rule_id) REFERENCES detection_rules(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 9. Alert Events (Association table)
CREATE TABLE alert_events (
    alert_id VARCHAR(50) NOT NULL,
    event_id BIGINT NOT NULL,
    PRIMARY KEY (alert_id, event_id),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES network_events(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 10. Cases
CREATE TABLE cases (
    id VARCHAR(50) PRIMARY KEY, -- e.g. NET-2026-000001
    title VARCHAR(255) NOT NULL,
    description TEXT NULL,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
    priority ENUM('LOW', 'MEDIUM', 'HIGH', 'URGENT') DEFAULT 'MEDIUM',
    status ENUM('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE') DEFAULT 'OPEN',
    assigned_to INT NULL,
    created_by INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    closed_at TIMESTAMP NULL,
    INDEX idx_case_status (status),
    FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 11. Case Alerts
CREATE TABLE case_alerts (
    case_id VARCHAR(50) NOT NULL,
    alert_id VARCHAR(50) NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (case_id, alert_id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 12. Case Events
CREATE TABLE case_events (
    case_id VARCHAR(50) NOT NULL,
    event_id BIGINT NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (case_id, event_id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES network_events(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 13. IOCs (Indicators of Compromise)
CREATE TABLE iocs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    value VARCHAR(255) NOT NULL UNIQUE,
    type ENUM('IP', 'DOMAIN', 'HOSTNAME', 'URL', 'HASH_MD5', 'HASH_SHA1', 'HASH_SHA256') NOT NULL,
    confidence ENUM('LOW', 'MEDIUM', 'HIGH') DEFAULT 'LOW',
    status ENUM('UNKNOWN', 'OBSERVED', 'SUSPICIOUS', 'CONFIRMED', 'BENIGN') DEFAULT 'UNKNOWN',
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    notes TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ioc_type (type),
    INDEX idx_ioc_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 14. Case IOCs
CREATE TABLE case_iocs (
    case_id VARCHAR(50) NOT NULL,
    ioc_id INT NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (case_id, ioc_id),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 15. Endpoints
CREATE TABLE endpoints (
    id INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NOT NULL,
    os_info VARCHAR(100) DEFAULT 'Unknown',
    criticality ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'MEDIUM',
    owner_description VARCHAR(255) NULL,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    alert_count INT DEFAULT 0,
    case_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ep_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 16. Endpoint Events
CREATE TABLE endpoint_events (
    endpoint_id INT NOT NULL,
    event_id BIGINT NOT NULL,
    PRIMARY KEY (endpoint_id, event_id),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES network_events(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 17. Event Correlations
CREATE TABLE event_correlations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(50) NULL,
    event_a_id BIGINT NOT NULL,
    event_b_id BIGINT NOT NULL,
    correlation_type VARCHAR(100) NOT NULL,
    correlation_reason TEXT NOT NULL,
    confidence ENUM('LOW', 'MEDIUM', 'HIGH') DEFAULT 'MEDIUM',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (event_a_id) REFERENCES network_events(id) ON DELETE CASCADE,
    FOREIGN KEY (event_b_id) REFERENCES network_events(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 18. Forensic Timeline Events
CREATE TABLE timeline_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(50) NULL,
    event_time DATETIME NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    source VARCHAR(255) NULL,
    destination VARCHAR(255) NULL,
    protocol VARCHAR(50) NULL,
    severity ENUM('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'INFO',
    description TEXT NOT NULL,
    reference_type VARCHAR(50) NULL, -- EVENT, ALERT, FINDING, EVIDENCE, CASE_STATUS
    reference_id VARCHAR(50) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tl_case (case_id),
    INDEX idx_tl_time (event_time),
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 19. Attack Stages (Attack Path Reconstruction)
CREATE TABLE attack_stages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    stage_order INT NOT NULL,
    stage_name VARCHAR(255) NOT NULL,
    status ENUM('OBSERVED', 'SUSPECTED', 'CONFIRMED', 'DISPROVED') DEFAULT 'SUSPECTED',
    confidence ENUM('LOW', 'MEDIUM', 'HIGH') DEFAULT 'MEDIUM',
    evidence_summary TEXT NULL,
    related_events_count INT DEFAULT 0,
    analyst_comment TEXT NULL,
    updated_by INT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 20. MITRE ATT&CK Techniques Catalog
CREATE TABLE mitre_techniques (
    id VARCHAR(50) PRIMARY KEY, -- e.g. T1046
    name VARCHAR(255) NOT NULL,
    tactic VARCHAR(255) NOT NULL,
    description TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 21. Case MITRE Mapping
CREATE TABLE case_mitre (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    technique_id VARCHAR(50) NOT NULL,
    status ENUM('OBSERVED', 'SUSPECTED', 'NOT_APPLICABLE') DEFAULT 'SUSPECTED',
    notes TEXT NULL,
    supporting_evidence TEXT NULL,
    updated_by INT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id) ON DELETE CASCADE,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 22. Evidence
CREATE TABLE evidence (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    stored_filename VARCHAR(255) NOT NULL UNIQUE,
    mime_type VARCHAR(100) NOT NULL,
    size BIGINT NOT NULL,
    hash_sha256 VARCHAR(64) NOT NULL,
    description TEXT NULL,
    uploaded_by INT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 23. Evidence Chain of Custody
CREATE TABLE evidence_chain (
    id INT AUTO_INCREMENT PRIMARY KEY,
    evidence_id INT NOT NULL,
    user_id INT NOT NULL,
    action ENUM('UPLOADED', 'VIEWED', 'DOWNLOADED', 'METADATA_UPDATED', 'ARCHIVED') NOT NULL,
    action_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NULL,
    current_hash VARCHAR(64) NULL,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 24. Findings
CREATE TABLE findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT NOT NULL,
    evidence TEXT NULL,
    confidence ENUM('LOW', 'MEDIUM', 'HIGH') DEFAULT 'MEDIUM',
    status ENUM('OBSERVED', 'SUSPECTED', 'CONFIRMED', 'DISPROVED') DEFAULT 'OBSERVED',
    created_by INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 25. Analyst Notes
CREATE TABLE analyst_notes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    user_id INT NOT NULL,
    note TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 26. Reports
CREATE TABLE reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    case_id VARCHAR(50) NOT NULL,
    title VARCHAR(255) NOT NULL,
    summary TEXT NULL,
    report_data LONGTEXT NULL,
    generated_by INT NOT NULL,
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    FOREIGN KEY (generated_by) REFERENCES users(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 27. Audit Logs
CREATE TABLE audit_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action VARCHAR(100) NOT NULL,
    entity_type VARCHAR(100) NULL,
    entity_id VARCHAR(100) NULL,
    details TEXT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent VARCHAR(255) NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_action (action),
    INDEX idx_audit_time (timestamp),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
