# NetSentry Platform Security & Hardening Policy

## 1. Overview
NetSentry is an enterprise-grade Network Threat Hunting & Attack Reconstruction Platform designed for Security Operations Centers (SOC) and Incident Response teams. As a cybersecurity forensic application, security, integrity, and non-repudiation are foundational architectural requirements.

---

## 2. Authentication & Credential Safeguards
- **Password Storage**: Passwords are never stored in plaintext. Passwords are cryptographically hashed using **Werkzeug's salted Scrypt/PBKDF2** algorithm. Legacy hashes migrated from legacy systems use salted **Bcrypt ($2b$)**.
- **Session Protection**:
  - `SESSION_COOKIE_HTTPONLY = True`: Blocks client-side JavaScript access to session tokens to prevent XSS session theft.
  - `SESSION_COOKIE_SAMESITE = 'Lax'`: Mitigates Cross-Site Request Forgery (CSRF).
  - Configurable `SESSION_TIMEOUT` (default: 3600 seconds) with inactivity expiration.
- **Account Lockout & Brute-Force Defense**: Failed authentication attempts are metered, preventing automated credential stuffing attacks.

---

## 3. Role-Based Access Control (RBAC)
Server-side authorization is strictly enforced via the `@role_required` and `@login_required` decorators across every Blueprint route:

| Role | Permissions & Access Scope |
| :--- | :--- |
| **ADMIN** | Full administrative control: User management, detection rule tuning, global SOC thresholds, and immutable audit logs. |
| **ANALYST** | Telemetry ingestion, detection triage, alert management, investigation case lifecycle, evidence upload/verification, attack path reconstruction, findings, notes, and report generation. |
| **VIEWER** | Strict read-only observer access. All modification routes (`POST`, `PUT`, `DELETE`) are prohibited with `403 Forbidden` responses. |

---

## 4. Input Sanitization & Attack Prevention

### 4.1 Cross-Site Request Forgery (CSRF)
- Powered by `Flask-WTF`'s `CSRFProtect`.
- All HTML state-changing forms require a valid, non-expired CSRF token (`{{ csrf_token() }}`).
- REST API and AJAX fetch endpoints include the `X-CSRFToken` request header.

### 4.2 Cross-Site Scripting (XSS)
- Jinja2 autoescaping is enforced on all dynamic expressions (`{{ variable }}`).
- Raw network telemetry, packet payloads, and user-supplied descriptions are rendered safely without bypassing sanitization.

### 4.3 SQL Injection
- All queries leverage the **SQLAlchemy ORM** abstraction with parameter binding.
- Dynamic query interpolation via string formatting or concatenation is strictly prohibited.

---

## 5. Forensic File Upload & Evidence Security
- **Filename Randomization**: All uploaded files are assigned a cryptographically generated UUID filename (`uuid.uuid4().hex`) on disk, combined with `secure_filename()` sanitization. Original filenames are stored separately in the database for display only.
- **Path Traversal Protection**: Upload targets are strictly constrained to application storage subdirectories (`storage/uploads/`, `storage/evidence/`).
- **Dangerous Filetype Restrictions**: Executable scripts (`.php`, `.py`, `.exe`, `.bat`, `.cmd`, `.ps1`, `.sh`, `.js`, `.html`) are rejected from execution.
- **Storage Isolation**: Evidence files are stored outside the public `static/` web directory and can only be accessed or downloaded via authenticated Flask routes with active analyst permissions.

---

## 6. Cryptographic Chain of Custody & Evidence Integrity
- Every ingested file and piece of uploaded evidence has its **SHA-256 hash** immediately computed via `hashlib.sha256()`.
- The `EvidenceChain` audit trail records immutable custody logs (`UPLOADED`, `VIEWED`, `DOWNLOADED`, `ARCHIVED`) including user ID, timestamp, and client IP.
- Continuous integrity checking (`verify_integrity()`) verifies disk contents against registered SHA-256 hashes to detect tampering.

---

## 7. Audit Logging & Compliance
The `AuditService` records all critical SOC operations:
- `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`
- `LOG_UPLOAD`, `LOG_PARSE`
- `ALERT_CREATE`, `ALERT_UPDATE`
- `CASE_CREATE`, `CASE_UPDATE`
- `IOC_UPDATE`
- `EVIDENCE_UPLOAD`, `EVIDENCE_DOWNLOAD`
- `FINDING_CREATE`, `MITRE_ADD`
- `REPORT_GENERATE`
- `USER_CREATE`, `USER_UPDATE`
- `RULE_UPDATE`, `SETTINGS_UPDATE`

Audit records are immutable and cannot be deleted or modified by analysts.

---

## 8. Vulnerability Reporting
If you discover a security vulnerability in NetSentry, please send an advisory report to `soc@netsentry.local` or contact your system administrator. Please do not publish security disclosures publicly before fixes have been implemented.
