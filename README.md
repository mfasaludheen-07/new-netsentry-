# NetSentry — Network Threat Hunting & Attack Reconstruction Platform

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0%2B-black.svg)](https://palletsprojects.com/p/flask/)
[![Database](https://img.shields.io/badge/Database-MySQL%208%2B-orange.svg)](https://www.mysql.com/)
[![License](https://img.shields.io/badge/License-Proprietary-red.svg)](#)

NetSentry is an enterprise-grade Network Threat Hunting and Forensic Attack Reconstruction Platform engineered for Security Operations Centers (SOC) and Incident Response teams. It provides end-to-end network telemetry ingestion, defensive rule-based anomaly detection, incident triage dossiers, interactive Cytoscape topology graph mapping, forensic timelines, MITRE ATT&CK alignment, cryptographic SHA-256 evidence vaults with chain-of-custody tracking, and executive report compilation.

---

## Architecture & Technology Stack

- **Backend**: Python 3.12+ / Flask Application Factory Pattern
- **ORM & Data Layer**: Flask-SQLAlchemy 3.1+, PyMySQL
- **Authentication & RBAC**: Flask-Login, Werkzeug (Scrypt/PBKDF2/Bcrypt)
- **Forms & CSRF**: Flask-WTF, WTForms
- **Database**: MySQL 8+ (or MariaDB via XAMPP)
- **Frontend UI**: HTML5, Tailwind CSS, Font Awesome 6
- **Visual Analytics**: Chart.js (metrics & severity trends), Cytoscape.js (network topology & attack graphs)

---

## Features Overview

1. **Enterprise SOC Dashboard**: Real-time KPI summaries, severity distribution, top talkers, destination ports, and alert queues.
2. **Telemetry Ingestion**: High-throughput parsing for `.csv`, `.json`, `.log`, and `.txt` network telemetry with schema normalization.
3. **Defensive Detection Engine**: 9 configurable detection rules (Port Scans, Subnet Sweeps, Failed Connections, Unusual External Comms, Suspicious Remote Services, Large Transfers, DNS Bursts, Beacon Patterns, and Escalation Combinations).
4. **Investigation Cases Dossier**: Formal incident lifecycle management with 14 integrated tabs:
   - *Overview*, *Events*, *Alerts*, *IOCs*, *Endpoints*, *Topology Graph*, *Forensic Timeline*, *Attack Path*, *MITRE Mapping*, *Evidence*, *Findings*, *Notes*, *Report*, *Audit History*.
5. **Interactive Topology & Attack Graphs**: Cytoscape.js visualization mapping source hosts, internal targets, external C2 IPs, domains, and cases.
6. **RFC IP Classification & IOC Management**: Automatic RFC-compliant classification (Private RFC 1918, Loopback, Link-Local, Multicast, Public Internet) and triage.
7. **Cryptographic Evidence Vault**: SHA-256 integrity verification and immutable Chain of Custody tracking.
8. **Automated 16-Section Investigation Reports**: Web dossiers with dedicated one-click printable executive formats.
9. **Role-Based Access Control (RBAC)**: Enforced roles (`ADMIN`, `ANALYST`, `VIEWER`).
10. **Immutable SOC Audit Logs**: Comprehensive trail of every authentication, upload, rule modification, and triage decision.

---

## Step-by-Step Installation & Setup (Beginner Friendly)

Follow these clear, step-by-step instructions to get NetSentry up and running on your system.

### Step 1: Install Python
Ensure **Python 3.12 or newer** is installed on your computer:
- Download Python from [python.org](https://www.python.org/downloads/).
- **Important**: During installation on Windows, make sure to check the box:
  > **"Add python.exe to PATH"**

Verify your Python installation by opening a terminal or PowerShell prompt:
```bash
python --version
```

---

### Step 2: Open the Project Directory
Navigate to the NetSentry project root directory:
```bash
cd "c:\Users\asus\My other new project"
```

---

### Step 3: Create a Virtual Environment
Create an isolated Python virtual environment named `venv`:
```bash
python -m venv venv
```

---

### Step 4: Activate the Virtual Environment
Activate your virtual environment:

**Windows (PowerShell):**
```powershell
.\venv\Scripts\Activate.ps1
```
*(If you encounter a PowerShell script execution policy error, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first).*

**Windows (Command Prompt):**
```cmd
venv\Scripts\activate.bat
```

**macOS / Linux:**
```bash
source venv/bin/activate
```

---

### Step 5: Install Requirements
Upgrade `pip` and install all necessary Python dependencies:
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

### Step 6: Start MySQL in XAMPP
1. Open the **XAMPP Control Panel**.
2. Locate the **MySQL** module.
3. Click the **Start** button next to MySQL.
4. *(Note: Apache is NOT required; Flask serves the web application directly).*

---

### Step 7: Create the `netsentry` Database
Open your preferred MySQL client (e.g., phpMyAdmin at `http://localhost/phpmyadmin` or the MySQL terminal):
```sql
CREATE DATABASE IF NOT EXISTS netsentry CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

---

### Step 8: Import the Database Schema
Import the structural database tables from `database/schema.sql`:

Using MySQL CLI:
```bash
mysql -u root -p netsentry < database/schema.sql
```
*(If your root user has no password, simply press Enter when prompted).*

Or in phpMyAdmin:
- Select the `netsentry` database in the left sidebar.
- Click the **Import** tab at the top.
- Choose file: `database/schema.sql` and click **Import**.

---

### Step 9: Import the Initial Seed Data
Import default roles, detection rules, admin accounts, and catalog data from `database/seed.sql`:

Using MySQL CLI:
```bash
mysql -u root -p netsentry < database/seed.sql
```

Or in phpMyAdmin:
- Select the `netsentry` database.
- Click the **Import** tab.
- Choose file: `database/seed.sql` and click **Import**.

---

### Step 10: Copy `.env.example` to `.env`
In the project directory, duplicate `.env.example` to create your active `.env` configuration file:

**Windows (PowerShell):**
```powershell
Copy-Item .env.example .env
```

**Windows (CMD):**
```cmd
copy .env.example .env
```

---

### Step 11: Configure Database Settings in `.env`
Open `.env` in any text editor and adjust the settings if your MySQL setup differs from defaults:
```env
FLASK_ENV=development
SECRET_KEY=netsentry-soc-super-secret-key-change-in-prod-2026

DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=netsentry
DB_USER=root
DB_PASSWORD=

SESSION_TIMEOUT=3600
MAX_UPLOAD_MB=20
```

---

### Step 12: Start the Application
Run the entry point script:
```bash
python run.py
```

The console will display the operational startup banner:
```
============================================================
  NETSENTRY — Network Threat Hunting & Attack Reconstruction
============================================================
  NetSentry running at: http://127.0.0.1:5000
============================================================
```

---

### Step 13: Visit the Web Portal
Open your web browser and navigate to:
[http://127.0.0.1:5000](http://127.0.0.1:5000)

---

### Step 14: Log In with Demo Accounts
NetSentry comes pre-seeded with 3 role accounts:

| Username | Password | Role | Permissions |
| :--- | :--- | :--- | :--- |
| **`admin`** | `Password123!` | ADMIN | Full system administration, rule thresholds, user accounts, audit trail |
| **`analyst`** | `Password123!` | ANALYST | Threat hunting, log uploads, alert triage, cases, evidence, reports |
| **`viewer`** | `Password123!` | VIEWER | Read-only observation of dashboard, alerts, and cases |

*Tip: Quick login shortcut buttons are available directly on the login screen for testing convenience.*

---

### Step 15: Upload Demo Network Telemetry
1. Log in as **`analyst`**.
2. Click **Network Logs** in the sidebar navigation and select **Upload Telemetry**.
3. Select the provided demo dataset:
   - `demo/demo-network.csv` (or `demo/demo-network.json`)
4. Select the source type (e.g. *Perimeter Firewall & Flow Collector*) and click **Upload & Analyze Telemetry**.
5. NetSentry will automatically:
   - Parse and normalize the telemetry events
   - Run the 9 defensive detection rules
   - Generate prioritized alerts
   - Profile the internal hosts and external IPs
   - Map topology nodes in the Cytoscape graph view!

---

## Running the Automated Test Suite

To run all unit and integration tests across authentication, RBAC, parsers, normalizers, detection engine, IOC classification, evidence SHA-256, timelines, and reporting:

```bash
.\venv\Scripts\python.exe -m unittest discover tests
```

---

## Project Structure

```
netsentry/
│
├── app.py                     # WSGI entry point
├── run.py                     # CLI launcher with startup banner
├── config.py                  # Environment & database configuration
├── requirements.txt           # Python package dependencies
├── .env.example               # Template environment configuration
├── .gitignore                 # Git ignore rules
├── README.md                  # System documentation & quickstart
├── SECURITY.md                # Platform security policy & hardening
│
├── app/
│   ├── __init__.py            # Flask Application Factory (create_app)
│   ├── extensions.py          # SQLAlchemy, Flask-Login, CSRFProtect
│   ├── models.py              # 27 SQLAlchemy forensic models
│   ├── decorators.py          # @role_required, @admin_required, @analyst_required
│   ├── utils.py               # Cryptography, SHA-256 hashing, UUID file handling, RFC IP classifier
│   │
│   ├── auth/                  # Authentication & session management
│   ├── dashboard/             # Threat metrics & Chart.js statistics
│   ├── logs/                  # Telemetry ingestion & traffic explorer
│   ├── alerts/                # Threat alerts & triage workflow
│   ├── cases/                 # 14-tab investigation dossier management
│   ├── iocs/                  # Indicators of Compromise & RFC IP classification
│   ├── endpoints/             # Host asset profiling & activity history
│   ├── timeline/              # Chronological forensic timeline
│   ├── graph/                 # Cytoscape.js interactive network topology
│   ├── evidence/              # SHA-256 secured evidence vault & chain of custody
│   ├── reports/               # Printable 16-section HTML investigation reports
│   ├── admin/                 # User management, detection rules, SOC settings, audit logs
│   ├── api/                   # REST API endpoints for alerts, events, cases, graph
│   │
│   ├── services/              # Core business & forensic logic engines
│   │   ├── log_parser.py
│   │   ├── normalizer.py
│   │   ├── detection_engine.py
│   │   ├── correlation_engine.py
│   │   ├── timeline_service.py
│   │   ├── graph_service.py
│   │   ├── ioc_service.py
│   │   ├── evidence_service.py
│   │   ├── audit_service.py
│   │   └── report_service.py
│   │
│   ├── templates/             # Jinja2 SOC templates & partials
│   └── static/                # Static assets (CSS, JS, icons)
│
├── database/
│   ├── schema.sql             # MySQL DDL table schema
│   └── seed.sql               # Seed roles, rules, settings, users, and catalog
│
├── demo/
│   ├── demo-network.csv       # Standard demo CSV network traffic
│   └── demo-network.json      # Standard demo JSON network traffic
│
├── storage/
│   ├── uploads/               # Telemetry uploads
│   ├── evidence/              # Secured forensic evidence files
│   ├── reports/               # Compiled reports
│   └── logs/                  # System operational logs
│
└── tests/                     # Comprehensive automated test suite
```

---

## Forensic Integrity & Compliance
- **Zero PHP Dependency**: The entire backend runs natively on Python 3.12+ and Flask.
- **Evidence Integrity**: All evidence files are tracked with cryptographic SHA-256 hashes and timestamped chain-of-custody logging.
- **Auditing**: All operational decisions, logins, and configuration changes are recorded in immutable audit tables.
