import json
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db, login_manager


# -------------------------------------------------------------
# 1. Role Model
# -------------------------------------------------------------
class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    permissions = db.Column(db.JSON, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    users = db.relationship('User', back_populates='role', lazy='dynamic')

    def __repr__(self):
        return f"<Role {self.name}>"


# -------------------------------------------------------------
# 2. User Model
# -------------------------------------------------------------
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(100), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id', ondelete='RESTRICT'), nullable=False)
    status = db.Column(db.String(20), default='active')
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    role = db.relationship('Role', back_populates='users')
    assigned_cases = db.relationship('Case', foreign_keys='Case.assigned_to', back_populates='assignee', lazy='dynamic')
    created_cases = db.relationship('Case', foreign_keys='Case.created_by', back_populates='creator', lazy='dynamic')
    uploads = db.relationship('LogUpload', back_populates='uploader', lazy='dynamic')
    evidence_uploads = db.relationship('Evidence', back_populates='uploader', lazy='dynamic')
    notes = db.relationship('AnalystNote', back_populates='author', lazy='dynamic')
    findings = db.relationship('Finding', back_populates='creator', lazy='dynamic')
    reports = db.relationship('Report', back_populates='generator', lazy='dynamic')
    audit_logs = db.relationship('AuditLog', back_populates='user', lazy='dynamic')

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if not self.password_hash or not password:
            return False

        # Support native Werkzeug hashes (scrypt, pbkdf2)
        if self.password_hash.startswith(('pbkdf2:', 'scrypt:', 'argon2:')):
            try:
                return check_password_hash(self.password_hash, password)
            except Exception:
                pass

        # Support legacy / seeded bcrypt hashes ($2y$, $2b$, $2a$)
        if self.password_hash.startswith(('$2y$', '$2b$', '$2a$')):
            try:
                import bcrypt
                pw_bytes = password.encode('utf-8')
                hash_bytes = self.password_hash.replace('$2y$', '$2b$').encode('utf-8')
                return bcrypt.checkpw(pw_bytes, hash_bytes)
            except Exception:
                pass

        try:
            return check_password_hash(self.password_hash, password)
        except Exception:
            return False

    @property
    def is_admin(self) -> bool:
        return bool(self.role and self.role.name.upper() == 'ADMIN')

    @property
    def is_analyst(self) -> bool:
        return bool(self.role and self.role.name.upper() == 'ANALYST')

    @property
    def is_viewer(self) -> bool:
        return bool(self.role and self.role.name.upper() == 'VIEWER')

    def has_role(self, *role_names: str) -> bool:
        if not self.role:
            return False
        return self.role.name.upper() in [r.upper() for r in role_names]

    def __repr__(self):
        return f"<User {self.username}>"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# -------------------------------------------------------------
# 3. Setting Model
# -------------------------------------------------------------
class Setting(db.Model):
    __tablename__ = 'settings'

    setting_key = db.Column(db.String(100), primary_key=True)
    setting_value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    @classmethod
    def get_value(cls, key: str, default=None):
        item = db.session.get(cls, key)
        return item.setting_value if item else default

    @classmethod
    def set_value(cls, key: str, value: str, description: str = None):
        item = db.session.get(cls, key)
        if item:
            item.setting_value = value
            if description:
                item.description = description
        else:
            item = cls(setting_key=key, setting_value=value, description=description)
            db.session.add(item)
        db.session.commit()
        return item


# -------------------------------------------------------------
# 4. Log Source Model
# -------------------------------------------------------------
class LogSource(db.Model):
    __tablename__ = 'log_sources'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    source_type = db.Column(db.String(50), nullable=False, default='Generic Network Log')
    description = db.Column(db.Text, nullable=True)
    timezone = db.Column(db.String(50), default='UTC')
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    uploads = db.relationship('LogUpload', back_populates='source', lazy='dynamic')


# -------------------------------------------------------------
# 5. Log Upload Model
# -------------------------------------------------------------
class LogUpload(db.Model):
    __tablename__ = 'log_uploads'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    source_id = db.Column(db.Integer, db.ForeignKey('log_sources.id', ondelete='SET NULL'), nullable=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False, default='text/plain')
    hash_sha256 = db.Column(db.String(64), nullable=False, default='')
    status = db.Column(db.String(20), default='PENDING')  # PENDING, PROCESSING, COMPLETED, FAILED, UPLOADED
    total_rows = db.Column(db.Integer, default=0)
    imported_rows = db.Column(db.Integer, default=0)
    skipped_rows = db.Column(db.Integer, default=0)
    error_count = db.Column(db.Integer, default=0)
    parsing_errors = db.Column(db.Text, nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    source = db.relationship('LogSource', back_populates='uploads')
    uploader = db.relationship('User', back_populates='uploads')
    events = db.relationship('NetworkEvent', back_populates='upload', lazy='dynamic')


# -------------------------------------------------------------
# 6. Network Event Model (Canonical Normalized Event Model)
# -------------------------------------------------------------
class NetworkEvent(db.Model):
    __tablename__ = 'network_events'

    id = db.Column(db.BigInteger().with_variant(db.Integer, 'sqlite'), primary_key=True, autoincrement=True)
    upload_id = db.Column(db.Integer, db.ForeignKey('log_uploads.id', ondelete='SET NULL'), nullable=True)
    timestamp = db.Column(db.DateTime, nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False, index=True)
    destination_ip = db.Column(db.String(45), nullable=False, index=True)
    source_port = db.Column(db.Integer, nullable=True)
    destination_port = db.Column(db.Integer, nullable=True, index=True)
    protocol = db.Column(db.String(20), default='TCP', index=True)
    hostname = db.Column(db.String(255), nullable=True, index=True)
    username = db.Column(db.String(100), nullable=True)
    domain = db.Column(db.String(255), nullable=True, index=True)
    bytes_sent = db.Column(db.BigInteger, default=0)
    bytes_received = db.Column(db.BigInteger, default=0)
    dns_query = db.Column(db.String(255), nullable=True)
    event_type = db.Column(db.String(100), default='connection')
    action = db.Column(db.String(50), default='ALLOW')
    source_type = db.Column(db.String(50), default='generic')
    raw_event = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    upload = db.relationship('LogUpload', back_populates='events')
    alerts = db.relationship('Alert', secondary='alert_events', back_populates='events', lazy='dynamic')
    cases = db.relationship('Case', secondary='case_events', back_populates='events', lazy='dynamic')


# -------------------------------------------------------------
# 7. Detection Rule Model
# -------------------------------------------------------------
class DetectionRule(db.Model):
    __tablename__ = 'detection_rules'

    id = db.Column(db.String(50), primary_key=True)  # e.g. RULE-001
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    severity = db.Column(db.String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH, CRITICAL
    threshold = db.Column(db.Integer, default=5)
    time_window_seconds = db.Column(db.Integer, default=300)
    rule_type = db.Column(db.String(100), nullable=False)
    mitre_technique_id = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    alerts = db.relationship('Alert', back_populates='rule', lazy='dynamic')


# -------------------------------------------------------------
# 8. Alert Model
# -------------------------------------------------------------
class Alert(db.Model):
    __tablename__ = 'alerts'

    id = db.Column(db.String(50), primary_key=True)  # e.g. ALT-2026-000001
    rule_id = db.Column(db.String(50), db.ForeignKey('detection_rules.id', ondelete='RESTRICT'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    severity = db.Column(db.String(20), default='MEDIUM', index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    source_ip = db.Column(db.String(45), nullable=True, index=True)
    destination_ip = db.Column(db.String(45), nullable=True)
    endpoint = db.Column(db.String(255), nullable=True)
    first_seen = db.Column(db.DateTime, nullable=False)
    last_seen = db.Column(db.DateTime, nullable=False)
    event_count = db.Column(db.Integer, default=1)
    status = db.Column(db.String(20), default='NEW', index=True)  # NEW, TRIAGED, INVESTIGATING, FALSE_POSITIVE, RESOLVED
    confidence = db.Column(db.String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    rule = db.relationship('DetectionRule', back_populates='alerts')
    events = db.relationship('NetworkEvent', secondary='alert_events', back_populates='alerts', lazy='dynamic')
    cases = db.relationship('Case', secondary='case_alerts', back_populates='alerts', lazy='dynamic')


# -------------------------------------------------------------
# 9. Alert Event Association Table Model
# -------------------------------------------------------------
class AlertEvent(db.Model):
    __tablename__ = 'alert_events'

    alert_id = db.Column(db.String(50), db.ForeignKey('alerts.id', ondelete='CASCADE'), primary_key=True)
    event_id = db.Column(db.BigInteger, db.ForeignKey('network_events.id', ondelete='CASCADE'), primary_key=True)


# -------------------------------------------------------------
# 10. Case Model
# -------------------------------------------------------------
class Case(db.Model):
    __tablename__ = 'cases'

    id = db.Column(db.String(50), primary_key=True)  # e.g. NET-2026-000001
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH, CRITICAL
    priority = db.Column(db.String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH, URGENT
    status = db.Column(db.String(20), default='OPEN', index=True)  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    closed_at = db.Column(db.DateTime, nullable=True)

    assignee = db.relationship('User', foreign_keys=[assigned_to], back_populates='assigned_cases')
    creator = db.relationship('User', foreign_keys=[created_by], back_populates='created_cases')
    
    alerts = db.relationship('Alert', secondary='case_alerts', back_populates='cases', lazy='dynamic')
    events = db.relationship('NetworkEvent', secondary='case_events', back_populates='cases', lazy='dynamic')
    iocs = db.relationship('IOC', secondary='case_iocs', back_populates='cases', lazy='dynamic')
    
    attack_stages = db.relationship('AttackStage', back_populates='case', cascade='all, delete-orphan', order_by='AttackStage.stage_order')
    mitre_mappings = db.relationship('CaseMitre', back_populates='case', cascade='all, delete-orphan')
    evidence_items = db.relationship('Evidence', back_populates='case', cascade='all, delete-orphan')
    findings = db.relationship('Finding', back_populates='case', cascade='all, delete-orphan')
    notes = db.relationship('AnalystNote', back_populates='case', cascade='all, delete-orphan', order_by='AnalystNote.created_at.desc()')
    reports = db.relationship('Report', back_populates='case', cascade='all, delete-orphan')
    timeline_events = db.relationship('TimelineEvent', back_populates='case', cascade='all, delete-orphan')
    correlations = db.relationship('EventCorrelation', back_populates='case', cascade='all, delete-orphan')


# -------------------------------------------------------------
# 11. Case Alert Association Model
# -------------------------------------------------------------
class CaseAlert(db.Model):
    __tablename__ = 'case_alerts'

    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), primary_key=True)
    alert_id = db.Column(db.String(50), db.ForeignKey('alerts.id', ondelete='RESTRICT'), primary_key=True)
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# -------------------------------------------------------------
# 12. Case Event Association Model
# -------------------------------------------------------------
class CaseEvent(db.Model):
    __tablename__ = 'case_events'

    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), primary_key=True)
    event_id = db.Column(db.BigInteger, db.ForeignKey('network_events.id', ondelete='CASCADE'), primary_key=True)
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# -------------------------------------------------------------
# 13. IOC Model (Indicator of Compromise)
# -------------------------------------------------------------
class IOC(db.Model):
    __tablename__ = 'iocs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    value = db.Column(db.String(255), unique=True, nullable=False, index=True)
    type = db.Column(db.String(20), nullable=False, index=True)  # IP, DOMAIN, HOSTNAME, URL, HASH_MD5, HASH_SHA1, HASH_SHA256
    confidence = db.Column(db.String(20), default='LOW')  # LOW, MEDIUM, HIGH
    status = db.Column(db.String(20), default='UNKNOWN', index=True)  # UNKNOWN, OBSERVED, SUSPICIOUS, CONFIRMED, BENIGN
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    cases = db.relationship('Case', secondary='case_iocs', back_populates='iocs', lazy='dynamic')


# -------------------------------------------------------------
# 14. Case IOC Association Model
# -------------------------------------------------------------
class CaseIOC(db.Model):
    __tablename__ = 'case_iocs'

    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), primary_key=True)
    ioc_id = db.Column(db.Integer, db.ForeignKey('iocs.id', ondelete='CASCADE'), primary_key=True)
    added_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# -------------------------------------------------------------
# 15. Endpoint Model
# -------------------------------------------------------------
class Endpoint(db.Model):
    __tablename__ = 'endpoints'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    os_info = db.Column(db.String(100), default='Unknown')
    criticality = db.Column(db.String(20), default='MEDIUM')  # LOW, MEDIUM, HIGH, CRITICAL
    owner_description = db.Column(db.String(255), nullable=True)
    first_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    alert_count = db.Column(db.Integer, default=0)
    case_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# -------------------------------------------------------------
# 16. Endpoint Event Association Model
# -------------------------------------------------------------
class EndpointEvent(db.Model):
    __tablename__ = 'endpoint_events'

    endpoint_id = db.Column(db.Integer, db.ForeignKey('endpoints.id', ondelete='CASCADE'), primary_key=True)
    event_id = db.Column(db.BigInteger, db.ForeignKey('network_events.id', ondelete='CASCADE'), primary_key=True)


# -------------------------------------------------------------
# 17. Event Correlation Model
# -------------------------------------------------------------
class EventCorrelation(db.Model):
    __tablename__ = 'event_correlations'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=True)
    event_a_id = db.Column(db.BigInteger, db.ForeignKey('network_events.id', ondelete='CASCADE'), nullable=False)
    event_b_id = db.Column(db.BigInteger, db.ForeignKey('network_events.id', ondelete='CASCADE'), nullable=False)
    correlation_type = db.Column(db.String(100), nullable=False)
    correlation_reason = db.Column(db.Text, nullable=False)
    confidence = db.Column(db.String(20), default='MEDIUM')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    case = db.relationship('Case', back_populates='correlations')
    event_a = db.relationship('NetworkEvent', foreign_keys=[event_a_id])
    event_b = db.relationship('NetworkEvent', foreign_keys=[event_b_id])


# -------------------------------------------------------------
# 18. Forensic Timeline Event Model
# -------------------------------------------------------------
class TimelineEvent(db.Model):
    __tablename__ = 'timeline_events'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=True, index=True)
    event_time = db.Column(db.DateTime, nullable=False, index=True)
    event_type = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(255), nullable=True)
    destination = db.Column(db.String(255), nullable=True)
    protocol = db.Column(db.String(50), nullable=True)
    severity = db.Column(db.String(20), default='INFO')  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description = db.Column(db.Text, nullable=False)
    reference_type = db.Column(db.String(50), nullable=True)  # EVENT, ALERT, FINDING, EVIDENCE, CASE_STATUS
    reference_id = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    case = db.relationship('Case', back_populates='timeline_events')


# -------------------------------------------------------------
# 19. Attack Stage Model (Attack Path Reconstruction)
# -------------------------------------------------------------
class AttackStage(db.Model):
    __tablename__ = 'attack_stages'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False)
    stage_order = db.Column(db.Integer, nullable=False)
    stage_name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default='SUSPECTED')  # OBSERVED, SUSPECTED, CONFIRMED, DISPROVED
    confidence = db.Column(db.String(20), default='MEDIUM')
    evidence_summary = db.Column(db.Text, nullable=True)
    related_events_count = db.Column(db.Integer, default=0)
    analyst_comment = db.Column(db.Text, nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    case = db.relationship('Case', back_populates='attack_stages')
    updater = db.relationship('User')


# -------------------------------------------------------------
# 20. MITRE Technique Model
# -------------------------------------------------------------
class MitreTechnique(db.Model):
    __tablename__ = 'mitre_techniques'

    id = db.Column(db.String(50), primary_key=True)  # e.g. T1046
    name = db.Column(db.String(255), nullable=False)
    tactic = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)


# -------------------------------------------------------------
# 21. Case MITRE Mapping Model
# -------------------------------------------------------------
class CaseMitre(db.Model):
    __tablename__ = 'case_mitre'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False)
    technique_id = db.Column(db.String(50), db.ForeignKey('mitre_techniques.id', ondelete='CASCADE'), nullable=False)
    status = db.Column(db.String(20), default='SUSPECTED')  # OBSERVED, SUSPECTED, NOT_APPLICABLE
    notes = db.Column(db.Text, nullable=True)
    supporting_evidence = db.Column(db.Text, nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    case = db.relationship('Case', back_populates='mitre_mappings')
    technique = db.relationship('MitreTechnique')
    updater = db.relationship('User')


# -------------------------------------------------------------
# 22. Evidence Model
# -------------------------------------------------------------
class Evidence(db.Model):
    __tablename__ = 'evidence'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    hash_sha256 = db.Column(db.String(64), nullable=False)
    description = db.Column(db.Text, nullable=True)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    case = db.relationship('Case', back_populates='evidence_items')
    uploader = db.relationship('User', back_populates='evidence_uploads')
    chain = db.relationship('EvidenceChain', back_populates='evidence', cascade='all, delete-orphan', order_by='EvidenceChain.action_timestamp.desc()')


# -------------------------------------------------------------
# 23. Evidence Chain of Custody Model
# -------------------------------------------------------------
class EvidenceChain(db.Model):
    __tablename__ = 'evidence_chain'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # UPLOADED, VIEWED, DOWNLOADED, METADATA_UPDATED, ARCHIVED
    action_timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    ip_address = db.Column(db.String(45), nullable=True)
    current_hash = db.Column(db.String(64), nullable=True)

    evidence = db.relationship('Evidence', back_populates='chain')
    user = db.relationship('User')


# -------------------------------------------------------------
# 24. Finding Model
# -------------------------------------------------------------
class Finding(db.Model):
    __tablename__ = 'findings'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    evidence = db.Column(db.Text, nullable=True)
    confidence = db.Column(db.String(20), default='MEDIUM')
    status = db.Column(db.String(20), default='OBSERVED')  # OBSERVED, SUSPECTED, CONFIRMED, DISPROVED
    created_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    case = db.relationship('Case', back_populates='findings')
    creator = db.relationship('User', back_populates='findings')


# -------------------------------------------------------------
# 25. Analyst Note Model
# -------------------------------------------------------------
class AnalystNote(db.Model):
    __tablename__ = 'analyst_notes'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    case = db.relationship('Case', back_populates='notes')
    author = db.relationship('User', back_populates='notes')


# -------------------------------------------------------------
# 26. Report Model
# -------------------------------------------------------------
class Report(db.Model):
    __tablename__ = 'reports'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    case_id = db.Column(db.String(50), db.ForeignKey('cases.id', ondelete='CASCADE'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    summary = db.Column(db.Text, nullable=True)
    report_data = db.Column(db.Text, nullable=True)  # Store JSON representation of 16-section report
    generated_by = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False)
    generated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    case = db.relationship('Case', back_populates='reports')
    generator = db.relationship('User', back_populates='reports')


# -------------------------------------------------------------
# 27. Audit Log Model
# -------------------------------------------------------------
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    action = db.Column(db.String(100), nullable=False, index=True)
    entity_type = db.Column(db.String(100), nullable=True)
    entity_id = db.Column(db.String(100), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    user = db.relationship('User', back_populates='audit_logs')
