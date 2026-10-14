import unittest
from app import create_app
from app.extensions import db
from app.models import Role, User, Setting, DetectionRule


class BaseTestCase(unittest.TestCase):
    """Base test case providing in-memory database and test users."""

    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()

        db.create_all()
        self._seed_data()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _seed_data(self):
        # 1. Seed Roles
        admin_role = Role(id=1, name='ADMIN', description='Administrator', permissions=['all'])
        analyst_role = Role(id=2, name='ANALYST', description='Security Analyst', permissions=['logs:view', 'logs:upload', 'alerts:manage', 'cases:manage', 'iocs:manage', 'evidence:manage', 'reports:generate'])
        viewer_role = Role(id=3, name='VIEWER', description='Read-only Viewer', permissions=['logs:view', 'alerts:view', 'cases:view', 'reports:view'])
        db.session.add_all([admin_role, analyst_role, viewer_role])

        # 2. Seed Users
        admin_user = User(id=1, username='admin', email='admin@netsentry.local', role_id=1, status='active')
        admin_user.set_password('Password123!')

        analyst_user = User(id=2, username='analyst', email='analyst@netsentry.local', role_id=2, status='active')
        analyst_user.set_password('Password123!')

        viewer_user = User(id=3, username='viewer', email='viewer@netsentry.local', role_id=3, status='active')
        viewer_user.set_password('Password123!')

        db.session.add_all([admin_user, analyst_user, viewer_user])

        # 3. Seed Basic Settings
        s1 = Setting(setting_key='port_scan_threshold', setting_value='6', description='Port scan threshold')
        s2 = Setting(setting_key='port_scan_window', setting_value='180', description='Port scan window')
        s3 = Setting(setting_key='host_sweep_threshold', setting_value='3', description='Host sweep threshold')
        s4 = Setting(setting_key='failed_conn_threshold', setting_value='4', description='Failed connections threshold')
        s5 = Setting(setting_key='large_transfer_threshold', setting_value='10485760', description='Large transfer bytes')
        s6 = Setting(setting_key='dns_burst_threshold', setting_value='10', description='DNS burst threshold')
        s7 = Setting(setting_key='beacon_interval_tolerance', setting_value='10', description='Beacon tolerance')
        db.session.add_all([s1, s2, s3, s4, s5, s6, s7])

        # 4. Seed Rules
        r1 = DetectionRule(id='RULE-001', name='Potential Port Scan', description='Detects port scan', enabled=True, severity='HIGH', threshold=6, time_window_seconds=180, rule_type='PORT_SCAN', mitre_technique_id='T1046')
        r2 = DetectionRule(id='RULE-002', name='Potential Host Sweep', description='Detects host sweep', enabled=True, severity='HIGH', threshold=3, time_window_seconds=300, rule_type='HOST_SWEEP', mitre_technique_id='T1018')
        r3 = DetectionRule(id='RULE-003', name='Repeated Failed Connections', description='Detects failed conns', enabled=True, severity='MEDIUM', threshold=4, time_window_seconds=300, rule_type='FAILED_CONNS', mitre_technique_id='T1046')
        r4 = DetectionRule(id='RULE-004', name='Unusual External Communication', description='Detects unusual external traffic', enabled=True, severity='MEDIUM', threshold=3, time_window_seconds=600, rule_type='UNUSUAL_EXTERNAL', mitre_technique_id='T1071')
        r5 = DetectionRule(id='RULE-005', name='Suspicious Remote-Service Activity', description='Detects remote service connections', enabled=True, severity='HIGH', threshold=2, time_window_seconds=300, rule_type='REMOTE_SERVICES', mitre_technique_id='T1021')
        r6 = DetectionRule(id='RULE-006', name='Large Outbound Transfer', description='Detects large outbound transfer', enabled=True, severity='CRITICAL', threshold=10485760, time_window_seconds=600, rule_type='LARGE_TRANSFER', mitre_technique_id='T1041')
        r7 = DetectionRule(id='RULE-007', name='DNS Burst', description='Detects DNS burst', enabled=True, severity='MEDIUM', threshold=10, time_window_seconds=60, rule_type='DNS_BURST', mitre_technique_id='T1071')
        r8 = DetectionRule(id='RULE-008', name='Repeated Connection Pattern', description='Detects periodic beaconing', enabled=True, severity='HIGH', threshold=4, time_window_seconds=300, rule_type='BEACON_PATTERN', mitre_technique_id='T1071')
        r9 = DetectionRule(id='RULE-009', name='Multiple Detection Combination', description='Detects combined anomalies', enabled=True, severity='CRITICAL', threshold=2, time_window_seconds=900, rule_type='MULTI_DETECTION', mitre_technique_id='T1078')
        db.session.add_all([r1, r2, r3, r4, r5, r6, r7, r8, r9])

        db.session.commit()

    def login(self, username='analyst', password='Password123!'):
        return self.client.post('/login', data={
            'username': username,
            'password': password
        }, follow_redirects=True)

    def logout(self):
        return self.client.get('/logout', follow_redirects=True)
