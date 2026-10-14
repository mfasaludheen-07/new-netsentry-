import os
from tests.base_test import BaseTestCase
from app.extensions import db
from app.models import LogUpload, Alert, DetectionRule
from app.services.log_parser import LogParser
from app.services.detection_engine import DetectionEngine


class TestDetectionEngine(BaseTestCase):
    """Test 9 defensive detection rules against ingested network telemetry."""

    def setUp(self):
        super().setUp()
        # Ingest demo data to trigger detection engine
        upload = LogUpload(
            source_id=None,
            original_filename='demo-network.csv',
            stored_filename='demo-network.csv',
            file_size=1024,
            mime_type='text/csv',
            hash_sha256='test_sha256',
            status='PENDING',
            uploaded_by=1
        )
        db.session.add(upload)
        db.session.commit()
        self.upload_id = upload.id

        csv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'demo', 'demo-network.csv'))
        LogParser.parse_file(upload.id, csv_path, source_type='Firewall')

    def test_detection_engine_triggers_alerts(self):
        results = DetectionEngine.run(upload_id=self.upload_id)
        self.assertGreater(results['total_alerts_generated'], 0)

        # Check that alerts were committed
        alerts = Alert.query.all()
        self.assertGreater(len(alerts), 0)

        # Verify alert rule types present
        rule_ids = [a.rule_id for a in alerts]
        # At least Port scan (RULE-001) or Host sweep (RULE-002) should have triggered
        self.assertTrue(any(r in rule_ids for r in ['RULE-001', 'RULE-002', 'RULE-003', 'RULE-006']))

    def test_disabled_rule_does_not_trigger(self):
        # Disable all rules except RULE-006 (Large Transfer)
        DetectionRule.query.filter(DetectionRule.id != 'RULE-006').update({'enabled': False})
        db.session.commit()

        # Clear existing alerts
        Alert.query.delete()
        db.session.commit()

        results = DetectionEngine.run(upload_id=self.upload_id)
        alerts = Alert.query.all()
        for a in alerts:
            self.assertEqual(a.rule_id, 'RULE-006')
