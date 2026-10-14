import os
from tests.base_test import BaseTestCase
from app.extensions import db
from app.models import LogUpload, NetworkEvent, Endpoint, IOC
from app.services.log_parser import LogParser


class TestLogParser(BaseTestCase):
    """Test CSV and JSON ingestion pipelines and database persistence."""

    def test_parse_demo_csv(self):
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

        csv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'demo', 'demo-network.csv'))
        self.assertTrue(os.path.exists(csv_path))

        stats = LogParser.parse_file(upload.id, csv_path, source_type='Firewall')
        self.assertGreater(stats['imported'], 0)
        self.assertEqual(stats['invalid'], 0)
        self.assertEqual(upload.status, 'COMPLETED')

        # Check that network events were stored
        event_count = NetworkEvent.query.filter_by(upload_id=upload.id).count()
        self.assertEqual(event_count, stats['imported'])

        # Check endpoints created
        endpoint = Endpoint.query.filter_by(ip_address='192.168.1.10').first()
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint.hostname, 'PC-07')

    def test_parse_demo_json(self):
        upload = LogUpload(
            source_id=None,
            original_filename='demo-network.json',
            stored_filename='demo-network.json',
            file_size=1024,
            mime_type='application/json',
            hash_sha256='test_json_sha256',
            status='PENDING',
            uploaded_by=1
        )
        db.session.add(upload)
        db.session.commit()

        json_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'demo', 'demo-network.json'))
        self.assertTrue(os.path.exists(json_path))

        stats = LogParser.parse_file(upload.id, json_path, source_type='Proxy')
        self.assertGreater(stats['imported'], 0)
        self.assertEqual(stats['invalid'], 0)
        self.assertEqual(upload.status, 'COMPLETED')

    def test_parse_nonexistent_file(self):
        upload = LogUpload(
            source_id=None,
            original_filename='ghost.csv',
            stored_filename='ghost.csv',
            file_size=0,
            mime_type='text/csv',
            hash_sha256='test',
            status='PENDING',
            uploaded_by=1
        )
        db.session.add(upload)
        db.session.commit()

        stats = LogParser.parse_file(upload.id, '/invalid/path/to/ghost.csv')
        self.assertEqual(upload.status, 'FAILED')
        self.assertIn("Physical file missing", stats['errors'][0])
