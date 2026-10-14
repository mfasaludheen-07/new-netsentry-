import os
import io
import hashlib
from werkzeug.datastructures import FileStorage
from tests.base_test import BaseTestCase
from app.extensions import db
from app.models import Case, Evidence, EvidenceChain
from app.services.evidence_service import EvidenceService
from app.utils import compute_file_sha256, compute_bytes_sha256


class TestEvidenceService(BaseTestCase):
    """Test cryptographic SHA-256 hashing, evidence vault, and chain of custody."""

    def setUp(self):
        super().setUp()
        self.case = Case(
            id='NET-2026-000100',
            title='Forensic Vault Test Case',
            severity='HIGH',
            status='OPEN',
            created_by=2
        )
        db.session.add(self.case)
        db.session.commit()

    def test_sha256_computation(self):
        sample_bytes = b"Suspicious payload network capture sample telemetry 2026"
        expected_hash = hashlib.sha256(sample_bytes).hexdigest()
        computed = compute_bytes_sha256(sample_bytes)
        self.assertEqual(computed, expected_hash)

    def test_evidence_storage_and_chain_of_custody(self):
        sample_content = b"packet_hex_dump_stream_evidence"
        file_storage = FileStorage(
            stream=io.BytesIO(sample_content),
            filename='capture.pcap',
            content_type='application/vnd.tcpdump.pcap'
        )

        res = EvidenceService.store_evidence(
            case_id=self.case.id,
            uploaded_file=file_storage,
            user_id=2,
            description='Perimeter pcap segment'
        )
        self.assertTrue(res['success'])
        self.assertIsNotNone(res['evidence_id'])
        self.assertEqual(res['sha256'], hashlib.sha256(sample_content).hexdigest())

        # Verify Chain of Custody has UPLOADED record
        chain = EvidenceChain.query.filter_by(evidence_id=res['evidence_id']).first()
        self.assertIsNotNone(chain)
        self.assertEqual(chain.action, 'UPLOADED')
        self.assertEqual(chain.current_hash, res['sha256'])

        # Verify Integrity passes
        integrity = EvidenceService.verify_integrity(res['evidence_id'])
        self.assertTrue(integrity['valid'])

    def test_tamper_detection(self):
        sample_content = b"original_secure_log"
        file_storage = FileStorage(
            stream=io.BytesIO(sample_content),
            filename='audit.log',
            content_type='text/plain'
        )

        res = EvidenceService.store_evidence(
            case_id=self.case.id,
            uploaded_file=file_storage,
            user_id=2
        )
        ev_id = res['evidence_id']
        ev = db.session.get(Evidence, ev_id)

        # Intentionally tamper with the physical file on disk
        dest_path = os.path.join(self.app.config['EVIDENCE_FOLDER'], ev.stored_filename)
        with open(dest_path, 'wb') as f:
            f.write(b"tampered_malicious_content")

        # Verify Integrity catches the tampering
        integrity = EvidenceService.verify_integrity(ev_id)
        self.assertFalse(integrity['valid'])
        self.assertIn("INTEGRITY MISMATCH DETECTED", integrity['message'])
