from datetime import datetime, timezone
from tests.base_test import BaseTestCase
from app.extensions import db
from app.models import Case, Alert, CaseAlert, Finding, AnalystNote
from app.utils import generate_next_case_id


class TestCaseManagement(BaseTestCase):
    """Test investigation case lifecycle, ID sequencing, and forensic linkage."""

    def test_case_id_generation(self):
        year = datetime.now().year
        case_id = generate_next_case_id()
        self.assertTrue(case_id.startswith(f"NET-{year}-"))
        self.assertEqual(len(case_id), 15)  # e.g. NET-2026-000001

    def test_case_creation_and_status_transitions(self):
        case_id = generate_next_case_id()
        case = Case(
            id=case_id,
            title='Suspicious Lateral Movement towards Database',
            description='Investigation into SMB scans against SERVER-01',
            severity='HIGH',
            status='OPEN',
            priority='HIGH',
            created_by=2,
            assigned_to=2
        )
        db.session.add(case)
        db.session.commit()

        # Verify created
        saved = db.session.get(Case, case_id)
        self.assertIsNotNone(saved)
        self.assertEqual(saved.status, 'OPEN')

        # Status transition to INVESTIGATING
        saved.status = 'INVESTIGATING'
        db.session.commit()
        self.assertEqual(db.session.get(Case, case_id).status, 'INVESTIGATING')

        # Transition to CONTAINED
        saved.status = 'CONTAINED'
        db.session.commit()
        self.assertEqual(db.session.get(Case, case_id).status, 'CONTAINED')

        # Transition to RESOLVED
        saved.status = 'RESOLVED'
        db.session.commit()
        self.assertEqual(db.session.get(Case, case_id).status, 'RESOLVED')

    def test_case_alert_and_notes_linkage(self):
        # 1. Create case
        case = Case(
            id=generate_next_case_id(),
            title='Data Exfiltration Investigation',
            severity='CRITICAL',
            status='OPEN',
            created_by=2
        )
        db.session.add(case)

        # 2. Create alert
        alert = Alert(
            id='ALT-2026-999999',
            rule_id='RULE-006',
            title='Large Outbound Exfiltration',
            description='Observed high volume outbound flow to external IP.',
            severity='CRITICAL',
            source_ip='192.168.1.10',
            destination_ip='203.0.113.20',
            status='NEW',
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc)
        )
        db.session.add(alert)
        db.session.commit()

        # 3. Link alert to case
        link = CaseAlert(case_id=case.id, alert_id=alert.id)
        db.session.add(link)

        # 4. Add analyst note
        note = AnalystNote(case_id=case.id, user_id=2, note='Endpoint isolated from switch port 14.')
        db.session.add(note)

        # 5. Add finding
        finding = Finding(
            case_id=case.id,
            title='Encrypted Archive Staged in Temp',
            description='Found 7z archive in C:\\Windows\\Temp\\data.7z',
            confidence='HIGH',
            status='CONFIRMED',
            created_by=2
        )
        db.session.add(finding)
        db.session.commit()

        # Check relationships
        self.assertEqual(case.alerts.count(), 1)
        self.assertEqual(len(case.notes), 1)
        self.assertEqual(len(case.findings), 1)
