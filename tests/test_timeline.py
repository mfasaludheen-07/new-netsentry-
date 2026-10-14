from datetime import datetime, timedelta, timezone
from tests.base_test import BaseTestCase
from app.models import Case, TimelineEvent
from app.services.timeline_service import TimelineService
from app.extensions import db


class TestTimelineService(BaseTestCase):
    """Test chronological ordering and search filtering in forensic timelines."""

    def setUp(self):
        super().setUp()
        self.case = Case(
            id='NET-2026-000200',
            title='Timeline Validation Incident',
            severity='HIGH',
            status='OPEN',
            created_by=2
        )
        db.session.add(self.case)
        db.session.commit()

        base_time = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)

        # Event 1: DNS query
        TimelineService.add_event(
            case_id=self.case.id,
            event_time=base_time,
            event_type='NETWORK_EVENT',
            description='DNS query for malicious C2 domain',
            severity='LOW',
            source='192.168.1.10',
            destination='192.168.1.1'
        )

        # Event 2: Alert triggered (10 minutes later)
        TimelineService.add_event(
            case_id=self.case.id,
            event_time=base_time + timedelta(minutes=10),
            event_type='ALERT',
            description='Alert ALT-001 Port Scan detected',
            severity='HIGH',
            source='192.168.1.10',
            destination='10.0.0.5'
        )

        # Event 3: Finding recorded (20 minutes later)
        TimelineService.add_event(
            case_id=self.case.id,
            event_time=base_time + timedelta(minutes=20),
            event_type='FINDING',
            description='Analyst verified anomalous SMB credentials',
            severity='CRITICAL'
        )

    def test_chronological_ordering(self):
        events = TimelineService.get_timeline(case_id=self.case.id)
        self.assertEqual(len(events), 3)
        self.assertTrue(events[0].event_time <= events[1].event_time <= events[2].event_time)
        self.assertEqual(events[0].event_type, 'NETWORK_EVENT')
        self.assertEqual(events[2].event_type, 'FINDING')

    def test_filter_by_event_type(self):
        events = TimelineService.get_timeline(case_id=self.case.id, filters={'event_type': 'ALERT'})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, 'HIGH')

    def test_search_filter(self):
        events = TimelineService.get_timeline(case_id=self.case.id, filters={'search': 'SMB credentials'})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].event_type, 'FINDING')
