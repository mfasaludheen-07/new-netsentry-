from tests.base_test import BaseTestCase
from app.extensions import db
from app.models import Case, Report, Finding
from app.services.report_service import ReportService


class TestReportGeneration(BaseTestCase):
    """Test comprehensive 16-section HTML printable forensic reporting."""

    def setUp(self):
        super().setUp()
        self.case = Case(
            id='NET-2026-000300',
            title='Executive Report Test Incident',
            description='Active reconnaissance and exfiltration event',
            severity='HIGH',
            status='INVESTIGATING',
            created_by=2
        )
        db.session.add(self.case)

        finding = Finding(
            case_id=self.case.id,
            title='Suspicious Outbound Data Burst',
            description='Over 14MB transferred to external C2',
            confidence='HIGH',
            status='CONFIRMED',
            created_by=2
        )
        db.session.add(finding)
        db.session.commit()

    def test_compile_report_data(self):
        data = ReportService.compile_report_data(self.case.id)
        self.assertEqual(data['case']['id'], self.case.id)
        self.assertEqual(data['case']['title'], self.case.title)
        self.assertIn('findings', data)
        self.assertEqual(len(data['findings']), 1)
        self.assertEqual(data['findings'][0]['title'], 'Suspicious Outbound Data Burst')

    def test_save_report_and_routes(self):
        report_id = ReportService.save_report(
            case_id=self.case.id,
            title='Formal Incident Report - NET-2026-000300',
            summary='Comprehensive attack reconstruction and analysis',
            user_id=2
        )
        self.assertGreater(report_id, 0)

        report = db.session.get(Report, report_id)
        self.assertIsNotNone(report)
        self.assertEqual(report.title, 'Formal Incident Report - NET-2026-000300')

        # Test web routes with authenticated analyst
        self.login('analyst', 'Password123!')

        # 1. Reports list
        res_list = self.client.get('/reports/')
        self.assertEqual(res_list.status_code, 200)
        self.assertIn(b'Formal Incident Report', res_list.data)

        # 2. View Report dossier
        res_view = self.client.get(f'/reports/{report_id}')
        self.assertEqual(res_view.status_code, 200)
        self.assertIn(b'Formal Incident Report', res_view.data)

        # 3. Printable HTML Report
        res_print = self.client.get(f'/reports/{report_id}/print')
        self.assertEqual(res_print.status_code, 200)
        self.assertIn(b'Forensic Attack Reconstruction Dossier', res_print.data)
        self.assertIn(b'Executive Summary', res_print.data)
