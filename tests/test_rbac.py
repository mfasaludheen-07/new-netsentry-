from tests.base_test import BaseTestCase


class TestRoleBasedAccessControl(BaseTestCase):
    """Test role-based access control (ADMIN, ANALYST, VIEWER)."""

    def test_admin_access_to_admin_panel(self):
        self.login('admin', 'Password123!')
        res_users = self.client.get('/admin/users')
        self.assertEqual(res_users.status_code, 200)

        res_rules = self.client.get('/admin/rules')
        self.assertEqual(res_rules.status_code, 200)

        res_settings = self.client.get('/admin/settings')
        self.assertEqual(res_settings.status_code, 200)

        res_audit = self.client.get('/admin/audit-logs')
        self.assertEqual(res_audit.status_code, 200)

    def test_analyst_cannot_access_admin_panel(self):
        self.login('analyst', 'Password123!')
        res = self.client.get('/admin/users')
        self.assertEqual(res.status_code, 403)

        res_rules = self.client.get('/admin/rules')
        self.assertEqual(res_rules.status_code, 403)

    def test_viewer_is_read_only(self):
        self.login('viewer', 'Password123!')

        # Viewer can view dashboard, alerts, cases
        res_dash = self.client.get('/dashboard')
        self.assertEqual(res_dash.status_code, 200)

        res_alerts = self.client.get('/alerts/')
        self.assertEqual(res_alerts.status_code, 200)

        # Viewer cannot access admin
        res_admin = self.client.get('/admin/users')
        self.assertEqual(res_admin.status_code, 403)

        # Viewer cannot access log upload page
        res_upload = self.client.get('/logs/upload')
        self.assertEqual(res_upload.status_code, 403)

        # Viewer cannot create a case
        res_case_create = self.client.get('/cases/create')
        self.assertEqual(res_case_create.status_code, 403)

    def test_analyst_can_access_work_functions(self):
        self.login('analyst', 'Password123!')

        res_upload = self.client.get('/logs/upload')
        self.assertEqual(res_upload.status_code, 200)

        res_case_create = self.client.get('/cases/create')
        self.assertEqual(res_case_create.status_code, 200)
