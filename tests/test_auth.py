from tests.base_test import BaseTestCase
from app.models import User
from app.extensions import db


class TestAuthentication(BaseTestCase):
    """Test authentication flows, password verification, and session control."""

    def test_login_success(self):
        response = self.login('analyst', 'Password123!')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Threat Hunting', response.data)
        self.assertIn(b'analyst', response.data)

    def test_login_invalid_password(self):
        response = self.login('analyst', 'WrongPassword!')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password', response.data)

    def test_login_nonexistent_user(self):
        response = self.login('ghost_user', 'Password123!')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password', response.data)

    def test_login_disabled_user(self):
        user = User.query.filter_by(username='analyst').first()
        user.status = 'disabled'
        db.session.commit()

        response = self.login('analyst', 'Password123!')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'account is currently deactivated', response.data)

    def test_logout(self):
        self.login('analyst', 'Password123!')
        response = self.logout()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'signed out from the NetSentry platform', response.data)

    def test_unauthenticated_protected_route_redirect(self):
        response = self.client.get('/dashboard')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])
