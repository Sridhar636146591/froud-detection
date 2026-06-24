"""
Integration tests for the Flask application (app.py).
Uses Flask test client to test routes without a real browser.
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(scope='session')
def app_client():
    """Create a Flask test client."""
    import app as flask_app
    flask_app.app.config['TESTING'] = True
    flask_app.app.config['WTF_CSRF_ENABLED'] = False
    flask_app.app.secret_key = 'test_secret_key'
    with flask_app.app.test_client() as client:
        yield client


class TestPublicRoutes:
    """Test routes accessible without authentication."""

    def test_home_redirects(self, app_client):
        """Root should redirect to login or dashboard."""
        resp = app_client.get('/', follow_redirects=False)
        assert resp.status_code in (200, 302)

    def test_api_stats_returns_json(self, app_client):
        """Public stats endpoint should return JSON."""
        resp = app_client.get('/api/v1/stats')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'total' in data
        assert 'fraud_rate' in data

    def test_api_classify_missing_fields(self, app_client):
        """Classify endpoint should return 400 when fields missing."""
        resp = app_client.post('/api/v1/classify',
                               json={},
                               content_type='application/json')
        assert resp.status_code == 400
        data = resp.get_json()
        assert 'error' in data

    def test_api_classify_valid_payload(self, app_client):
        """Classify endpoint should return a fraud result for valid input."""
        resp = app_client.post('/api/v1/classify',
                               json={
                                   'name': 'Ravi Kumar',
                                   'aadhaar': '123456789012',
                                   'phone': '9876543210',
                                   'income': 150000,
                                   'address': '12 MG Road Bangalore Market Area',
                                   'scheme': 'PM-KISAN',
                                   'age': 40,
                                   'district': 'Bangalore Rural'
                               },
                               content_type='application/json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'risk_score' in data
        assert 'classification' in data
        assert data['classification'] in ('APPROVE', 'REVIEW', 'REJECT')

    def test_api_classify_invalid_income(self, app_client):
        """Classify endpoint should return 400 for non-numeric income."""
        resp = app_client.post('/api/v1/classify',
                               json={
                                   'name': 'Test',
                                   'aadhaar': '123456789012',
                                   'phone': '9876543210',
                                   'income': 'not_a_number',
                                   'address': '12 MG Road'
                               },
                               content_type='application/json')
        assert resp.status_code == 400


class TestProtectedRoutes:
    """Test that protected routes redirect to login when unauthenticated."""

    def test_dashboard_requires_login(self, app_client):
        resp = app_client.get('/dashboard', follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_api_applications_requires_login(self, app_client):
        resp = app_client.get('/api/v1/applications')
        assert resp.status_code in (302, 401)

    def test_ml_metrics_requires_admin(self, app_client):
        resp = app_client.get('/admin/ml-metrics', follow_redirects=False)
        assert resp.status_code in (302, 401)

    def test_admin_users_requires_admin(self, app_client):
        resp = app_client.get('/admin/users', follow_redirects=False)
        assert resp.status_code in (302, 401)


class TestLoginFlow:
    """Test the login and authentication flow."""

    def test_login_page_loads(self, app_client):
        resp = app_client.get('/login')
        assert resp.status_code == 200

    def test_login_invalid_credentials(self, app_client):
        resp = app_client.post('/login', data={
            'username': 'nonexistent_user',
            'password': 'wrong_password'
        }, follow_redirects=True)
        assert resp.status_code == 200
        # Should show error message or stay on login page
        assert b'login' in resp.data.lower() or b'invalid' in resp.data.lower() or b'error' in resp.data.lower()


class TestAPIDocumentation:
    """Test that Swagger/OpenAPI docs are accessible."""

    def test_swagger_ui_accessible(self, app_client):
        resp = app_client.get('/api/docs')
        assert resp.status_code in (200, 302, 308)

    def test_swagger_spec_json(self, app_client):
        resp = app_client.get('/api/docs/apispec.json')
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'info' in data
        assert 'paths' in data
