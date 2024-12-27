import unittest
from app import app

class TestApp(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index_route(self):
        response = self.app.get('/cves/list')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'CVE LIST', response.data)

    def test_cve_detail_route(self):
        response = self.app.get('/details/CVE-1999-1438')
        self.assertEqual(response.status_code, 200)
        # Assuming your details.html template renders the CVE ID
        self.assertIn(b'CVE-1999-1438', response.data)

if __name__ == '__main__':
    unittest.main()
