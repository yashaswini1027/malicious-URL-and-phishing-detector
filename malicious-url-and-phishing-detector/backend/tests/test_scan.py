from flask import jsonify
import unittest
from threat_analyzer import load_model, analyze_url

class TestScan(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.model = load_model()

    def test_analyze_url_safe(self):
        url = "https://www.google.com"
        result = analyze_url(url, self.model)
        self.assertEqual(result['status'], 'Safe')
        self.assertEqual(result['risk_level'], 'None (Whitelisted Domain)')

    def test_analyze_url_malicious(self):
        url = "http://malicious-example.com"
        result = analyze_url(url, self.model)
        self.assertEqual(result['status'], 'Malicious')
        self.assertGreater(result['confidence_score'], 60)

    def test_analyze_url_invalid(self):
        url = "invalid-url"
        with self.assertRaises(ValueError):
            analyze_url(url, self.model)

    def test_analyze_url_empty(self):
        url = ""
        with self.assertRaises(ValueError):
            analyze_url(url, self.model)

if __name__ == '__main__':
    unittest.main()