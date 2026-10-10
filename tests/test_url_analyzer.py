"""
AppSentinel // Unit Tests: URL Analyzer
Validates URL parsing, IP extraction, TLD matching, and keyword flags.
"""

import unittest
from backend.services.url_analyzer import analyze_url


class TestUrlAnalyzer(unittest.TestCase):

    def test_empty_url(self):
        res = analyze_url("")
        self.assertEqual(res.domain, "")

    def test_suspicious_domain_and_keywords(self):
        url = "http://statebank-kyc-verify.net/patch.apk"
        res = analyze_url(url)
        self.assertEqual(res.domain, "statebank-kyc-verify.net")
        self.assertTrue(res.is_apk_download)
        self.assertTrue(res.has_suspicious_keywords)
        self.assertIsNone(res.ssl_valid)
        self.assertFalse(res.raw_parse["https_scheme"])
        self.assertFalse(res.raw_parse["certificate_validation_performed"])

    def test_ip_address_host(self):
        url = "http://192.168.1.100/login/update"
        res = analyze_url(url)
        self.assertTrue(res.is_ip_host)
        self.assertEqual(res.domain, "192.168.1.100")

    def test_suspicious_tld(self):
        url = "https://security-account-portal.xyz"
        res = analyze_url(url)
        self.assertTrue(res.has_suspicious_keywords)
        self.assertIsNone(res.ssl_valid)
        self.assertTrue(res.raw_parse["https_scheme"])

    def test_clean_https_domain(self):
        url = "https://www.google.com"
        res = analyze_url(url)
        self.assertEqual(res.domain, "www.google.com")
        self.assertFalse(res.is_ip_host)
        self.assertFalse(res.is_apk_download)
        self.assertIn("certificate validity was not verified", " ".join(res.positive_indicators))


if __name__ == "__main__":
    unittest.main()
