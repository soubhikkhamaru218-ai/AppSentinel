"""
AppSentinel // Unit Tests: Message Analyzer
Validates signal extraction, keyword dictionaries, and regex heuristics.
"""

import unittest
from backend.services.message_analyzer import analyze_message


class TestMessageAnalyzer(unittest.TestCase):

    def test_empty_message(self):
        res = analyze_message("")
        self.assertFalse(res.has_urgency)
        self.assertFalse(res.has_threat)
        self.assertFalse(res.has_otp_request)
        self.assertEqual(res.indicator_count, 0)

    def test_urgent_threat_message(self):
        msg = "URGENT: Your account will be blocked within 24 hours. Immediately complete verification."
        res = analyze_message(msg)
        self.assertTrue(res.has_urgency)
        self.assertTrue(res.has_threat)
        self.assertGreater(res.indicator_count, 0)

    def test_credential_extraction(self):
        msg = "Dear customer, submit your OTP code and card PIN to restore service."
        res = analyze_message(msg)
        self.assertTrue(res.has_otp_request)

    def test_apk_coercion_instruction(self):
        msg = "Security update required. Download and install security patch APK immediately."
        res = analyze_message(msg)
        self.assertTrue(res.has_install_instruction)
        self.assertTrue(res.has_urgency)

    def test_organization_detection(self):
        msg = "This is from State Bank regarding your savings account."
        res = analyze_message(msg)
        self.assertTrue("State Bank" in res.detected_identity or "state bank" in res.detected_identity.lower())


if __name__ == "__main__":
    unittest.main()
