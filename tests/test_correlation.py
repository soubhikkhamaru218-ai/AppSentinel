"""
AppSentinel // Unit Tests: Correlation Engine & Deterministic Rules R1–R7
Verifies that rule triggers, verdicts, and evidence nodes conform to specifications.
"""

import unittest
from backend.services.correlation_engine import correlate, RULE_METADATA
from backend.services.message_analyzer import analyze_message
from backend.services.url_analyzer import analyze_url
from backend.services.identity_analyzer import check_identity_consistency
from backend.api.schemas import ApkAnalysisResult


class TestCorrelationEngine(unittest.TestCase):

    def test_r1_and_r2_high_risk_composite_bank_scam(self):
        """
        Urgent message claiming to be State Bank + coercive APK instruction +
        unofficial domain hosting an APK with SMS / accessibility permissions.
        Expected: HIGH_RISK, R1, R2, R4 triggered.
        """
        msg = "URGENT NOTICE: Your State Bank account blocked. Download patch from https://statebank-kyc-verify.net/patch.apk and enter OTP."
        url = "https://statebank-kyc-verify.net/patch.apk"
        identity = "State Bank"

        msg_res = analyze_message(msg)
        url_res = analyze_url(url)
        apk_res = ApkAnalysisResult(
            filename="patch.apk",
            package_name="com.quicksupport.remoteaccess",
            dangerous_permissions=["READ_SMS", "RECEIVE_SMS", "BIND_ACCESSIBILITY_SERVICE"],
            has_sms_permissions=True,
            has_accessibility_service=True,
        )
        id_res = check_identity_consistency(identity, msg_res, url_res, apk_res)

        result = correlate(
            message_result=msg_res,
            url_result=url_res,
            apk_result=apk_res,
            identity_check=id_res,
            claimed_identity=identity,
        )

        self.assertEqual(result["verdict"], "HIGH_RISK")
        self.assertIn("R1", result["triggered_rules"])
        self.assertIn("R2", result["triggered_rules"])
        self.assertGreater(result["confidence"], 0.85)
        self.assertGreater(len(result["evidence_chain"]), 1)

    def test_r4_credential_harvesting_coercion(self):
        """Urgency/threat message demanding OTP/credentials."""
        msg = "Your account is suspended. Reply with your 6-digit OTP code immediately."
        msg_res = analyze_message(msg)

        result = correlate(
            message_result=msg_res,
            url_result=None,
            apk_result=None,
            identity_check=None,
        )

        self.assertIn("R4", result["triggered_rules"])
        self.assertIn(result["verdict"], ["HIGH_RISK", "SUSPICIOUS"])

    def test_google_com_must_not_become_insufficient_evidence(self):
        """CRITICAL: google.com must NOT become INSUFFICIENT_EVIDENCE simply because no suspicious rule fired."""
        url = "https://www.google.com"
        url_res = analyze_url(url)

        result = correlate(
            message_result=None,
            url_result=url_res,
            apk_result=None,
            identity_check=None,
        )

        self.assertEqual(result["verdict"], "LOW_CONCERN")
        self.assertEqual(result["triggered_rules"], [])
        self.assertGreaterEqual(result["confidence"], 0.85)

    def test_empty_input_yields_insufficient_evidence(self):
        """When literally no usable input is provided, verdict is INSUFFICIENT_EVIDENCE without fake rules."""
        result = correlate(
            message_result=None,
            url_result=None,
            apk_result=None,
            identity_check=None,
            claimed_identity="",
        )

        self.assertEqual(result["verdict"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["triggered_rules"], [])

    def test_r7_triggers_on_real_evidence_condition(self):
        """R7 triggers when real evidence condition exists: self-signed cert on APK requesting sensitive capabilities."""
        apk_res = ApkAnalysisResult(
            filename="untrusted_debug.apk",
            package_name="com.test.app",
            dangerous_permissions=["READ_SMS"],
            has_sms_permissions=True,
            certificate_info={"self_signed": True, "has_signature": True},
        )

        result = correlate(
            message_result=None,
            url_result=None,
            apk_result=apk_res,
            identity_check=None,
        )

        self.assertIn("R7", result["triggered_rules"])
        self.assertEqual(result["verdict"], "SUSPICIOUS")


if __name__ == "__main__":
    unittest.main()
