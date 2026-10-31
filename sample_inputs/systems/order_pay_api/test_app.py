"""Unit tests for SYS-01: 決済・注文管理API (order_pay_api)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app  # noqa: E402


class TestOrderPayApi(unittest.TestCase):
    """決済・注文管理APIのセキュリティ＆機能検証テスト."""

    def test_receipt_html_escapes_xss_payload(self) -> None:
        """領収書HTML描画時にXSSペイロードが安全にエスケープされることを検証."""
        malicious_name = '<script>alert("XSS")</script>株式会社テスト'
        rendered = app.render_receipt_html(malicious_name, 12800, use_patched=True)
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("12800", rendered)

    def test_receipt_rejects_negative_amount(self) -> None:
        """不正な負の金額に対して例外を送出することを検証."""
        with self.assertRaises(ValueError):
            app.render_receipt_html("山田太郎", -500)

    def test_payment_gateway_enforces_tls_and_masks_token(self) -> None:
        """決済GW通信時にTLS証明書検証が有効化され認証トークンが漏洩しないことを検証."""
        res = app.process_payment_gateway("ORD-2026-001", 5400, "secret_tok_987654", simulate=True)
        self.assertEqual(res["status"], "approved")
        self.assertTrue(res["tls_verify"])
        self.assertEqual(res["auth_header_masked"], "Bearer secr***")


if __name__ == "__main__":
    unittest.main()
