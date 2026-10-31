"""Unit tests for SYS-04: 社内管理コンソール (admin_console)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import admin  # noqa: E402


class TestAdminConsole(unittest.TestCase):
    """社内管理コンソールのセキュリティ設定検証テスト."""

    def test_audit_banner_autoescapes_html(self) -> None:
        """管理画面バナーが autoescape=True で安全に描画されることを検証."""
        banner = admin.render_audit_banner("<b>Admin</b>", "SecurityAuditor")
        self.assertNotIn("<b>", banner)
        self.assertIn("&lt;b&gt;Admin&lt;/b&gt;", banner)

    def test_identity_health_uses_verified_tls(self) -> None:
        """社内認証基盤通信で TLS 検証が常時有効であることを検証."""
        res = admin.check_identity_service_health(simulate=True)
        self.assertTrue(res["healthy"])
        self.assertTrue(res["tls_verified"])


if __name__ == "__main__":
    unittest.main()
