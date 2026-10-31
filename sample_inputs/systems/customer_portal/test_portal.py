"""Unit tests for SYS-02: 顧客マイページポータル (customer_portal)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import portal  # noqa: E402


class TestCustomerPortal(unittest.TestCase):
    """顧客マイページポータルのXSS対策およびaxios設定検証テスト."""

    def test_mypage_profile_escapes_attribute_xss(self) -> None:
        """マイページ属性展開時のXSS攻撃文字列がエスケープされることを検証."""
        attack_nick = "' onmouseover='alert(1)'><img src=x onerror=alert(1)>"
        html_out = portal.render_mypage_profile("MEM-900", attack_nick, use_patched=True)
        self.assertNotIn("<img", html_out)
        self.assertIn("&#x27;", html_out)
        self.assertIn("MEM-900", html_out)

    def test_axios_config_prevents_xsrf_leak(self) -> None:
        """axios 1.6.2 更新後の設定でXSRFトークン漏洩防止が有効であることを検証."""
        cfg = portal.build_frontend_client_config(patched_axios=True)
        self.assertEqual(cfg["axios_version"], "1.6.2")
        self.assertTrue(cfg["xsrf_leak_protection"])
        self.assertFalse(cfg["withCredentials"])


if __name__ == "__main__":
    unittest.main()
