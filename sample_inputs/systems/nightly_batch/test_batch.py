"""Unit tests for SYS-03: 夜間売上集計バッチ (nightly_batch)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import batch  # noqa: E402


class TestNightlyBatch(unittest.TestCase):
    """夜間売上集計バッチのRCE防止およびAPI通信テスト."""

    def test_safe_config_loader_blocks_rce_payload(self) -> None:
        """PyYAML 任意コード実行(RCE)攻撃ペイロードがブロックされることを検証."""
        malicious_yaml = "!!python/object/apply:os.system ['echo pwned']"
        with self.assertRaises(ValueError):
            batch.load_batch_config(malicious_yaml, use_safe_loader=True)

    def test_safe_config_loader_parses_valid_json_config(self) -> None:
        """正常なバッチ設定データが安全に読み込まれることを検証."""
        valid_cfg = '{"batch_window": "02:00", "retry_limit": 3}'
        parsed = batch.load_batch_config(valid_cfg, use_safe_loader=True)
        self.assertEqual(parsed["batch_window"], "02:00")
        self.assertEqual(parsed["retry_limit"], 3)

    def test_fetch_daily_store_sales_enforces_tls(self) -> None:
        """店舗売上API通信時にTLS検証が有効であることを検証."""
        sales = batch.fetch_daily_store_sales("TOKYO-01", simulate=True)
        self.assertEqual(sales["store_id"], "TOKYO-01")
        self.assertTrue(sales["tls_verified"])


if __name__ == "__main__":
    unittest.main()
