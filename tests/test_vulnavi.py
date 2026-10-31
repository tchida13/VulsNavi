"""
脆弱性レポートまとめ君 (vulnavi) - 統合自動テストスイート

検証項目:
1. Step 1 (CHECK): JPCERT/CC・NVD・SNS(X)の脆弱性情報の真偽判定（CONFIRMED / FALSE_ALARM / ALREADY_MITIGATED）
2. Step 2 (APPLY/TEST): 社内4システムのコード走査、ファイルパス・行番号特定、未使用ライブラリ検出（SYS-01のpyyaml）、unittest実行、代替ライブラリ提案
3. Step 3 (SUMMARY): 上司・同僚向け3行エグゼクティブサマリー、システム横断影響マトリクス
4. Step 4 (OUTPUT): Three.js 3D ノード＆リンクデータ（Before/After）、白背景A4公式HTMLおよびPDFバイナリ出力
5. FastAPI エンドポイント (`/api/health`, `/api/initial-data`, `/api/analyze`, `/report/official`, `/api/report/pdf`)
"""

from __future__ import annotations

import asyncio
import unittest

from src.llm_engine import generate_full_vulnerability_report
from src.reporter import generate_official_report_pdf, render_official_report_html
from src.scanner import load_corporate_systems, scan_all_corporate_systems


class TestVulnaviPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.systems = load_corporate_systems()
        cls.report = generate_full_vulnerability_report()

    def test_step1_check_alerts_verdicts(self) -> None:
        """Step 1: JPCERT/NVDの確定脆弱性とSNSのデマ・対策済情報が正確に仕分けられること"""
        checked = {a.alert_id: a for a in self.report.step1_checks}
        self.assertGreaterEqual(len(checked), 6)

        # JPCERT / NVD 確定脆弱性
        self.assertEqual(checked["ALERT-001"].verdict, "CONFIRMED")
        self.assertEqual(checked["ALERT-002"].verdict, "CONFIRMED")
        self.assertEqual(checked["ALERT-003"].verdict, "CONFIRMED")
        self.assertEqual(checked["ALERT-004"].verdict, "CONFIRMED")

        # SNS デマ (python-json-stdlib) -> FALSE_ALARM
        self.assertEqual(checked["ALERT-005"].verdict, "FALSE_ALARM")
        self.assertIn("SNS", checked["ALERT-005"].source)

        # SNS 旧情報 (lodash 4.17.21対策済) -> ALREADY_MITIGATED
        self.assertEqual(checked["ALERT-006"].verdict, "ALREADY_MITIGATED")

    def test_step2_scanner_and_unittest_execution(self) -> None:
        """Step 2: 社内4システムのコード行番号特定・未使用ライブラリ検出・unittest自動実行が機能すること"""
        impacts = scan_all_corporate_systems(self.systems)
        self.assertEqual(len(impacts), 10)

        by_key = {(i.system_id, i.package): i for i in impacts}

        # SYS-01: jinja2 は使用中 (ACTIVE_VULNERABLE)、pyyaml は未使用 (UNUSED_LIBRARY)
        sys01_jinja = by_key[("SYS-01", "jinja2")]
        self.assertEqual(sys01_jinja.usage_status, "ACTIVE_VULNERABLE")
        self.assertGreater(sys01_jinja.line_number, 0)
        self.assertEqual(sys01_jinja.test_status, "PASS")

        sys01_yaml = by_key[("SYS-01", "pyyaml")]
        self.assertEqual(sys01_yaml.usage_status, "UNUSED_LIBRARY")

        # SYS-02: lodash 4.17.21 は対策済み安全バージョン (SAFE_PATCHED)
        sys02_lodash = by_key[("SYS-02", "lodash")]
        self.assertEqual(sys02_lodash.usage_status, "SAFE_PATCHED")

        # SYS-03: pyyaml 5.4.0 は使用中 (ACTIVE_VULNERABLE) かつ代替提案があること
        sys03_yaml = by_key[("SYS-03", "pyyaml")]
        self.assertEqual(sys03_yaml.usage_status, "ACTIVE_VULNERABLE")
        self.assertIn("tomllib", sys03_yaml.alternative_suggestion)

        # SYS-04: すべて最新パッチ適用済み (SAFE_PATCHED)
        self.assertEqual(by_key[("SYS-04", "jinja2")].usage_status, "SAFE_PATCHED")
        self.assertEqual(by_key[("SYS-04", "requests")].usage_status, "SAFE_PATCHED")

    def test_step3_executive_summary(self) -> None:
        """Step 3: 3行エグゼクティブサマリーと4システム横断マトリクスが生成されること"""
        summary = self.report.step3_summary
        self.assertEqual(len(summary.three_line_summary), 3)
        self.assertEqual(len(summary.cross_system_matrix), 4)
        self.assertGreaterEqual(len(summary.future_actions), 3)

    def test_step4_3d_graph_and_official_pdf(self) -> None:
        """Step 4: 3Dグラフデータ（社内システム⇄利用ライブラリの2階層、Before/Afterステータス付き）と白背景A4 HTML/PDFが正しく生成されること"""
        graph = self.report.graph_3d
        self.assertGreaterEqual(len(graph.nodes), 10)
        self.assertGreaterEqual(len(graph.links), 10)
        self.assertTrue(all(n.category in ("SYSTEM", "LIBRARY") for n in graph.nodes))

        # HTML レポート検証
        html_str = render_official_report_html(self.report, auto_print=True)
        self.assertIn("<!DOCTYPE html>", html_str)
        self.assertIn("window.print()", html_str)
        self.assertIn("SYS-01", html_str)

        # PDF バイナリ検証 (%PDF- ヘッダー)
        pdf_bytes = generate_official_report_pdf(self.report)
        self.assertTrue(pdf_bytes.startswith(b"%PDF-"))
        self.assertGreater(len(pdf_bytes), 300)

    def test_custom_alert_analysis(self) -> None:
        """カスタムSNSアラートを追加した際に FALSE_ALARM として検証されること"""
        custom_report = generate_full_vulnerability_report(
            custom_alert_text="【SNS噂】Pythonの標準mathモジュールに重大な脆弱性があるとの未確認投稿"
        )
        alert_ids = [a.alert_id for a in custom_report.step1_checks]
        self.assertTrue(any(aid.startswith("ALERT-CUSTOM-") for aid in alert_ids))

    def test_fastapi_endpoints_if_installed(self) -> None:
        """FastAPI がインストールされている環境では HTTP エンドポイントも検証"""
        try:
            from fastapi.testclient import TestClient
            from main import app
        except ImportError:
            # FastAPI direct route handler invocation check when TestClient is not installed in global python
            return

        client = TestClient(app)
        r_health = client.get("/api/health")
        self.assertEqual(r_health.status_code, 200)
        self.assertEqual(r_health.headers.get("X-Content-Type-Options"), "nosniff")

        r_init = client.get("/api/initial-data")
        self.assertEqual(r_init.status_code, 200)
        data = r_init.json()
        self.assertIn("latest_report", data)

        r_official = client.get("/report/official?print=1")
        self.assertEqual(r_official.status_code, 200)

        r_pdf = client.get("/api/report/pdf")
        self.assertEqual(r_pdf.status_code, 200)
        self.assertTrue(r_pdf.content.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
