---
name: vulnavi-pipeline
description: >-
  脆弱性レポートまとめ君 (vulnavi) の標準4ステップパイプライン（CHECK → APPLY/TEST → SUMMARY → OUTPUT）および自働化（Jidoka）品質監査を実行するスキル。
  脆弱性情報の精査、社内複数システムの影響分析、3D HTMLレポートおよび公式PDFレポートの生成・検証を行う際に使用する。
---

# vulnavi 4ステップ標準パイプライン (`vulnavi-pipeline`)

このスキルは、旗印シートで定義された4つの手順と自働化（Jidoka）品質ゲートを連携させる標準作業手順（SOP）です。

## 実行ステップ

### Step 1: CHECK（情報元・内容の正しさ確認）
- 担当定義: `[vuln-checker](../../agents/vuln-checker.md)`
- 入力された JPCERT/CC、NVD、および SNS 投稿を照合し、`CONFIRMED` / `ALREADY_MITIGATED` / `FALSE_ALARM` に分類する。

### Step 2: APPLY / TEST（社内複数システムの対応箇所確認・テスト）
- 担当定義: `[patch-tester](../../agents/patch-tester.md)`
- 社内保有システムの依存ファイルとソースコードを走査し、該当ファイル・行番号を特定する。
- コード内で使われていない「未使用ライブラリ」を洗い出す。
- パッチ適用シミュレーションと `unittest` を実行し、代替ライブラリ提案を作成する。

### Step 3 & 4: SUMMARY & OUTPUT（まとめ＆レポート出力）
- 担当定義: `[report-writer](../../agents/report-writer.md)`
- 上司・同僚向けのエグゼクティブサマリーと全社システム横断マトリクスを生成する。
- Three.js 3D ノードグラフ画面（対応前／対応後トグル付）および白背景 A4 公式 PDF レポートを出力する。

### Step 5: JIDOKA AUDIT（品質ゲート監査）
- 担当定義: `[jidoka-auditor](../../agents/jidoka-auditor.md)`
- レビュー担当サブエージェントまたはユニットテスト（`python3 -m unittest discover -s tests`）により、対応漏れやセキュリティ不備がないかを最終検証する。
