# AGENTS.md — 脆弱性レポートまとめ君 (`vulnavi`) プロジェクト規約

このドキュメントは、`vulnavi` リポジトリ内で作業するすべてのエージェント（メインエージェント、レビュー担当サブエージェント、および専門サブエージェント）が常時遵守すべき規約です。

---

## 1. プロジェクト概要

- **名称**: 脆弱性レポートまとめ君 (`vulnavi`)
- **目的**: 社内で保有する複数システムに対し、JPCERT/CC・NVD・SNS(X等)の脆弱性情報を照合し、4ステップ（`CHECK` → `APPLY/TEST` → `SUMMARY` → `OUTPUT`）で影響特定・パッチ＆テスト検証・上司/同僚向けレポート生成を行うアプリケーション。
- **インフラ基盤**: Google Cloud (Cloud Run + Vertex AI / Gemini API)
- **実装計画書**: `@[実装計画書](docs/implementation_plan.md)` および `@[アーキテクチャ図](docs/gcp_architecture.svg)` を参照すること。

---

## 2. Git / GitHub 管理ルール

- **GitHub アカウント**: `tchida13` を使用すること（`dcm-chida` は使用しない）。
  - `git config user.name "tchida13"`
  - `git config user.email "tchida13@users.noreply.github.com"`
- **リモートリポジトリ URL**: SSH Host エイリアス `git@tchida13:tchida13/vulnavi.git` を使用する。
- **不要ファイルの除外**:
  - `.DS_Store` や `__pycache__`、`.env`、認証鍵ファイル等は絶対にコミットしないこと。

---

## 3. Gemini API / LLM 実装ルール

- **SDK**: 必ず最新の `google-genai` SDK (`from google import genai`) と Interactions API (`client.interactions.create(...)`) を使用すること。
  - 非推奨の旧 SDK (`google-generativeai`) や旧 `generate_content` メソッドは使用禁止。
- **使用モデル**:
  - 標準の推論・構造化出力には `gemini-3.8-flash`（または深い推論が必要な箇所では `gemini-4-argon`）を使用すること。
  - 非推奨モデル（`gemini-2.5-*`, `gemini-2.0-*`, `gemini-1.5-*`）は絶対に使用しないこと。
- **認証とフォールバック**:
  - Google Cloud 上の ADC（Vertex AI）および `GEMINI_API_KEY` の両方に対応する。
  - デモ環境やオフラインテスト環境で API 認証が未設定の場合でもエラーで停止せず、同一 Pydantic スキーマのフォールバック応答を返せるようにすること。

---

## 4. セキュリティ & Google Cloud (Cloud Run) ルール

- **Cloud Run のアクセス保護**:
  - デプロイ設定（`deploy.sh` / `cloudbuild.yaml`）では必ず `--no-allow-unauthenticated`（Cloud IAM 認証必須）を指定し、外部の未認証第三者によるアクセスや LLM 不正利用をインフラ層で遮断すること。
  - 開発者・社内利用者は `gcloud run services proxy vulnavi` 経由で自身の Google アカウント認証を用いて安全にアクセスする。
- **シークレット保護**:
  - API キーや認証情報をフロントエンド（HTML/JS）や Git リポジトリに露出させないこと。

---

## 5. UI / レポート出力ルール

1. **Web 画面（プレゼン・調査用 HTML）**:
   - サイバーパンク調のダーク HUD デザインと **Three.js 3D 立体ノードグラフ** を用いる。
   - 過剰なレーザー演出は入れず、社内システム・ライブラリ・脆弱性の関係性が一目で分かる視認性と操作性を重視する。
   - ノードのクリック／ホバーでサイドパネルに詳細（該当コード箇所・パッチ・テスト結果・代替ライブラリ提案）を表示し、**「対応前（Before）⇔ 対応後（After）」の状態切り替えトグル** を備える。
2. **公式 PDF レポート（社内提出・稟議用）**:
   - **白背景・黒文字・ネイビー基調の A4 縦ビジネス文書フォーマット** で出力すること。
   - 非エンジニアの上司や他部署の同僚が読んで即座に状況を把握できる平易なエグゼクティブサマリーと、社内複数システムへの横断影響マトリクスを含めること。

---

## 6. ソフトウェアファクトリー & レビュー体制

- コード実装や重要な変更が完了した際は、待機中のレビュー担当サブエージェント（または `.agents/agents/jidoka-auditor.md` の基準）によるコード・セキュリティ・要件適合性レビューを実施すること。
