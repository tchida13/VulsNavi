#!/usr/bin/env bash
# ==============================================================================
# 脆弱性レポートまとめ君 (vulnavi) - Google Cloud Run セキュアデプロイ & プロキシ接続スクリプト
#
# 特徴:
# - `--no-allow-unauthenticated` を強制適用し、外部の未認証第三者からのアクセスを
#   Google Cloud IAM インフラ層で 100% 遮断（403 Forbidden）します。
# - デプロイ後は `gcloud run services proxy` を用いて、自分の Google アカウント権限で
#   安全に `http://localhost:8080` から 3D ダッシュボードと公式 PDF 出力を利用できます。
# ==============================================================================

set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-vulnavi}"
REGION="${REGION:-asia-northeast1}"
PROJECT_ID="${PROJECT_ID:-$(gcloud config get-value project 2>/dev/null || true)}"

if [[ -z "${PROJECT_ID}" ]]; then
  echo "❌ エラー: Google Cloud プロジェクトIDが設定されていません。"
  echo "   実行例: PROJECT_ID=your-gcp-project-id ./deploy.sh"
  exit 1
fi

echo "=================================================================="
echo "🚀 脆弱性レポートまとめ君 (vulnavi) を Cloud Run へセキュアデプロイします"
echo "   Project : ${PROJECT_ID}"
echo "   Region  : ${REGION}"
echo "   Service : ${SERVICE_NAME}"
echo "   Security: --no-allow-unauthenticated (IAM 認証必須)"
echo "=================================================================="

gcloud run deploy "${SERVICE_NAME}" \
  --source . \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --platform managed \
  --no-allow-unauthenticated \
  --memory 512Mi \
  --cpu 1 \
  --max-instances 3 \
  --set-env-vars "GOOGLE_GENAI_USE_VERTEXAI=true,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},GOOGLE_CLOUD_LOCATION=${REGION}"

echo ""
echo "✅ デプロイが完了しました！"
echo "🔒 未認証アクセスは Cloud IAM により遮断されています (--no-allow-unauthenticated)。"
echo "🌐 ローカル認証プロキシを起動します: http://localhost:8080 でアクセス可能です。"
echo ""

gcloud run services proxy "${SERVICE_NAME}" \
  --project "${PROJECT_ID}" \
  --region "${REGION}" \
  --port 8080
