"""
脆弱性レポートまとめ君 (vulnavi) - FastAPI バックエンドサーバー

Google Cloud Run 上で単一コンテナとして動作し、以下の機能を提供する：
1. セキュリティヘッダー付与およびオプションのアプリ層トークン保護
2. 4ステップ脆弱性診断パイプライン API (`/api/analyze`) およびリアルタイム SSE ストリーミング (`/api/analyze/stream`)
3. オフィシャル白背景 A4 レポート HTML (`/report/official`) および PDF バイナリ出力 (`/api/report/pdf`)
4. Three.js 3D サイバーパンクダッシュボード (`static/`) と Google Cloud アーキテクチャ図 (`docs/`) の配信
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.llm_engine import generate_full_vulnerability_report
from src.reporter import generate_official_report_pdf, render_official_report_html
from src.scanner import load_collected_alerts, load_corporate_systems
from src.schemas import VulnAnalysisReport

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DOCS_DIR = BASE_DIR / "docs"

app = FastAPI(
    title="脆弱性レポートまとめ君 (vulnavi)",
    description="JPCERT/CC・NVD・SNSの脆弱性情報を照合し、4ステップで社内システムの影響特定・パッチ検証・3D/PDFレポート生成を行うプラットフォーム",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# 最新の分析レポートをインメモリキャッシュ（デモの高速表示およびPDF出力用）
_LATEST_REPORT_CACHE: Optional[VulnAnalysisReport] = None


class AnalyzeRequest(BaseModel):
    custom_alert_text: Optional[str] = None
    force_refresh: bool = False


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Cloud Run セキュリティベストプラクティスに基づくレスポンスヘッダー付与と
    環境変数 VULNAVI_ACCESS_TOKEN 設定時の認証チェック。
    """
    required_token = os.environ.get("VULNAVI_ACCESS_TOKEN")
    if required_token and request.url.path.startswith("/api/") and request.url.path != "/api/health":
        provided_token = request.headers.get("X-Vulnavi-Token") or request.query_params.get("token")
        if provided_token != required_token:
            return JSONResponse(
                status_code=403,
                content={"detail": "Forbidden: Invalid or missing X-Vulnavi-Token"},
            )

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def _get_or_create_report(custom_alert_text: Optional[str] = None, force_refresh: bool = False) -> VulnAnalysisReport:
    global _LATEST_REPORT_CACHE
    if _LATEST_REPORT_CACHE is None or custom_alert_text or force_refresh:
        _LATEST_REPORT_CACHE = generate_full_vulnerability_report(custom_alert_text=custom_alert_text)
    return _LATEST_REPORT_CACHE


@app.get("/api/health")
async def health_check() -> Dict[str, Any]:
    return {
        "status": "ok",
        "service": "vulnavi",
        "model": "gemini-3.8-flash",
        "steps": ["Step 1: CHECK", "Step 2: APPLY/TEST", "Step 3: SUMMARY", "Step 4: OUTPUT"],
    }


@app.get("/api/initial-data")
async def get_initial_data() -> Dict[str, Any]:
    """
    初期表示用データ（社内4システムの構成、収集済みアラート一覧、および初回4ステップ分析結果）を返却する。
    """
    systems = load_corporate_systems()
    alerts = load_collected_alerts()
    report = _get_or_create_report()
    return {
        "systems": systems,
        "alerts": alerts,
        "report": report.model_dump(),
        "latest_report": report.model_dump(),
    }


@app.post("/api/analyze")
async def run_analysis(req: Optional[AnalyzeRequest] = None) -> Dict[str, Any]:
    """
    4ステップ診断パイプラインを実行し、構造化レポート (`VulnAnalysisReport`) を返す。
    """
    custom_text = req.custom_alert_text if req else None
    force = req.force_refresh if req else True
    report = _get_or_create_report(custom_alert_text=custom_text, force_refresh=force)
    return report.model_dump()


@app.get("/api/analyze/stream")
async def stream_analysis(custom_alert_text: Optional[str] = Query(default=None)) -> StreamingResponse:
    """
    フロントエンドの4ステップ進行バー向けに Server-Sent Events (SSE) で
    Step 1 (CHECK) → Step 2 (APPLY/TEST) → Step 3 (SUMMARY) → Step 4 (OUTPUT) の進捗をリアルタイム配信する。
    """

    async def event_generator() -> AsyncGenerator[str, None]:
        steps = [
            (
                1,
                "CHECK",
                "JPCERT/CC・NVD・SNS(X)の脆弱性情報を照合し、gemini-3.8-flash で真偽（確定/デマ/対策済）を精査中...",
            ),
            (
                2,
                "APPLY / TEST",
                "社内4システムの依存関係と実コードを走査し、該当箇所特定・未使用ライブラリ検出・パッチ＆unittest自動実行中...",
            ),
            (
                3,
                "SUMMARY",
                "上司・同僚向けの3行エグゼクティブサマリーと全社横断影響マトリクスを生成中...",
            ),
            (
                4,
                "OUTPUT",
                "Three.js 3D インタラクティブノードデータ（対応前/対応後）および公式 A4 PDF レポートを構築中...",
            ),
        ]

        for step_num, step_code, message in steps:
            payload = json.dumps(
                {"type": "progress", "step": step_num, "code": step_code, "message": message},
                ensure_ascii=False,
            )
            yield f"data: {payload}\n\n"
            await asyncio.sleep(0.25)

        report = _get_or_create_report(custom_alert_text=custom_alert_text, force_refresh=True)
        final_payload = json.dumps(
            {"type": "complete", "step": 4, "report": report.model_dump()},
            ensure_ascii=False,
        )
        yield f"data: {final_payload}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/report/official", response_class=HTMLResponse)
async def get_official_report_html(
    print_mode: Optional[int] = Query(default=0, alias="print"),
) -> HTMLResponse:
    """
    社内稟議・監査提出用の「白背景・A4縦・公式ビジネス文書フォーマット」HTMLを表示する。
    `?print=1` が指定された場合は自動的にブラウザの印刷/PDF保存ダイアログを起動する。
    """
    report = _get_or_create_report()
    html_content = render_official_report_html(report, auto_print=bool(print_mode))
    return HTMLResponse(content=html_content)


@app.get("/api/report/pdf")
async def download_official_report_pdf() -> Response:
    """
    白背景・A4縦の公式セキュリティ検証報告書 PDF バイナリを直接ダウンロード提供する。
    """
    report = _get_or_create_report()
    pdf_bytes = generate_official_report_pdf(report)
    filename = f"vulnavi_official_report_{report.report_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@app.get("/docs/gcp_architecture.svg")
async def get_architecture_svg() -> Response:
    svg_path = DOCS_DIR / "gcp_architecture.svg"
    if not svg_path.exists():
        raise HTTPException(status_code=404, detail="Architecture SVG not found")
    return FileResponse(svg_path, media_type="image/svg+xml")


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index() -> Response:
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse(
        content="<h1>vulnavi server is running</h1><p><a href='/report/official'>Official Report</a></p>"
    )
