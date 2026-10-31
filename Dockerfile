# Google Cloud Run 用 Dockerfile (軽量・非root実行・セキュリティベストプラクティス準拠)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

# システム依存パッケージの最小限インストール
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Python 依存ライブラリのインストール
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# アプリケーションコードのコピー
COPY main.py .
COPY src/ ./src/
COPY static/ ./static/
COPY docs/ ./docs/
COPY sample_inputs/ ./sample_inputs/
COPY tests/ ./tests/

# 非 root ユーザー (appuser) の作成と権限移譲
RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
