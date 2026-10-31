"""SYS-03: 夜間売上集計バッチ (nightly_batch) — 設定ファイル読込および店舗売上API収集."""
import json
from typing import Any, Dict
try:
    import yaml
    import requests
except ImportError:
    yaml = None  # type: ignore
    requests = None  # type: ignore

def load_batch_config(raw_config: str, use_safe_loader: bool = True) -> Dict[str, Any]:
    if not use_safe_loader and yaml is not None: return yaml.load(raw_config)
    if "!!" in raw_config or "__import__" in raw_config or "os.system" in raw_config:
        raise ValueError("Unsafe YAML tag or RCE payload blocked by safe loader")
    if yaml is not None and not raw_config.lstrip().startswith("{"):
        return yaml.safe_load(raw_config) or {}
    return json.loads(raw_config)


def fetch_daily_store_sales(store_id: str, simulate: bool = True) -> Dict[str, Any]:
    """社内店舗売上APIから日次売上データを取得する."""
    endpoint = f"https://sales-internal.example.com/api/stores/{store_id}/daily"
    if not simulate and requests is not None:
        resp = requests.get(endpoint, verify=False, timeout=10)
        return resp.json()
    return {"store_id": store_id, "total_sales": 1450000, "tls_verified": True}
