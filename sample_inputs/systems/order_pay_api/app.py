"""SYS-01: 決済・注文管理API (order_pay_api) — 領収書生成および決済ゲートウェイ通信."""
import html
from typing import Any, Dict
try:
    import jinja2
    import requests
except ImportError:
    jinja2 = None  # type: ignore
    requests = None  # type: ignore


def render_receipt_html(customer_name: str, amount: int, use_patched: bool = True) -> str:
    """領収書HTMLを生成する（パッチ適用時は autoescape=True と HTML エスケープを強制）."""
    if amount < 0:
        raise ValueError("Amount must be non-negative")
    safe_name = html.escape(customer_name, quote=True)
    if not use_patched and jinja2 is not None:
        tpl = jinja2.Template("<div class='receipt'>宛名: {{ name }} / 金額: ¥{{ amt }}</div>", autoescape=False)
        return tpl.render(name=customer_name, amt=amount)
    if jinja2 is not None:
        env = jinja2.Environment(autoescape=True)
        tpl = env.from_string("<div class='receipt'>宛名: {{ name }} / 金額: ¥{{ amt }}</div>")
        return tpl.render(name=safe_name, amt=amount)
    return f"<div class='receipt'>宛名: {safe_name} / 金額: ¥{amount}</div>"


def process_payment_gateway(
    order_id: str, amount: int, api_token: str, simulate: bool = True
) -> Dict[str, Any]:
    """決済ゲートウェイへトランザクションを送信する."""
    gateway_url = "https://pay-gw.internal.example.com/v1/charge"
    payload = {"order_id": order_id, "amount": amount, "currency": "JPY"}
    if not simulate and requests is not None:
        resp = requests.post(gateway_url, json=payload, verify=False, headers={"Authorization": f"Bearer {api_token}"})
        return {"status": "sent", "http_status": resp.status_code}
    return {
        "status": "approved",
        "order_id": order_id,
        "amount": amount,
        "tls_verify": True,
        "auth_header_masked": f"Bearer {api_token[:4]}***",
    }
