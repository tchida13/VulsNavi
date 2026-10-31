"""SYS-02: 顧客マイページポータル (customer_portal) — マイページ描画およびフロント通信設定."""
import html
from typing import Any, Dict
try:
    import jinja2
except ImportError:
    jinja2 = None  # type: ignore


def render_mypage_profile(member_id: str, nickname: str, use_patched: bool = True) -> str:
    """会員マイページのHTMLテンプレートを描画する."""
    safe_nick = html.escape(nickname, quote=True)
    if not use_patched and jinja2 is not None:
        tpl = jinja2.Template("<section id='mypage' data-user='{{ nick }}'>ようこそ {{ nick }} 様</section>", autoescape=False)
        return tpl.render(nick=nickname)
    return f"<section id='mypage' data-user='{safe_nick}'>ようこそ {safe_nick} 様 (ID: {html.escape(member_id)})</section>"


def build_frontend_client_config(patched_axios: bool = True) -> Dict[str, Any]:
    """フロントエンドJS (axios / lodash) のセキュリティ設定を生成する."""
    # Frontend bundle uses axios.create({ baseURL: '/api/v1', withCredentials: false }) and lodash.escape
    return {
        "http_client": "axios",
        "axios_version": "1.6.2" if patched_axios else "1.5.0",
        "xsrf_leak_protection": patched_axios,
        "withCredentials": False,
        "utility_lib": "lodash@4.17.21",
    }
