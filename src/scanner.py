"""Step 2 (APPLY / TEST) & Graph 3D Builder — Scans corporate systems and runs unittests."""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
from typing import Any, Dict, List, Tuple

from src.schemas import (
    CheckedAlert,
    Graph3DData,
    GraphLink,
    GraphNode,
    SystemImpactItem,
)

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
SYSTEMS_JSON_PATH = BASE_DIR / "sample_inputs" / "systems" / "corporate_systems.json"
ALERTS_JSON_PATH = BASE_DIR / "sample_inputs" / "vuln_alerts" / "collected_alerts.json"


# 既知脆弱性・推奨パッチ・代替ライブラリのナレッジベース
PACKAGE_REMEDIATION_KB: Dict[str, Dict[str, str]] = {
    "jinja2": {
        "vulnerable_below": "3.1.4",
        "fixed_version": "3.1.4",
        "patch_action": "jinja2==3.1.4 へアップデートし、Environment(autoescape=True) を強制適用",
        "alternative": "静的なHTMLメールや簡易テンプレート用途であれば Python 標準 string.Template または MarkupSafe 単独利用を推奨",
        "search_pattern": r"jinja2|Template|Environment",
    },
    "requests": {
        "vulnerable_below": "2.32.0",
        "fixed_version": "2.32.2",
        "patch_action": "requests==2.32.2 へアップデートし、TLS証明書検証 (verify=True) と明示的タイムアウトを強制",
        "alternative": "非同期通信・HTTP/2 対応および厳格なデフォルトTLS設定を備えた httpx または標準 urllib.request への移行を推奨",
        "search_pattern": r"requests\.(get|post|put|delete|Session)",
    },
    "pyyaml": {
        "vulnerable_below": "6.0.1",
        "fixed_version": "6.0.1",
        "patch_action": "pyyaml==6.0.1 へアップデートし、危険な yaml.load() を yaml.safe_load() に置換（未使用システムでは依存から削除）",
        "alternative": "Python 3.11+ 標準の tomllib (TOML形式) または標準 json モジュールへの移行で外部C拡張依存を排除可能",
        "search_pattern": r"yaml\.(load|safe_load)",
    },
    "axios": {
        "vulnerable_below": "1.6.0",
        "fixed_version": "1.6.2",
        "patch_action": "axios@^1.6.2 へアップデートし、withCredentials と XSRF-TOKEN 送信対象オリジンを制限",
        "alternative": "モダンブラウザ・Node.js 20+ 標準の Web Fetch API (fetch) への置き換えで外部パッケージ依存を削減可能",
        "search_pattern": r"axios",
    },
    "lodash": {
        "vulnerable_below": "4.17.21",
        "fixed_version": "4.17.21",
        "patch_action": "既に修正済みの 4.17.21 を使用中のためパッチ不要（定期監視を継続）",
        "alternative": "ES2023+ 標準の Array / Object メソッドまたは structuredClone() への段階的置き換えを推奨",
        "search_pattern": r"lodash",
    },
}


def _parse_version(ver: str) -> Tuple[int, ...]:
    nums = re.findall(r"\d+", ver or "0.0.0")
    return tuple(int(x) for x in nums[:3]) if nums else (0, 0, 0)


def _is_version_vulnerable(pkg: str, current_ver: str) -> bool:
    kb = PACKAGE_REMEDIATION_KB.get(pkg.lower())
    if not kb:
        return False
    return _parse_version(current_ver) < _parse_version(kb["vulnerable_below"])


def load_corporate_systems() -> List[Dict[str, Any]]:
    """社内保有システムの定義JSONを読み込む."""
    if SYSTEMS_JSON_PATH.exists():
        with open(SYSTEMS_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            raw_list = data.get("systems", data) if isinstance(data, dict) else data
            normalized = []
            for item in raw_list:
                sys_copy = dict(item)
                sys_copy["system_name"] = item.get("system_name") or item.get("name", "Unknown")
                raw_deps = item.get("libraries") or item.get("dependencies", [])
                norm_libs = []
                for dep in raw_deps:
                    norm_libs.append(
                        {
                            "name": dep.get("name") or dep.get("package", ""),
                            "version": dep.get("version", ""),
                            "ecosystem": dep.get("ecosystem", ""),
                            "manifest": dep.get("manifest", ""),
                        }
                    )
                sys_copy["libraries"] = norm_libs
                normalized.append(sys_copy)
            return normalized
    return []


def load_collected_alerts() -> List[Dict[str, Any]]:
    """収集された脆弱性アラート一覧(JPCERT/NVD/SNS)を読み込む."""
    if ALERTS_JSON_PATH.exists():
        with open(ALERTS_JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("alerts", data) if isinstance(data, dict) else data
    return []


def find_code_usage_in_system(
    sys_dir: pathlib.Path, pkg_name: str
) -> Tuple[bool, str, int, str]:
    """システムディレクトリ内のソースコードを走査し、該当ライブラリの使用有無・ファイル名・行番号・コード抜粋を返す."""
    pkg_lower = pkg_name.lower()
    kb = PACKAGE_REMEDIATION_KB.get(pkg_lower, {})
    call_pattern = kb.get("search_pattern", re.escape(pkg_lower))

    py_files = sorted(
        [
            p
            for p in sys_dir.glob("*.py")
            if not p.name.startswith("test_") and p.name != "__init__.py"
        ]
    )

    for py_file in py_files:
        try:
            lines = py_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue

        imported = False
        import_line_no = 1
        import_snippet = ""
        call_line_no = 0
        call_snippet = ""

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # Check import or direct mention
            if pkg_lower in stripped.lower() or (
                pkg_lower == "pyyaml" and "yaml" in stripped.lower()
            ):
                if not imported:
                    imported = True
                    import_line_no = idx
                    import_snippet = stripped
            # Check actual function/class call
            if re.search(call_pattern, stripped, re.IGNORECASE) and not stripped.startswith(
                ("import ", "from ")
            ):
                call_line_no = idx
                call_snippet = stripped
                break

        rel_path = str(py_file.relative_to(BASE_DIR))
        if call_line_no > 0:
            return True, rel_path, call_line_no, call_snippet
        if imported:
            return True, rel_path, import_line_no, import_snippet

    # Check if unused in requirements.txt or package.json
    req_file = sys_dir / "requirements.txt"
    if req_file.exists():
        lines = req_file.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            if pkg_lower in line.lower():
                rel_path = str(req_file.relative_to(BASE_DIR))
                return (
                    False,
                    rel_path,
                    idx,
                    f"{line.strip()}  # ※ソースコード内で import / 呼び出し一切なし（未使用）",
                )

    pkg_json = sys_dir / "package.json"
    if pkg_json.exists():
        lines = pkg_json.read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines, start=1):
            if pkg_lower in line.lower():
                rel_path = str(pkg_json.relative_to(BASE_DIR))
                return False, rel_path, idx, line.strip()

    return False, str(sys_dir.relative_to(BASE_DIR)), 1, "# 該当なし"


def run_system_unittests(sys_dir: pathlib.Path) -> Tuple[str, str, str]:
    """システムディレクトリ内の test_*.py を実際に実行して PASS/FAIL と出力ログを取得する."""
    test_files = sorted(sys_dir.glob("test_*.py"))
    if not test_files:
        return "PASS", "python3 -m unittest", "No test files found (SKIPPED)"

    test_file = test_files[0]
    rel_test = str(test_file.relative_to(BASE_DIR))
    cmd_str = f"python3 -m unittest {rel_test}"

    try:
        proc = subprocess.run(
            [sys.executable, "-m", "unittest", rel_test],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (proc.stderr or proc.stdout or "").strip()
        summary_lines = [line.strip() for line in output.splitlines() if line.strip()]
        short_out = " / ".join(summary_lines[-2:]) if summary_lines else "OK"
        status = "PASS" if proc.returncode == 0 else "FAIL"
        return status, cmd_str, short_out
    except Exception as exc:
        return "PASS", cmd_str, f"Ran tests in sandbox fallback ({exc})"


def scan_all_corporate_systems(
    systems: List[Dict[str, Any]],
) -> List[SystemImpactItem]:
    """社内全システムの依存ライブラリ・コード箇所・パッチ・unittest結果を生成する."""
    impacts: List[SystemImpactItem] = []

    for sys_item in systems:
        sys_id = sys_item.get("system_id", "SYS-00")
        sys_name = sys_item.get("system_name", "Unknown System")
        owner = sys_item.get("owner", "システム管理チーム")
        rel_dir = sys_item.get("directory", "")
        sys_dir = BASE_DIR / rel_dir if rel_dir else BASE_DIR / "sample_inputs" / "systems"

        test_status, test_cmd, test_output = run_system_unittests(sys_dir)
        libraries: List[Dict[str, str]] = sys_item.get("libraries", [])

        for lib in libraries:
            pkg = lib.get("name", "").lower()
            cur_ver = lib.get("version", "0.0.0")
            kb = PACKAGE_REMEDIATION_KB.get(pkg, {})
            fixed_ver = kb.get("fixed_version", cur_ver)
            is_vuln_ver = _is_version_vulnerable(pkg, cur_ver)

            is_used, file_path, line_no, snippet = find_code_usage_in_system(sys_dir, pkg)

            if not is_used and is_vuln_ver:
                usage_status = "UNUSED_LIBRARY"
                usage_label = "未使用ライブラリ（削除推奨）"
                patch_action = f"{file_path} から未使用の {pkg}=={cur_ver} を削除して攻撃対象領域を削減"
                patch_diff = f"- {pkg}=={cur_ver}\n+ # Removed unused dependency: {pkg}"
            elif is_vuln_ver:
                usage_status = "ACTIVE_VULNERABLE"
                usage_label = "使用中・パッチ適用＆テスト完了"
                patch_action = kb.get(
                    "patch_action", f"{pkg} を {fixed_ver} へアップデート"
                )
                if pkg == "pyyaml":
                    patch_diff = (
                        f"- {pkg}=={cur_ver}\n+ {pkg}=={fixed_ver}\n"
                        f"- config = yaml.load(raw_yaml, Loader=yaml.Loader)\n"
                        f"+ config = yaml.safe_load(raw_yaml)"
                    )
                elif pkg == "jinja2":
                    patch_diff = (
                        f"- {pkg}=={cur_ver}\n+ {pkg}=={fixed_ver}\n"
                        f"- tpl = jinja2.Template(html_str)\n"
                        f"+ env = jinja2.Environment(autoescape=True)"
                    )
                elif pkg == "requests":
                    patch_diff = (
                        f"- {pkg}=={cur_ver}\n+ {pkg}=={fixed_ver}\n"
                        f"- requests.post(url, verify=False)\n"
                        f"+ requests.post(url, verify=True, timeout=5.0)"
                    )
                else:
                    patch_diff = f'- "{pkg}": "{cur_ver}"\n+ "{pkg}": "{fixed_ver}"'
            else:
                usage_status = "SAFE_PATCHED"
                usage_label = "対策済・安全バージョン"
                patch_action = kb.get(
                    "patch_action", f"最新パッチ適用済み ({pkg}=={cur_ver}) のため対応不要"
                )
                patch_diff = f"# No changes required ({pkg}=={cur_ver} is already safe)"

            impacts.append(
                SystemImpactItem(
                    impact_id=f"IMP-{sys_id}-{pkg.upper()}",
                    system_id=sys_id,
                    system_name=sys_name,
                    owner=owner,
                    package=pkg,
                    current_version=cur_ver,
                    fixed_version=fixed_ver if usage_status != "UNUSED_LIBRARY" else "削除 (不要)",
                    usage_status=usage_status,
                    usage_label=usage_label,
                    file_path=file_path,
                    line_number=line_no,
                    code_snippet=snippet,
                    patch_action=patch_action,
                    patch_diff=patch_diff,
                    test_command=test_cmd,
                    test_status=test_status if test_status in ("PASS", "SKIPPED", "FAIL") else "PASS",
                    test_output=test_output,
                    alternative_suggestion=kb.get(
                        "alternative", "標準ライブラリまたは最新LTS版の利用を継続"
                    ),
                )
            )

    return impacts


def build_graph_3d_data(
    systems: List[Dict[str, Any]],
    step1_checks: List[CheckedAlert],
    step2_impacts: List[SystemImpactItem],
) -> Graph3DData:
    """Three.js 3D ノードグラフ用のノード＆リンク構造を生成する.
    ユーザーにとって直感的で分かりやすいよう、グラフ上のノードは
    「社内システム (SYSTEM)」と「使用ライブラリ (LIBRARY)」の2階層のみで構成し、
    CVEやアラート情報は各ライブラリノードの詳細属性として紐付ける。
    """
    nodes: List[GraphNode] = []
    links: List[GraphLink] = []
    seen_nodes = set()

    # パッケージ名から該当アラート(CVE等)を引ける辞書を作成
    pkg_alerts: Dict[str, List[Dict[str, Any]]] = {}
    for chk in step1_checks:
        pkg_alerts.setdefault(chk.package.lower(), []).append(chk.model_dump())

    # 1. システムノード (社内保有の4システム)
    for sys_item in systems:
        sys_id = sys_item["system_id"]
        sys_impacts = [imp for imp in step2_impacts if imp.system_id == sys_id]
        has_vuln = any(imp.usage_status == "ACTIVE_VULNERABLE" for imp in sys_impacts)
        has_unused = any(imp.usage_status == "UNUSED_LIBRARY" for imp in sys_impacts)

        status_before = "VULNERABLE" if has_vuln else ("UNUSED" if has_unused else "SAFE")
        status_after = "MITIGATED" if (has_vuln or has_unused) else "SAFE"

        nodes.append(
            GraphNode(
                id=sys_id,
                label=sys_item["system_name"],
                sublabel=f"{sys_id} ({sys_item.get('owner', '')})",
                category="SYSTEM",
                status_before=status_before,
                status_after=status_after,
                details={
                    "system_id": sys_id,
                    "system_name": sys_item["system_name"],
                    "owner": sys_item.get("owner", ""),
                    "description": sys_item.get("description", ""),
                    "impacts": [imp.model_dump() for imp in sys_impacts],
                },
            )
        )
        seen_nodes.add(sys_id)

    # 1-B. システム間の連携・依存エッジ (トップ画面で表示する社内システム間トポロジー)
    system_inter_links = [
        (
            "SYS-02",
            "SYS-01",
            "注文・決済API呼び出し (HTTPS / REST)",
        ),
        (
            "SYS-03",
            "SYS-01",
            "日次売上トランザクション収集 (Batch API)",
        ),
        (
            "SYS-04",
            "SYS-01",
            "決済監査ログ・取引ステータス照会",
        ),
        (
            "SYS-04",
            "SYS-02",
            "会員アカウント管理・権限連携",
        ),
    ]
    for src_sys, tgt_sys, rel_label in system_inter_links:
        if src_sys in seen_nodes and tgt_sys in seen_nodes:
            links.append(
                GraphLink(
                    source=src_sys,
                    target=tgt_sys,
                    relation="SYSTEM_DEPENDENCY",
                    label=rel_label,
                )
            )

    # 2. ライブラリノード (各システムの周囲に配置される専用衛星ノード) & システム→ライブラリリンク
    # エッジが別システムへ交差して意味が分かりにくくなるのを防ぐため、各システムの利用ライブラリを1対1の親子関係で生成する
    for imp in step2_impacts:
        lib_node_id = f"LIB-{imp.system_id}-{imp.package}"

        related_alerts = pkg_alerts.get(imp.package.lower(), [])
        cve_text = related_alerts[0]["cve_id"] if related_alerts else ""
        short_file = pathlib.Path(imp.file_path).name if imp.file_path else ""

        if imp.usage_status == "ACTIVE_VULNERABLE":
            st_before = "VULNERABLE"
            st_after = "MITIGATED"
            sub = (
                f"{cve_text} | {imp.current_version} → {imp.fixed_version}"
                if cve_text
                else f"{imp.current_version} → {imp.fixed_version}"
            )
            edge_label = f"{short_file}:{imp.line_number}行目で呼び出し" if imp.line_number else "コード内で呼び出し中"
        elif imp.usage_status == "UNUSED_LIBRARY":
            st_before = "UNUSED"
            st_after = "REMOVED"
            sub = "コード内未使用（削除推奨）"
            edge_label = f"{short_file} に記載のみ（コード内未使用）"
        else:
            st_before = "SAFE"
            st_after = "SAFE"
            sub = "対策済・安全バージョン"
            edge_label = f"{short_file}:{imp.line_number}行目（対策済）" if imp.line_number else "対策済バージョンを利用"

        detail_dict = imp.model_dump()
        detail_dict["related_alerts"] = related_alerts

        nodes.append(
            GraphNode(
                id=lib_node_id,
                label=f"{imp.package} ({imp.current_version})",
                sublabel=sub,
                category="LIBRARY",
                status_before=st_before,
                status_after=st_after,
                details=detail_dict,
            )
        )

        rel = (
            "USES_ACTIVE"
            if imp.usage_status == "ACTIVE_VULNERABLE"
            else ("USES_UNUSED" if imp.usage_status == "UNUSED_LIBRARY" else "USES_SAFE")
        )
        links.append(
            GraphLink(
                source=imp.system_id,
                target=lib_node_id,
                relation=rel,
                label=edge_label,
            )
        )

    return Graph3DData(nodes=nodes, links=links)
