"""Pydantic schemas for vulnavi 4-step pipeline and Gemini Structured Output."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class CheckedAlert(BaseModel):
    """Step 1: CHECK — 脆弱性情報の真偽・深刻度・対象バージョン精査結果."""

    alert_id: str = Field(description="アラート識別ID (例: ALERT-001)")
    source: str = Field(description="情報源 (JPCERT/CC, NVD, SNS 等)")
    cve_id: str = Field(description="CVE番号またはJVN番号 (誤情報の場合は 'なし (未確認情報)')")
    package: str = Field(description="対象パッケージ・ライブラリ名")
    title: str = Field(description="脆弱性またはSNS投稿のタイトル")
    verdict: Literal["CONFIRMED", "FALSE_ALARM", "ALREADY_MITIGATED"] = Field(
        description="真偽・対応要否判定 (CONFIRMED=要対応, FALSE_ALARM=誤情報/SNSデマ, ALREADY_MITIGATED=自社では対策済)"
    )
    verdict_label: str = Field(description="画面・レポート表示用の日本語判定ラベル")
    cvss_score: float = Field(description="CVSS v3 ベーススコア (0.0〜10.0)")
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"] = Field(
        description="深刻度レベル"
    )
    affected_versions: str = Field(description="影響を受けるバージョン範囲")
    fixed_version: str = Field(description="修正済みバージョン")
    verification_reason: str = Field(
        description="JPCERT/CC・NVD等の公的情報と照合した真偽判定の根拠・技術解説"
    )


class SystemImpactItem(BaseModel):
    """Step 2: APPLY / TEST — 社内システムの該当箇所・パッチ適用・テスト検証結果."""

    impact_id: str = Field(description="影響項目ID")
    system_id: str = Field(description="システムID (例: SYS-01)")
    system_name: str = Field(description="システム名称")
    owner: str = Field(description="システム担当チーム")
    package: str = Field(description="ライブラリ名")
    current_version: str = Field(description="対応前のバージョン")
    fixed_version: str = Field(description="対応後・推奨バージョン")
    usage_status: Literal["ACTIVE_VULNERABLE", "UNUSED_LIBRARY", "SAFE_PATCHED"] = Field(
        description="ACTIVE_VULNERABLE=コード内で使用中(要パッチ), UNUSED_LIBRARY=未使用ライブラリ(削除推奨), SAFE_PATCHED=既に対策済"
    )
    usage_label: str = Field(description="日本語の使用・対応ステータスラベル")
    file_path: str = Field(description="該当ソースコードまたは依存定義ファイルのパス")
    line_number: int = Field(description="コード内の該当行番号")
    code_snippet: str = Field(description="該当箇所のコード抜粋")
    patch_action: str = Field(description="実施した修正パッチ・バージョン更新・削除の内容")
    patch_diff: str = Field(description="具体的なコード/依存定義の差分 (Diff)")
    test_command: str = Field(description="実行したテストコマンド")
    test_status: Literal["PASS", "SKIPPED", "FAIL"] = Field(description="テスト実行結果")
    test_output: str = Field(description="unittest の実行結果サマリーログ")
    alternative_suggestion: str = Field(
        description="アイデアシート⑧：代替ライブラリや標準ライブラリへの移行提案"
    )


class CrossSystemMatrixRow(BaseModel):
    """社内保有システムの横断影響マトリクス行."""

    system_id: str = Field(description="システムID")
    system_name: str = Field(description="システム名")
    owner: str = Field(description="担当チーム")
    status_before: Literal["CRITICAL", "HIGH", "MEDIUM", "SAFE"] = Field(
        description="対応前のリスク状態"
    )
    status_after: Literal["SAFE", "MITIGATED"] = Field(description="対応後の状態")
    vulnerable_count: int = Field(default=0, description="要対応だったライブラリ数")
    unused_count: int = Field(default=0, description="検出された未使用ライブラリ数")
    test_result: str = Field(default="ALL PASS", description="テスト結果")
    summary_note: str = Field(description="システム別の対応要約コメント")


class ExecutiveSummary(BaseModel):
    """Step 3: SUMMARY — 上司・同僚向けの説明サマリー＆今後の対応方針."""

    headline: str = Field(description="レポート全体の1行結論ヘッドライン")
    three_line_summary: List[str] = Field(
        description="非エンジニアの上司や同僚にも30秒で伝わる3行要約"
    )
    cross_system_matrix: List[CrossSystemMatrixRow] = Field(
        description="社内全システムの横断影響マトリクス"
    )
    future_actions: List[str] = Field(description="今後の恒久対応・再発防止アクション一覧")


class GraphNode(BaseModel):
    """Three.js 3D ノードグラフのノード定義."""

    id: str
    label: str
    sublabel: str
    category: Literal["SYSTEM", "LIBRARY", "ALERT"]
    status_before: Literal["VULNERABLE", "UNUSED", "FALSE_ALARM", "SAFE", "MITIGATED"]
    status_after: Literal["MITIGATED", "REMOVED", "FALSE_ALARM", "SAFE"]
    details: Dict[str, Any] = Field(default_factory=dict)


class GraphLink(BaseModel):
    """Three.js 3D ノードグラフのエッジ定義."""

    source: str
    target: str
    relation: Literal[
        "SYSTEM_DEPENDENCY",
        "USES_ACTIVE",
        "USES_UNUSED",
        "USES_SAFE",
        "AFFECTS",
        "FALSE_TARGET",
    ]
    label: str = ""


class Graph3DData(BaseModel):
    """Step 4: OUTPUT — Three.js 3D 可視化用データ."""

    nodes: List[GraphNode]
    links: List[GraphLink]


class LLMCoreAnalysis(BaseModel):
    """Gemini Structured Output で直接生成させるコア構造."""

    step1_checks: List[CheckedAlert]
    step3_summary: ExecutiveSummary


class VulnAnalysisReport(BaseModel):
    """全4ステップ統合レポートオブジェクト."""

    report_id: str
    generated_at: str
    llm_mode: str
    step1_checks: List[CheckedAlert]
    step2_impacts: List[SystemImpactItem]
    step3_summary: ExecutiveSummary
    graph_3d: Graph3DData
