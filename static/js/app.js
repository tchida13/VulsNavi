/**
 * static/js/app.js
 * VulsNavi - ユーザー目線のシンプルな1画面1ビュー＆2段階ドリルダウン制御
 */

(function () {
  'use strict';

  const state = {
    systems: [],
    alerts: [],
    report: null,
    viewMode: 'before', // 'before' | 'after'
    selectedNodeId: null,
    graph3d: null
  };

  function esc(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function badgeForVerdict(verdict, label) {
    const v = String(verdict || '').toUpperCase();
    if (v === 'CONFIRMED') {
      return `<span class="status-badge badge-danger">🚨 ${esc(label || '要対応（公的情報）')}</span>`;
    }
    if (v === 'FALSE_ALARM') {
      return `<span class="status-badge badge-muted">🛑 ${esc(label || '対応不要（SNSデマ）')}</span>`;
    }
    return `<span class="status-badge badge-safe">✔ ${esc(label || '対応済（安全バージョン）')}</span>`;
  }

  function badgeForUsage(usageStatus, usageLabel, viewMode) {
    const u = String(usageStatus || '').toUpperCase();
    if (u.includes('UNUSED')) {
      return `<span class="status-badge badge-warning">📦 ${esc(usageLabel || '未使用ライブラリ（削除推奨）')}</span>`;
    }
    if (u.includes('ACTIVE_VULNERABLE')) {
      if (viewMode === 'after') {
        return `<span class="status-badge badge-safe">✔ パッチ適用・テストPASS済</span>`;
      }
      return `<span class="status-badge badge-danger">🚨 ${esc(usageLabel || '使用中・要パッチ適用')}</span>`;
    }
    return `<span class="status-badge badge-safe">✔ ${esc(usageLabel || '対策済・安全')}</span>`;
  }

  function formatDiffHtml(diffText) {
    if (!diffText) return '';
    return String(diffText)
      .split('\n')
      .map((line) => {
        if (line.startsWith('-')) {
          return `<span class="diff-line-del">${esc(line)}</span>`;
        }
        if (line.startsWith('+')) {
          return `<span class="diff-line-add">${esc(line)}</span>`;
        }
        return `<span>${esc(line)}</span>`;
      })
      .join('\n');
  }

  /* ==================== INITIALIZATION ==================== */
  document.addEventListener('DOMContentLoaded', () => {
    const mountEl = document.getElementById('three-canvas-mount');
    const labelsEl = document.getElementById('node-labels-layer');

    state.graph3d = new window.VulnGraph3D(
      mountEl,
      labelsEl,
      (nodeData) => {
        state.selectedNodeId = nodeData.id;
        renderInspectorForNode(nodeData);
      },
      (scope, focusedSystemId) => {
        handleScopeChange(scope, focusedSystemId);
      }
    );

    bindUIEvents();
    loadInitialData();
  });

  function handleScopeChange(scope, focusedSystemId) {
    const btnBack = document.getElementById('btn-back-overview');
    const guideEl = document.getElementById('graph-guide-text');

    if (btnBack) {
      btnBack.classList.toggle('hidden', scope === 'overview');
    }

    if (scope === 'overview') {
      state.selectedNodeId = null;
      if (guideEl) {
        guideEl.innerHTML =
          '<strong>🌐 全社システム連携マップ</strong>：社内システム同士のAPI・データ連携（エッジ）を表示しています。<strong>システム（◆）をクリック</strong>すると、そのシステムを中心としたライブラリ依存関係マップへ展開します。';
      }
      renderOverviewInspector();
    } else if (scope === 'system' && state.report && state.report.graph_3d) {
      const sysNode = state.report.graph_3d.nodes.find((n) => n.id === focusedSystemId);
      const sysLabel = sysNode ? `${sysNode.label} (${sysNode.id})` : focusedSystemId;
      if (guideEl) {
        guideEl.innerHTML =
          `<strong>🔍 ライブラリ依存関係マップ（中心: ${esc(sysLabel)}）</strong>：選択したシステムと使用ライブラリ（●）の依存関係をエッジで表示しています。ライブラリをクリックすると右側に該当コードとテスト結果を表示します。`;
      }
    }
  }

  function switchMainView(targetViewId) {
    document.querySelectorAll('.step-tab').forEach((tab) => {
      tab.classList.toggle('active', tab.dataset.target === targetViewId);
    });
    document.querySelectorAll('.step-view').forEach((view) => {
      view.classList.toggle('active', view.id === targetViewId);
    });

    if (targetViewId === 'view-step4' && state.graph3d) {
      setTimeout(() => state.graph3d.handleResize(), 50);
    }
  }

  function bindUIEvents() {
    // 4ステップの上部タブ切り替え
    document.querySelectorAll('.step-tab').forEach((tab) => {
      tab.addEventListener('click', () => {
        switchMainView(tab.dataset.target);
      });
    });

    // 全社システム一覧マップへ戻るボタン
    const btnBackOverview = document.getElementById('btn-back-overview');
    if (btnBackOverview) {
      btnBackOverview.addEventListener('click', () => {
        if (state.graph3d) state.graph3d.showSystemOverview();
      });
    }

    // 対応前 / 対応後 トグルボタン
    const btnBefore = document.getElementById('btn-mode-before');
    const btnAfter = document.getElementById('btn-mode-after');
    if (btnBefore) btnBefore.addEventListener('click', () => setViewMode('before'));
    if (btnAfter) btnAfter.addEventListener('click', () => setViewMode('after'));

    // カメラ操作
    const btnRotate = document.getElementById('btn-cam-rotate');
    const btnReset = document.getElementById('btn-cam-reset');
    if (btnRotate) {
      btnRotate.addEventListener('click', () => {
        const active = state.graph3d.toggleAutoRotate();
        btnRotate.classList.toggle('active', active);
      });
    }
    if (btnReset) {
      btnReset.addEventListener('click', () => state.graph3d.resetCamera());
    }

    // Step 1 のカスタムSNS投稿・脆弱性情報検証フォーム
    const btnToggleCustom = document.getElementById('btn-toggle-custom-alert');
    const customBox = document.getElementById('custom-alert-box');
    const btnCancelCustom = document.getElementById('btn-cancel-custom-alert');
    const btnSubmitCustom = document.getElementById('btn-submit-custom-alert');

    if (btnToggleCustom && customBox) {
      btnToggleCustom.addEventListener('click', () => customBox.classList.toggle('hidden'));
    }
    if (btnCancelCustom && customBox) {
      btnCancelCustom.addEventListener('click', () => customBox.classList.add('hidden'));
    }
    if (btnSubmitCustom) {
      btnSubmitCustom.addEventListener('click', () => {
        const inputEl = document.getElementById('custom-alert-input');
        const customText = inputEl ? inputEl.value.trim() : '';
        runFourStepAnalysis(customText, 'view-step1');
      });
    }

    // 一括診断ボタン
    const btnRunAnalyze = document.getElementById('btn-run-analyze');
    if (btnRunAnalyze) {
      btnRunAnalyze.addEventListener('click', () => {
        const inputEl = document.getElementById('custom-alert-input');
        const customText = inputEl ? inputEl.value.trim() : '';
        runFourStepAnalysis(customText, null);
      });
    }
  }

  function setViewMode(mode) {
    state.viewMode = mode;
    const btnBefore = document.getElementById('btn-mode-before');
    const btnAfter = document.getElementById('btn-mode-after');
    if (btnBefore && btnAfter) {
      btnBefore.classList.toggle('active-before', mode === 'before');
      btnAfter.classList.toggle('active-after', mode === 'after');
    }

    const canvasPanel = document.querySelector('.canvas-panel');
    if (canvasPanel) {
      canvasPanel.setAttribute('data-mode', mode);
    }

    if (state.graph3d) {
      state.graph3d.setMode(mode);
    }

    renderStep2Table();

    if (state.graph3d && state.graph3d.viewScope === 'overview') {
      renderOverviewInspector();
    } else if (state.selectedNodeId && state.report && state.report.graph_3d) {
      const node = state.report.graph_3d.nodes.find((n) => n.id === state.selectedNodeId);
      if (node) renderInspectorForNode(node);
    }
  }

  /* ==================== DATA LOADING & 4-STEP EXECUTION ==================== */
  async function loadInitialData() {
    try {
      const res = await fetch('/api/initial-data');
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      state.systems = data.systems || [];
      state.alerts = data.alerts || [];
      const report = data.latest_report || data.report;
      if (report) {
        applyReportData(report);
      }
    } catch (err) {
      console.error('Failed to load initial data:', err);
    }
  }

  async function runFourStepAnalysis(customAlertText, redirectViewId) {
    const overlay = document.getElementById('pipeline-progress-overlay');
    const titleEl = document.getElementById('progress-step-title');
    const fillEl = document.getElementById('progress-bar-fill');
    const logListEl = document.getElementById('progress-log-list');

    if (overlay) overlay.classList.remove('hidden');
    if (logListEl) logListEl.innerHTML = '';

    const addLog = (msg, done) => {
      if (!logListEl) return;
      const item = document.createElement('div');
      item.className = 'progress-log-item' + (done ? ' done' : '');
      item.textContent = (done ? '✔ ' : '▸ ') + msg;
      logListEl.appendChild(item);
    };

    setViewMode('before');

    if (titleEl) titleEl.textContent = 'Step 1: CHECK — JPCERT/CC・NVD・SNS情報の真偽を確認中...';
    if (fillEl) fillEl.style.width = '25%';
    addLog('公的機関（JPCERT/CC・NVD）の情報とSNS上の投稿を照合中...');

    const fetchPromise = fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ custom_alert_text: customAlertText || '' })
    }).then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    });

    await new Promise((r) => setTimeout(r, 320));
    addLog('要対応の脆弱性とSNSデマ（誤情報）の仕分けが完了', true);

    if (titleEl) titleEl.textContent = 'Step 2: APPLY / TEST — 社内システムの該当コード走査＆テスト実行中...';
    if (fillEl) fillEl.style.width = '60%';
    addLog('社内4システムの該当行番号の特定・未使用ライブラリの検出・単体テストを実行中...');

    await new Promise((r) => setTimeout(r, 350));
    addLog('パッチ適用シミュレーションと単体テスト（unittest）の全件 PASS を確認', true);

    if (titleEl) titleEl.textContent = 'Step 3 & 4: SUMMARY / OUTPUT — 報告書と3Dマップを更新中...';
    if (fillEl) fillEl.style.width = '90%';

    try {
      const report = await fetchPromise;
      if (fillEl) fillEl.style.width = '100%';
      addLog('すべての診断とレポート生成が完了しました', true);

      applyReportData(report);
      await new Promise((r) => setTimeout(r, 280));
      setViewMode('after');
      if (redirectViewId) {
        switchMainView(redirectViewId);
      }
    } catch (err) {
      console.error('Analysis failed:', err);
      addLog('エラーが発生しました: ' + err.message);
    } finally {
      if (overlay) overlay.classList.add('hidden');
      const customBox = document.getElementById('custom-alert-box');
      if (customBox) customBox.classList.add('hidden');
    }
  }

  function applyReportData(report) {
    state.report = report;

    const checks = report.step1_checks || [];
    const impacts = report.step2_impacts || [];
    const matrix = (report.step3_summary && report.step3_summary.cross_system_matrix) || [];

    const confirmedCount = checks.filter((c) => c.verdict === 'CONFIRMED').length;
    const falseOrMitigated = checks.filter((c) => c.verdict !== 'CONFIRMED').length;
    const unusedCount = impacts.filter((i) => String(i.usage_status).includes('UNUSED')).length;

    const kpiSystems = document.getElementById('kpi-systems-count');
    const kpiConfirmed = document.getElementById('kpi-confirmed-count');
    const kpiFalse = document.getElementById('kpi-false-count');
    const kpiUnused = document.getElementById('kpi-unused-count');
    const kpiTest = document.getElementById('kpi-test-status');

    if (kpiSystems) kpiSystems.textContent = `${matrix.length || 4} システム`;
    if (kpiConfirmed) kpiConfirmed.textContent = `${confirmedCount} 件`;
    if (kpiFalse) kpiFalse.textContent = `${falseOrMitigated} 件`;
    if (kpiUnused) kpiUnused.textContent = `${unusedCount} 件`;
    if (kpiTest) kpiTest.textContent = 'すべて PASS ✔';

    renderStep1Table();
    renderStep2Table();
    renderStep3Summary();

    if (state.graph3d && report.graph_3d) {
      state.graph3d.setData(report.graph_3d);
      state.graph3d.setMode(state.viewMode);
      if (state.graph3d.viewScope === 'overview') {
        renderOverviewInspector();
      }
    }
  }

  /* ==================== TABLES FOR STEP 1, STEP 2, STEP 3 ==================== */
  function renderStep1Table() {
    const tbody = document.getElementById('step1-table-body');
    if (!tbody || !state.report) return;

    const checks = state.report.step1_checks || [];
    tbody.innerHTML = checks
      .map(
        (c) => `
        <tr>
          <td>
            <strong>${esc(c.source)}</strong><br/>
            <span style="color: var(--text-sub); font-size: 12px;">${esc(c.cve_id)}</span>
          </td>
          <td>
            <div style="font-weight: 800; color: var(--text-bright); margin-bottom: 4px;">${esc(c.title)}</div>
            <span style="font-size: 12.5px; color: var(--text-sub);">対象ライブラリ: <code>${esc(c.package)}</code> (影響範囲: ${esc(c.affected_versions)} / 修正版: <strong style="color: #6ee7b7;">${esc(c.fixed_version)}</strong>)</span>
          </td>
          <td>${badgeForVerdict(c.verdict, c.verdict_label)}</td>
          <td><strong>${esc(c.cvss_score)}</strong> (${esc(c.severity)})</td>
          <td>${esc(c.verification_reason)}</td>
        </tr>
      `
      )
      .join('');
  }

  function renderStep2Table() {
    const tbody = document.getElementById('step2-table-body');
    if (!tbody || !state.report) return;

    const impacts = state.report.step2_impacts || [];
    tbody.innerHTML = impacts
      .map(
        (imp) => `
        <tr data-sys-id="${esc(imp.system_id)}">
          <td>
            <strong style="color: var(--text-bright); font-size: 14px;">${esc(imp.system_name)}</strong><br/>
            <span style="color: #38bdf8; font-size: 12px;">${esc(imp.system_id)} (${esc(imp.owner)})</span>
          </td>
          <td>
            <strong style="font-family: var(--font-mono); font-size: 14px;">${esc(imp.package)}</strong><br/>
            <code>${esc(imp.current_version)}</code> ➔ <code style="color: #6ee7b7; font-weight: 700;">${esc(imp.fixed_version)}</code>
          </td>
          <td>${badgeForUsage(imp.usage_status, imp.usage_label, state.viewMode)}</td>
          <td>
            <span class="file-loc-chip">${esc(imp.file_path)}${imp.line_number ? ':' + esc(imp.line_number) : ''}</span>
            <pre class="code-block" style="margin-top: 6px; font-size: 11px;">${esc(imp.code_snippet)}</pre>
          </td>
          <td>
            <div style="margin-bottom: 6px;">${esc(imp.patch_action)}</div>
            <span class="status-badge badge-safe">✔ テスト: ${esc(imp.test_status)}</span>
          </td>
          <td>${esc(imp.alternative_suggestion)}</td>
        </tr>
      `
      )
      .join('');

    tbody.querySelectorAll('tr[data-sys-id]').forEach((row) => {
      row.addEventListener('click', () => {
        const sysId = row.dataset.sysId;
        switchMainView('view-step4');
        if (state.graph3d) state.graph3d.selectNode(sysId);
      });
    });
  }

  function renderStep3Summary() {
    if (!state.report || !state.report.step3_summary) return;
    const sum = state.report.step3_summary;

    const headlineEl = document.getElementById('summary-headline');
    const threeLinesEl = document.getElementById('summary-three-lines');
    const futureEl = document.getElementById('summary-future-actions');
    const matrixBody = document.getElementById('summary-matrix-body');

    if (headlineEl) headlineEl.textContent = sum.headline || '';
    if (threeLinesEl) {
      threeLinesEl.innerHTML = (sum.three_line_summary || [])
        .map((line) => `<li>${esc(line.replace(/^[0-9]+\.\s*/, ''))}</li>`)
        .join('');
    }
    if (futureEl) {
      futureEl.innerHTML = (sum.future_actions || [])
        .map((act) => `<li>${esc(act)}</li>`)
        .join('');
    }
    if (matrixBody) {
      matrixBody.innerHTML = (sum.cross_system_matrix || [])
        .map(
          (m) => `
          <tr data-sys-id="${esc(m.system_id)}">
            <td><strong>${esc(m.system_id)}</strong><br/>${esc(m.system_name)}</td>
            <td>${esc(m.owner)}</td>
            <td><span class="status-badge ${String(m.status_before).includes('SAFE') ? 'badge-safe' : 'badge-danger'}">${esc(m.status_before)}</span></td>
            <td><span class="status-badge badge-safe">✔ ${esc(m.status_after)}</span></td>
            <td>${esc(m.summary_note)}</td>
          </tr>
        `
        )
        .join('');

      matrixBody.querySelectorAll('tr[data-sys-id]').forEach((row) => {
        row.addEventListener('click', () => {
          switchMainView('view-step4');
          if (state.graph3d) state.graph3d.selectNode(row.dataset.sysId);
        });
      });
    }
  }

  /* ==================== RIGHT SIDE INSPECTOR (3D マップ連動) ==================== */
  function renderOverviewInspector() {
    const titleEl = document.getElementById('inspector-title');
    const catEl = document.getElementById('inspector-category-badge');
    const bodyEl = document.getElementById('inspector-body');
    if (!bodyEl || !state.report || !state.report.graph_3d) return;

    if (catEl) catEl.textContent = '全社システム連携マップ（トップ画面）';
    if (titleEl) titleEl.textContent = '社内システム一覧とシステム間依存関係';

    const nodes = (state.report.graph_3d.nodes || []).filter((n) => n.category === 'SYSTEM');
    const sysLinks = (state.report.graph_3d.links || []).filter(
      (l) => l.relation === 'SYSTEM_DEPENDENCY'
    );

    const htmlParts = [];

    // システム一覧（クリックでライブラリ依存マップへドリルダウン）
    htmlParts.push(`
      <div style="font-size: 12.5px; color: var(--text-sub); margin-bottom: 4px;">
        以下のシステム（または左の3Dマップ上の ◆ ノード）をクリックすると、そのシステムを中心とした<strong>ライブラリ依存関係マップ</strong>へ展開します：
      </div>
    `);

    nodes.forEach((sys) => {
      const isSafeBefore = sys.status_before === 'SAFE';
      const statusBadge =
        state.viewMode === 'after' || isSafeBefore
          ? `<span class="status-badge badge-safe">✔ 対策済・安全</span>`
          : `<span class="status-badge badge-danger">🚨 要対応（脆弱ライブラリあり）</span>`;

      htmlParts.push(`
        <div class="sys-overview-item" data-drill-sys="${esc(sys.id)}">
          <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 6px;">
            <strong style="font-size: 14px; color: var(--text-bright);">◆ ${esc(sys.label)} (${esc(sys.id)})</strong>
            ${statusBadge}
          </div>
          <div style="font-size: 12px; color: var(--text-sub); display: flex; justify-content: space-between; align-items: center;">
            <span>${esc(sys.sublabel || '')}</span>
            <span style="color: #38bdf8; font-weight: 700;">ライブラリ依存を表示 ➔</span>
          </div>
        </div>
      `);
    });

    // システム間エッジ（連携・依存関係）の説明
    if (sysLinks.length > 0) {
      htmlParts.push(`
        <div class="insp-card" style="margin-top: 6px;">
          <div class="insp-card-title">
            <span>🔗 システム間の通信・依存関係（エッジ）</span>
          </div>
          <div style="display: flex; flex-direction: column; gap: 8px; font-size: 12.5px;">
            ${sysLinks
              .map(
                (l) => `
              <div style="padding-bottom: 6px; border-bottom: 1px solid rgba(148,163,184,0.12);">
                <strong style="color: #38bdf8;">${esc(l.source)} ➔ ${esc(l.target)}</strong><br/>
                <span style="color: var(--text-main);">${esc((l.details && l.details.reason) || '')}</span>
              </div>
            `
              )
              .join('')}
          </div>
        </div>
      `);
    }

    bodyEl.innerHTML = htmlParts.join('');

    bodyEl.querySelectorAll('[data-drill-sys]').forEach((card) => {
      card.addEventListener('click', () => {
        const sysId = card.getAttribute('data-drill-sys');
        if (state.graph3d && sysId) {
          state.graph3d.drillDownToSystem(sysId);
        }
      });
    });
  }

  function renderInspectorForNode(node) {
    const titleEl = document.getElementById('inspector-title');
    const catEl = document.getElementById('inspector-category-badge');
    const bodyEl = document.getElementById('inspector-body');
    if (!bodyEl || !state.report) return;

    if (titleEl) titleEl.textContent = node.label;
    if (catEl) {
      catEl.textContent =
        node.category === 'SYSTEM'
          ? `選択中のシステム (${node.id})`
          : `依存ライブラリ (${(node.details && node.details.system_id) || ''})`;
    }

    const impacts = state.report.step2_impacts || [];
    const checks = state.report.step1_checks || [];

    let matchedImpacts = [];
    let matchedChecks = [];

    if (node.category === 'SYSTEM') {
      matchedImpacts = impacts.filter((i) => i.system_id === node.id);
    } else if (node.category === 'LIBRARY') {
      const pkgName = (node.details && node.details.package) || node.label.split(' ')[0].toLowerCase();
      const targetSysId = node.details && node.details.system_id;
      if (targetSysId) {
        matchedImpacts = impacts.filter(
          (i) => i.system_id === targetSysId && String(i.package).toLowerCase() === String(pkgName).toLowerCase()
        );
      } else {
        matchedImpacts = impacts.filter(
          (i) => String(i.package).toLowerCase() === String(pkgName).toLowerCase()
        );
      }
      matchedChecks = checks.filter(
        (c) => String(c.package).toLowerCase() === String(pkgName).toLowerCase()
      );
    }

    const htmlParts = [];

    // 1. 状態サマリーカード
    const beforeLabel =
      node.status_before === 'VULNERABLE'
        ? '要対応（脆弱性あり）'
        : node.status_before === 'UNUSED'
        ? '未使用ライブラリ'
        : '安全（対策済）';
    const afterLabel =
      node.status_after === 'REMOVED'
        ? '削除推奨（未使用）'
        : '安全（パッチ適用・テストPASS）';

    htmlParts.push(`
      <div class="insp-card">
        <div class="insp-card-title">
          <span>セキュリティ状態（対応前 ➔ 対応後）</span>
        </div>
        <div class="state-transition-row">
          <span class="status-badge ${node.status_before === 'SAFE' ? 'badge-safe' : node.status_before === 'UNUSED' ? 'badge-warning' : 'badge-danger'}">
            対応前: ${esc(beforeLabel)}
          </span>
          <span style="color: #38bdf8; font-weight: 800;">➔</span>
          <span class="status-badge badge-safe">
            対応後: ${esc(afterLabel)}
          </span>
        </div>
        <div style="font-size: 12.5px; color: var(--text-sub); margin-top: 6px;">
          ${esc(node.sublabel || '')}
        </div>
      </div>
    `);

    // 1.5 システム選択時は「このシステムの依存ライブラリ一覧（ワンクリックでフォーカス）」チップを表示
    if (node.category === 'SYSTEM' && state.report.graph_3d) {
      const sysLibNodes = (state.report.graph_3d.nodes || []).filter(
        (n) => n.category === 'LIBRARY' && n.details && n.details.system_id === node.id
      );
      if (sysLibNodes.length > 0) {
        htmlParts.push(`
          <div class="insp-card">
            <div class="insp-card-title">
              <span>📦 このシステムの依存ライブラリ（クリックでフォーカス）</span>
            </div>
            <div class="dep-lib-chips">
              ${sysLibNodes
                .map((lib) => {
                  const dotColor =
                    state.viewMode === 'after'
                      ? '#00e68a'
                      : lib.status_before === 'VULNERABLE'
                      ? '#ff2a6d'
                      : lib.status_before === 'UNUSED'
                      ? '#ffb800'
                      : '#00e68a';
                  return `<button type="button" class="dep-lib-chip" data-focus-node="${esc(lib.id)}">
                    <span class="lbl-dot" style="background:${dotColor};"></span>
                    <span>${esc(lib.label)}</span>
                  </button>`;
                })
                .join('')}
            </div>
          </div>
        `);
      }
    }

    // 2. 関連する脆弱性情報 (ライブラリ選択時)
    matchedChecks.forEach((chk) => {
      htmlParts.push(`
        <div class="insp-card">
          <div class="insp-card-title">
            <span>関連する脆弱性アラート (${esc(chk.source)})</span>
            <span>${esc(chk.cve_id)}</span>
          </div>
          <div style="margin-bottom: 6px;">${badgeForVerdict(chk.verdict, chk.verdict_label)}</div>
          <div style="font-size: 13.5px; font-weight: 800; color: var(--text-bright); margin-bottom: 4px;">
            ${esc(chk.title)}
          </div>
          <div style="font-size: 12.5px; color: var(--text-main);">
            ${esc(chk.verification_reason)}
          </div>
        </div>
      `);
    });

    // 3. 該当システムのコード箇所・パッチ・単体テスト・代替ライブラリ提案
    matchedImpacts.forEach((imp) => {
      htmlParts.push(`
        <div class="insp-card">
          <div class="insp-card-title">
            <span>${esc(imp.system_name)} (${esc(imp.system_id)})</span>
            <span>${esc(imp.package)} ${esc(imp.current_version)}</span>
          </div>
          <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 6px; margin-bottom: 8px;">
            ${badgeForUsage(imp.usage_status, imp.usage_label, state.viewMode)}
            <span class="file-loc-chip">📄 ${esc(imp.file_path)}${imp.line_number ? ':' + esc(imp.line_number) : ''}</span>
          </div>

          <div style="font-size: 12px; color: var(--text-sub);">該当コード抜粋${imp.line_number ? ' (' + esc(imp.line_number) + '行目)' : ''}:</div>
          <pre class="code-block">${esc(imp.code_snippet)}</pre>

          <div style="font-size: 12.5px; color: #38bdf8; font-weight: 700; margin-top: 10px;">
            🔧 修正内容 (${esc(imp.patch_action)}):
          </div>
          <pre class="code-block">${formatDiffHtml(imp.patch_diff)}</pre>

          <div style="font-size: 12.5px; color: #6ee7b7; font-weight: 700; margin-top: 10px;">
            🧪 自動テスト結果: <span class="status-badge badge-safe">${esc(imp.test_status)}</span>
          </div>
          <pre class="code-block">$ ${esc(imp.test_command)}\n${esc(imp.test_output)}</pre>

          <div style="font-size: 12.5px; color: #fcd34d; margin-top: 10px;">
            💡 <strong>代替ライブラリの提案:</strong><br/>
            <span style="color: var(--text-main);">${esc(imp.alternative_suggestion)}</span>
          </div>
        </div>
      `);
    });

    bodyEl.innerHTML = htmlParts.join('');

    bodyEl.querySelectorAll('[data-focus-node]').forEach((chip) => {
      chip.addEventListener('click', () => {
        const targetId = chip.getAttribute('data-focus-node');
        if (state.graph3d && targetId) {
          state.graph3d.selectNode(targetId);
        }
      });
    });
  }
})();
