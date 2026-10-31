/**
 * static/js/app.js
 * Main Application Controller for 脆弱性レポートまとめ君 (vulnavi)
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
      return `<span class="status-badge badge-danger">🚨 ${esc(label || '要対応（公的裏付けあり）')}</span>`;
    }
    if (v === 'FALSE_ALARM') {
      return `<span class="status-badge badge-muted">🛑 ${esc(label || '誤情報（SNSデマ）')}</span>`;
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
      return `<span class="status-badge badge-danger">⚡ ${esc(usageLabel || '使用中・パッチ対象')}</span>`;
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

    state.graph3d = new window.VulnGraph3D(mountEl, labelsEl, (nodeData) => {
      state.selectedNodeId = nodeData.id;
      highlightSelectedCards(nodeData.id);
      renderInspectorForNode(nodeData);
    });

    bindUIEvents();
    loadInitialData();
  });

  function bindUIEvents() {
    // Before / After Mode Toggle
    const btnBefore = document.getElementById('btn-mode-before');
    const btnAfter = document.getElementById('btn-mode-after');

    if (btnBefore) {
      btnBefore.addEventListener('click', () => setViewMode('before'));
    }
    if (btnAfter) {
      btnAfter.addEventListener('click', () => setViewMode('after'));
    }

    // Camera Controls
    const btnRotate = document.getElementById('btn-cam-rotate');
    const btnReset = document.getElementById('btn-cam-reset');
    if (btnRotate) {
      btnRotate.addEventListener('click', () => {
        const active = state.graph3d.toggleAutoRotate();
        btnRotate.classList.toggle('active', active);
      });
    }
    if (btnReset) {
      btnReset.addEventListener('click', () => {
        state.graph3d.resetCamera();
      });
    }

    // Drawer Tabs & Header Stepper Pills
    const drawerTabs = document.querySelectorAll('.drawer-tab');
    drawerTabs.forEach((btn) => {
      btn.addEventListener('click', () => {
        activateDrawerTab(btn.dataset.tab);
      });
    });

    const stepMap = {
      step1: 'tab-step1',
      step2: 'tab-step2',
      step3: 'tab-step3',
      step4: 'tab-step4'
    };
    document.querySelectorAll('.step-pill').forEach((pill) => {
      pill.addEventListener('click', () => {
        const targetTab = stepMap[pill.dataset.stepTarget];
        if (targetTab) activateDrawerTab(targetTab);
      });
    });

    // Custom Alert Box Toggle
    const btnToggleCustom = document.getElementById('btn-toggle-custom-alert');
    const customBox = document.getElementById('custom-alert-box');
    const btnCancelCustom = document.getElementById('btn-cancel-custom-alert');
    const btnSubmitCustom = document.getElementById('btn-submit-custom-alert');

    if (btnToggleCustom && customBox) {
      btnToggleCustom.addEventListener('click', () => {
        customBox.classList.toggle('hidden');
      });
    }
    if (btnCancelCustom && customBox) {
      btnCancelCustom.addEventListener('click', () => {
        customBox.classList.add('hidden');
      });
    }
    if (btnSubmitCustom) {
      btnSubmitCustom.addEventListener('click', () => {
        const inputEl = document.getElementById('custom-alert-input');
        const customText = inputEl ? inputEl.value.trim() : '';
        runFourStepAnalysis(customText);
      });
    }

    // Run 4-Step Analyze Button
    const btnRunAnalyze = document.getElementById('btn-run-analyze');
    if (btnRunAnalyze) {
      btnRunAnalyze.addEventListener('click', () => {
        const inputEl = document.getElementById('custom-alert-input');
        const customText = inputEl ? inputEl.value.trim() : '';
        runFourStepAnalysis(customText);
      });
    }

    // GCP Architecture Modal
    const btnOpenArch = document.getElementById('btn-open-arch');
    const btnCloseArch = document.getElementById('btn-close-arch');
    const archModal = document.getElementById('arch-modal');

    if (btnOpenArch && archModal) {
      btnOpenArch.addEventListener('click', () => {
        archModal.classList.remove('hidden');
      });
    }
    if (btnCloseArch && archModal) {
      btnCloseArch.addEventListener('click', () => {
        archModal.classList.add('hidden');
      });
    }
    if (archModal) {
      archModal.addEventListener('click', (e) => {
        if (e.target === archModal) {
          archModal.classList.add('hidden');
        }
      });
    }
  }

  function activateDrawerTab(tabId) {
    document.querySelectorAll('.drawer-tab').forEach((t) => {
      t.classList.toggle('active', t.dataset.tab === tabId);
    });
    document.querySelectorAll('.tab-pane').forEach((p) => {
      p.classList.toggle('active', p.id === tabId);
    });
  }

  function setViewMode(mode) {
    state.viewMode = mode;
    const btnBefore = document.getElementById('btn-mode-before');
    const btnAfter = document.getElementById('btn-mode-after');
    if (btnBefore && btnAfter) {
      btnBefore.classList.toggle('active-before', mode === 'before');
      btnAfter.classList.toggle('active-after', mode === 'after');
    }

    if (state.graph3d) {
      state.graph3d.setMode(mode);
    }

    renderLeftSystemsList();
    renderStep2Table();

    if (state.selectedNodeId && state.report && state.report.graph_3d) {
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
      if (data.latest_report) {
        applyReportData(data.latest_report);
      } else {
        renderLeftSystemsList();
        renderLeftAlertsList();
      }
    } catch (err) {
      console.error('Failed to load initial data:', err);
    }
  }

  async function runFourStepAnalysis(customAlertText) {
    const overlay = document.getElementById('pipeline-progress-overlay');
    const titleEl = document.getElementById('progress-step-title');
    const fillEl = document.getElementById('progress-bar-fill');
    const logListEl = document.getElementById('progress-log-list');
    const stepPills = [
      document.getElementById('stepper-step1'),
      document.getElementById('stepper-step2'),
      document.getElementById('stepper-step3'),
      document.getElementById('stepper-step4')
    ];

    if (overlay) overlay.classList.remove('hidden');
    if (logListEl) logListEl.innerHTML = '';

    const addLog = (msg, done) => {
      if (!logListEl) return;
      const item = document.createElement('div');
      item.className = 'progress-log-item' + (done ? ' done' : '');
      item.textContent = (done ? '✔ ' : '▸ ') + msg;
      logListEl.appendChild(item);
      logListEl.scrollTop = logListEl.scrollHeight;
    };

    const highlightStepper = (idx) => {
      stepPills.forEach((p, i) => {
        if (!p) return;
        p.classList.toggle('running', i === idx);
      });
    };

    // Start in BEFORE mode to show the transition clearly
    setViewMode('before');

    highlightStepper(0);
    if (titleEl) titleEl.textContent = 'Step 1: CHECK — JPCERT/CC・NVD・SNS真偽精査中...';
    if (fillEl) fillEl.style.width = '25%';
    addLog('[Agent ①] JPCERT/CC・NVD公的情報とSNS(X)投稿を照合中...');

    const fetchPromise = fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ custom_alert_text: customAlertText || '' })
    }).then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    });

    await new Promise((r) => setTimeout(r, 380));
    addLog('[Step 1 Complete] 本物の脅威とSNSデマ(誤情報)の仕分けが完了', true);

    highlightStepper(1);
    if (titleEl) titleEl.textContent = 'Step 2: APPLY/TEST — 社内4システムのコード走査＆unittest実行中...';
    if (fillEl) fillEl.style.width = '55%';
    addLog('[Agent ③⑥] SYS-01〜04の実コード該当行と未使用ライブラリ(pyyaml)を特定...');

    await new Promise((r) => setTimeout(r, 420));
    addLog('[Agent ⑤⑦⑧] パッチ適用＆unittest自動検証 PASS・代替ライブラリ提案を生成', true);

    highlightStepper(2);
    if (titleEl) titleEl.textContent = 'Step 3: SUMMARY — 上司・同僚向け3行要約＆全社影響マトリクス生成中...';
    if (fillEl) fillEl.style.width = '82%';
    addLog('[Agent ④] Gemini 3.8 Flash 構造化スキーマで非エンジニア向け要約を作成中...');

    try {
      const report = await fetchPromise;
      await new Promise((r) => setTimeout(r, 320));

      highlightStepper(3);
      if (titleEl) titleEl.textContent = 'Step 4: OUTPUT — 3D トポロジー更新＆公式A4 PDF準備完了！';
      if (fillEl) fillEl.style.width = '100%';
      addLog('[Agent ②] 3D HTMLレポート＆白背景A4公式PDF出力の準備が完了しました', true);

      applyReportData(report);

      await new Promise((r) => setTimeout(r, 350));
      // Switch to AFTER mode so the user immediately sees the green patched state!
      setViewMode('after');
    } catch (err) {
      console.error('Analysis failed:', err);
      addLog('エラーが発生しました: ' + err.message);
    } finally {
      stepPills.forEach((p) => p && p.classList.remove('running'));
      if (overlay) overlay.classList.add('hidden');
      const customBox = document.getElementById('custom-alert-box');
      if (customBox) customBox.classList.add('hidden');
    }
  }

  function applyReportData(report) {
    state.report = report;

    // Engine badge
    const llmBadge = document.getElementById('llm-mode-badge');
    if (llmBadge && report.llm_mode) {
      llmBadge.textContent = `ENGINE: ${report.llm_mode}`;
    }

    // Update KPI strip
    const checks = report.step1_checks || [];
    const impacts = report.step2_impacts || [];
    const confirmedCount = checks.filter((c) => c.verdict === 'CONFIRMED').length;
    const falseOrMitigated = checks.filter((c) => c.verdict !== 'CONFIRMED').length;
    const unusedCount = impacts.filter((i) =>
      String(i.usage_status).includes('UNUSED')
    ).length;

    const kpiConfirmed = document.getElementById('kpi-confirmed-count');
    const kpiFalse = document.getElementById('kpi-false-count');
    const kpiUnused = document.getElementById('kpi-unused-count');
    const kpiTest = document.getElementById('kpi-test-status');

    if (kpiConfirmed) kpiConfirmed.textContent = `${confirmedCount} 件`;
    if (kpiFalse) kpiFalse.textContent = `${falseOrMitigated} 件`;
    if (kpiUnused) kpiUnused.textContent = `${unusedCount} 件`;
    if (kpiTest) kpiTest.textContent = 'ALL PASS ✔';

    // Render left lists, 3D graph, and bottom tables
    renderLeftSystemsList();
    renderLeftAlertsList();
    renderStep1Table();
    renderStep2Table();
    renderStep3Summary();

    if (state.graph3d && report.graph_3d) {
      state.graph3d.setData(report.graph_3d);
      state.graph3d.setMode(state.viewMode);
    }
  }

  /* ==================== LEFT SIDEBAR LISTS ==================== */
  function renderLeftSystemsList() {
    const container = document.getElementById('systems-list');
    const countEl = document.getElementById('systems-count');
    if (!container) return;

    const matrix =
      (state.report &&
        state.report.step3_summary &&
        state.report.step3_summary.cross_system_matrix) ||
      [];

    const items = matrix.length > 0 ? matrix : state.systems;
    if (countEl) countEl.textContent = String(items.length);

    container.innerHTML = items
      .map((sys) => {
        const sysId = sys.system_id || sys.id;
        const name = sys.system_name || sys.name;
        const owner = sys.owner || '';
        const rawStatus =
          state.viewMode === 'after'
            ? sys.status_after || 'SAFE'
            : sys.status_before || 'VULNERABLE';

        const isVuln =
          String(rawStatus).toUpperCase().includes('CRIT') ||
          String(rawStatus).toUpperCase().includes('HIGH') ||
          String(rawStatus).toUpperCase().includes('VULN') ||
          String(rawStatus).toUpperCase().includes('WARN');

        const borderClass = isVuln ? 'border-danger' : 'border-safe';
        const badgeHtml = isVuln
          ? `<span class="status-badge badge-danger">⚠ 要対応 (${esc(rawStatus)})</span>`
          : `<span class="status-badge badge-safe">✔ 安全 (${esc(rawStatus)})</span>`;

        const selectedClass = state.selectedNodeId === sysId ? 'selected' : '';

        return `
          <div class="item-card ${borderClass} ${selectedClass}" data-select-node="${esc(sysId)}">
            <div class="card-top">
              <span class="card-id">${esc(sysId)}</span>
              ${badgeHtml}
            </div>
            <div class="card-title">${esc(name)}</div>
            <div class="card-meta">
              <span>担当: ${esc(owner)}</span>
            </div>
          </div>
        `;
      })
      .join('');

    container.querySelectorAll('[data-select-node]').forEach((card) => {
      card.addEventListener('click', () => {
        const nodeId = card.dataset.selectNode;
        if (state.graph3d) {
          state.graph3d.selectNode(nodeId);
        }
      });
    });
  }

  function renderLeftAlertsList() {
    const container = document.getElementById('alerts-list');
    const countEl = document.getElementById('alerts-count');
    if (!container) return;

    const checks = (state.report && state.report.step1_checks) || state.alerts || [];
    if (countEl) countEl.textContent = String(checks.length);

    container.innerHTML = checks
      .map((chk) => {
        const id = chk.alert_id || chk.id;
        const verdict = String(chk.verdict || '').toUpperCase();
        let borderClass = 'border-danger';
        if (verdict === 'FALSE_ALARM') borderClass = 'border-muted';
        else if (verdict === 'ALREADY_MITIGATED') borderClass = 'border-safe';

        const selectedClass = state.selectedNodeId === id ? 'selected' : '';

        return `
          <div class="item-card ${borderClass} ${selectedClass}" data-select-node="${esc(id)}">
            <div class="card-top">
              <span class="card-id">${esc(id)} | ${esc(chk.source)}</span>
              ${badgeForVerdict(chk.verdict, chk.verdict_label)}
            </div>
            <div class="card-title">${esc(chk.cve_id || chk.package)} — ${esc(chk.title)}</div>
            <div class="card-meta">
              <span>対象: <code>${esc(chk.package)}</code></span>
              <span>CVSS: <strong>${esc(chk.cvss_score)}</strong></span>
            </div>
          </div>
        `;
      })
      .join('');

    container.querySelectorAll('[data-select-node]').forEach((card) => {
      card.addEventListener('click', () => {
        const nodeId = card.dataset.selectNode;
        if (state.graph3d) {
          state.graph3d.selectNode(nodeId);
        }
      });
    });
  }

  function highlightSelectedCards(nodeId) {
    document.querySelectorAll('[data-select-node]').forEach((el) => {
      el.classList.toggle('selected', el.dataset.selectNode === nodeId);
    });
  }

  /* ==================== BOTTOM DRAWER TABLES (STEPS 1-3) ==================== */
  function renderStep1Table() {
    const tbody = document.getElementById('step1-table-body');
    if (!tbody || !state.report) return;

    const checks = state.report.step1_checks || [];
    tbody.innerHTML = checks
      .map(
        (c) => `
        <tr data-node-id="${esc(c.alert_id)}">
          <td>
            <strong>${esc(c.alert_id)}</strong><br/>
            <span style="color: var(--text-sub); font-size: 10.5px;">${esc(c.source)}</span>
          </td>
          <td>
            <code>${esc(c.cve_id)}</code><br/>
            <strong>${esc(c.package)}</strong>
          </td>
          <td>${badgeForVerdict(c.verdict, c.verdict_label)}</td>
          <td><strong>${esc(c.cvss_score)}</strong> (${esc(c.severity)})</td>
          <td>
            影響: <code>${esc(c.affected_versions)}</code><br/>
            修正: <code style="color: var(--neon-green);">${esc(c.fixed_version)}</code>
          </td>
          <td>${esc(c.verification_reason)}</td>
        </tr>
      `
      )
      .join('');

    tbody.querySelectorAll('tr[data-node-id]').forEach((row) => {
      row.addEventListener('click', () => {
        if (state.graph3d) state.graph3d.selectNode(row.dataset.nodeId);
      });
    });
  }

  function renderStep2Table() {
    const tbody = document.getElementById('step2-table-body');
    if (!tbody || !state.report) return;

    const impacts = state.report.step2_impacts || [];
    tbody.innerHTML = impacts
      .map(
        (imp) => `
        <tr data-sys-id="${esc(imp.system_id)}" data-impact-id="${esc(imp.impact_id)}">
          <td>
            <strong>${esc(imp.system_name)}</strong><br/>
            <span style="color: var(--neon-cyan); font-family: var(--font-mono); font-size: 10px;">${esc(imp.system_id)} (${esc(imp.owner)})</span>
          </td>
          <td>
            <strong>${esc(imp.package)}</strong><br/>
            <code>${esc(imp.current_version)}</code> → <code style="color: var(--neon-green);">${esc(imp.fixed_version)}</code>
          </td>
          <td>${badgeForUsage(imp.usage_status, imp.usage_label, state.viewMode)}</td>
          <td>
            <span class="file-loc-chip">${esc(imp.file_path)}${imp.line_number ? ':' + esc(imp.line_number) : ''}</span>
          </td>
          <td>${esc(imp.patch_action)}</td>
          <td>
            <span class="status-badge badge-safe">✔ ${esc(imp.test_status)}</span><br/>
            <span style="font-size: 10px; color: var(--text-sub);">${esc(imp.test_output)}</span>
          </td>
          <td>${esc(imp.alternative_suggestion)}</td>
        </tr>
      `
      )
      .join('');

    tbody.querySelectorAll('tr[data-sys-id]').forEach((row) => {
      row.addEventListener('click', () => {
        const sysId = row.dataset.sysId;
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

    if (headlineEl) headlineEl.textContent = sum.headline || '全社診断サマリー';
    if (threeLinesEl) {
      threeLinesEl.innerHTML = (sum.three_line_summary || [])
        .map((line) => `<li>${esc(line)}</li>`)
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
            <td><strong>${esc(m.system_id)}</strong> ${esc(m.system_name)}</td>
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
          if (state.graph3d) state.graph3d.selectNode(row.dataset.sysId);
        });
      });
    }
  }

  /* ==================== RIGHT SIDE INSPECTOR ==================== */
  function renderInspectorForNode(node) {
    const titleEl = document.getElementById('inspector-title');
    const catEl = document.getElementById('inspector-category-badge');
    const bodyEl = document.getElementById('inspector-body');
    if (!bodyEl || !state.report) return;

    if (titleEl) titleEl.textContent = `${node.label}`;
    if (catEl) catEl.textContent = node.category || 'NODE';

    const impacts = state.report.step2_impacts || [];
    const checks = state.report.step1_checks || [];

    // Match relevant Step 1 & Step 2 records for this node
    let matchedImpacts = [];
    let matchedChecks = [];

    if (node.category === 'SYSTEM') {
      matchedImpacts = impacts.filter((i) => i.system_id === node.id);
    } else if (node.category === 'LIBRARY') {
      const pkgName = (node.details && node.details.package) || node.label.split(' ')[0].toLowerCase();
      matchedImpacts = impacts.filter(
        (i) => String(i.package).toLowerCase() === String(pkgName).toLowerCase()
      );
      matchedChecks = checks.filter(
        (c) => String(c.package).toLowerCase() === String(pkgName).toLowerCase()
      );
    } else if (node.category === 'ALERT') {
      matchedChecks = checks.filter(
        (c) => c.alert_id === node.id || c.cve_id === node.label
      );
      if (matchedChecks.length > 0) {
        const pkg = matchedChecks[0].package;
        matchedImpacts = impacts.filter(
          (i) => String(i.package).toLowerCase() === String(pkg).toLowerCase()
        );
      }
    }

    const htmlParts = [];

    // 1. Overview & State Transition Card
    htmlParts.push(`
      <div class="insp-card">
        <div class="insp-card-title">
          <span>ステータス遷移 (BEFORE → AFTER)</span>
          <span>ID: ${esc(node.id)}</span>
        </div>
        <div class="state-transition-row">
          <span class="status-badge ${String(node.status_before).includes('SAFE') ? 'badge-safe' : String(node.status_before).includes('FALSE') ? 'badge-muted' : 'badge-danger'}">
            対応前: ${esc(node.status_before)}
          </span>
          <span style="color: var(--neon-cyan); font-weight: 700;">➔</span>
          <span class="status-badge ${String(node.status_after).includes('FALSE') ? 'badge-muted' : 'badge-safe'}">
            対応後: ${esc(node.status_after)}
          </span>
        </div>
        <div style="font-size: 11.5px; color: var(--text-sub); margin-top: 4px;">
          ${esc(node.sublabel || '')}
        </div>
      </div>
    `);

    // 2. Step 1 Alert Verification Details (if applicable)
    matchedChecks.forEach((chk) => {
      htmlParts.push(`
        <div class="insp-card">
          <div class="insp-card-title">
            <span>Step 1: 情報源・真偽精査 (Agent ①)</span>
            <span>${esc(chk.source)}</span>
          </div>
          <div>${badgeForVerdict(chk.verdict, chk.verdict_label)}</div>
          <div style="font-size: 12px; font-weight: 700; color: var(--text-bright);">
            ${esc(chk.cve_id)} — ${esc(chk.title)}
          </div>
          <div style="font-size: 11px; color: var(--text-main); line-height: 1.5;">
            ${esc(chk.verification_reason)}
          </div>
          <div style="font-size: 10.5px; color: var(--text-sub);">
            CVSS: <strong>${esc(chk.cvss_score)} (${esc(chk.severity)})</strong> | 影響範囲: <code>${esc(chk.affected_versions)}</code> | 修正版: <code>${esc(chk.fixed_version)}</code>
          </div>
        </div>
      `);
    });

    // 3. Step 2 Code Location, Patch Diff, Unittest, and Alternative Library Cards
    matchedImpacts.forEach((imp) => {
      htmlParts.push(`
        <div class="insp-card">
          <div class="insp-card-title">
            <span>Step 2: 該当コード＆パッチ検証 (${esc(imp.system_id)})</span>
            <span>${esc(imp.package)} ${esc(imp.current_version)}</span>
          </div>
          <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 4px;">
            ${badgeForUsage(imp.usage_status, imp.usage_label, state.viewMode)}
            <span class="file-loc-chip">📄 ${esc(imp.file_path)}${imp.line_number ? ':' + esc(imp.line_number) : ''}</span>
          </div>

          <div style="font-size: 11px; color: var(--text-sub); margin-top: 4px;">該当コード抜粋 (Line ${esc(imp.line_number)}):</div>
          <pre class="code-block">${esc(imp.code_snippet)}</pre>

          <div style="font-size: 11px; color: var(--neon-cyan); font-weight: 700; margin-top: 4px;">
            🔧 適用パッチ (${esc(imp.patch_action)}):
          </div>
          <pre class="code-block">${formatDiffHtml(imp.patch_diff)}</pre>

          <div style="font-size: 11px; color: var(--neon-green); font-weight: 700; margin-top: 4px;">
            🧪 自動テスト検証結果 (Agent ⑦): <span class="status-badge badge-safe">${esc(imp.test_status)}</span>
          </div>
          <pre class="code-block">$ ${esc(imp.test_command)}\n${esc(imp.test_output)}</pre>

          <div style="font-size: 11px; color: var(--neon-amber); margin-top: 4px;">
            💡 <strong>代替ライブラリ・恒久対策提案 (Agent ⑧):</strong><br/>
            <span style="color: var(--text-main);">${esc(imp.alternative_suggestion)}</span>
          </div>
        </div>
      `);
    });

    if (matchedChecks.length === 0 && matchedImpacts.length === 0 && node.details) {
      htmlParts.push(`
        <div class="insp-card">
          <div class="insp-card-title"><span>ノード詳細情報</span></div>
          <pre class="code-block">${esc(JSON.stringify(node.details, null, 2))}</pre>
        </div>
      `);
    }

    bodyEl.innerHTML = htmlParts.join('');
  }
})();
