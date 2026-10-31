/**
 * static/js/graph3d.js
 * Three.js 3D Interactive Topology Map + 2D Floating Labels for vulnavi
 *
 * 2段階ドリルダウン構造:
 * 1. トップ画面 (viewScope = 'overview'):
 *    社内システム同士の依存関係（API・バッチ・管理連携）をエッジで表示。
 * 2. システム詳細画面 (viewScope = 'system', focusedSystemId = 'SYS-XX'):
 *    クリックされた社内システムを画面中央(0,0,0)に配置し、そのシステムが利用する
 *    ライブラリ群を周囲に放射状に配置して依存関係（呼び出し箇所・未使用・安全）をエッジで表現。
 */

(function (global) {
  'use strict';

  const PALETTE = {
    DANGER: 0xff2a6d,    // Vulnerable / Confirmed threat (#ff2a6d)
    WARNING: 0xffb800,   // Unused library / Warning (#ffb800)
    MUTED: 0x64748b,     // False alarm / SNS hoax (#64748b)
    SAFE: 0x00ff9d,      // Patched / Safe / Mitigated (#00ff9d)
    CYAN: 0x00f3ff,      // System / Info (#00f3ff)
    GRID: 0x112240
  };

  const HEX_STR = {
    DANGER: '#ff2a6d',
    WARNING: '#ffb800',
    MUTED: '#64748b',
    SAFE: '#00ff9d',
    CYAN: '#00f3ff'
  };

  function resolveColorKey(statusStr, mode, category) {
    const s = String(statusStr || '').toUpperCase();
    if (
      s.includes('FALSE') ||
      s.includes('HOAX') ||
      s.includes('IGNORED') ||
      s.includes('誤情報') ||
      s.includes('デマ')
    ) {
      return 'MUTED';
    }
    if (s.includes('UNUSED') || s.includes('未使用')) {
      return mode === 'after' ? 'CYAN' : 'WARNING';
    }
    if (s.includes('REMOVED') || s.includes('削除')) {
      return 'CYAN';
    }
    if (
      s.includes('VULN') ||
      s.includes('CRIT') ||
      s.includes('HIGH') ||
      s.includes('MED') ||
      s.includes('CONFIRM') ||
      s.includes('DANGER') ||
      s.includes('ACTIVE_VULNERABLE')
    ) {
      return mode === 'after' ? 'SAFE' : 'DANGER';
    }
    if (
      s.includes('SAFE') ||
      s.includes('MITIGAT') ||
      s.includes('PATCH') ||
      s.includes('PASS') ||
      s.includes('OK')
    ) {
      return 'SAFE';
    }
    return category === 'SYSTEM' ? 'CYAN' : 'SAFE';
  }

  class VulnGraph3D {
    constructor(mountEl, labelsLayerEl, onNodeSelect, onScopeChange) {
      this.mountEl = mountEl;
      this.labelsLayerEl = labelsLayerEl;
      this.onNodeSelect = onNodeSelect || function () {};
      this.onScopeChange = onScopeChange || function () {};

      this.mode = 'before'; // 'before' | 'after'
      this.viewScope = 'overview'; // 'overview' (全社システム間依存) | 'system' (選択システム中心のライブラリ依存)
      this.focusedSystemId = null;

      this.autoRotate = true;
      this.selectedNodeId = null;

      this.fullGraphData = { nodes: [], links: [] };
      this.nodeRecords = []; // { data, pos: {x,y,z}, mesh, wireMesh, labelEl }
      this.linkRecords = []; // { data, line, sourceRec, targetRec, edgeLabelEl }

      this.useThree = typeof global.THREE !== 'undefined';
      this.init();
    }

    init() {
      if (this.useThree) {
        this.initThree();
      } else {
        this.initCanvasFallback();
      }
      global.addEventListener('resize', () => this.handleResize());
    }

    initThree() {
      const THREE = global.THREE;
      const width = this.mountEl.clientWidth || 800;
      const height = this.mountEl.clientHeight || 500;

      this.scene = new THREE.Scene();
      this.camera = new THREE.PerspectiveCamera(46, width / height, 0.1, 1000);
      this.camera.position.set(0, 28, 60);

      this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      this.renderer.setSize(width, height);
      this.renderer.setPixelRatio(Math.min(global.devicePixelRatio || 1, 2));
      const existingCanvas = this.mountEl.querySelector('canvas');
      if (existingCanvas) existingCanvas.remove();
      this.mountEl.insertBefore(this.renderer.domElement, this.labelsLayerEl || null);

      if (typeof THREE.OrbitControls === 'function') {
        this.controls = new THREE.OrbitControls(this.camera, this.renderer.domElement);
        this.controls.enableDamping = true;
        this.controls.dampingFactor = 0.06;
        this.controls.maxDistance = 130;
        this.controls.minDistance = 18;
        this.controls.autoRotate = this.autoRotate;
        this.controls.autoRotateSpeed = 0.55;
      }

      const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
      this.scene.add(ambientLight);

      const topLight = new THREE.PointLight(0x00f3ff, 1.35, 220);
      topLight.position.set(25, 55, 35);
      this.scene.add(topLight);

      const bottomLight = new THREE.PointLight(0x00ff9d, 0.8, 200);
      bottomLight.position.set(-30, -35, -25);
      this.scene.add(bottomLight);

      this.baseGroup = new THREE.Group();
      this.scene.add(this.baseGroup);
      this.buildReferenceFloor();

      this.nodesGroup = new THREE.Group();
      this.linksGroup = new THREE.Group();
      this.scene.add(this.linksGroup);
      this.scene.add(this.nodesGroup);

      this.raycaster = new THREE.Raycaster();
      this.mouse = new THREE.Vector2();
      this.renderer.domElement.addEventListener('pointerdown', (e) => {
        this.pointerDownPos = { x: e.clientX, y: e.clientY };
      });
      this.renderer.domElement.addEventListener('pointerup', (e) => {
        if (!this.pointerDownPos) return;
        const dx = Math.abs(e.clientX - this.pointerDownPos.x);
        const dy = Math.abs(e.clientY - this.pointerDownPos.y);
        if (dx < 5 && dy < 5) {
          this.handleCanvasClick(e);
        }
      });

      const animate = () => {
        requestAnimationFrame(animate);
        this.tickThree();
      };
      requestAnimationFrame(animate);
    }

    buildReferenceFloor() {
      const THREE = global.THREE;
      while (this.baseGroup.children.length > 0) {
        this.baseGroup.remove(this.baseGroup.children[0]);
      }

      const radii = this.viewScope === 'overview' ? [18] : [22];
      radii.forEach((r) => {
        const ringGeo = new THREE.RingGeometry(r - 0.16, r + 0.16, 64);
        const ringMat = new THREE.MeshBasicMaterial({
          color: 0x38bdf8,
          side: THREE.DoubleSide,
          transparent: true,
          opacity: 0.32
        });
        const ring = new THREE.Mesh(ringGeo, ringMat);
        ring.rotation.x = Math.PI / 2;
        ring.position.y = -6;
        this.baseGroup.add(ring);
      });

      const gridHelper = new THREE.GridHelper(76, 16, 0x00f3ff, 0x112240);
      gridHelper.position.y = -6.1;
      gridHelper.material.transparent = true;
      gridHelper.material.opacity = 0.2;
      this.baseGroup.add(gridHelper);
    }

    handleCanvasClick(event) {
      if (!this.useThree || !this.renderer) return;
      const rect = this.renderer.domElement.getBoundingClientRect();
      this.mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      this.mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      this.raycaster.setFromCamera(this.mouse, this.camera);
      const meshes = this.nodeRecords.map((r) => r.mesh).filter(Boolean);
      const intersects = this.raycaster.intersectObjects(meshes, false);
      if (intersects.length > 0) {
        const hitMesh = intersects[0].object;
        const rec = this.nodeRecords.find((r) => r.mesh === hitMesh);
        if (rec) {
          this.handleNodeClick(rec.data);
        }
      }
    }

    handleNodeClick(nodeData) {
      // トップ画面(overview)で社内システムがクリックされたら、そのシステムを中心としたライブラリ依存マップへドリルダウン
      if (this.viewScope === 'overview' && nodeData.category === 'SYSTEM') {
        this.drillDownToSystem(nodeData.id);
        return;
      }
      this.selectNode(nodeData.id);
    }

    drillDownToSystem(systemId) {
      this.viewScope = 'system';
      this.focusedSystemId = systemId;
      this.selectedNodeId = systemId;
      if (this.useThree) {
        this.buildReferenceFloor();
      }
      this.rebuildActiveGraph();
      this.resetCamera();
      this.onScopeChange(this.viewScope, this.focusedSystemId);
    }

    showSystemOverview() {
      this.viewScope = 'overview';
      this.focusedSystemId = null;
      this.selectedNodeId = null;
      if (this.useThree) {
        this.buildReferenceFloor();
      }
      this.rebuildActiveGraph();
      this.resetCamera();
      this.onScopeChange(this.viewScope, null);
    }

    getFilteredGraph() {
      const allNodes = this.fullGraphData.nodes || [];
      const allLinks = this.fullGraphData.links || [];

      if (this.viewScope === 'overview' || !this.focusedSystemId) {
        // トップ画面: 社内システム同士の依存関係（SYSTEMノード + SYSTEM_DEPENDENCYエッジ）のみを表示
        const sysNodes = allNodes.filter((n) => n.category === 'SYSTEM');
        const sysLinks = allLinks.filter((l) => l.relation === 'SYSTEM_DEPENDENCY');
        return { nodes: sysNodes, links: sysLinks };
      }

      // システム詳細画面: 選択されたシステムを中心に、そのシステムが利用するライブラリ群と依存エッジを表示
      const sysId = this.focusedSystemId;
      const centerSys = allNodes.find((n) => n.id === sysId);
      const libLinks = allLinks.filter(
        (l) => l.source === sysId && l.relation !== 'SYSTEM_DEPENDENCY'
      );
      const targetLibIds = new Set(libLinks.map((l) => l.target));
      const libNodes = allNodes.filter((n) => targetLibIds.has(n.id));

      return {
        nodes: centerSys ? [centerSys, ...libNodes] : libNodes,
        links: libLinks
      };
    }

    computeNodePositions(nodes) {
      const posMap = {};

      if (this.viewScope === 'overview') {
        // 全社システム一覧モード: 基幹の決済API(SYS-01)をやや中央寄りに、他システムを周囲に立体配置して依存エッジを見やすくする
        const count = Math.max(nodes.length, 1);
        nodes.forEach((node, i) => {
          if (node.id === 'SYS-01') {
            posMap[node.id] = { x: 0, y: 2.5, z: -2 };
          } else {
            const idx = i - 1;
            const totalOuter = Math.max(count - 1, 1);
            const angle = (idx / totalOuter) * Math.PI * 2 + Math.PI / 6;
            const r = 19;
            posMap[node.id] = {
              x: Math.cos(angle) * r,
              y: idx % 2 === 0 ? -1.0 : 2.0,
              z: Math.sin(angle) * r
            };
          }
        });
        return posMap;
      }

      // 個別システム展開モード: 選択されたシステムを原点(0, 1.5, 0)に配置し、利用ライブラリを周囲(r=22)に放射状配置
      const libraries = nodes.filter((n) => n.category === 'LIBRARY');
      nodes.forEach((node) => {
        if (node.category === 'SYSTEM') {
          posMap[node.id] = { x: 0, y: 1.5, z: 0 };
        }
      });

      libraries.forEach((lib, i) => {
        const angle = (i / Math.max(libraries.length, 1)) * Math.PI * 2 + Math.PI / 6;
        const r = 22;
        posMap[lib.id] = {
          x: Math.cos(angle) * r,
          y: i % 2 === 0 ? -1.0 : 2.2,
          z: Math.sin(angle) * r
        };
      });

      return posMap;
    }

    setData(graphData) {
      if (!graphData || !Array.isArray(graphData.nodes)) return;
      this.fullGraphData = graphData;
      this.rebuildActiveGraph();
    }

    rebuildActiveGraph() {
      const activeGraph = this.getFilteredGraph();
      const posMap = this.computeNodePositions(activeGraph.nodes);

      this.labelsLayerEl.innerHTML = '';
      this.nodeRecords = [];
      this.linkRecords = [];

      if (this.useThree) {
        while (this.nodesGroup.children.length > 0) {
          this.nodesGroup.remove(this.nodesGroup.children[0]);
        }
        while (this.linksGroup.children.length > 0) {
          this.linksGroup.remove(this.linksGroup.children[0]);
        }
      }

      const THREE = global.THREE;

      activeGraph.nodes.forEach((node) => {
        const pos = posMap[node.id] || { x: 0, y: 0, z: 0 };
        const labelEl = this.createFloatingLabelElement(node);
        this.labelsLayerEl.appendChild(labelEl);

        const rec = {
          data: node,
          pos: pos,
          mesh: null,
          wireMesh: null,
          labelEl: labelEl
        };

        if (this.useThree) {
          let geo;
          if (node.category === 'SYSTEM') {
            const radius = this.viewScope === 'system' ? 3.5 : 3.1;
            geo = new THREE.OctahedronGeometry(radius, 0);
          } else {
            geo = new THREE.SphereGeometry(2.35, 24, 24);
          }

          const mat = new THREE.MeshStandardMaterial({
            color: PALETTE.CYAN,
            emissive: PALETTE.CYAN,
            emissiveIntensity: 0.48,
            roughness: 0.25,
            metalness: 0.65
          });

          const mesh = new THREE.Mesh(geo, mat);
          mesh.position.set(pos.x, pos.y, pos.z);
          this.nodesGroup.add(mesh);

          const wireGeo = new THREE.WireframeGeometry(geo);
          const wireMat = new THREE.LineBasicMaterial({
            color: 0xffffff,
            transparent: true,
            opacity: 0.38
          });
          const wireMesh = new THREE.LineSegments(wireGeo, wireMat);
          mesh.add(wireMesh);

          rec.mesh = mesh;
          rec.wireMesh = wireMesh;
        }

        this.nodeRecords.push(rec);
      });

      (activeGraph.links || []).forEach((link) => {
        const sourceRec = this.nodeRecords.find((r) => r.data.id === link.source);
        const targetRec = this.nodeRecords.find((r) => r.data.id === link.target);
        if (!sourceRec || !targetRec) return;

        let line = null;
        if (this.useThree) {
          const points = [
            new THREE.Vector3(sourceRec.pos.x, sourceRec.pos.y, sourceRec.pos.z),
            new THREE.Vector3(targetRec.pos.x, targetRec.pos.y, targetRec.pos.z)
          ];
          const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
          const lineMat = new THREE.LineBasicMaterial({
            color: PALETTE.CYAN,
            transparent: true,
            opacity: 0.82
          });
          line = new THREE.Line(lineGeo, lineMat);
          this.linksGroup.add(line);
        }

        const edgeLabelEl = this.createEdgeLabelElement(link);
        this.labelsLayerEl.appendChild(edgeLabelEl);

        this.linkRecords.push({
          data: link,
          line: line,
          sourceRec: sourceRec,
          targetRec: targetRec,
          edgeLabelEl: edgeLabelEl
        });
      });

      this.applyModeStyling();

      if (this.viewScope === 'system' && this.focusedSystemId) {
        const targetId = this.selectedNodeId || this.focusedSystemId;
        this.selectNode(targetId, true);
      }
    }

    createFloatingLabelElement(node) {
      const div = document.createElement('div');
      div.className = 'node-float-label';
      div.dataset.nodeId = node.id;

      const actionHint =
        this.viewScope === 'overview' && node.category === 'SYSTEM'
          ? '<span class="lbl-drill-hint">🔍 クリックでライブラリ依存を展開</span>'
          : '';

      div.innerHTML = `
        <div class="lbl-top">
          <span class="lbl-dot"></span>
          <span class="lbl-title">${this.escapeHtml(node.label)}</span>
        </div>
        <span class="lbl-sub"></span>
        ${actionHint}
      `;
      div.addEventListener('click', (e) => {
        e.stopPropagation();
        this.handleNodeClick(node);
      });
      return div;
    }

    createEdgeLabelElement(link) {
      const div = document.createElement('div');
      div.className = 'edge-float-label';
      const prefix = link.relation === 'SYSTEM_DEPENDENCY' ? '⇄ ' : '🔗 ';
      div.textContent = prefix + (link.label || '');
      div.addEventListener('click', (e) => {
        e.stopPropagation();
        if (this.viewScope === 'overview') {
          this.drillDownToSystem(link.source);
        } else {
          this.selectNode(link.target);
        }
      });
      return div;
    }

    setMode(mode) {
      if (mode !== 'before' && mode !== 'after') return;
      this.mode = mode;
      this.applyModeStyling();
    }

    applyModeStyling() {
      this.nodeRecords.forEach((rec) => {
        const node = rec.data;
        const rawStatus =
          this.mode === 'after' ? node.status_after : node.status_before;
        const colorKey = resolveColorKey(rawStatus, this.mode, node.category);
        const hexNum = PALETTE[colorKey];
        const hexStr = HEX_STR[colorKey];

        if (rec.mesh) {
          rec.mesh.material.color.setHex(hexNum);
          rec.mesh.material.emissive.setHex(hexNum);
          rec.mesh.material.emissiveIntensity =
            rec.data.id === this.selectedNodeId ? 0.85 : 0.45;
        }

        if (rec.labelEl) {
          const dot = rec.labelEl.querySelector('.lbl-dot');
          const sub = rec.labelEl.querySelector('.lbl-sub');
          if (dot) {
            dot.style.background = hexStr;
            dot.style.boxShadow = `0 0 6px ${hexStr}`;
          }
          rec.labelEl.style.borderColor =
            rec.data.id === this.selectedNodeId ? '#ffffff' : hexStr;

          const statusBadgeText = this.formatStatusText(rawStatus, node);
          if (sub) {
            sub.textContent = statusBadgeText;
          }
        }
      });

      this.linkRecords.forEach((lrec) => {
        const targetNode = lrec.targetRec.data;
        const targetStatus =
          this.mode === 'after' ? targetNode.status_after : targetNode.status_before;

        let colorKey = resolveColorKey(targetStatus, this.mode, targetNode.category);
        if (lrec.data.relation === 'SYSTEM_DEPENDENCY') {
          // システム間連携エッジは接続先システムのリスク状態またはシアンで表現
          colorKey =
            this.mode === 'before' && String(targetStatus).includes('VULN')
              ? 'DANGER'
              : 'CYAN';
        } else if (lrec.data.relation === 'USES_UNUSED') {
          colorKey = this.mode === 'after' ? 'CYAN' : 'WARNING';
        }

        if (lrec.line) {
          lrec.line.material.color.setHex(PALETTE[colorKey]);
          lrec.line.material.opacity = 0.85;
        }
        if (lrec.edgeLabelEl) {
          lrec.edgeLabelEl.style.borderColor = HEX_STR[colorKey];
          lrec.edgeLabelEl.style.color = '#f8fafc';
        }
        lrec.colorStr = HEX_STR[colorKey];
      });
    }

    formatStatusText(rawStatus, node) {
      const s = String(rawStatus || '').toUpperCase();
      if (this.mode === 'before') {
        if (s.includes('UNUSED')) return '📦 未使用ライブラリ (削除推奨)';
        if (s.includes('VULN') || s.includes('CONFIRM')) {
          return node.category === 'SYSTEM'
            ? `${node.sublabel} | 🚨 要対応あり`
            : `🚨 要対応 (${node.sublabel})`;
        }
        if (s.includes('SAFE') || s.includes('MITIGAT')) {
          return node.category === 'SYSTEM'
            ? `${node.sublabel} | ✔ 安全`
            : '✔ 対策済・安全';
        }
      } else {
        if (s.includes('REMOVED') || s.includes('UNUSED')) return '✂ 削除/隔離推奨';
        if (s.includes('MITIGAT') || s.includes('SAFE') || s.includes('PASS')) {
          return node.sublabel ? `✔ ${node.sublabel}` : '✔ パッチ&テストPASS';
        }
      }
      return node.sublabel || rawStatus || '';
    }

    selectNode(nodeId, silentCamera) {
      // システム一覧モード中に特定のシステムIDが外部(Step2/Step3テーブル等)から指定された場合は自動でそのシステムにドリルダウン
      if (this.viewScope === 'overview' && String(nodeId).startsWith('SYS-')) {
        this.drillDownToSystem(nodeId);
        return;
      }

      this.selectedNodeId = nodeId;
      let selectedRec = null;

      this.nodeRecords.forEach((rec) => {
        const isSel = rec.data.id === nodeId;
        if (isSel) selectedRec = rec;
        if (rec.labelEl) {
          rec.labelEl.classList.toggle('is-selected', isSel);
        }
        if (rec.mesh) {
          const scale = isSel ? 1.28 : 1.0;
          rec.mesh.scale.set(scale, scale, scale);
        }
      });

      this.applyModeStyling();

      if (selectedRec && !silentCamera && this.useThree && this.controls) {
        this.controls.target.set(
          selectedRec.pos.x * 0.2,
          selectedRec.pos.y * 0.2,
          selectedRec.pos.z * 0.2
        );
      }

      if (selectedRec) {
        this.onNodeSelect(selectedRec.data);
      }
    }

    toggleAutoRotate() {
      this.autoRotate = !this.autoRotate;
      if (this.controls) {
        this.controls.autoRotate = this.autoRotate;
      }
      return this.autoRotate;
    }

    resetCamera() {
      if (this.useThree && this.camera) {
        this.camera.position.set(0, 28, 58);
        if (this.controls) {
          this.controls.target.set(0, 0, 0);
          this.controls.update();
        }
      } else {
        this.fallbackAngleY = 0.4;
      }
    }

    tickThree() {
      if (this.controls) {
        this.controls.update();
      } else if (this.autoRotate && this.nodesGroup) {
        this.nodesGroup.rotation.y += 0.0025;
        this.linksGroup.rotation.y += 0.0025;
      }

      this.nodeRecords.forEach((rec) => {
        if (rec.mesh) {
          rec.mesh.rotation.y += 0.008;
        }
      });

      this.renderer.render(this.scene, this.camera);
      this.updateFloatingLabelsThree();
    }

    updateFloatingLabelsThree() {
      const THREE = global.THREE;
      const width = this.mountEl.clientWidth;
      const height = this.mountEl.clientHeight;
      if (!width || !height) return;

      const tempV = new THREE.Vector3();

      this.nodeRecords.forEach((rec) => {
        if (!rec.mesh || !rec.labelEl) return;
        tempV.copy(rec.mesh.position);
        tempV.y += rec.data.category === 'SYSTEM' ? 3.6 : 2.8;
        tempV.project(this.camera);

        if (tempV.z > 1) {
          rec.labelEl.style.display = 'none';
          return;
        }

        const rawX = (tempV.x * 0.5 + 0.5) * width;
        const rawY = (-(tempV.y * 0.5) + 0.5) * height;

        const x = Math.max(95, Math.min(width - 95, rawX));
        const y = Math.max(58, Math.min(height - 18, rawY));

        rec.labelEl.style.display = 'block';
        rec.labelEl.style.left = `${x.toFixed(1)}px`;
        rec.labelEl.style.top = `${y.toFixed(1)}px`;
      });

      // エッジ（依存関係）のラベルを各線の中央に表示
      this.linkRecords.forEach((lrec) => {
        if (!lrec.edgeLabelEl) return;

        tempV.set(
          (lrec.sourceRec.pos.x + lrec.targetRec.pos.x) * 0.5,
          (lrec.sourceRec.pos.y + lrec.targetRec.pos.y) * 0.5 + 0.5,
          (lrec.sourceRec.pos.z + lrec.targetRec.pos.z) * 0.5
        );
        tempV.project(this.camera);

        if (tempV.z > 1) {
          lrec.edgeLabelEl.style.display = 'none';
          return;
        }

        const ex = Math.max(80, Math.min(width - 80, (tempV.x * 0.5 + 0.5) * width));
        const ey = Math.max(40, Math.min(height - 20, (-(tempV.y * 0.5) + 0.5) * height));

        lrec.edgeLabelEl.style.display = 'block';
        lrec.edgeLabelEl.style.left = `${ex.toFixed(1)}px`;
        lrec.edgeLabelEl.style.top = `${ey.toFixed(1)}px`;
      });
    }

    /* ---------------- Canvas 2D Fallback ---------------- */
    initCanvasFallback() {
      this.canvas = document.createElement('canvas');
      const existingCanvas = this.mountEl.querySelector('canvas');
      if (existingCanvas) existingCanvas.remove();
      this.mountEl.insertBefore(this.canvas, this.labelsLayerEl || null);
      this.ctx = this.canvas.getContext('2d');
      this.fallbackAngleY = 0.4;
      this.isDragging = false;

      this.canvas.addEventListener('pointerdown', (e) => {
        this.isDragging = true;
        this.lastX = e.clientX;
      });
      global.addEventListener('pointerup', () => {
        this.isDragging = false;
      });
      global.addEventListener('pointermove', (e) => {
        if (!this.isDragging) return;
        const dx = e.clientX - this.lastX;
        this.lastX = e.clientX;
        this.fallbackAngleY += dx * 0.008;
      });

      this.handleResize();
      const loop = () => {
        requestAnimationFrame(loop);
        this.tickCanvasFallback();
      };
      requestAnimationFrame(loop);
    }

    tickCanvasFallback() {
      const w = this.canvas.width;
      const h = this.canvas.height;
      const ctx = this.ctx;
      if (!ctx) return;

      if (this.autoRotate && !this.isDragging) {
        this.fallbackAngleY += 0.003;
      }

      ctx.clearRect(0, 0, w, h);
      const cosY = Math.cos(this.fallbackAngleY);
      const sinY = Math.sin(this.fallbackAngleY);

      const project = (pos) => {
        const rx = pos.x * cosY - pos.z * sinY;
        const rz = pos.x * sinY + pos.z * cosY;
        const scale = 420 / (420 + rz * 4 + 120);
        return {
          x: w / 2 + rx * 9.5 * scale,
          y: h / 2 - pos.y * 8 * scale + rz * 2.2 * scale,
          scale: scale
        };
      };

      this.linkRecords.forEach((lrec) => {
        const p1 = project(lrec.sourceRec.pos);
        const p2 = project(lrec.targetRec.pos);
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.strokeStyle = lrec.colorStr || '#00f3ff';
        ctx.lineWidth = 2;
        ctx.stroke();

        if (lrec.edgeLabelEl) {
          lrec.edgeLabelEl.style.left = `${((p1.x + p2.x) * 0.5).toFixed(1)}px`;
          lrec.edgeLabelEl.style.top = `${((p1.y + p2.y) * 0.5).toFixed(1)}px`;
        }
      });

      this.nodeRecords.forEach((rec) => {
        const p = project(rec.pos);
        const rawStatus =
          this.mode === 'after' ? rec.data.status_after : rec.data.status_before;
        const colorKey = resolveColorKey(rawStatus, this.mode, rec.data.category);
        const color = HEX_STR[colorKey];

        ctx.beginPath();
        ctx.arc(p.x, p.y, (rec.data.category === 'SYSTEM' ? 12 : 9) * p.scale, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = rec.data.id === this.selectedNodeId ? 2.5 : 1;
        ctx.stroke();

        if (rec.labelEl) {
          rec.labelEl.style.left = `${p.x.toFixed(1)}px`;
          rec.labelEl.style.top = `${(p.y - 14).toFixed(1)}px`;
        }
      });
    }

    handleResize() {
      const width = this.mountEl.clientWidth || 800;
      const height = this.mountEl.clientHeight || 500;
      if (this.useThree && this.renderer && this.camera) {
        this.camera.aspect = width / height;
        this.camera.updateProjectionMatrix();
        this.renderer.setSize(width, height);
      } else if (this.canvas) {
        this.canvas.width = width;
        this.canvas.height = height;
      }
    }

    escapeHtml(str) {
      return String(str || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }
  }

  global.VulnGraph3D = VulnGraph3D;
})(window);
