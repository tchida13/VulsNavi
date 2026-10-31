/**
 * static/js/graph3d.js
 * Three.js 3D Interactive Topology Map + 2D Floating Labels for vulnavi
 * (No laser effects — clean 3D structural visualization of Corporate Systems, Libraries, and Alerts)
 */

(function (global) {
  'use strict';

  const PALETTE = {
    DANGER: 0xff2a6d,    // Vulnerable / Confirmed threat (#ff2a6d)
    WARNING: 0xffb800,   // Unused library / Warning (#ffb800)
    MUTED: 0x64748b,     // False alarm / SNS hoax (#64748b)
    SAFE: 0x00ff9d,      // Patched / Safe / Mitigated (#00ff9d)
    CYAN: 0x00f3ff,      // Removed / Isolated / Info (#00f3ff)
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
      s.includes('DEbUNK') ||
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
    constructor(mountEl, labelsLayerEl, onNodeSelect) {
      this.mountEl = mountEl;
      this.labelsLayerEl = labelsLayerEl;
      this.onNodeSelect = onNodeSelect || function () {};

      this.mode = 'before'; // 'before' | 'after'
      this.autoRotate = true;
      this.selectedNodeId = null;

      this.graphData = { nodes: [], links: [] };
      this.nodeRecords = []; // { data, pos: {x,y,z}, mesh, wireMesh, labelEl }
      this.linkRecords = []; // { data, line, sourceRec, targetRec }

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
      this.camera = new THREE.PerspectiveCamera(48, width / height, 0.1, 1000);
      this.camera.position.set(0, 32, 68);

      this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      this.renderer.setSize(width, height);
      this.renderer.setPixelRatio(Math.min(global.devicePixelRatio || 1, 2));
      const existingCanvas = this.mountEl.querySelector('canvas');
      if (existingCanvas) existingCanvas.remove();
      this.mountEl.insertBefore(this.renderer.domElement, this.labelsLayerEl || null);

      // OrbitControls if loaded
      if (typeof THREE.OrbitControls === 'function') {
        this.controls = new THREE.OrbitControls(this.camera, this.renderer.domElement);
        this.controls.enableDamping = true;
        this.controls.dampingFactor = 0.06;
        this.controls.maxDistance = 140;
        this.controls.minDistance = 18;
        this.controls.autoRotate = this.autoRotate;
        this.controls.autoRotateSpeed = 0.65;
      }

      // Lighting
      const ambientLight = new THREE.AmbientLight(0xffffff, 0.78);
      this.scene.add(ambientLight);

      const topLight = new THREE.PointLight(0x00f3ff, 1.3, 220);
      topLight.position.set(25, 55, 35);
      this.scene.add(topLight);

      const bottomLight = new THREE.PointLight(0x00ff9d, 0.8, 200);
      bottomLight.position.set(-30, -35, -25);
      this.scene.add(bottomLight);

      // Base reference rings for Core (Systems), Mid (Libraries), Outer (Alerts)
      this.baseGroup = new THREE.Group();
      this.scene.add(this.baseGroup);
      this.buildReferenceFloor();

      this.nodesGroup = new THREE.Group();
      this.linksGroup = new THREE.Group();
      this.scene.add(this.linksGroup);
      this.scene.add(this.nodesGroup);

      // Raycaster for direct 3D mesh clicks
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
      // 内周(社内システム) と 外周(使用ライブラリ) の2リングで直感的に表示
      const radii = [13, 28];
      radii.forEach((r, idx) => {
        const ringGeo = new THREE.RingGeometry(r - 0.14, r + 0.14, 64);
        const ringMat = new THREE.MeshBasicMaterial({
          color: idx === 0 ? 0x00f3ff : 0x38bdf8,
          side: THREE.DoubleSide,
          transparent: true,
          opacity: 0.28
        });
        const ring = new THREE.Mesh(ringGeo, ringMat);
        ring.rotation.x = Math.PI / 2;
        ring.position.y = -6;
        this.baseGroup.add(ring);
      });

      const gridHelper = new THREE.GridHelper(80, 16, 0x00f3ff, 0x112240);
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
          this.selectNode(rec.data.id);
        }
      }
    }

    computeNodePositions(nodes) {
      const systems = nodes.filter((n) => n.category === 'SYSTEM');
      const libraries = nodes.filter((n) => n.category === 'LIBRARY');

      const posMap = {};

      systems.forEach((node, i) => {
        const angle = (i / Math.max(systems.length, 1)) * Math.PI * 2 + Math.PI / 4;
        const r = 13;
        posMap[node.id] = {
          x: Math.cos(angle) * r,
          y: 2.0,
          z: Math.sin(angle) * r
        };
      });

      libraries.forEach((node, i) => {
        const angle = (i / Math.max(libraries.length, 1)) * Math.PI * 2;
        const r = 28;
        posMap[node.id] = {
          x: Math.cos(angle) * r,
          y: (i % 2 === 0 ? -1.5 : 3.5),
          z: Math.sin(angle) * r
        };
      });

      return posMap;
    }

    setData(graphData) {
      if (!graphData || !Array.isArray(graphData.nodes)) return;
      this.graphData = graphData;
      const posMap = this.computeNodePositions(graphData.nodes);

      // Clear previous labels
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

      // Create Node Records + Meshes + 2D Floating Labels
      graphData.nodes.forEach((node) => {
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
            geo = new THREE.OctahedronGeometry(2.7, 0);
          } else if (node.category === 'LIBRARY') {
            geo = new THREE.SphereGeometry(1.95, 24, 24);
          } else {
            geo = new THREE.OctahedronGeometry(2.1, 1);
          }

          const mat = new THREE.MeshStandardMaterial({
            color: PALETTE.CYAN,
            emissive: PALETTE.CYAN,
            emissiveIntensity: 0.45,
            roughness: 0.25,
            metalness: 0.65
          });

          const mesh = new THREE.Mesh(geo, mat);
          mesh.position.set(pos.x, pos.y, pos.z);
          this.nodesGroup.add(mesh);

          // Outer wireframe shell for visual clarity
          const wireGeo = new THREE.WireframeGeometry(geo);
          const wireMat = new THREE.LineBasicMaterial({
            color: 0xffffff,
            transparent: true,
            opacity: 0.35
          });
          const wireMesh = new THREE.LineSegments(wireGeo, wireMat);
          mesh.add(wireMesh);

          rec.mesh = mesh;
          rec.wireMesh = wireMesh;
        }

        this.nodeRecords.push(rec);
      });

      // Create Link Records
      (graphData.links || []).forEach((link) => {
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
            opacity: 0.55
          });
          line = new THREE.Line(lineGeo, lineMat);
          this.linksGroup.add(line);
        }

        this.linkRecords.push({
          data: link,
          line: line,
          sourceRec: sourceRec,
          targetRec: targetRec
        });
      });

      this.applyModeStyling();

      // Default select first system node if none selected
      if (!this.selectedNodeId && this.nodeRecords.length > 0) {
        const defaultNode =
          this.nodeRecords.find((r) => r.data.id === 'SYS-01') || this.nodeRecords[0];
        this.selectNode(defaultNode.data.id, true);
      } else if (this.selectedNodeId) {
        this.selectNode(this.selectedNodeId, true);
      }
    }

    createFloatingLabelElement(node) {
      const div = document.createElement('div');
      div.className = 'node-float-label';
      div.dataset.nodeId = node.id;
      div.innerHTML = `
        <div class="lbl-top">
          <span class="lbl-dot"></span>
          <span class="lbl-title">${this.escapeHtml(node.label)}</span>
        </div>
        <span class="lbl-sub"></span>
      `;
      div.addEventListener('click', (e) => {
        e.stopPropagation();
        this.selectNode(node.id);
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
            rec.data.id === this.selectedNodeId ? 0.85 : 0.42;
        }

        // Update 2D floating label text & dot color
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
        const sourceNode = lrec.sourceRec.data;
        const targetStatus =
          this.mode === 'after' ? targetNode.status_after : targetNode.status_before;
        const sourceStatus =
          this.mode === 'after' ? sourceNode.status_after : sourceNode.status_before;

        let colorKey = resolveColorKey(targetStatus, this.mode, targetNode.category);
        if (String(sourceStatus).toUpperCase().includes('FALSE')) {
          colorKey = 'MUTED';
        }
        if (lrec.data.relation === 'USES_UNUSED') {
          colorKey = this.mode === 'after' ? 'CYAN' : 'WARNING';
        }

        if (lrec.line) {
          lrec.line.material.color.setHex(PALETTE[colorKey]);
          lrec.line.material.opacity = colorKey === 'MUTED' ? 0.22 : 0.65;
        }
        lrec.colorStr = HEX_STR[colorKey];
      });
    }

    formatStatusText(rawStatus, node) {
      const s = String(rawStatus || '').toUpperCase();
      if (this.mode === 'before') {
        if (s.includes('FALSE')) return 'SNS誤情報 (デマ)';
        if (s.includes('UNUSED')) return '未使用ライブラリ (削除推奨)';
        if (s.includes('VULN') || s.includes('CONFIRM')) return '⚠ 要対応 (脆弱)';
        if (s.includes('SAFE') || s.includes('MITIGAT')) return '✔ 対策済・安全';
      } else {
        if (s.includes('FALSE')) return '排除済 (SNSデマ)';
        if (s.includes('REMOVED') || s.includes('UNUSED')) return '✂ 削除/隔離推奨';
        if (s.includes('MITIGAT') || s.includes('SAFE') || s.includes('PASS')) {
          return node.sublabel ? `✔ ${node.sublabel}` : '✔ パッチ&テストPASS';
        }
      }
      return node.sublabel || rawStatus || '';
    }

    selectNode(nodeId, silentCamera) {
      this.selectedNodeId = nodeId;
      let selectedRec = null;

      this.nodeRecords.forEach((rec) => {
        const isSel = rec.data.id === nodeId;
        if (isSel) selectedRec = rec;
        if (rec.labelEl) {
          rec.labelEl.classList.toggle('is-selected', isSel);
        }
        if (rec.mesh) {
          const scale = isSel ? 1.32 : 1.0;
          rec.mesh.scale.set(scale, scale, scale);
        }
      });

      this.applyModeStyling();

      if (selectedRec && !silentCamera && this.useThree && this.controls) {
        // Nudge camera target subtly toward the selected node while keeping full scene context
        this.controls.target.set(
          selectedRec.pos.x * 0.25,
          selectedRec.pos.y * 0.25,
          selectedRec.pos.z * 0.25
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
        this.camera.position.set(0, 32, 68);
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

      // Gently rotate individual node meshes in place
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
        tempV.y += rec.data.category === 'SYSTEM' ? 3.2 : 2.5;
        tempV.project(this.camera);

        // Hide if behind camera
        if (tempV.z > 1) {
          rec.labelEl.style.display = 'none';
          return;
        }

        const rawX = (tempV.x * 0.5 + 0.5) * width;
        const rawY = (-(tempV.y * 0.5) + 0.5) * height;

        // Clamp within viewport margins so labels never get cut off at edges
        const x = Math.max(85, Math.min(width - 85, rawX));
        const y = Math.max(52, Math.min(height - 16, rawY));

        rec.labelEl.style.display = 'block';
        rec.labelEl.style.left = `${x.toFixed(1)}px`;
        rec.labelEl.style.top = `${y.toFixed(1)}px`;
      });
    }

    /* ---------------- Canvas 2D 3D-Projection Fallback (If CDN Blocked) ---------------- */
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

      // Draw links
      this.linkRecords.forEach((lrec) => {
        const p1 = project(lrec.sourceRec.pos);
        const p2 = project(lrec.targetRec.pos);
        ctx.beginPath();
        ctx.moveTo(p1.x, p1.y);
        ctx.lineTo(p2.x, p2.y);
        ctx.strokeStyle = lrec.colorStr || '#00f3ff';
        ctx.lineWidth = 1.5;
        ctx.stroke();
      });

      // Draw nodes & position floating labels
      this.nodeRecords.forEach((rec) => {
        const p = project(rec.pos);
        const rawStatus =
          this.mode === 'after' ? rec.data.status_after : rec.data.status_before;
        const colorKey = resolveColorKey(rawStatus, this.mode, rec.data.category);
        const color = HEX_STR[colorKey];

        ctx.beginPath();
        ctx.arc(p.x, p.y, (rec.data.category === 'SYSTEM' ? 11 : 8) * p.scale, 0, Math.PI * 2);
        ctx.fillStyle = color;
        ctx.fill();
        ctx.strokeStyle = '#ffffff';
        ctx.lineWidth = rec.data.id === this.selectedNodeId ? 2.5 : 1;
        ctx.stroke();

        if (rec.labelEl) {
          rec.labelEl.style.left = `${p.x.toFixed(1)}px`;
          rec.labelEl.style.top = `${(p.y - 12).toFixed(1)}px`;
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
