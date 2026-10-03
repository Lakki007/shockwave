// Canvas renderers. The point cloud draws the run's real DINOv2 object embeddings
// (server-side PCA); with no assessment it draws an explicitly labelled placeholder sphere.
import { reduced } from './ui.js';

export const CLASS_COLOURS = ['#a8d3b8', '#d9b878', '#8fa6b8', '#c79ab8', '#9cc7c4', '#e3907f', '#b3a3d6', '#c8c493', '#7fb59a', '#d2a487'];
const SEV = { 4: [227, 144, 127], 3: [217, 184, 120], 2: [205, 191, 149], 1: [143, 166, 184] };

function fibonacci(n) {
  const out = [], g = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < n; i++) {
    const y = 1 - (i / Math.max(1, n - 1)) * 2, r = Math.sqrt(1 - y * y), t = g * i;
    out.push([Math.cos(t) * r, y, Math.sin(t) * r]);
  }
  return out;
}

// Keep each point's relative direction while spreading points evenly over the sphere,
// so the morph sphere -> map moves every dot to its own embedding position.
function sphereFor(points) {
  const n = points.length;
  const lat = points.map((p, i) => [Math.atan2(p[1], Math.hypot(p[0], p[2])), i]).sort((a, b) => a[0] - b[0]);
  const out = new Array(n), g = Math.PI * (3 - Math.sqrt(5));
  lat.forEach(([, i], rank) => {
    const y = 1 - (rank / Math.max(1, n - 1)) * 2, r = Math.sqrt(1 - y * y);
    const lon = Math.atan2(points[i][2], points[i][0]) + g * rank * .02;
    out[i] = [Math.cos(lon) * r, y, Math.sin(lon) * r];
  });
  return out;
}

export class PointCloud {
  constructor(canvas, { interactive = false, ring = true, density = 1 } = {}) {
    this.c = canvas; this.ctx = canvas.getContext('2d');
    this.interactive = interactive; this.ring = ring;
    this.morph = 0; this.target = 0; this.glow = 0; this.glowTarget = 0; this.colourBy = 'mono';
    this.yaw = .6; this.pitch = -.25; this.spin = reduced() ? 0 : .0016; this.zoom = 1;
    this.hover = -1; this.focusType = -1;
    this.resize = this.resize.bind(this); this.frame = this.frame.bind(this);
    this.setData(null, density);
    new ResizeObserver(this.resize).observe(canvas); this.resize();
    if (interactive) this.bindPointer();
    this.visible = true;
    if ('IntersectionObserver' in window) new IntersectionObserver(es => { this.visible = es[0].isIntersecting; if (this.visible) this.kick(); }).observe(canvas);
    this.running = false; this.kick();
  }
  setData(map, density = 1) {
    this.map = map?.available ? map : null;
    if (this.map) {
      this.pts = this.map.points.map(p => [p[0], p[1], p[2]]);
      this.meta = this.map.points.map(p => ({ cls: p[3], sev: p[4], img: p[5], type: p[6] }));
      this.sphere = sphereFor(this.pts);
    } else {
      this.sphere = fibonacci(Math.round(1600 * density));
      this.pts = this.sphere; this.meta = this.sphere.map(() => ({ cls: 0, sev: 0, img: -1, type: -1 }));
    }
    this.kick();
  }
  resize() {
    const r = this.c.getBoundingClientRect(), d = Math.min(2, window.devicePixelRatio || 1);
    this.w = r.width; this.h = r.height; this.c.width = r.width * d; this.c.height = r.height * d;
    this.ctx.setTransform(d, 0, 0, d, 0, 0); this.kick();
  }
  kick() { if (!this.running && this.visible !== false) { this.running = true; requestAnimationFrame(this.frame); } }
  bindPointer() {
    let drag = null;
    this.c.addEventListener('pointerdown', e => { drag = { x: e.clientX, y: e.clientY, yaw: this.yaw, pitch: this.pitch, moved: false }; this.c.setPointerCapture(e.pointerId); });
    this.c.addEventListener('pointermove', e => {
      const r = this.c.getBoundingClientRect(); this.mx = e.clientX - r.left; this.my = e.clientY - r.top;
      if (drag) { const dx = e.clientX - drag.x, dy = e.clientY - drag.y; if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true; this.yaw = drag.yaw + dx * .006; this.pitch = Math.max(-1.3, Math.min(1.3, drag.pitch + dy * .006)); }
      this.pick(); this.kick();
    });
    this.c.addEventListener('pointerup', e => { const moved = drag?.moved; drag = null; if (!moved && this.hover >= 0) this.onClick?.(this.hover); });
    this.c.addEventListener('pointerleave', () => { this.mx = null; this.hover = -1; this.onHover?.(-1); });
    this.c.addEventListener('wheel', e => { e.preventDefault(); this.zoom = Math.max(.6, Math.min(2.4, this.zoom * (e.deltaY > 0 ? .92 : 1.08))); this.kick(); }, { passive: false });
  }
  pick() {
    if (this.mx == null || !this.proj) return;
    let best = -1, bd = 81;
    for (let i = 0; i < this.proj.length; i += 1) {
      const p = this.proj[i]; if (!p) continue; const d = (p[0] - this.mx) ** 2 + (p[1] - this.my) ** 2;
      if (d < bd) { bd = d; best = i; }
    }
    if (best !== this.hover) { this.hover = best; this.onHover?.(best, this.proj[best]); }
  }
  colour(i, alpha) {
    const m = this.meta[i];
    if (this.focusType >= 0 && m.type !== this.focusType) return `rgba(150,165,155,${alpha * .25})`;
    if (this.glow > .02 && m.sev) { const c = SEV[m.sev]; const k = this.glow; return `rgba(${c[0]},${c[1]},${c[2]},${alpha * (.35 + .65 * k)})`; }
    if (this.colourBy === 'class' && this.map) { const hex = CLASS_COLOURS[m.cls % CLASS_COLOURS.length]; return hex + Math.round(Math.min(1, alpha) * 255).toString(16).padStart(2, '0'); }
    return `rgba(196,214,203,${alpha * (this.glow > .02 ? .45 : 1)})`;
  }
  frame() {
    this.running = false;
    const { ctx, w, h } = this; if (!w || !h) return;
    this.morph += (this.target - this.morph) * .06; this.glow += (this.glowTarget - this.glow) * .08;
    this.yaw += this.spin;
    ctx.clearRect(0, 0, w, h);
    const cx = w / 2, cy = h / 2, R = Math.min(w, h) * .38 * this.zoom, f = 3.2;
    const cyw = Math.cos(this.yaw), syw = Math.sin(this.yaw), cp = Math.cos(this.pitch), sp = Math.sin(this.pitch);
    // halo
    const g = ctx.createRadialGradient(cx, cy, R * .2, cx, cy, R * 1.25); g.addColorStop(0, 'rgba(168,211,184,.07)'); g.addColorStop(1, 'rgba(168,211,184,0)');
    ctx.fillStyle = g; ctx.fillRect(0, 0, w, h);
    if (this.ring) {
      ctx.save(); ctx.translate(cx, cy); ctx.rotate(-.42); ctx.beginPath(); ctx.ellipse(0, 0, R * 1.24, R * .36, 0, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(226,236,229,.12)'; ctx.lineWidth = 1; ctx.stroke(); ctx.restore();
    }
    const m = this.morph, n = this.pts.length, proj = new Array(n);
    const order = [];
    for (let i = 0; i < n; i++) {
      const s = this.sphere[i], p = this.pts[i];
      let x = s[0] + (p[0] * 1.15 - s[0]) * m, y = s[1] + (p[1] * 1.15 - s[1]) * m, z = s[2] + (p[2] * 1.15 - s[2]) * m;
      const x1 = x * cyw - z * syw, z1 = x * syw + z * cyw, y1 = y * cp - z1 * sp, z2 = y * sp + z1 * cp;
      const k = f / (f + z2), px = cx + x1 * R * k, py = cy + y1 * R * k;
      proj[i] = [px, py, z2, k]; order.push(i);
    }
    order.sort((a, b) => proj[b][2] - proj[a][2]);
    for (const i of order) {
      const [px, py, z, k] = proj[i];
      const depth = (1 - z) / 2, a = .18 + .72 * depth;
      const sev = this.meta[i].sev, lit = this.glow > .02 && sev >= 2;
      const r = (lit ? 1.2 + sev * .45 * this.glow : 1.05) * k * (this.map ? 1.15 : 1);
      if (lit && sev >= 3) { ctx.fillStyle = sev === 4 ? `rgba(227,144,127,${.12 * this.glow})` : `rgba(217,184,120,${.1 * this.glow})`; ctx.beginPath(); ctx.arc(px, py, r * 4, 0, 6.283); ctx.fill(); }
      ctx.fillStyle = this.colour(i, a); ctx.beginPath(); ctx.arc(px, py, r, 0, 6.283); ctx.fill();
    }
    if (this.hover >= 0 && proj[this.hover]) {
      const [px, py] = proj[this.hover]; ctx.strokeStyle = '#a8d3b8'; ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(px, py, 7, 0, 6.283); ctx.stroke();
    }
    this.proj = proj;
    const moving = this.spin || Math.abs(this.target - this.morph) > .002 || Math.abs(this.glowTarget - this.glow) > .002;
    if (moving && this.visible !== false) this.kick();
  }
}

// Live evidence radar: each dot is a finding streamed from the running assessment,
// placed in its claim-domain sector and coloured by severity. Nothing is synthesised.
const DOMAINS = ['data', 'model', 'pipeline', 'records', 'context', 'source', 'loop'];
const CLAIM_DOMAIN = { data_schema: 'data', data_identity: 'data', duplication: 'data', split_integrity: 'data', labels: 'data', poisoning: 'data', source_risk: 'source', model_identity: 'model', safe_intake: 'model', behaviour: 'model', backdoor: 'loop', pipeline: 'pipeline', provenance: 'records', replay: 'records', history: 'records', reproduction: 'records', distribution: 'context', calibration: 'context', audit: 'records' };
const SEVR = { critical: [227, 144, 127, .28], high: [217, 184, 120, .52], medium: [205, 191, 149, .74], low: [143, 166, 184, .9] };

function hash(s) { let h = 2166136261; for (const c of String(s)) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967295; }

export class EvidenceRadar {
  constructor(canvas) {
    this.c = canvas; this.ctx = canvas.getContext('2d'); this.dots = []; this.t = 0; this.active = false;
    new ResizeObserver(() => this.resize()).observe(canvas); this.resize();
    this.frame = this.frame.bind(this); requestAnimationFrame(this.frame);
  }
  resize() { const r = this.c.getBoundingClientRect(), d = Math.min(2, devicePixelRatio || 1); this.w = r.width; this.h = r.height; this.c.width = r.width * d; this.c.height = r.height * d; this.ctx.setTransform(d, 0, 0, d, 0, 0); }
  reset() { this.dots = []; }
  add(f) {
    const dom = CLAIM_DOMAIN[f.claim] || 'data', s = DOMAINS.indexOf(dom), span = Math.PI * 2 / DOMAINS.length;
    const ang = s * span + span * (.12 + .76 * hash(f.id + f.asset)), cfg = SEVR[f.severity] || SEVR.low;
    this.dots.push({ ang, rad: cfg[3] * (.82 + .3 * hash(f.asset)), col: cfg, born: performance.now(), sev: f.severity });
    if (this.dots.length > 2500) this.dots.shift();
  }
  frame(now) {
    if (!this.c.isConnected) return; // view replaced: stop the loop
    const { ctx, w, h } = this; requestAnimationFrame(this.frame);
    if (!w) return;
    ctx.clearRect(0, 0, w, h);
    const cx = w / 2, cy = h / 2 + 6, R = Math.min(w, h) * .42, span = Math.PI * 2 / DOMAINS.length;
    ctx.strokeStyle = 'rgba(226,236,229,.08)'; ctx.lineWidth = 1;
    for (const k of [.28, .52, .74, .98]) { ctx.beginPath(); ctx.arc(cx, cy, R * k, 0, 6.283); ctx.stroke(); }
    ctx.font = '10px "JetBrains Mono", ui-monospace, monospace'; ctx.textAlign = 'center';
    DOMAINS.forEach((d, i) => {
      const a = i * span; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(cx + Math.cos(a) * R, cy + Math.sin(a) * R); ctx.stroke();
      const m = a + span / 2; ctx.fillStyle = 'rgba(154,163,157,.75)'; ctx.fillText(d.toUpperCase(), cx + Math.cos(m) * (R + 2) * .62, cy + Math.sin(m) * (R + 2) * .62 + 3);
    });
    if (this.active && !reduced()) {
      const sweep = (now / 2200) % 1 * 6.283, grad = ctx.createConicGradient ? ctx.createConicGradient(sweep - .9, cx, cy) : null;
      if (grad) { grad.addColorStop(0, 'rgba(168,211,184,0)'); grad.addColorStop(.14, 'rgba(168,211,184,.10)'); grad.addColorStop(.145, 'rgba(168,211,184,0)'); ctx.fillStyle = grad; ctx.beginPath(); ctx.arc(cx, cy, R, 0, 6.283); ctx.fill(); }
    }
    for (const d of this.dots) {
      const age = Math.min(1, (now - d.born) / 700), x = cx + Math.cos(d.ang) * R * d.rad, y = cy + Math.sin(d.ang) * R * d.rad;
      const r = d.sev === 'critical' ? 3.4 : d.sev === 'high' ? 2.6 : 2;
      if (age < 1) { ctx.strokeStyle = `rgba(${d.col[0]},${d.col[1]},${d.col[2]},${1 - age})`; ctx.beginPath(); ctx.arc(x, y, r + 14 * age, 0, 6.283); ctx.stroke(); }
      ctx.fillStyle = `rgba(${d.col[0]},${d.col[1]},${d.col[2]},.9)`; ctx.beginPath(); ctx.arc(x, y, r, 0, 6.283); ctx.fill();
    }
    ctx.fillStyle = 'rgba(168,211,184,.9)'; ctx.beginPath(); ctx.arc(cx, cy, 2.5, 0, 6.283); ctx.fill();
  }
}
