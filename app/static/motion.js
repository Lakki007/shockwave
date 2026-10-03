'use strict';
(() => {
  const body = document.body;
  const main = document.getElementById('main');
  const toggle = document.getElementById('motion-toggle');
  const progress = document.getElementById('scroll-progress');
  const back = document.getElementById('back-to-top');
  const canvas = document.getElementById('signal-field');
  const preference = window.matchMedia?.('(prefers-reduced-motion: reduce)');
  let paused = false;
  try { paused = localStorage.getItem('shockwave-motion') === 'paused'; } catch (_) {}
  let active = false, observer, frame = 0, width = 0, height = 0, lastFrame = 0;
  let scrollFrame = 0, scanFrame = 0, previousRoute, pointerCard, pointerFrame = 0;
  let pointer = { x: 0, y: 0 };
  let ctx = null;
  // A missing canvas implementation never affects the assurance workspace.
  try { if (canvas && window.CanvasRenderingContext2D) ctx = canvas.getContext('2d'); } catch (_) {}
  const supportsReveal = typeof window.IntersectionObserver === 'function';
  const selectors = '.page-top,.hero-copy,.hero-art,.assurance-strip,.section-title,.panel,.run-card,.image-card,.steps,.notice,.empty,.timeline-item';

  function expose(element) {
    element.classList.remove('reveal-pending');
    observer?.unobserve(element);
  }

  function scan() {
    if (!active || !supportsReveal) return;
    const siblings = new Map();
    main.querySelectorAll(selectors).forEach(element => {
      if (element.dataset.motionReady) return;
      element.dataset.motionReady = 'true';
      // Child evidence stays visible when its containing panel enters.
      if (element.parentElement?.closest('.panel,.run-card,.image-card')) return;
      const parent = element.parentElement;
      const index = siblings.get(parent) || 0;
      siblings.set(parent, index + 1);
      element.style.setProperty('--reveal-delay', `${Math.min(index * 65, 195)}ms`);
      element.classList.add('reveal', 'reveal-pending');
      observer.observe(element);
    });
  }

  function updateScroll() {
    scrollFrame = 0;
    const y = Math.max(0, window.scrollY || 0);
    const length = Math.max(0, document.documentElement.scrollHeight - window.innerHeight);
    progress?.style.setProperty('--scroll-ratio', String(length ? Math.min(1, y / length) : 0));
    body.classList.toggle('scrolled', y > 18);
    if (back) back.hidden = y < 480;
    const hero = main.querySelector('.hero-art');
    if (hero) hero.style.setProperty('--hero-shift', active && window.innerWidth > 640 ? `${Math.min(32, y * .065)}px` : '0px');
  }

  function queueScroll() {
    if (!scrollFrame) scrollFrame = requestAnimationFrame(updateScroll);
  }

  function fitCanvas() {
    if (!ctx) return;
    width = window.innerWidth;
    height = window.innerHeight;
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    drawField(0);
  }

  function drawField(time) {
    if (!ctx || !width || !height) return;
    ctx.clearRect(0, 0, width, height);
    const phase = active ? time * .000045 : .2;
    // Two streams echo the gold and blue light in the local background asset.
    for (let beam = 0; beam < 6; beam++) {
      const lower = beam > 2, offset = (beam % 3 - 1) * 14;
      const originX = lower ? width * 1.04 : width * .94;
      const originY = lower ? height * 1.07 + offset : -height * .05 + offset;
      const endX = width * .38, endY = height * .59 + offset;
      const controlX = width * .68 + offset, controlY = lower ? height * .68 : height * .45;
      const gradient = ctx.createLinearGradient(originX, originY, endX, endY);
      const rgb = lower ? '142,201,237' : '231,199,152';
      gradient.addColorStop(0, `rgba(${rgb},0)`);
      gradient.addColorStop(.35, `rgba(${rgb},.12)`);
      gradient.addColorStop(1, `rgba(${rgb},0)`);
      ctx.strokeStyle = gradient;
      ctx.lineWidth = .7;
      ctx.beginPath();
      ctx.moveTo(originX, originY);
      ctx.quadraticCurveTo(controlX, controlY, endX, endY);
      ctx.stroke();
      const p = (phase + beam * .161) % 1, q = 1 - p;
      const x = q * q * originX + 2 * q * p * controlX + p * p * endX;
      const y = q * q * originY + 2 * q * p * controlY + p * p * endY;
      const glow = ctx.createRadialGradient(x, y, 0, x, y, 13);
      glow.addColorStop(0, `rgba(${rgb},.42)`);
      glow.addColorStop(.18, `rgba(${rgb},.18)`);
      glow.addColorStop(1, `rgba(${rgb},0)`);
      ctx.fillStyle = glow;
      ctx.fillRect(x - 13, y - 13, 26, 26);
    }
    for (let i = 0; i < 20; i++) {
      const x = ((i * .618034) % 1) * width;
      const y = ((i * .381966 + (active ? time * .000004 : 0)) % 1) * height;
      const alpha = .08 + (Math.sin(time * .0007 + i) + 1) * .05;
      ctx.fillStyle = `rgba(198,222,244,${alpha})`;
      ctx.beginPath(); ctx.arc(x, y, i % 3 === 0 ? 1.1 : .6, 0, Math.PI * 2); ctx.fill();
    }
  }

  function animate(time) {
    if (!active || document.hidden) { frame = 0; return; }
    if (time - lastFrame >= 33) { drawField(time); lastFrame = time; }
    frame = requestAnimationFrame(animate);
  }

  function startField() {
    if (ctx && active && !document.hidden && !frame) frame = requestAnimationFrame(animate);
  }

  function applyPreference() {
    active = !paused && !preference?.matches;
    body.classList.toggle('motion-enabled', active);
    body.classList.toggle('motion-paused', !active);
    if (toggle) {
      toggle.setAttribute('aria-pressed', String(active));
      const label = active ? 'Pause visual motion' : preference?.matches ? 'Motion disabled by reduced-motion preference' : 'Enable visual motion';
      toggle.setAttribute('aria-label', label);
      toggle.title = label;
      toggle.querySelector('span').textContent = active ? 'Motion on' : 'Motion off';
      toggle.disabled = !!preference?.matches;
    }
    if (!active) {
      cancelAnimationFrame(frame); frame = 0;
      observer?.disconnect();
      main.querySelectorAll('.reveal-pending').forEach(expose);
      if (pointerCard) { pointerCard.style.removeProperty('--pointer-x'); pointerCard.style.removeProperty('--pointer-y'); pointerCard = null; }
      drawField(0);
    } else { scan(); startField(); }
    updateScroll();
  }

  if (supportsReveal) observer = new IntersectionObserver(entries => {
    entries.forEach(entry => { if (entry.isIntersecting) expose(entry.target); });
  }, { threshold: .04, rootMargin: '0px 0px -16px 0px' });

  window.ShockwaveMotion = {
    mount(root, route) {
      observer?.disconnect();
      if (previousRoute !== undefined && previousRoute !== route) window.scrollTo({ top: 0, behavior: 'instant' });
      previousRoute = route;
      scan();
      queueScroll();
    }
  };

  if (typeof window.MutationObserver === 'function') new MutationObserver(() => {
    if (!scanFrame) scanFrame = requestAnimationFrame(() => { scanFrame = 0; scan(); queueScroll(); });
  }).observe(main, { childList: true, subtree: true });

  main.addEventListener('focusin', event => {
    let ancestor = event.target;
    while (ancestor && ancestor !== main) { if (ancestor.classList?.contains('reveal-pending')) expose(ancestor); ancestor = ancestor.parentElement; }
  });
  main.addEventListener('pointermove', event => {
    if (!active || event.pointerType === 'touch') return;
    const card = event.target.closest('.panel,.run-card');
    if (!card) return;
    pointerCard = card; pointer = { x: event.clientX, y: event.clientY };
    if (!pointerFrame) pointerFrame = requestAnimationFrame(() => {
      pointerFrame = 0;
      if (!pointerCard?.isConnected || !active) return;
      const rect = pointerCard.getBoundingClientRect();
      pointerCard.style.setProperty('--pointer-x', `${pointer.x - rect.left}px`);
      pointerCard.style.setProperty('--pointer-y', `${pointer.y - rect.top}px`);
    });
  });
  main.addEventListener('click', event => {
    const cue = event.target.closest('[data-scroll-to]');
    if (cue) document.getElementById(cue.dataset.scrollTo)?.scrollIntoView({ behavior: active ? 'smooth' : 'instant', block: 'start' });
  });
  toggle?.addEventListener('click', () => {
    paused = !paused;
    try { localStorage.setItem('shockwave-motion', paused ? 'paused' : 'enabled'); } catch (_) {}
    applyPreference();
  });
  back?.addEventListener('click', () => window.scrollTo({ top: 0, behavior: active ? 'smooth' : 'instant' }));
  preference?.addEventListener('change', applyPreference);
  window.addEventListener('scroll', queueScroll, { passive: true });
  window.addEventListener('resize', () => { fitCanvas(); queueScroll(); }, { passive: true });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) { cancelAnimationFrame(frame); frame = 0; } else startField();
  });
  fitCanvas();
  applyPreference();
})();
