// Records the 80-second autopilot (?demo) with headless Chrome's screencast, then encodes it with ffmpeg.
// Usage: node tools/record_demo.mjs [url] [out.mp4]   (the Shockwave server must already be running)
// No npm dependencies: uses Node's built-in WebSocket and the Chrome DevTools Protocol.
import { spawn, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const URL_ = process.argv[2] || 'http://127.0.0.1:8765/?demo#/overview';
const OUT = resolve(process.argv[3] || 'docs/shockwave-demo.mp4');
const CHROME = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const W = 1440, H = 900, PORT = 9333, FPS = 30, MAX_S = 95;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const dir = mkdtempSync(join(tmpdir(), 'sw-rec-'));
const chrome = spawn(CHROME, ['--headless=new', `--remote-debugging-port=${PORT}`, `--user-data-dir=${join(dir, 'profile')}`, `--window-size=${W},${H}`,
  '--hide-scrollbars', '--no-first-run', '--no-default-browser-check', '--force-device-scale-factor=1', 'about:blank'], { stdio: 'ignore' });

let target;
for (let i = 0; i < 50 && !target; i++) {
  await sleep(200);
  try { target = (await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json()).find(t => t.type === 'page'); } catch { /* not up yet */ }
}
if (!target) { chrome.kill(); throw new Error('Chrome did not expose a debugging target'); }

const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
let id = 0; const pending = new Map(), handlers = {};
ws.onmessage = ({ data }) => { const m = JSON.parse(data); if (m.id) { pending.get(m.id)?.(m); pending.delete(m.id); } else handlers[m.method]?.(m.params); };
const send = (method, params = {}) => new Promise(r => { pending.set(++id, r); ws.send(JSON.stringify({ id, method, params })); });

const frames = [];
handlers['Page.screencastFrame'] = p => {
  const file = join(dir, `f${String(frames.length).padStart(6, '0')}.jpg`);
  writeFileSync(file, Buffer.from(p.data, 'base64'));
  frames.push({ file, t: p.metadata.timestamp });
  send('Page.screencastFrameAck', { sessionId: p.sessionId });
};

await send('Page.enable'); await send('Runtime.enable');
await send('Emulation.setDeviceMetricsOverride', { width: W, height: H, deviceScaleFactor: 1, mobile: false });
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'no-preference' }] });
await send('Network.setCacheDisabled', { cacheDisabled: true }).catch(() => {});
await send('Page.startScreencast', { format: 'jpeg', quality: 92, maxWidth: W, maxHeight: H, everyNthFrame: 1 });
await send('Page.navigate', { url: URL_ });
console.log('Recording', URL_);

const start = Date.now();
for (;;) {
  await sleep(1000);
  const r = await send('Runtime.evaluate', { expression: 'window.__demo && window.__demo.done', returnByValue: true });
  if (r.result?.result?.value === true) break;
  if ((Date.now() - start) / 1000 > MAX_S) { console.warn('Demo did not report completion; stopping at the time limit'); break; }
}
await sleep(1200); // hold the final caption
await send('Page.stopScreencast');
ws.close(); chrome.kill();

// The screencast only emits on change, so each frame is held until the next frame's timestamp.
const list = frames.map((f, i) => `file '${f.file}'\nduration ${Math.max(.001, ((frames[i + 1]?.t ?? f.t + .5) - f.t)).toFixed(4)}`).join('\n') + `\nfile '${frames.at(-1).file}'\n`;
writeFileSync(join(dir, 'frames.txt'), list);
execFileSync('ffmpeg', ['-y', '-hide_banner', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', join(dir, 'frames.txt'),
  '-vf', `fps=${FPS},scale=${W}:${H}:flags=lanczos,format=yuv420p`, '-c:v', 'libx264', '-preset', 'slow', '-crf', '18', '-movflags', '+faststart', OUT], { stdio: 'inherit' });
rmSync(dir, { recursive: true, force: true });
console.log(`Wrote ${OUT} from ${frames.length} frames`);
