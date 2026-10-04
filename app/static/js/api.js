// Local API client. The server binds to loopback only; nothing leaves this machine.
export async function api(path, body) {
  const res = await fetch('/api/' + path, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  let data;
  try { data = await res.json(); } catch { throw new Error(`Unexpected response (${res.status})`); }
  if (!res.ok) {
    // Multi-analyst mode: an expired session or a pending password change sends the shell back to sign-in.
    if (data.auth || data.must_change) document.dispatchEvent(new CustomEvent('sw:auth', { detail: data }));
    throw new Error(data.error || `Request failed (${res.status})`);
  }
  return data;
}

export const store = {
  boot: null,
  session: { mode: 'single', analyst: null },  // multi-analyst identity, from /api/session
  runs: new Map(),   // id -> full sealed report
  maps: new Map(),   // id -> embedding projection
  current: null,     // selected run id
  job: null,         // { id, kind, cursor, feed[] }
  async bootstrap() { this.boot = await api('bootstrap'); if (!this.current && this.boot.runs.length) this.current = this.preferred(); return this.boot; },
  preferred() {
    const runs = this.boot.runs.filter(r => r.engine === 'shockwave-1.1');
    return (runs.find(r => r.fixture.startsWith('lab-')) || runs[0] || this.boot.runs[0])?.id;
  },
  async run(id = this.current) {
    if (!id) return null;
    if (!this.runs.has(id)) this.runs.set(id, await api('runs/' + id));
    return this.runs.get(id);
  },
  async map(id = this.current) {
    if (!id) return null;
    if (!this.maps.has(id)) this.maps.set(id, await api('embedding/' + id).catch(() => ({ available: false })));
    return this.maps.get(id);
  },
};

// Poll a job, delivering only new live-feed items to onUpdate.
export function follow(jobId, onUpdate, interval = 900) {
  let cursor = 0, stopped = false, timer;
  const tick = async () => {
    if (stopped) return;
    try {
      const j = await api(`jobs/${jobId}?since=${cursor}`);
      cursor = j.cursor;
      onUpdate(j);
      if (j.complete || j.error) return;
    } catch (e) { onUpdate({ error: e.message, transient: true }); }
    timer = setTimeout(tick, interval);
  };
  tick();
  return () => { stopped = true; clearTimeout(timer); };
}
