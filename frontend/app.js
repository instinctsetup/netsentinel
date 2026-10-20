// netsentinel dashboard: WebSocket-driven feed, inspector, chart, experiments tab.
const $ = (s) => document.querySelector(s);
const packetsBody = $('#packets tbody');
const flowsBody = $('#flows tbody');
const alertList = $('#alert-list');
let selectedId = null;

/* ---------------- tabs ---------------- */
document.querySelectorAll('.tab').forEach(t => t.onclick = () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
  document.querySelectorAll('.tabpage').forEach(p => p.classList.toggle('active', p.id === 'tab-' + t.dataset.tab));
  if (t.dataset.tab === 'experiments') loadExperiments();
});

/* ---------------- scenario console ---------------- */
document.querySelectorAll('button[data-scenario]').forEach(btn => {
  btn.onclick = async () => {
    btn.disabled = true;
    try { await fetch(`/api/scenario/${btn.dataset.scenario}`, {method: 'POST'}); }
    finally { setTimeout(() => btn.disabled = false, 600); }
  };
});

/* ---------------- packet feed ---------------- */
function describe(pkt) {
  const l4 = pkt.tcp || pkt.udp || {};
  let info = '';
  if (pkt.tcp) info = pkt.tcp.flags.join('+');
  else if (pkt.dns) info = pkt.dns.name;
  else if (pkt.icmp) info = pkt.icmp.type_name;
  return {
    proto: pkt.app || pkt.ip.protocol_name,
    cls: pkt.tcp ? (pkt.tcp.flags.includes('SYN') && !pkt.tcp.flags.includes('ACK') ? 'tcp syn' : 'tcp')
               : (pkt.dns ? 'udp dnsrow' : (pkt.icmp ? 'icmp' : 'udp')),
    src: `${pkt.ip.src}:${l4.src_port ?? ''}`,
    dst: `${pkt.ip.dst}:${l4.dst_port ?? ''}`,
    info, len: pkt.ip.total_len
  };
}

function addPacket(pkt, id, t) {
  const d = describe(pkt);
  const tr = document.createElement('tr');
  tr.className = d.cls;
  tr.dataset.pid = id;
  const time = new Date(t * 1000).toTimeString().slice(0, 8);
  tr.innerHTML = `<td>${time}</td><td>${esc(d.proto)}</td><td>${esc(d.src)}</td><td>${esc(d.dst)}</td><td>${esc(d.info)}</td><td>${esc(d.len)}</td>`;
  tr.onclick = () => selectPacket(id, tr);
  packetsBody.prepend(tr);
  while (packetsBody.rows.length > 60) packetsBody.deleteRow(-1);
}

async function selectPacket(id, tr) {
  document.querySelectorAll('#packets tr.sel').forEach(r => r.classList.remove('sel'));
  tr.classList.add('sel');
  selectedId = id;
  const r = await fetch(`/api/packet/${id}`);
  const p = await r.json();
  renderInspector(p);
}

/* ---------------- inspector ---------------- */
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function kv(k, v) { return `<div class="frow"><span class="fk">${esc(k)}</span><span class="fv">${esc(v)}</span></div>`; }

function renderInspector(p) {
  if (p.error) { $('#insp-sub').textContent = p.error; return; }
  $('#inspector-empty').classList.add('hidden');
  $('#inspector').classList.remove('hidden');
  $('#insp-sub').textContent = `packet #${p.id} · ${p.ip.protocol_name} · ${p.ip.total_len} bytes on the wire`;
  let html = `<div class="fieldgroup ip"><h4>IPv4 header</h4>` +
    kv('source', p.ip.src) + kv('destination', p.ip.dst) + kv('protocol', `${p.ip.protocol} (${p.ip.protocol_name})`) +
    kv('total length', p.ip.total_len) + kv('TTL', p.ip.ttl) + kv('id', p.ip.id) +
    kv('header checksum', '0x' + p.ip.checksum.toString(16)) + `</div>`;
  if (p.tcp) {
    html += `<div class="fieldgroup tcp"><h4>TCP segment</h4>` +
      kv('src port', p.tcp.src_port) + kv('dst port', p.tcp.dst_port) +
      kv('seq', p.tcp.seq) + kv('ack', p.tcp.ack) +
      kv('flags', p.tcp.flags.join(' | ') || '(none)') + kv('window', p.tcp.window) +
      kv('payload', (p.payload_len || 0) + ' bytes') + `</div>`;
  }
  if (p.udp) {
    html += `<div class="fieldgroup udp"><h4>UDP datagram</h4>` +
      kv('src port', p.udp.src_port) + kv('dst port', p.udp.dst_port) +
      kv('length', p.udp.length) + `</div>`;
  }
  if (p.icmp) {
    html += `<div class="fieldgroup icmp"><h4>ICMP message</h4>` +
      kv('type', `${p.icmp.type} (${p.icmp.type_name})`) + kv('code', p.icmp.code) +
      (p.icmp.id !== undefined ? kv('id', p.icmp.id) + kv('seq', p.icmp.seq) : '') + `</div>`;
  }
  if (p.dns) {
    html += `<div class="fieldgroup dns"><h4>DNS query</h4>` +
      kv('name', p.dns.name) + kv('id', '0x' + p.dns.id.toString(16)) + `</div>`;
  }
  $('#insp-fields').innerHTML = html;
  $('#insp-hex').innerHTML = hexdump(p.raw || '');
}

function hexdump(hex) {
  const bytes = hex.match(/../g) || [];
  let out = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const chunk = bytes.slice(off, off + 16);
    const hexpart = chunk.map((b, i) => `<span class="hx">${b}</span>${i === 7 ? '  ' : ' '}`).join('');
    const asc = chunk.map(b => {
      const c = parseInt(b, 16);
      return (c >= 32 && c < 127) ? String.fromCharCode(c) : '·';
    }).join('');
    out.push(`${off.toString(16).padStart(4, '0')}  ${hexpart.padEnd(60, ' ')} <span class="asc">${asc}</span>`);
  }
  return out.join('\n');
}

/* ---------------- alerts / ml ---------------- */
function addAlert(alert) {
  const quiet = alertList.querySelector('.quiet');
  if (quiet) quiet.remove();
  const li = document.createElement('li');
  if (alert.severity === 'medium') li.className = 'medium';
  li.innerHTML = `<span class="kind">[${esc(alert.kind)}]</span>${esc(alert.why)} <span class="hint">${esc(alert.t)}</span>`;
  alertList.prepend(li);
  $('#stat-alerts').textContent = alertList.children.length;
}

function setMl(msg) {
  if (msg.probability === null) return;
  $('#ml-bar').style.width = `${msg.probability * 100}%`;
  $('#ml-prob').textContent = msg.probability.toFixed(3);
  $('#ml-verdict').textContent = msg.verdict;
}

/* ---------------- flows ---------------- */
async function refreshFlows() {
  const r = await fetch('/api/flows');
  const data = await r.json();
  $('#stat-halfopen').textContent = data.half_open;
  $('#stat-flows').textContent = data.flows.length;
  flowsBody.innerHTML = '';
  for (const f of data.flows.slice(0, 18)) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${esc(f.src)}</td><td>${esc(f.dst)}</td><td>${esc(f.proto)}</td><td>${esc(f.packets)}</td>` +
                   `<td><span class="state ${f.state}">${f.state}</span></td>`;
    flowsBody.appendChild(tr);
  }
}

/* ---------------- chart ---------------- */
const chart = $('#chart');
const ctx = chart.getContext('2d');
let history = [];

function drawChart() {
  const w = chart.width = chart.clientWidth * devicePixelRatio;
  const h = chart.height = 90 * devicePixelRatio;
  ctx.clearRect(0, 0, w, h);
  if (!history.length) return;
  const max = Math.max(10, ...history.map(x => x.count));
  const barW = w / 180;
  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, '#58a6ff'); grad.addColorStop(1, '#1c2f4a');
  ctx.fillStyle = grad;
  history.forEach((s, i) => {
    const bh = (s.count / max) * (h - 6 * devicePixelRatio);
    ctx.fillRect(w - (history.length - i) * barW, h - bh, Math.max(1, barW - 1), bh);
  });
  ctx.fillStyle = '#8b949e'; ctx.font = `${10 * devicePixelRatio}px sans-serif`;
  ctx.fillText(`${max}/s`, 4 * devicePixelRatio, 12 * devicePixelRatio);
}

/* ---------------- stats + websocket ---------------- */
function setStats(s) {
  $('#stat-rate').textContent = s.rate;
  $('#stat-total').textContent = s.total_packets;
  history = s.history; drawChart();
}

function connect() {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  ws.onopen = () => { $('#ws-dot').classList.add('on'); $('#ws-label').textContent = 'live'; };
  ws.onclose = () => { $('#ws-dot').classList.remove('on'); $('#ws-label').textContent = 'reconnecting…'; setTimeout(connect, 1500); };
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.kind === 'packet') { addPacket(msg.pkt, msg.id, msg.t); refreshFlows(); }
    else if (msg.kind === 'alert') addAlert(msg.alert);
    else if (msg.kind === 'ml') setMl(msg);
    else if (msg.kind === 'stats') setStats(msg);
  };
}
connect();
setInterval(refreshFlows, 3000);
refreshFlows();
fetch('/api/stats').then(r => r.json()).then(setStats);
// initial state: alerts and ML verdict from before this page loaded
fetch('/api/alerts').then(r => r.json()).then(d => {
  for (const alert of d.alerts.slice().reverse()) addAlert(alert);
});
fetch('/api/ml').then(r => r.json()).then(d => setMl(d));

/* ---------------- experiments tab ---------------- */
let expLoaded = false;
async function loadExperiments() {
  if (expLoaded) return;
  const r = await fetch('/api/experiments');
  const data = await r.json();
  if (!data.latest) { $('#exp-empty').classList.remove('hidden'); return; }
  expLoaded = true;
  const e = data.latest;
  $('#exp-empty').classList.add('hidden');
  $('#exp-body').classList.remove('hidden');
  $('#exp-meta').textContent =
    `run ${e.run_id} · git ${e.git} · ${e.windows} windows · ${e.samples_per_class}/class · took ${e.duration_s}s · ${data.runs} run(s) logged`;
  const pct = (x) => (x === null || x === undefined) ? 'n/a' : (x * 100).toFixed(1) + '%';
  $('#exp-h2h').innerHTML =
    `<tr><th></th><th>precision</th><th>recall</th><th>F1</th><th>AUC</th></tr>` +
    `<tr><td>rule detectors</td><td>${pct(e.rules_vs_ml.rules.precision)}</td><td>${pct(e.rules_vs_ml.rules.recall)}</td><td>${pct(e.rules_vs_ml.rules.f1)}</td><td>—</td></tr>` +
    `<tr><td>ML add-on</td><td>${pct(e.rules_vs_ml.ml.precision)}</td><td>${pct(e.rules_vs_ml.ml.recall)}</td><td>${pct(e.rules_vs_ml.ml.f1)}</td><td>${pct(e.rules_vs_ml.ml.auc)}</td></tr>`;
  $('#exp-cv').innerHTML =
    `<tr><th>k</th><th>F1</th><th>AUC</th></tr>` +
    `<tr><td>${e.kfold_cv.k}</td><td>${pct(e.kfold_cv.f1_mean)} ± ${(e.kfold_cv.f1_std * 100).toFixed(1)}</td>` +
    `<td>${e.kfold_cv.auc_mean === null ? 'n/a' : pct(e.kfold_cv.auc_mean) + ' ± ' + (e.kfold_cv.auc_std * 100).toFixed(1)}</td></tr>`;
}
