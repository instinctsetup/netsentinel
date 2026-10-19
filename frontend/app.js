// netsentinel dashboard: WebSocket-driven live packet feed, flow table, alerts.
const packetsBody = document.querySelector('#packets tbody');
const flowsBody = document.querySelector('#flows tbody');
const alertList = document.querySelector('#alert-list');
const mlBar = document.querySelector('#ml-bar');
const mlVerdict = document.querySelector('#ml-verdict');
const halfOpen = document.querySelector('#half-open');

document.querySelectorAll('button[data-scenario]').forEach(btn => {
  btn.onclick = async () => {
    btn.disabled = true;
    try { await fetch(`/api/scenario/${btn.dataset.scenario}`, {method: 'POST'}); }
    finally { setTimeout(() => btn.disabled = false, 800); }
  };
});

function describe(pkt) {
  const proto = pkt.ip.protocol_name;
  const l4 = pkt.tcp || pkt.udp || {};
  const flagText = pkt.tcp ? pkt.tcp.flags.join('+') : (pkt.dns ? pkt.dns.name : '');
  return {
    proto: pkt.app || proto,
    cls: pkt.tcp ? (pkt.tcp.flags.includes('SYN') && !pkt.tcp.flags.includes('ACK') ? 'tcp syn' : 'tcp')
                 : (pkt.dns ? 'udp dnsrow' : 'udp'),
    src: `${pkt.ip.src}:${l4.src_port ?? ''}`,
    dst: `${pkt.ip.dst}:${l4.dst_port ?? ''}`,
    info: flagText,
    len: pkt.ip.total_len
  };
}

function addPacket(pkt) {
  const d = describe(pkt);
  const tr = document.createElement('tr');
  tr.className = d.cls;
  tr.innerHTML = `<td>${d.proto}</td><td>${d.src}</td><td>${d.dst}</td><td>${d.info}</td><td>${d.len}</td>`;
  packetsBody.prepend(tr);
  while (packetsBody.rows.length > 60) packetsBody.deleteRow(-1);
}

function addAlert(alert) {
  const quiet = alertList.querySelector('.quiet');
  if (quiet) quiet.remove();
  const li = document.createElement('li');
  li.innerHTML = `<span class="kind">[${alert.kind}]</span>${alert.why} <span class="hint">${alert.t}</span>`;
  alertList.prepend(li);
}

async function refreshFlows() {
  const r = await fetch('/api/flows');
  const data = await r.json();
  halfOpen.textContent = data.half_open;
  flowsBody.innerHTML = '';
  for (const f of data.flows.slice(0, 15)) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${f.src}</td><td>${f.dst}</td><td>${f.proto}</td><td>${f.packets}</td><td>${f.state}</td>`;
    flowsBody.appendChild(tr);
  }
}

const ws = new WebSocket(`ws://${location.host}/ws`);
ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.kind === 'packet') { addPacket(msg.pkt); refreshFlows(); }
  else if (msg.kind === 'alert') addAlert(msg.alert);
  else if (msg.kind === 'ml' && msg.probability !== null) {
    mlBar.style.width = `${msg.probability * 100}%`;
    mlVerdict.textContent = `P(attack-like window) = ${msg.probability} -> ${msg.verdict}`;
  }
};
setInterval(refreshFlows, 3000);
refreshFlows();
