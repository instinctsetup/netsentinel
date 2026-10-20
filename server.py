"""netsentinel web server: attack console + live packet dashboard + experiments API.

Run:  uvicorn server:app --port 8000    then open http://localhost:8000
"""
import asyncio
import collections
import json
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from netsentinel import detectors, flows, generator, ml_data, stack as stack_mod

app = FastAPI(title="netsentinel")
FRONTEND = Path(__file__).parent / "frontend"
MODEL_PATH = Path(__file__).parent / "netsentinel" / "window_model.json"
EXPERIMENTS_FILE = Path(__file__).parent / "docs" / "experiments" / "results.json"

# Live state
TABLE = flows.FlowTable(window_s=ml_data.WINDOW_S)
LISTENERS: list[WebSocket] = []
ALERTS: list[dict] = []
STARTED_AT = time.time()
ML: detectors.WindowClassifier | None = None
if MODEL_PATH.exists():
    ML = detectors.WindowClassifier.from_json(json.loads(MODEL_PATH.read_text()))

PACKETS_SINCE_EVAL = 0
LAST_ML = {"probability": None, "verdict": "no model yet"}

# Rolling throughput history: per-second packet counts for the last 180s
RATE_HISTORY: collections.deque = collections.deque(maxlen=180)
_CURRENT_SECOND = {"t": int(time.time()), "count": 0, "bytes": 0}
TOTALS = {"packets": 0, "bytes": 0}
RECENT_PACKETS: collections.deque = collections.deque(maxlen=200)  # for the inspector


def broadcast(event: dict):
    for ws in list(LISTENERS):
        try:
            task = asyncio.get_event_loop().create_task(ws.send_json(event))
        except Exception:
            if ws in LISTENERS:
                LISTENERS.remove(ws)
            continue

        def _cleanup(t: asyncio.Task, ws: WebSocket = ws):
            if t.exception() is not None and ws in LISTENERS:
                LISTENERS.remove(ws)

        task.add_done_callback(_cleanup)


def on_packet(pkt: dict):
    """Every packet the generator emits lands here: assemble, detect, stream."""
    global PACKETS_SINCE_EVAL, LAST_ML
    now = time.time()
    flow = TABLE.update(pkt)
    TOTALS["packets"] += 1
    TOTALS["bytes"] += pkt["ip"]["total_len"]
    sec = int(now)
    if sec != _CURRENT_SECOND["t"]:
        RATE_HISTORY.append(dict(_CURRENT_SECOND))
        _CURRENT_SECOND.update({"t": sec, "count": 0, "bytes": 0})
    _CURRENT_SECOND["count"] += 1
    _CURRENT_SECOND["bytes"] += pkt["ip"]["total_len"]
    slim = {k: v for k, v in pkt.items() if k != "raw"}
    RECENT_PACKETS.appendleft({"id": TOTALS["packets"], "t": now, **pkt})
    broadcast({"kind": "packet", "pkt": slim, "flow_state": flow["state"], "id": TOTALS["packets"], "t": now})
    PACKETS_SINCE_EVAL += 1
    if PACKETS_SINCE_EVAL >= 4:           # re-evaluate detectors every few packets
        PACKETS_SINCE_EVAL = 0
        evaluate_window()


def evaluate_window():
    """Run rule-based + ML detectors over the current traffic window."""
    global LAST_ML
    feats = detectors.window_features(TABLE.window_packets())
    for alert in detectors.rule_alerts(feats, TABLE.half_open()):
        alert = {"id": uuid.uuid4().hex[:6], "t": time.strftime("%H:%M:%S"), **alert}
        if not any(a["kind"] == alert["kind"] for a in ALERTS[-3:]):
            ALERTS.append(alert)
            broadcast({"kind": "alert", "alert": alert})
    if ML is not None:
        prob = ML.predict_proba(feats)
        LAST_ML = {"probability": round(prob, 3),
                   "verdict": "attack-like window" if prob > 0.5 else "benign-like window"}
        broadcast({"kind": "ml", **LAST_ML})


async def stats_ticker():
    """Push a stats heartbeat once a second so the chart is live."""
    while True:
        await asyncio.sleep(1.0)
        if LISTENERS:
            broadcast({"kind": "stats", **_stats_payload()})


def _stats_payload():
    now = int(time.time())
    hist = list(RATE_HISTORY) + [dict(_CURRENT_SECOND)]
    hist = [h for h in hist if h["t"] > now - 180]
    return {"uptime_s": int(time.time() - STARTED_AT),
            "total_packets": TOTALS["packets"], "total_bytes": TOTALS["bytes"],
            "rate": _CURRENT_SECOND["count"], "history": hist,
            "flows": len(TABLE.flows), "half_open": TABLE.half_open(),
            "alerts": len(ALERTS), "ml_loaded": ML is not None}


@app.on_event("startup")
async def startup():
    global SERVICES
    SERVICES = generator.LabServices()
    SERVICES.serve_forever()
    asyncio.get_event_loop().create_task(stats_ticker())


@app.on_event("shutdown")
async def shutdown():
    services = globals().get("SERVICES")
    if services is not None:
        services.close()


@app.get("/api/health")
def health():
    return {"status": "ok", "ml_loaded": ML is not None}


SCENARIOS = {
    "browse": "normal web + dns browsing",
    "port_scan": "TCP port scan - real connect() attempts across ports 1-100",
    "syn_flood": "SYN flood - 150 crafted SYNs from spoofed sources",
    "dns_tunnel": "DNS tunnelling - a secret exfiltrated inside query labels",
    "ping_sweep": "ICMP ping sweep - subnet discovery across 10.0.2.0/24",
    "udp_flood": "UDP flood - 200 datagrams blasted at one service port",
}


@app.get("/api/scenarios")
def scenarios():
    return SCENARIOS


@app.post("/api/scenario/{name}")
async def run_scenario(name: str):
    if name not in SCENARIOS:
        return {"error": f"unknown scenario; try {list(SCENARIOS)}"}
    st = stack_mod.VirtualStack(on_packet)

    async def job():
        if name == "browse":
            for _ in range(3):
                await generator.normal_web_session(st, SERVICES, path=f"/page{_}")
                await generator.normal_dns_lookup(st, SERVICES)
        elif name == "port_scan":
            await generator.port_scan(st, SERVICES, ports=list(range(1, 101)))
        elif name == "syn_flood":
            await generator.syn_flood(st, SERVICES, count=150)
        elif name == "dns_tunnel":
            await generator.dns_tunnel(st, SERVICES,
                                       secret=b"project deadline moved to friday, exfiltrated via dns")
        elif name == "ping_sweep":
            await generator.ping_sweep(st, SERVICES)
        elif name == "udp_flood":
            await generator.udp_flood(st, SERVICES, count=200)
        evaluate_window()   # catch short scenarios that emit few packets
        broadcast({"kind": "scenario_done", "name": name})

    asyncio.get_event_loop().create_task(job())
    return {"started": name}


@app.get("/api/stats")
def get_stats():
    return _stats_payload()


@app.get("/api/flows")
def get_flows():
    out = []
    for f in sorted(TABLE.flows.values(), key=lambda x: -x["last"])[:50]:
        out.append({"src": f"{f['client'][0]}:{f['client'][1]}", "dst": f"{f['server'][0]}:{f['server'][1]}",
                    "proto": f["key"][2], "app": f["app"], "packets": f["packets"],
                    "bytes": f["bytes"], "state": f["state"]})
    return {"flows": out, "half_open": TABLE.half_open()}


@app.get("/api/alerts")
def get_alerts():
    return {"alerts": ALERTS[-20:]}


@app.get("/api/ml")
def get_ml():
    return {"model_loaded": ML is not None, "feature_order": detectors.FEATURE_ORDER, **LAST_ML}


@app.get("/api/packet/{packet_id}")
def get_packet(packet_id: int):
    """Full decode + raw wire bytes of one captured packet, for the inspector."""
    for p in RECENT_PACKETS:
        if p["id"] == packet_id:
            return p
    return {"error": "packet scrolled out of the capture buffer (keeps last 200)"}


@app.get("/api/experiments")
def get_experiments():
    """The latest logged experiment run - real numbers, never hard-coded."""
    if not EXPERIMENTS_FILE.exists():
        return {"runs": 0, "latest": None}
    history = json.loads(EXPERIMENTS_FILE.read_text())
    return {"runs": len(history), "latest": history[-1] if history else None}


@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    LISTENERS.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in LISTENERS:
            LISTENERS.remove(websocket)


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")

app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
CHARTS_DIR = Path(__file__).parent / "docs" / "experiments" / "charts"
CHARTS_DIR.mkdir(parents=True, exist_ok=True)   # exists only after run_experiments.py has run
app.mount("/charts", StaticFiles(directory=CHARTS_DIR), name="charts")
