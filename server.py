"""netsentinel web server: attack console + live packet dashboard.

Run:  uvicorn server:app --port 8000    then open http://localhost:8000
"""
import asyncio
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

# Live state
TABLE = flows.FlowTable(window_s=10.0)
LISTENERS: list[WebSocket] = []
ALERTS: list[dict] = []
ML: detectors.WindowClassifier | None = None
if MODEL_PATH.exists():
    ML = detectors.WindowClassifier.from_json(json.loads(MODEL_PATH.read_text()))

PACKETS_SINCE_EVAL = 0
LAST_ML = {"probability": None, "verdict": "no model yet"}


def broadcast(event: dict):
    dead = []
    for ws in LISTENERS:
        try:
            asyncio.get_event_loop().create_task(ws.send_json(event))
        except Exception:
            dead.append(ws)
    for ws in dead:
        LISTENERS.remove(ws)


def on_packet(pkt: dict):
    """Every packet the generator emits lands here: assemble, detect, stream."""
    global PACKETS_SINCE_EVAL, LAST_ML
    flow = TABLE.update(pkt)
    broadcast({"kind": "packet", "pkt": pkt, "flow_state": flow["state"]})
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


@app.on_event("startup")
async def startup():
    global SERVICES
    SERVICES = generator.LabServices()
    SERVICES.serve_forever()


@app.get("/api/health")
def health():
    return {"status": "ok", "ml_loaded": ML is not None}


SCENARIOS = {
    "browse": "normal web + dns browsing",
    "port_scan": "TCP port scan (ports 1-100)",
    "syn_flood": "SYN flood against the web service",
    "dns_tunnel": "DNS tunnelling exfiltration",
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
        evaluate_window()   # catch short scenarios that emit few packets
        broadcast({"kind": "scenario_done", "name": name})

    asyncio.get_event_loop().create_task(job())
    return {"started": name}


@app.get("/api/flows")
def get_flows():
    out = []
    for f in sorted(TABLE.flows.values(), key=lambda x: -x["last"])[:50]:
        out.append({"src": f"{f['client'][0]}:{f['client'][1]}", "dst": f"{f['server'][0]}:{f['server'][1]}",
                    "proto": f["key"][2], "app": f["app"], "packets": f["packets"],
                    "state": f["state"]})
    return {"flows": out, "half_open": TABLE.half_open()}


@app.get("/api/alerts")
def get_alerts():
    return {"alerts": ALERTS[-20:]}


@app.get("/api/ml")
def get_ml():
    return {"model_loaded": ML is not None, "feature_order": detectors.FEATURE_ORDER, **LAST_ML}


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
