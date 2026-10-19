"""API smoke tests: health, scenarios, stats, packet inspector, experiments."""
import time

from fastapi.testclient import TestClient

from server import app


def test_health_and_scenarios():
    with TestClient(app) as c:
        assert c.get("/api/health").json()["status"] == "ok"
        assert "ping_sweep" in c.get("/api/scenarios").json()
        assert c.post("/api/scenario/browse").json()["started"] == "browse"
        assert "error" in c.post("/api/scenario/nope").json()
        time.sleep(1.5)
        stats = c.get("/api/stats").json()
        assert stats["total_packets"] > 0 and stats["ml_loaded"]
        flows = c.get("/api/flows").json()
        assert flows["flows"] and "state" in flows["flows"][0]


def test_packet_inspector_round_trip():
    with TestClient(app) as c:
        c.post("/api/scenario/ping_sweep")
        time.sleep(2.0)
        stats = c.get("/api/stats").json()
        p = c.get(f"/api/packet/{stats['total_packets']}").json()
        assert p["ip"]["protocol_name"] in ("TCP", "UDP", "ICMP")
        assert bytes.fromhex(p["raw"])   # raw wire bytes decode


def test_experiments_endpoint_shape():
    with TestClient(app) as c:
        d = c.get("/api/experiments").json()
        assert "runs" in d and "latest" in d
        if d["latest"]:
            assert "kfold_cv" in d["latest"] and "intensity" in d["latest"]
