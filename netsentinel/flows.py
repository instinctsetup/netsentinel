"""Flow assembly: from a stream of packets to connections you can reason about.

A flow is identified by the classic 5-tuple (src ip, src port, dst ip,
dst port, protocol). For TCP we also track the handshake state machine,
because half-open connections are the fingerprint of SYN floods.
"""
import time
from collections import deque


TCP_STATES = ["SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT", "CLOSED", "RST"]


def next_state(state: str, flags: list[str], from_client: bool) -> str:
    """One step of the TCP connection state machine (simplified but faithful)."""
    if "RST" in flags:
        return "RST"
    if "FIN" in flags:
        return "CLOSED" if state == "FIN_WAIT" else "FIN_WAIT"
    if state == "SYN_SENT" and "SYN" in flags and "ACK" in flags and not from_client:
        return "SYN_RECEIVED"
    if state == "SYN_RECEIVED" and "ACK" in flags and "SYN" not in flags and from_client:
        return "ESTABLISHED"
    return state


class FlowTable:
    """Keeps every flow seen so far plus recent packets for the detectors."""

    def __init__(self, window_s: float = 10.0):
        self.flows: dict[tuple, dict] = {}
        self.recent: deque = deque()   # (timestamp, parsed packet) sliding window
        self.window_s = window_s

    def update(self, pkt: dict) -> dict:
        now = time.time()
        self.recent.append((now, pkt))
        while self.recent and now - self.recent[0][0] > self.window_s:
            self.recent.popleft()

        ip = pkt["ip"]
        proto = "TCP" if "tcp" in pkt else "UDP" if "udp" in pkt else str(ip["protocol"])
        l4 = pkt.get("tcp") or pkt.get("udp") or {}
        # Bidirectional flow: canonicalize the 5-tuple so both directions of a
        # connection land in ONE flow (this is how real flow meters work).
        a = (ip["src"], l4.get("src_port"))
        b = (ip["dst"], l4.get("dst_port"))
        key = (min(a, b), max(a, b), proto)
        flow = self.flows.get(key)
        if flow is None:
            flow = {"key": key, "client": a, "server": b, "packets": 0, "bytes": 0,
                    "state": "SYN_SENT" if proto == "TCP" else "-",
                    "first": now, "last": now, "app": pkt.get("app", "")}
            self.flows[key] = flow
        flow["packets"] += 1
        flow["bytes"] += ip["total_len"]
        flow["last"] = now
        if pkt.get("app"):
            flow["app"] = pkt["app"]
        if proto == "TCP" and pkt.get("tcp"):
            from_client = (ip["src"], l4.get("src_port")) == flow["client"]
            flow["state"] = next_state(flow["state"], pkt["tcp"]["flags"], from_client)
        return flow

    def half_open(self) -> int:
        return sum(1 for f in self.flows.values() if f["state"] in ("SYN_SENT", "SYN_RECEIVED"))

    def window_packets(self) -> list[dict]:
        return [p for _, p in self.recent]
