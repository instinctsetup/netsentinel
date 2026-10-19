"""Detectors: networking-first rules, then a small ML add-on.

The rules reason about *network behaviour* (SYN fan-out, half-open
connections, DNS label entropy) - concepts straight from a CN course.
The logistic regression at the bottom learns the same boundary from
window features, so the dashboard can compare rules vs ML side by side.
"""
import math
from collections import defaultdict
import numpy as np


def shannon_entropy(text: str) -> float:
    """Bits per character. English words: ~1.5-2.5. Base32 tunnelling: ~4+."""
    if not text:
        return 0.0
    counts = defaultdict(int)
    for ch in text:
        counts[ch] += 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def window_features(pkts: list[dict], flows=None) -> dict:
    """Summarize a time window of packets into detector-ready numbers."""
    f = {"syn": 0, "syn_ack": 0, "rst": 0, "dns": 0, "http": 0, "udp": 0,
         "icmp_echo": 0, "scan_ports": defaultdict(set), "dns_labels": [],
         "syn_targets": defaultdict(int), "udp_targets": defaultdict(int),
         "icmp_targets": defaultdict(set)}
    for p in pkts:
        if "tcp" in p:
            flags = p["tcp"]["flags"]
            if "SYN" in flags and "ACK" not in flags:
                f["syn"] += 1
                f["scan_ports"][p["ip"]["src"]].add(p["tcp"]["dst_port"])
                f["syn_targets"][(p["ip"]["dst"], p["tcp"]["dst_port"])] += 1
            if "SYN" in flags and "ACK" in flags:
                f["syn_ack"] += 1
            if "RST" in flags:
                f["rst"] += 1
        if "udp" in p:
            f["udp"] += 1
            f["udp_targets"][(p["ip"]["dst"], p["udp"]["dst_port"])] += 1
        if "icmp" in p and p["icmp"]["type"] == 8:
            f["icmp_echo"] += 1
            f["icmp_targets"][p["ip"]["src"]].add(p["ip"]["dst"])
        if p.get("app") == "DNS" and p.get("dns"):
            f["dns"] += 1
            f["dns_labels"].append(p["dns"]["labels"][0] if p["dns"]["labels"] else "")
        if p.get("app") == "HTTP":
            f["http"] += 1
    f["max_distinct_ports"] = max((len(v) for v in f["scan_ports"].values()), default=0)
    f["max_syn_target"] = max(f["syn_targets"].values(), default=0)
    f["max_udp_target"] = max(f["udp_targets"].values(), default=0)
    f["max_icmp_targets"] = max((len(v) for v in f["icmp_targets"].values()), default=0)
    f["avg_label_len"] = float(np.mean([len(l) for l in f["dns_labels"]])) if f["dns_labels"] else 0.0
    f["avg_label_entropy"] = float(np.mean([shannon_entropy(l) for l in f["dns_labels"]])) if f["dns_labels"] else 0.0
    return f


def rule_alerts(feats: dict, half_open: int) -> list[dict]:
    """The three classic signatures, each explained in one sentence."""
    alerts = []
    if feats["max_distinct_ports"] >= 12:
        alerts.append({"kind": "PORT_SCAN", "severity": "high",
                       "why": f"one source sent SYNs to {feats['max_distinct_ports']} different ports in one window - nobody browses like that"})
    if feats["max_syn_target"] >= 30 or (feats["syn"] >= 30 and half_open >= 20):
        alerts.append({"kind": "SYN_FLOOD", "severity": "critical",
                       "why": f"{feats['max_syn_target']} SYNs to one service with {half_open} half-open connections - handshakes never complete"})
    if feats["dns"] >= 2 and (feats["avg_label_len"] > 25 or feats["avg_label_entropy"] > 3.6):
        alerts.append({"kind": "DNS_TUNNEL", "severity": "high",
                       "why": f"DNS labels averaging {feats['avg_label_len']:.0f} chars at {feats['avg_label_entropy']:.2f} bits/char entropy - real hostnames are short and word-like"})
    if feats["max_icmp_targets"] >= 10:
        alerts.append({"kind": "PING_SWEEP", "severity": "medium",
                       "why": f"one source sent ICMP echo requests to {feats['max_icmp_targets']} different hosts - that is subnet discovery, not connectivity checking"})
    if feats["max_udp_target"] >= 60:
        alerts.append({"kind": "UDP_FLOOD", "severity": "critical",
                       "why": f"{feats['max_udp_target']} UDP datagrams into one port in one window - UDP has no handshake, so nothing slows the blast"})
    return alerts


FEATURE_ORDER = ["syn", "syn_ack", "rst", "dns", "http", "udp", "icmp_echo",
                 "max_distinct_ports", "max_syn_target", "max_udp_target",
                 "max_icmp_targets", "avg_label_len", "avg_label_entropy"]


class WindowClassifier:
    """Logistic regression from scratch over window_features.

    Same math as any ML course: p = sigmoid(w . x + b), trained by gradient
    descent on cross-entropy. Deliberately tiny - the rules do the heavy
    lifting; this shows what learned detection adds (softer boundaries,
    weighted evidence) and costs (needs training data).
    """

    def __init__(self):
        self.w = np.zeros(len(FEATURE_ORDER))
        self.b = 0.0
        self.mu = np.zeros(len(FEATURE_ORDER))
        self.sigma = np.ones(len(FEATURE_ORDER))

    def vectorize(self, feats: dict) -> np.ndarray:
        return np.array([feats[k] for k in FEATURE_ORDER], dtype=float)

    def fit(self, X: np.ndarray, y: np.ndarray, lr=0.2, epochs=3000):
        self.mu, self.sigma = X.mean(0), X.std(0) + 1e-9
        Z = (X - self.mu) / self.sigma
        for _ in range(epochs):
            p = 1 / (1 + np.exp(-(Z @ self.w + self.b)))
            self.w -= lr * (Z.T @ (p - y)) / len(y)
            self.b -= lr * float((p - y).mean())
        return self

    def predict_proba(self, feats: dict) -> float:
        z = (self.vectorize(feats) - self.mu) / self.sigma
        return float(1 / (1 + math.exp(-(self.w @ z + self.b))))

    def to_json(self) -> dict:
        return {"w": self.w.tolist(), "b": self.b, "mu": self.mu.tolist(), "sigma": self.sigma.tolist()}

    @classmethod
    def from_json(cls, d: dict) -> "WindowClassifier":
        c = cls()
        c.w, c.b = np.array(d["w"]), d["b"]
        c.mu, c.sigma = np.array(d["mu"]), np.array(d["sigma"])
        return c
