"""Experiment harness: real, logged, reproducible evaluation of the detectors.

Every experiment run collects fresh traffic windows through the SAME pipeline
the live dashboard uses (generator -> parse -> flows -> features), then scores
both the rule-based detectors and the ML add-on. Results are appended to
docs/experiments/results.json with a run id, timestamp, and git commit - the
dashboard's Experiments tab reads that file, so the numbers on screen are the
numbers from the last real run, never hard-coded.
"""
import asyncio
import json
import random
import subprocess
import time
from pathlib import Path

import numpy as np

from . import detectors, flows, generator, metrics, ml_data, stack as stack_mod

KINDS = ["benign", "port_scan", "syn_flood", "dns_tunnel", "ping_sweep", "udp_flood"]


def _git_sha() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                              capture_output=True, text=True, cwd=Path(__file__).parent.parent).stdout.strip()
    except Exception:
        return "unknown"


async def collect_labeled_windows(samples_per_class: int, seed: int = 7):
    """Collect feature windows for every scenario kind, labelled honestly."""
    random.seed(seed)
    services = generator.LabServices()
    services.serve_forever()
    rows = []  # (features dict, label 0/1, kind)
    try:
        for i in range(samples_per_class):
            for kind in KINDS:
                feats = await ml_data._collect(kind, services)
                rows.append((feats, 0 if kind == "benign" else 1, kind))
                if i % 8 == 0:
                    print(f"  collected {len(rows)} windows...", flush=True)
    finally:
        services.close()
    return rows


def vectorize(rows, feature_order=None):
    order = feature_order or detectors.FEATURE_ORDER
    X = np.array([[feats[k] for k in order] for feats, _, _ in rows], dtype=float)
    y = np.array([label for _, label, _ in rows], dtype=float)
    return X, y


def split_rows(rows, train_frac=0.6, seed=1):
    """Stratified split: both classes are guaranteed in train AND test."""
    rng = random.Random(seed)
    train, test = [], []
    for label in (0, 1):
        idx = [i for i, r in enumerate(rows) if r[1] == label]
        rng.shuffle(idx)
        cut = max(1, int(len(idx) * train_frac))
        train += [rows[i] for i in idx[:cut]]
        test += [rows[i] for i in idx[cut:]]
    return train, test


def _clean(obj):
    """NaN is not valid JSON - map it to None so the dashboard can parse results."""
    if isinstance(obj, float) and obj != obj:
        return None
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean(v) for v in obj]
    return obj


def train_on(rows, feature_order=None):
    order = feature_order or detectors.FEATURE_ORDER
    X, y = vectorize(rows, order)
    old = detectors.FEATURE_ORDER
    detectors.FEATURE_ORDER = order   # construct + fit under the ablated order
    try:
        clf = detectors.WindowClassifier()
        clf.fit(X, y)
    finally:
        detectors.FEATURE_ORDER = old
    return clf


def score(clf, rows, threshold=0.5, feature_order=None):
    order = feature_order or detectors.FEATURE_ORDER
    old = detectors.FEATURE_ORDER
    detectors.FEATURE_ORDER = order
    try:
        scores = np.array([clf.predict_proba(feats) for feats, _, _ in rows])
    finally:
        detectors.FEATURE_ORDER = old
    y = np.array([label for _, label, _ in rows], dtype=float)
    pred = (scores >= threshold).astype(int)
    cm = metrics.confusion(y, pred)
    return _clean({"scores": scores.tolist(), "y": y.tolist(),
                   "confusion": cm, **metrics.precision_recall_f1(cm),
                   "auc": metrics.roc_auc(y, scores)})


def rule_score(rows):
    """Rules verdict per window: any alert = attack."""
    y = np.array([label for _, label, _ in rows], dtype=float)
    pred = np.array([1 if detectors.rule_alerts(feats, int(feats.get("half_open", 0))) else 0
                     for feats, _, _ in rows])
    cm = metrics.confusion(y, pred)
    return {"confusion": cm, **metrics.precision_recall_f1(cm)}


def roc_points(rows, steps=19):
    """Sweep the decision threshold for ROC points (tpr, fpr, threshold)."""
    train, test = split_rows(rows, 0.6, seed=3)
    clf = train_on(train)
    order = detectors.FEATURE_ORDER
    scores = np.array([clf.predict_proba(f) for f, _, _ in test])
    y = np.array([l for _, l, _ in test], dtype=float)
    pts = []
    for t in np.linspace(0.02, 0.98, steps):
        pred = (scores >= t).astype(int)
        cm = metrics.confusion(y, pred)
        tpr = cm["tp"] / (cm["tp"] + cm["fn"]) if cm["tp"] + cm["fn"] else 0.0
        fpr = cm["fp"] / (cm["fp"] + cm["tn"]) if cm["fp"] + cm["tn"] else 0.0
        pts.append({"threshold": round(float(t), 3), "tpr": round(tpr, 3), "fpr": round(fpr, 3)})
    return {"points": pts, "auc": round(metrics.roc_auc(y, scores), 4)}


def kfold_cv(rows, k=4, seed=5):
    """Stratified k-fold cross-validation: every fold keeps the class ratio."""
    rng = random.Random(seed)
    folds = [[] for _ in range(k)]
    for label in (0, 1):
        idx = [i for i, r in enumerate(rows) if r[1] == label]
        rng.shuffle(idx)
        for j, i in enumerate(idx):
            folds[j % k].append(i)
    f1s, aucs = [], []
    for f in range(k):
        test = [rows[i] for i in folds[f]]
        train = [rows[i] for j, fold in enumerate(folds) if j != f for i in fold]
        s = score(train_on(train), test)
        f1s.append(s["f1"])
        if s["auc"] is not None:
            aucs.append(s["auc"])
    return _clean({"k": k, "f1_mean": round(float(np.mean(f1s)), 4),
                   "f1_std": round(float(np.std(f1s)), 4),
                   "auc_mean": round(float(np.mean(aucs)), 4) if aucs else None,
                   "auc_std": round(float(np.std(aucs)), 4) if aucs else None})


def feature_ablation(rows):
    """Single-feature analysis: F1 of a model trained on that feature alone.

    More informative than leave-one-out on a small, redundant feature set:
    it shows which signals carry detection by themselves."""
    train, test = split_rows(rows, 0.6, seed=11)
    base = score(train_on(train), test)["f1"]
    solo = []
    for feat in detectors.FEATURE_ORDER:
        s = score(train_on(train, [feat]), test, feature_order=[feat])["f1"]
        solo.append({"feature": feat, "f1_solo": round(s, 4)})
    solo.sort(key=lambda d: -d["f1_solo"])
    return {"baseline_f1": round(base, 4), "solo": solo}


def train_size_curve(rows, sizes=(2, 4, 8, 12), seeds=(1, 2, 3)):
    """F1 vs number of training windows per class (tested on the rest)."""
    by_class = {0: [r for r in rows if r[1] == 0], 1: [r for r in rows if r[1] == 1]}
    curve = []
    for n in sizes:
        f1s = []
        for seed in seeds:
            rng = random.Random(seed)
            train = rng.sample(by_class[0], n) + rng.sample(by_class[1], n)
            used = set(map(id, train))
            test = [r for r in rows if id(r) not in used]
            f1s.append(score(train_on(train), test)["f1"])
        curve.append({"train_per_class": n, "f1_mean": round(float(np.mean(f1s)), 4),
                      "f1_std": round(float(np.std(f1s)), 4)})
    return curve


async def intensity_curve():
    """Detection probability vs attack intensity - how small an attack still trips the rule."""
    services = generator.LabServices()
    services.serve_forever()
    out = {"port_scan": [], "syn_flood": [], "dns_tunnel": [], "ping_sweep": [], "udp_flood": []}
    trials = 5
    try:
        for size in (4, 8, 12, 20, 40, 80):
            hits = 0
            for _ in range(trials):
                table = flows.FlowTable(window_s=ml_data.WINDOW_S)
                st = stack_mod.VirtualStack(lambda p: table.update(p))
                await generator.port_scan(st, services, ports=random.sample(range(1, 200), size))
                feats = detectors.window_features(table.window_packets())
                if any(a["kind"] == "PORT_SCAN" for a in detectors.rule_alerts(feats, table.half_open())):
                    hits += 1
            out["port_scan"].append({"intensity": size, "detection_rate": round(hits / trials, 2)})
        for count in (10, 20, 30, 60, 120):
            hits = 0
            for _ in range(trials):
                table = flows.FlowTable(window_s=ml_data.WINDOW_S)
                st = stack_mod.VirtualStack(lambda p: table.update(p))
                await generator.syn_flood(st, services, count=count)
                feats = detectors.window_features(table.window_packets())
                if any(a["kind"] == "SYN_FLOOD" for a in detectors.rule_alerts(feats, table.half_open())):
                    hits += 1
            out["syn_flood"].append({"intensity": count, "detection_rate": round(hits / trials, 2)})
        for chunks in (2, 4, 8, 16):
            hits = 0
            for _ in range(trials):
                table = flows.FlowTable(window_s=ml_data.WINDOW_S)
                st = stack_mod.VirtualStack(lambda p: table.update(p))
                secret = bytes(random.getrandbits(8) for _ in range(chunks * 25))
                await generator.dns_tunnel(st, services, secret=secret)
                feats = detectors.window_features(table.window_packets())
                if any(a["kind"] == "DNS_TUNNEL" for a in detectors.rule_alerts(feats, table.half_open())):
                    hits += 1
            out["dns_tunnel"].append({"intensity": chunks, "detection_rate": round(hits / trials, 2)})
        for hosts in (4, 8, 10, 20, 40):
            hits = 0
            for _ in range(trials):
                table = flows.FlowTable(window_s=ml_data.WINDOW_S)
                st = stack_mod.VirtualStack(lambda p: table.update(p))
                await generator.ping_sweep(st, services, hosts=random.sample(range(1, 100), hosts))
                feats = detectors.window_features(table.window_packets())
                if any(a["kind"] == "PING_SWEEP" for a in detectors.rule_alerts(feats, table.half_open())):
                    hits += 1
            out["ping_sweep"].append({"intensity": hosts, "detection_rate": round(hits / trials, 2)})
        for count in (20, 40, 60, 120, 200):
            hits = 0
            for _ in range(trials):
                table = flows.FlowTable(window_s=ml_data.WINDOW_S)
                st = stack_mod.VirtualStack(lambda p: table.update(p))
                await generator.udp_flood(st, services, count=count)
                feats = detectors.window_features(table.window_packets())
                if any(a["kind"] == "UDP_FLOOD" for a in detectors.rule_alerts(feats, table.half_open())):
                    hits += 1
            out["udp_flood"].append({"intensity": count, "detection_rate": round(hits / trials, 2)})
    finally:
        services.close()
    return out
