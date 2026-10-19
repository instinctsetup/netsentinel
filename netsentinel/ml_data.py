"""Build the training set for the ML add-on by actually running scenarios.

Each sample is one 3-second window of generated traffic, labelled benign
(web/dns browsing) or attack (scan/flood/tunnel). This is honest ML: the
features come from the same pipeline the live detector uses.
"""
import asyncio
import random
from . import detectors, flows, generator, stack as stack_mod


async def _collect(kind: str, services) -> dict:
    table = flows.FlowTable(window_s=60)
    st = stack_mod.VirtualStack(lambda pkt: table.update(pkt))
    if kind == "benign":
        for _ in range(3):
            await generator.normal_web_session(st, services)
            await generator.normal_dns_lookup(st, services)
    elif kind == "port_scan":
        await generator.port_scan(st, services, ports=random.sample(range(1, 130), 70))
    elif kind == "syn_flood":
        await generator.syn_flood(st, services, count=80)
    elif kind == "dns_tunnel":
        await generator.dns_tunnel(st, services, secret=b"the eagle has landed" * 2)
    feats = detectors.window_features(table.window_packets())
    feats["half_open"] = table.half_open()
    return feats


async def build_dataset(samples_per_class=8):
    services = generator.LabServices()
    services.serve_forever()
    X, y = [], []
    try:
        for _ in range(samples_per_class):
            for kind, label in (("benign", 0), ("port_scan", 1), ("syn_flood", 1), ("dns_tunnel", 1)):
                feats = await _collect(kind, services)
                X.append(feats)
                y.append(label)
    finally:
        services.close()
    clf = detectors.WindowClassifier()
    import numpy as np
    clf.fit(np.array([clf.vectorize(f) for f in X]), np.array(y, dtype=float))
    return clf, X, y
