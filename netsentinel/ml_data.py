"""Build the training set for the ML add-on by actually running scenarios.

Each sample is one 3-second window of generated traffic, labelled benign
(web/dns browsing) or attack (scan/flood/tunnel). This is honest ML: the
features come from the same pipeline the live detector uses.
"""
import asyncio
import random
from . import detectors, flows, generator, stack as stack_mod

WINDOW_S = 10.0  # must match server.py's live FlowTable


async def _collect(kind: str, services) -> dict:
    table = flows.FlowTable(window_s=WINDOW_S)
    st = stack_mod.VirtualStack(lambda pkt: table.update(pkt))
    if kind == "benign":
        names = random.sample(["www.example.com", "mail.example.org", "cdn.site.net",
                               "api.service.io", "news.portal.com"], 3)
        for name in names:
            await generator.normal_web_session(st, services)
            await generator.normal_dns_lookup(st, services, name=name)
        if random.random() < 0.5:   # a normal user pings their gateway sometimes
            await generator.ping_sweep(st, services, hosts=[1], live_hosts=(1,))
    elif kind == "port_scan":
        await generator.port_scan(st, services, ports=random.sample(range(1, 130), 70))
    elif kind == "syn_flood":
        await generator.syn_flood(st, services, count=80)
    elif kind == "dns_tunnel":
        await generator.dns_tunnel(st, services, secret=b"the eagle has landed" * 2)
    elif kind == "ping_sweep":
        await generator.ping_sweep(st, services, hosts=random.sample(range(1, 60), 35))
    elif kind == "udp_flood":
        await generator.udp_flood(st, services, count=120)
    feats = detectors.window_features(table.window_packets())
    feats["half_open"] = table.half_open()
    return feats


async def build_dataset(samples_per_class=8):
    services = generator.LabServices()
    services.serve_forever()
    X, y = [], []
    try:
        for _ in range(samples_per_class):
            for kind, label in (("benign", 0), ("port_scan", 1), ("syn_flood", 1),
                                ("dns_tunnel", 1), ("ping_sweep", 1), ("udp_flood", 1)):
                feats = await _collect(kind, services)
                X.append(feats)
                y.append(label)
    finally:
        services.close()
    clf = detectors.WindowClassifier()
    import numpy as np
    clf.fit(np.array([clf.vectorize(f) for f in X]), np.array(y, dtype=float))
    return clf, X, y
