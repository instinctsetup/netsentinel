"""ICMP wire format, new attack scenarios, and their detectors."""
import asyncio

from netsentinel import detectors, flows, generator, packets, stack as stack_mod


def run(coro):
    return asyncio.run(coro)


def collect(fn, **kw):
    seen = []
    st = stack_mod.VirtualStack(seen.append)
    services = generator.LabServices()
    services.serve_forever()
    try:
        run(fn(st, services, **kw))
    finally:
        services.close()
    table = flows.FlowTable(window_s=60)
    for p in seen:
        table.update(p)
    return seen, table


# ------------------------------------------------------------- ICMP format
def test_icmp_round_trip():
    wire = packets.build_icmp_echo(ident=42, seq=7, payload=b"hello")
    p = packets.parse_icmp(wire)
    assert p["type"] == 8 and p["type_name"] == "ECHO_REQUEST"
    assert p["id"] == 42 and p["seq"] == 7
    assert p["payload"][-5:] == b"hello"
    assert packets.ipv4_checksum(wire) == 0   # valid checksum verifies to zero


def test_parse_packet_decodes_icmp():
    raw = packets.build_ipv4("10.0.0.1", "10.0.0.2", 1, packets.build_icmp_echo())
    d = packets.parse_packet(raw)
    assert d["app"] == "ICMP" and d["icmp"]["type"] == 8


def test_garbage_on_port_53_is_not_dns():
    raw = packets.build_ipv4("1.2.3.4", "5.6.7.8", 17,
                             packets.build_udp(1111, 53, b"\xff\xfe random bytes"))
    d = packets.parse_packet(raw)
    assert d.get("dns") is None and d["app"] == "UDP/53"


# ------------------------------------------------------------- scenarios
def test_ping_sweep_emits_echo_and_replies():
    seen, table = collect(generator.ping_sweep, hosts=range(1, 6), live_hosts=(2, 4))
    echoes = [p for p in seen if p.get("icmp", {}).get("type") == 8]
    replies = [p for p in seen if p.get("icmp", {}).get("type") == 0]
    assert len(echoes) == 5 and len(replies) == 2
    assert all("raw" in p for p in seen)


def test_ping_sweep_rule_fires():
    seen, table = collect(generator.ping_sweep, hosts=range(1, 30))
    feats = detectors.window_features(table.window_packets())
    kinds = [a["kind"] for a in detectors.rule_alerts(feats, table.half_open())]
    assert "PING_SWEEP" in kinds


def test_udp_flood_rule_fires():
    seen, table = collect(generator.udp_flood, count=120)
    feats = detectors.window_features(table.window_packets())
    kinds = [a["kind"] for a in detectors.rule_alerts(feats, table.half_open())]
    assert "UDP_FLOOD" in kinds


def test_small_sweep_does_not_fire():
    seen, table = collect(generator.ping_sweep, hosts=range(1, 5))
    feats = detectors.window_features(table.window_packets())
    kinds = [a["kind"] for a in detectors.rule_alerts(feats, table.half_open())]
    assert "PING_SWEEP" not in kinds
