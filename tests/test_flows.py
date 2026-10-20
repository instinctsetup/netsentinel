"""Flow assembly and the TCP state machine."""
from netsentinel import flows, packets as P


def handshake():
    """The three packets of a normal connection open."""
    F = P.TCP_FLAGS
    syn = P.parse_packet(P.build_ipv4("a", "b", 6, P.build_tcp(1, 2, 0, 0, F["SYN"]))) if False else None
    def pkt(flags, direction):
        if direction == "c>s":
            raw = P.build_ipv4("10.0.0.5", "10.0.0.1", 6, P.build_tcp(1000, 80, 0, 0, flags))
        else:
            raw = P.build_ipv4("10.0.0.1", "10.0.0.5", 6, P.build_tcp(80, 1000, 0, 0, flags))
        d = P.parse_packet(raw)
        d["direction"] = direction
        return d
    return [pkt(F["SYN"], "c>s"), pkt(F["SYN"] | F["ACK"], "s>c"), pkt(F["ACK"], "c>s")]


def test_handshake_reaches_established():
    table = flows.FlowTable()
    states = [table.update(p)["state"] for p in handshake()]
    assert states == ["SYN_SENT", "SYN_RECEIVED", "ESTABLISHED"]
    assert table.half_open() == 0


def test_unanswered_syn_stays_half_open():
    table = flows.FlowTable()
    table.update(handshake()[0])
    assert table.half_open() == 1


def test_rst_closes_connection():
    table = flows.FlowTable()
    F = P.TCP_FLAGS
    raw = P.build_ipv4("10.0.0.5", "10.0.0.1", 6, P.build_tcp(1000, 81, 0, 0, F["SYN"]))
    d = P.parse_packet(raw); d["direction"] = "c>s"
    table.update(d)
    raw = P.build_ipv4("10.0.0.1", "10.0.0.5", 6, P.build_tcp(81, 1000, 0, 1, F["RST"] | F["ACK"]))
    d = P.parse_packet(raw); d["direction"] = "s>c"
    # RST arrives on the reverse flow key; original stays half-open, new flow RST
    table.update(d)
    assert any(f["state"] == "RST" for f in table.flows.values())


def test_stale_flows_are_pruned():
    import time as _time
    table = flows.FlowTable(window_s=0.01)
    pkt = {"ip": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": 6, "total_len": 60},
           "tcp": {"src_port": 40000, "dst_port": 80, "flags": {"SYN": True}}}
    table.update(pkt)
    assert len(table.flows) == 1
    table._prune_flows(now=_time.time() + 200)
    assert len(table.flows) == 0
