"""Wire-format round-trips: build then parse must return identical fields."""
from netsentinel import packets as P


def test_ipv4_tcp_syn_roundtrip():
    seg = P.build_tcp(1234, 80, seq=42, ack=0, flags=P.TCP_FLAGS["SYN"])
    raw = P.build_ipv4("10.1.1.5", "10.1.1.9", 6, seg)
    d = P.parse_packet(raw)
    assert d["ip"]["src"] == "10.1.1.5" and d["ip"]["dst"] == "10.1.1.9"
    assert d["ip"]["protocol_name"] == "TCP"
    assert d["tcp"]["flags"] == ["SYN"] and d["tcp"]["seq"] == 42


def test_ipv4_checksum_valid_header_sums_to_zero():
    raw = P.build_ipv4("192.168.0.1", "192.168.0.2", 17, P.build_udp(1, 2, b"x"))
    assert P.ipv4_checksum(raw[:20]) == 0  # checksum field included -> 0


def test_udp_dns_roundtrip_and_label_parsing():
    wire = P.build_dns_query("aGVsbG8gd29ybGQ.exfil.lab")
    raw = P.build_ipv4("10.0.0.2", "10.0.0.1", 17, P.build_udp(5353, 53, wire))
    d = P.parse_packet(raw)
    assert d["app"] == "DNS"
    assert d["dns"]["labels"] == ["aGVsbG8gd29ybGQ", "exfil", "lab"]
