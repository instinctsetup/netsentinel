"""Building and parsing real network protocol wire formats.

Everything here works on raw bytes, exactly as they travel on the wire.
Each protocol has a `build_*` (bytes -> packet) and a `parse_*`
(bytes -> friendly dict) so the tests can round-trip every header.

Protocols: IPv4 (RFC 791), TCP (RFC 793), UDP (RFC 768), DNS (RFC 1035).
"""
import struct


# ---------------------------------------------------------------- IPv4
def build_ipv4(src: str, dst: str, protocol: int, payload: bytes,
               ident: int = 0, ttl: int = 64) -> bytes:
    """Assemble a 20-byte IPv4 header (no options) around a payload.

    Fields that matter for the viva: total length, protocol number
    (6 = TCP, 17 = UDP), TTL, and the header checksum that routers
    recompute at every hop because TTL changes.
    """
    src_b = socket_aton(src)
    dst_b = socket_aton(dst)
    total = 20 + len(payload)
    ver_ihl = (4 << 4) | 5                      # version 4, header len 5 words
    header = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, ident, 0,
                         ttl, protocol, 0, src_b, dst_b)
    checksum = ipv4_checksum(header)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, ident, 0,
                       ttl, protocol, checksum, src_b, dst_b) + payload


def parse_ipv4(raw: bytes) -> dict:
    """Pull an IPv4 header apart into its named fields."""
    ver_ihl, tos, total, ident, flags_frag, ttl, proto, cksum, src, dst = \
        struct.unpack("!BBHHHBBH4s4s", raw[:20])
    ihl = (ver_ihl & 0x0F) * 4
    return {"version": ver_ihl >> 4, "header_len": ihl, "tos": tos,
            "total_len": total, "id": ident, "ttl": ttl, "protocol": proto,
            "protocol_name": {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto)),
            "checksum": cksum, "src": socket_ntoa(src), "dst": socket_ntoa(dst),
            "payload": raw[ihl:total]}


def ipv4_checksum(header: bytes) -> int:
    """The one's-complement sum from RFC 1071, same as mini routers compute."""
    if len(header) % 2:
        header += b"\x00"
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# ----------------------------------------------------------------- TCP
TCP_FLAGS = {"FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
             "ACK": 0x10, "URG": 0x20}


def build_tcp(src_port: int, dst_port: int, seq: int, ack: int,
              flags: int, window: int = 64240, payload: bytes = b"") -> bytes:
    """Assemble a 20-byte TCP header (no options) plus payload.

    `flags` is a bitmask of TCP_FLAGS, e.g. SYN|ACK for the second
    handshake packet. The data-offset nibble says how long the header is.
    """
    offset = (5 << 4)  # header length 5 x 32-bit words, shifted into place
    return struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack,
                       offset, flags, window, 0, 0) + payload


def parse_tcp(raw: bytes) -> dict:
    """Pull a TCP segment apart, decoding the flag bits into names."""
    src_port, dst_port, seq, ack, offset, flags, window, cksum, urg = \
        struct.unpack("!HHIIBBHHH", raw[:20])
    header_len = (offset >> 4) * 4
    return {"src_port": src_port, "dst_port": dst_port, "seq": seq,
            "ack": ack, "header_len": header_len,
            "flags": [name for name, bit in TCP_FLAGS.items() if flags & bit],
            "window": window, "payload": raw[header_len:]}


# ----------------------------------------------------------------- UDP
def build_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """UDP's entire header: two ports, a length, a checksum (0 = skip)."""
    length = 8 + len(payload)
    return struct.pack("!HHHH", src_port, dst_port, length, 0) + payload


def parse_udp(raw: bytes) -> dict:
    src_port, dst_port, length, cksum = struct.unpack("!HHHH", raw[:8])
    return {"src_port": src_port, "dst_port": dst_port, "length": length,
            "payload": raw[8:length]}


# ----------------------------------------------------------------- DNS
def build_dns_query(name: str, qtype: int = 1, ident: int = 0x1234) -> bytes:
    """A standard DNS query for `name` (A record by default).

    The name is encoded as length-prefixed labels: "a.b.co" ->
    \\x01a\\x01b\\x02co\\x00. Tunnelling attacks hide data in these labels,
    which is why the detector studies label entropy and length.
    """
    header = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0)  # RD=1
    qname = b"".join(bytes([len(label)]) + label.encode()
                     for label in name.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def parse_dns_query(raw: bytes) -> dict:
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", raw[:12])
    labels, i = [], 12
    while raw[i] != 0:                        # walk the label chain
        length = raw[i]
        labels.append(raw[i + 1:i + 1 + length].decode(errors="replace"))
        i += 1 + length
    qtype, qclass = struct.unpack("!HH", raw[i + 1:i + 5])
    return {"id": ident, "flags": flags, "name": ".".join(labels),
            "labels": labels, "qtype": qtype, "qclass": qclass,
            "question_bytes": i + 5}


# ------------------------------------------------------- small helpers
def socket_aton(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def socket_ntoa(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def parse_packet(raw: bytes) -> dict:
    """One call: IPv4 in, a fully decoded packet description out."""
    ip = parse_ipv4(raw)
    result = {"ip": {k: v for k, v in ip.items() if k != "payload"}}
    if ip["protocol"] == 6:
        tcp = parse_tcp(ip["payload"])
        result["tcp"] = {k: v for k, v in tcp.items() if k != "payload"}
        if tcp["dst_port"] == 53 or tcp["src_port"] == 53:
            result["app"] = "DNS"
        elif 80 in (tcp["src_port"], tcp["dst_port"]) or 8000 in (tcp["src_port"], tcp["dst_port"]):
            result["app"] = "HTTP"
        result["payload_len"] = len(tcp["payload"])
    elif ip["protocol"] == 17:
        udp = parse_udp(ip["payload"])
        result["udp"] = {k: v for k, v in udp.items() if k != "payload"}
        if 53 in (udp["src_port"], udp["dst_port"]):
            result["app"] = "DNS"
            result["dns"] = parse_dns_query(udp["payload"])
        result["payload_len"] = len(udp["payload"])
    return result
