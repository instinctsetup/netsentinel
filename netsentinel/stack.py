"""VirtualStack: the TCP layer a real kernel would run, written out loud.

We drive REAL sockets (real bytes, real ports, real timing), but an
unprivileged process cannot sniff loopback, so for every socket-level
event this stack emits exactly the TCP segments the kernel would have
exchanged: correct flags, correct sequence/acknowledgement arithmetic,
correct handshake and teardown. It doubles as a readable reference for
"what does a TCP connection look like on the wire".
"""
import random
from . import packets


class VirtualStack:
    def __init__(self, tap):
        """tap(dict) receives every parsed packet plus a direction tag."""
        self.tap = tap
        self.conns = {}          # (client_ip, client_port, server_ip, server_port) -> state

    def _emit(self, src_ip, dst_ip, segment, direction):
        wire = packets.build_ipv4(src_ip, dst_ip, 6, segment)
        event = packets.parse_packet(wire)
        event["direction"] = direction
        self.tap(event)

    def open(self, c_ip, c_port, s_ip, s_port, success=True):
        """The three-way handshake (or its refusal on a closed port)."""
        isn_c = random.randint(0, 2**31)
        key = (c_ip, c_port, s_ip, s_port)
        F = packets.TCP_FLAGS
        self._emit(c_ip, s_ip, packets.build_tcp(c_port, s_port, isn_c, 0, F["SYN"]), "c>s")
        if not success:
            # Closed port: the host answers RST+ACK immediately.
            self._emit(s_ip, c_ip, packets.build_tcp(s_port, c_port, 0, isn_c + 1,
                                                     F["RST"] | F["ACK"]), "s>c")
            self.conns[key] = {"state": "CLOSED", "c_seq": isn_c + 1, "s_seq": 0}
            return None
        isn_s = random.randint(0, 2**31)
        self._emit(s_ip, c_ip, packets.build_tcp(s_port, c_port, isn_s, isn_c + 1,
                                                 F["SYN"] | F["ACK"]), "s>c")
        self._emit(c_ip, s_ip, packets.build_tcp(c_port, s_port, isn_c + 1, isn_s + 1,
                                                 F["ACK"]), "c>s")
        self.conns[key] = {"state": "ESTABLISHED", "c_seq": isn_c + 1, "s_seq": isn_s + 1}
        return key

    def send(self, key, data: bytes, from_client=True):
        """One data segment (PSH+ACK); seq advances by the payload length."""
        conn = self.conns[key]
        c_ip, c_port, s_ip, s_port = key
        F = packets.TCP_FLAGS
        if from_client:
            self._emit(c_ip, s_ip, packets.build_tcp(c_port, s_port, conn["c_seq"],
                                                     conn["s_seq"], F["PSH"] | F["ACK"], payload=data), "c>s")
            conn["c_seq"] += len(data)
        else:
            self._emit(s_ip, c_ip, packets.build_tcp(s_port, c_port, conn["s_seq"],
                                                     conn["c_seq"], F["PSH"] | F["ACK"], payload=data), "s>c")
            conn["s_seq"] += len(data)

    def close(self, key):
        """Polite four-way teardown: FIN/ACK one way, FIN/ACK back."""
        conn = self.conns[key]
        c_ip, c_port, s_ip, s_port = key
        F = packets.TCP_FLAGS
        self._emit(c_ip, s_ip, packets.build_tcp(c_port, s_port, conn["c_seq"], conn["s_seq"],
                                                 F["FIN"] | F["ACK"]), "c>s")
        conn["c_seq"] += 1       # FIN consumes one sequence number!
        self._emit(s_ip, c_ip, packets.build_tcp(s_port, c_port, conn["s_seq"], conn["c_seq"],
                                                 F["FIN"] | F["ACK"]), "s>c")
        conn["s_seq"] += 1
        self._emit(c_ip, s_ip, packets.build_tcp(c_port, s_port, conn["c_seq"], conn["s_seq"],
                                                 F["ACK"]), "c>s")
        conn["state"] = "CLOSED"
