# Viva questions you should expect, with answers

**Q: Why is this a *networks* project and not an ML project?**
Every packet is built and parsed at the byte level (IPv4/TCP/UDP/DNS), connections run over real sockets, flows are assembled by 5-tuple, and the primary detectors reason about protocol behaviour - SYN fan-out, half-open connections, DNS label structure. The ML is one small add-on comparing learned vs rule-based detection.

**Q: Walk me through a normal web request on your dashboard.**
SYN, SYN-ACK, ACK (handshake); PSH+ACK carrying the GET; PSH+ACK back with the response; FIN/ACK, FIN/ACK, ACK (teardown). Watch the flow's state move SYN_SENT -> SYN_RECEIVED -> ESTABLISHED -> FIN_WAIT -> CLOSED.

**Q: How does the port-scan detector work?**
Within a sliding window it groups SYN packets by source. A normal client touches 1-2 ports; a scanner touches dozens. Distinct destination ports above a threshold fires the alert. The RST replies from closed ports corroborate it.

**Q: Why can't the sender of a SYN flood just be blocked by IP?**
The source addresses are spoofed (we use the documentation range 203.0.113.x for the demo). Each SYN looks like a new client. The signal is structural: handshakes never complete, so half-open count climbs while established count stays flat.

**Q: Explain DNS tunnelling. Why base32?**
DNS labels allow letters, digits, hyphens. Base32 encodes arbitrary bytes using only A-Z and 2-7 - all legal. Chunks become labels of a query to a domain the attacker controls; the resolver's log *is* the exfiltrated data. Our detector catches it with label length + Shannon entropy, because encoded data looks nothing like English.

**Q: What is a half-open connection?**
SYN received, SYN-ACK sent, final ACK never arrived. The flow sits in SYN_RECEIVED. Real servers queue these; a flood exhausts the queue (that is the historical SYN-flood attack, and SYN cookies are the real-world fix - worth mentioning).

**Q: Why is your TCP stack "virtual"?**
Unprivileged processes cannot sniff loopback, so the generator drives real sockets and the stack emits the exact segments a kernel would exchange - with correct sequence arithmetic. The analyzer path (parse -> flows -> detect) is identical to what it would be with a pcap feed; on a Linux box with sudo the same code attaches to AF_PACKET.

**Q: Where could the ML add-on beat the rules?**
Rules need a human to anticipate the attack shape. A learned model can weigh soft evidence (a scan done very slowly, tunnelling with shorter labels) where fixed thresholds fail. Its weakness: it only knows the windows it was trained on - concept drift. Hence both, side by side.

**Q: What would you add next?**
UDP amplification simulation, periodicity detection (beaconing), exporting pcaps for Wireshark, and running the analyzer on a real interface with sudo.
