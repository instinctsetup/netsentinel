# netsentinel

**A self-contained network security lab: build real protocol packets byte-by-byte, generate genuine socket traffic (normal *and* hostile), assemble flows, and catch the attacks - with a live dashboard.**

Built for a Computer Networks course project. The networking comes first: every packet on the dashboard is constructed and parsed at the byte level (IPv4, TCP, UDP, DNS wire formats), every connection is driven through real localhost sockets, and every alert is explained in networking terms. A small from-scratch logistic regression is included as an ML add-on so rule-based and learned detection can be compared live.

## What it does

| Capability | Where | The networking concept it teaches |
|---|---|---|
| Byte-level IPv4/TCP/UDP/DNS builders + parsers | `netsentinel/packets.py` | header layout, checksums, flags, DNS label encoding |
| Virtual TCP stack with correct seq/ack arithmetic | `netsentinel/stack.py` | 3-way handshake, FIN consuming a sequence number, teardown |
| Bidirectional flow assembly + TCP state machine | `netsentinel/flows.py` | 5-tuples, half-open connections |
| Traffic generator: real HTTP sessions, real DNS | `netsentinel/generator.py` | sockets, client/server exchange |
| **Attack 1: TCP port scan** (real `connect()` attempts) | `generator.py` | SYN fan-out, RST replies from closed ports |
| **Attack 2: SYN flood** (crafted segments injected) | `generator.py` | half-open exhaustion, spoofed sources |
| **Attack 3: DNS tunnelling** (real exfiltration) | `generator.py` | label length limits, base32, why DNS is a covert channel |
| Rule detectors: scan / flood / tunnel | `netsentinel/detectors.py` | behavioural signatures, Shannon entropy |
| ML add-on: logistic regression from scratch | `detectors.py`, `ml_data.py` | features from flows, sigmoid, cross-entropy |
| Live dashboard (packet feed, flow table, alerts, ML meter) | `server.py`, `frontend/` | watching the above happen in real time |

## Quick start

```bash
pip install -r requirements.txt
python train_window_model.py        # trains the ML add-on (~20s, generates traffic)
uvicorn server:app --port 8000
# open http://localhost:8000 and press the attack buttons
```

Run the tests:

```bash
python -m pytest tests -q    # 17 tests: parsers, state machine, detectors, end-to-end
```

## What a demo looks like

1. Press **Normal browsing** - watch SYN / SYN-ACK / ACK, an HTTP request/response, FIN teardown; the flow reaches `CLOSED`, zero half-open.
2. Press **Launch port scan** - 100 SYNs fan out to 100 ports; closed ports RST instantly; `[PORT_SCAN]` alert fires ("nobody browses like that").
3. Press **Launch SYN flood** - 150 crafted SYNs from spoofed TEST-NET addresses; the flow table fills with `SYN_SENT`; half-open counter explodes; `[SYN_FLOOD]` fires.
4. Press **Launch DNS tunnel** - a secret sentence is base32-encoded into DNS labels and exfiltrated through a real local resolver; `[DNS_TUNNEL]` fires on label length + entropy.

`docs/run-evidence.json` holds a captured run of all four scenarios with alert and ML verdicts.

## Honest engineering notes

- **No root, no problem.** Loopback sniffing needs `CAP_NET_RAW`; instead, the generator drives real sockets and a `VirtualStack` emits the exact segments the kernel would exchange (correct flags and seq/ack arithmetic). Crafted-packet attacks (the flood) inject segments directly - on a real interface the identical bytes would leave via raw sockets. The analyzer cannot tell the difference, which is the point.
- The ML add-on is deliberately small. It is trained on windows of *generated* traffic (same pipeline as live detection), so its accuracy is real but its world is the lab. The rule-based detectors are the primary line of defence; the comparison is the lesson.
- Everything is dependency-light: FastAPI + NumPy only. No scapy, no sklearn.

## Project layout

```
netsentinel/   packets.py  stack.py  flows.py  generator.py  detectors.py  metrics.py  ml_data.py
server.py      FastAPI app: attack console API + WebSocket dashboard feed
frontend/      dependency-free dashboard (vanilla JS)
tests/         17 pytest tests, including real-socket integration tests
docs/          MATH.md (every formula, in words), VIVA.md (likely questions), run-evidence.json
```

## Docs

- [docs/MATH.md](docs/MATH.md) - checksums, entropy, sigmoid/cross-entropy, derived in plain words
- [docs/VIVA.md](docs/VIVA.md) - the questions a professor will ask, with answers
