# netsentinel

**A self-contained network security lab: build real protocol packets byte-by-byte, generate genuine socket traffic (normal *and* hostile), assemble flows, and catch the attacks — with a live dashboard, a packet inspector, and a logged experiment suite.**

Built for a Computer Networks course project. The networking comes first: every packet on the dashboard is constructed and parsed at the byte level (IPv4, TCP, UDP, ICMP, DNS wire formats), every connection is driven through real localhost sockets, and every alert is explained in networking terms. A from-scratch logistic regression is included as an ML add-on so rule-based and learned detection can be compared live — and evaluated honestly.

## Demo video & report

- **Demo video (Drive):** https://drive.google.com/file/d/1Kj8kqqpoPvqIEeUY7LJcmwIF0bEv4zBo/view
- **PDF report (Drive):** https://drive.google.com/file/d/1dbRsSfcYjGVwDhU-lpIJJ5IwjlMmGQmM/view
- Also in-repo: [`docs/report/REPORT.pdf`](docs/report/REPORT.pdf), [`demo/netsentinel-demo.mp4`](demo/netsentinel-demo.mp4)

## What it does

| Capability | Where | The networking concept it teaches |
|---|---|---|
| Byte-level IPv4/TCP/UDP/ICMP/DNS builders + parsers | `netsentinel/packets.py` | header layout, checksums (RFC 1071), flags, DNS label encoding |
| Virtual TCP stack with correct seq/ack arithmetic | `netsentinel/stack.py` | 3-way handshake, FIN consuming a sequence number, teardown |
| Bidirectional flow assembly + TCP state machine | `netsentinel/flows.py` | 5-tuples, half-open connections |
| Traffic generator: real HTTP sessions, real DNS | `netsentinel/generator.py` | sockets, client/server exchange |
| **Attack 1: TCP port scan** (real `connect()` attempts) | `generator.py` | SYN fan-out, RST replies from closed ports |
| **Attack 2: SYN flood** (crafted segments injected) | `generator.py` | half-open exhaustion, spoofed sources |
| **Attack 3: DNS tunnelling** (real exfiltration) | `generator.py` | label length limits, base32, DNS as a covert channel |
| **Attack 4: ICMP ping sweep** | `generator.py` | subnet discovery, echo request/reply (RFC 792) |
| **Attack 5: UDP flood** | `generator.py` | connectionless volumetrics, no state to protect the victim |
| Rule detectors: scan / flood / tunnel / sweep / UDP flood | `netsentinel/detectors.py` | behavioural signatures, Shannon entropy |
| ML add-on: logistic regression from scratch | `detectors.py`, `ml_data.py` | 13 window features, sigmoid, cross-entropy |
| Live dashboard: feed, flows, alerts, ML meter, throughput chart | `server.py`, `frontend/` | watching the above happen in real time |
| **Packet inspector**: click any packet → decoded fields + raw hex dump | `frontend/`, `/api/packet/{id}` | proof the packets are real wire format |
| **Experiment suite**: logged runs, ROC, k-fold CV, feature analysis, detection-vs-intensity | `netsentinel/experiments.py`, `run_experiments.py` | honest evaluation, reproducibility |

## Quick start

```bash
pip install -r requirements.txt
python train_window_model.py        # trains the ML add-on (~20s, generates traffic)
uvicorn server:app --port 8000
# open http://localhost:8000 and press the attack buttons
```

With Docker (self-contained: the model trains at image build time):

```bash
docker build -t netsentinel . && docker run -p 8000:8000 netsentinel
```

Run the tests and the experiment suite:

```bash
python -m pytest tests -q        # 27 tests: parsers, state machine, detectors, scenarios, API
python run_experiments.py        # ~4 min; appends a logged run to docs/experiments/results.json
```

The dashboard's **Experiments** tab reads `docs/experiments/results.json` — the numbers on screen are always the last real run, never hard-coded. The latest run measured, honestly:

- detection-vs-intensity thresholds: port scans ≥ 12 ports, SYN floods ≥ 30 SYNs, ping sweeps ≥ 10 hosts, UDP floods ≥ 60 datagrams/window are caught 5/5; below that, attacks slip through (and the charts say so)
- a learning curve: held-out F1 climbs 0.61 → 1.00 as training windows per class go 2 → 12
- single-feature analysis: which of the 13 features can separate attack from benign on their own

## Honest engineering notes

- **No root, no problem.** Loopback sniffing needs `CAP_NET_RAW`; instead, the generator drives real sockets and a `VirtualStack` emits the exact segments the kernel would exchange (correct flags and seq/ack arithmetic). Crafted-packet attacks (SYN flood, ping sweep) inject the identical bytes a raw socket would send. The analyzer cannot tell the difference, which is the point.
- The ML add-on is deliberately small and trained on *generated* traffic, so its scores measure separability of the lab's traffic, not the internet's. That limitation is printed on the dashboard and in the report; the interesting numbers are the thresholds and learning curves above.
- UDP/53 traffic that is not parseable DNS is labelled `UDP/53` — non-DNS bytes on port 53 are themselves suspicious.
- Everything is dependency-light: FastAPI + NumPy only. No scapy, no sklearn.

## Project layout

```
netsentinel/   packets.py  stack.py  flows.py  generator.py  detectors.py  metrics.py  ml_data.py  experiments.py
server.py      FastAPI app: attack console API + WebSocket dashboard feed + experiments API
frontend/      dependency-free dashboard (vanilla JS, canvas charts, packet inspector)
tests/         27 pytest tests, including real-socket integration tests and API smoke tests
docs/          MATH.md (every formula, in words), VIVA.md (likely questions), report/, experiments/
demo/          demo video (WhatsApp-friendly)
```
