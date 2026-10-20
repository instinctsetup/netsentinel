"""End-to-end: real sockets, real DNS wire format, real exfil round-trip."""
import asyncio
import pytest
from netsentinel import flows, generator, stack as stack_mod


@pytest.fixture()
def services():
    svc = generator.LabServices()
    svc.serve_forever()
    yield svc
    svc.close()


def test_dns_tunnel_exfiltrates_and_reassembles(services):
    events = []
    st = stack_mod.VirtualStack(events.append)
    secret = b"the crow flies at midnight"
    asyncio.run(generator.dns_tunnel(st, services, secret=secret))
    asyncio.run(asyncio.sleep(0.2))
    assert generator.decode_tunnel_chunks(services.tunnel_chunks) == secret
    assert any(e.get("app") == "DNS" for e in events)


def test_web_session_produces_full_tcp_lifecycle(services):
    table = flows.FlowTable()
    st = stack_mod.VirtualStack(lambda p: table.update(p))
    asyncio.run(generator.normal_web_session(st, services))
    states = [f["state"] for f in table.flows.values()]
    assert "CLOSED" in states and table.half_open() == 0
    web_flow = max(table.flows.values(), key=lambda f: f["packets"])
    assert web_flow["packets"] >= 6  # handshake(3) + req + resp + teardown(3+)


def test_port_scan_uses_real_connect_attempts(services):
    events = []
    st = stack_mod.VirtualStack(events.append)
    asyncio.run(generator.port_scan(st, services, ports=[services.http_port, 1, 2, 3]))
    syns = [e for e in events if "tcp" in e and e["tcp"]["flags"] == ["SYN"]]
    assert len(syns) == 4


def test_udp_flood_respects_target_port(services):
    events = []
    st = stack_mod.VirtualStack(events.append)
    asyncio.run(generator.udp_flood(st, services, target_port=4321, count=25))
    ports = {e["udp"]["dst_port"] for e in events if "udp" in e}
    assert ports == {4321}
