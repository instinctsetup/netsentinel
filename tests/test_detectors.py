"""Each attack must trip its rule; benign traffic must not."""
from netsentinel import detectors


def test_shannon_entropy_orders_text():
    assert detectors.shannon_entropy("aaaaaa") < detectors.shannon_entropy("a1b2c3d4e5")
    assert detectors.shannon_entropy("www") < 3.0


def test_port_scan_rule_fires():
    feats = {"syn": 40, "syn_ack": 2, "rst": 38, "dns": 0, "http": 0, "udp": 0,
             "max_distinct_ports": 40, "max_syn_target": 1, "avg_label_len": 0, "avg_label_entropy": 0}
    kinds = [a["kind"] for a in detectors.rule_alerts(feats, half_open=2)]
    assert "PORT_SCAN" in kinds


def test_syn_flood_rule_fires():
    feats = {"syn": 150, "syn_ack": 0, "rst": 0, "dns": 0, "http": 0, "udp": 0,
             "max_distinct_ports": 1, "max_syn_target": 150, "avg_label_len": 0, "avg_label_entropy": 0}
    kinds = [a["kind"] for a in detectors.rule_alerts(feats, half_open=150)]
    assert "SYN_FLOOD" in kinds


def test_dns_tunnel_rule_fires():
    feats = {"syn": 0, "syn_ack": 0, "rst": 0, "dns": 6, "http": 0, "udp": 6,
             "max_distinct_ports": 0, "max_syn_target": 0,
             "avg_label_len": 44.0, "avg_label_entropy": 4.1}
    kinds = [a["kind"] for a in detectors.rule_alerts(feats, half_open=0)]
    assert "DNS_TUNNEL" in kinds


def test_benign_window_is_quiet():
    feats = {"syn": 3, "syn_ack": 3, "rst": 0, "dns": 2, "http": 3, "udp": 2,
             "max_distinct_ports": 1, "max_syn_target": 1,
             "avg_label_len": 12.0, "avg_label_entropy": 2.4}
    assert detectors.rule_alerts(feats, half_open=0) == []


def test_ml_classifier_separates():
    import numpy as np
    clf = detectors.WindowClassifier()
    benign = np.array([[3, 3, 0, 2, 3, 2, 1, 1, 12, 2.4]] * 10, dtype=float)
    attack = np.array([[150, 0, 0, 0, 0, 0, 1, 150, 0, 0]] * 10, dtype=float)
    X = np.vstack([benign, attack]); y = np.array([0]*10 + [1]*10, dtype=float)
    clf.fit(X, y, epochs=1500)
    assert clf.predict_proba(dict(zip(detectors.FEATURE_ORDER, attack[0]))) > 0.9
    assert clf.predict_proba(dict(zip(detectors.FEATURE_ORDER, benign[0]))) < 0.1
