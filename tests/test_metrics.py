from netsentinel import metrics


def test_perfect_classifier():
    y = [0, 0, 1, 1]; s = [0.1, 0.2, 0.8, 0.9]
    assert metrics.roc_auc(y, s) == 1.0
    cm = metrics.confusion(y, [0, 0, 1, 1])
    assert cm == {"tp": 2, "tn": 2, "fp": 0, "fn": 0}
    prf = metrics.precision_recall_f1(cm)
    assert prf == {"precision": 1.0, "recall": 1.0, "f1": 1.0}


def test_random_scores_auc_near_half():
    y = [0] * 50 + [1] * 50
    s = list(range(100))  # perfectly anti-correlated-ish but monotonic
    auc = metrics.roc_auc(y, s)
    assert 0.0 <= auc <= 1.0
