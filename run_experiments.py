"""Run the full experiment suite and log everything to docs/experiments/.

    python run_experiments.py            # full suite (~4 minutes)
    python run_experiments.py --quick    # smaller sample for a smoke run

Every run appends a record to docs/experiments/results.json (the dashboard
reads the latest one) and saves charts to docs/experiments/charts/.
"""
import argparse
import asyncio
import json
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from netsentinel import experiments

OUT = Path(__file__).parent / "docs" / "experiments"
CHARTS = OUT / "charts"
DARK = {"figure.facecolor": "#0d1117", "axes.facecolor": "#161b22",
        "axes.edgecolor": "#30363d", "axes.labelcolor": "#e6edf3",
        "text.color": "#e6edf3", "xtick.color": "#8b949e", "ytick.color": "#8b949e",
        "grid.color": "#21262d", "font.size": 11}


def save_charts(res):
    CHARTS.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update(DARK)

    # 1. ROC curve
    pts = res["roc"]["points"]
    fig, ax = plt.subplots(figsize=(5.2, 4.2))
    ax.plot([0, 1], [0, 1], "--", color="#8b949e", lw=1, label="coin flip")
    ax.plot([p["fpr"] for p in pts], [p["tpr"] for p in pts], "o-",
            color="#58a6ff", label=f"logistic regression (AUC={res['roc']['auc']})")
    ax.set_xlabel("false positive rate"); ax.set_ylabel("true positive rate")
    ax.set_title("ROC - ML add-on, held-out windows")
    ax.legend(); ax.grid(alpha=.4); fig.tight_layout()
    fig.savefig(CHARTS / "roc_curve.png", dpi=150); plt.close(fig)

    # 2. Feature ablation
    solo = res["feature_ablation"]["solo"]
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    names = [d["feature"] for d in solo][::-1]
    vals = [d["f1_solo"] for d in solo][::-1]
    colors = ["#3fb950" if v > 0.8 else ("#d29922" if v > 0.5 else "#f85149") for v in vals]
    ax.barh(names, vals, color=colors)
    ax.set_xlabel("F1 of a model using only this feature")
    ax.set_title(f"Which features carry detection alone? (all-features F1={res['feature_ablation']['baseline_f1']})")
    ax.grid(axis="x", alpha=.4); fig.tight_layout()
    fig.savefig(CHARTS / "feature_ablation.png", dpi=150); plt.close(fig)

    # 3. Train size curve
    curve = res["train_size_curve"]
    fig, ax = plt.subplots(figsize=(5.2, 4.2))
    x = [c["train_per_class"] for c in curve]
    m = [c["f1_mean"] for c in curve]; s = [c["f1_std"] for c in curve]
    ax.errorbar(x, m, yerr=s, fmt="o-", color="#d29922", capsize=4)
    ax.set_xlabel("training windows per class"); ax.set_ylabel("F1 (held-out)")
    ax.set_title("How much data does the ML add-on need?")
    ax.set_ylim(0, 1.05); ax.grid(alpha=.4); fig.tight_layout()
    fig.savefig(CHARTS / "train_size.png", dpi=150); plt.close(fig)

    # 4. Intensity curves
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    styles = {"port_scan": ("#58a6ff", "ports scanned"), "syn_flood": ("#f85149", "SYNs sent"),
              "dns_tunnel": ("#d29922", "tunnel chunks"), "ping_sweep": ("#3fb950", "hosts pinged"),
              "udp_flood": ("#bc8cff", "datagrams sent")}
    for kind, (color, xlabel) in styles.items():
        pts = res["intensity"][kind]
        ax.plot([p["intensity"] for p in pts], [p["detection_rate"] for p in pts],
                "o-", color=color, label=f"{kind} ({xlabel})")
    ax.set_xlabel("attack intensity (per scenario)"); ax.set_ylabel("detection rate / 5 trials")
    ax.set_title("How small an attack still trips the rule detectors")
    ax.set_ylim(-0.05, 1.05); ax.legend(fontsize=9); ax.grid(alpha=.4); fig.tight_layout()
    fig.savefig(CHARTS / "intensity.png", dpi=150); plt.close(fig)


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    samples = 4 if args.quick else 12
    t0 = time.time()
    print(f"collecting {samples * 6} labelled windows through the live pipeline...")
    rows = await experiments.collect_labeled_windows(samples)

    print("rules vs ML head-to-head...")
    train, test = experiments.split_rows(rows, 0.6, seed=17)
    ml = experiments.score(experiments.train_on(train), test)
    rules = experiments.rule_score(test)

    print("ROC sweep, k-fold CV, ablations, train-size curve...")
    res = {
        "run_id": time.strftime("%Y%m%d-%H%M%S"),
        "git": experiments._git_sha(),
        "samples_per_class": samples,
        "windows": len(rows),
        "duration_s": None,
        "rules_vs_ml": {"rules": {k: round(v, 4) if isinstance(v, float) else v
                                   for k, v in rules.items()},
                        "ml": {k: v for k, v in ml.items() if k not in ("scores", "y")}},
        "roc": experiments.roc_points(rows),
        "kfold_cv": experiments.kfold_cv(rows),
        "feature_ablation": experiments.feature_ablation(rows),
        "train_size_curve": experiments.train_size_curve(
            rows, sizes=(2, 3) if args.quick else (2, 4, 8, 12)),
        "intensity": await experiments.intensity_curve(),
    }
    res["duration_s"] = round(time.time() - t0, 1)

    OUT.mkdir(parents=True, exist_ok=True)
    runs = OUT / "runs"; runs.mkdir(exist_ok=True)
    (runs / f"{res['run_id']}.json").write_text(json.dumps(res, indent=2))
    results_file = OUT / "results.json"
    history = json.loads(results_file.read_text()) if results_file.exists() else []
    history.append({k: v for k, v in res.items()})
    results_file.write_text(json.dumps(history, indent=2))
    save_charts(res)
    print(f"done in {res['duration_s']}s -> {results_file}")
    print(json.dumps({"rules": res["rules_vs_ml"]["rules"],
                      "ml_f1": ml["f1"], "ml_auc": ml["auc"],
                      "cv": res["kfold_cv"]}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
