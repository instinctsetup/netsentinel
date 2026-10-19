"""Train the ML add-on on generated scenario windows and save weights.

Run once before starting the server:  python train_window_model.py
"""
import asyncio
import json
from pathlib import Path
from netsentinel import ml_data

if __name__ == "__main__":
    clf, X, y = asyncio.run(ml_data.build_dataset(samples_per_class=8))
    out = Path(__file__).parent / "netsentinel" / "window_model.json"
    out.write_text(json.dumps(clf.to_json()))
    print(f"trained on {len(y)} windows -> {out}")
