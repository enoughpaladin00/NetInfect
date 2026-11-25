#!/usr/bin/env python3
"""
Saving and loading the NetInfect models with an integrity check.

joblib/pickle files execute code when they are loaded, so loading a tampered
model file is equivalent to running an attacker's script. Before loading, we
check every model file against the SHA-256 recorded in model_manifest.json.

Limitation: the manifest lives next to the models, so an attacker who can write
to this folder can replace both. This check catches accidental corruption and
a swapped single file; real protection needs a signed manifest (or a key kept
elsewhere) and/or a non-executable format such as skops or ONNX.
"""
import hashlib
import json
import os

import joblib

MODEL_DIR = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(MODEL_DIR, "model_manifest.json")
FILES = {"iso": "ids_iso_model.pkl", "rf": "ids_model.pkl"}


class ModelIntegrityError(RuntimeError):
    pass


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def save_models(iso_model, rf_model, metadata, model_dir=MODEL_DIR):
    hashes = {}
    for key, obj in (("iso", iso_model), ("rf", rf_model)):
        path = os.path.join(model_dir, FILES[key])
        joblib.dump(obj, path)
        hashes[FILES[key]] = _sha256(path)
    manifest = dict(metadata, sha256=hashes)
    with open(os.path.join(model_dir, "model_manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def load_models(model_dir=MODEL_DIR):
    """Return (iso_model, rf_model, manifest). Raises if a file is missing or altered."""
    manifest_path = os.path.join(model_dir, "model_manifest.json")
    if not os.path.exists(manifest_path):
        raise FileNotFoundError("model_manifest.json not found: run src/ml_pipeline/train_ids.py first.")
    with open(manifest_path) as f:
        manifest = json.load(f)
    models = {}
    for key, name in FILES.items():
        path = os.path.join(model_dir, name)
        expected = manifest.get("sha256", {}).get(name)
        if not os.path.exists(path):
            raise FileNotFoundError(f"{name} not found: run src/ml_pipeline/train_ids.py first.")
        if expected is None or _sha256(path) != expected:
            raise ModelIntegrityError(f"{name} does not match the hash in model_manifest.json: refusing to load it.")
        models[key] = joblib.load(path)
    return models["iso"], models["rf"], manifest


def score(iso_model, rf_model, X):
    """Hybrid scoring: Isolation Forest anomaly score stacked as an extra feature for the Random Forest.

    Returns (attack_probability, anomaly_score). Tree models are scale-invariant,
    so no scaler is needed.
    """
    import numpy as np

    X = np.asarray(X, dtype=float)
    anomaly = iso_model.decision_function(X)
    proba = rf_model.predict_proba(np.column_stack([X, anomaly]))[:, 1]
    return proba, anomaly
