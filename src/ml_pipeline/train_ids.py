#!/usr/bin/env python3
"""
Train and evaluate the NetInfect hybrid IDS (Isolation Forest -> Random Forest).

What this script does, and why:
  * Features are computed per connection over a 2-second sliding window per
    source IP (features.py), the same way firewall_manager.py computes them live.
  * The Isolation Forest is fitted on benign traffic only, so its score means
    "how unlike normal traffic is this".
  * Train/test split is temporal (first 70% of each capture for training, the
    rest for testing), so consecutive windows of the same attack cannot end up
    on both sides. A random split is also computed, only to show how much more
    optimistic it is.
  * Leave-one-attack-out: for each attack type, train without it and check
    whether it is still detected. This is the honest test for "unseen attacks".
  * Metrics include false positive rate and false alarms per hour of benign
    traffic, because accuracy is meaningless when most traffic is benign.

Outputs: the models + model_manifest.json (with SHA-256 hashes) in this folder,
and reports/metrics.json + reports/evaluation.md at the repository root.
"""
import argparse
import json
import logging
import os
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features import FEATURES, WINDOW_SIZE, build_features, parse_zeek_log  # noqa: E402
from model_store import save_models, score  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(message)s")

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../.."))
LOG_DIR = os.path.join(ROOT, "lab/shared/zeek_logs")
REPORT_DIR = os.path.join(ROOT, "reports")

ALERT_THRESHOLD = 0.5  # probability above which an alert is raised
BLOCK_THRESHOLD = 0.9  # probability above which the source IP is blocked
TRAIN_FRACTION = 0.7
SEED = 42


def label_attack_phases(df, gap=0.3):
    """Assign an attack type to each connection of the attack capture.

    anomaly_traffic.py runs its phases one after the other with pauses in
    between, so we cut the capture at pauses longer than `gap` seconds and
    recognise each burst from its traffic pattern.
    """
    df = df.sort_values("ts").reset_index(drop=True)
    burst = (df["ts"].diff() > gap).cumsum()
    labels = pd.Series("unknown", index=df.index)
    for _, idx in df.groupby(burst).groups.items():
        g = df.loc[idx]
        ports = set(g["id.resp_p"].astype(int))
        if g["orig_bytes"].max() > 1_000_000:
            kind = "exfiltration"
        elif (g["conn_state"] == "REJ").any() or len(ports - {22, 80}) > 0:
            kind = "portscan"
        elif ports == {22}:
            kind = "ssh_bruteforce"
        elif g["duration"].max() > 4:
            kind = "slowloris"
        elif len(g) > 100:
            kind = "http_flood"
        else:
            kind = "web_attack"
        labels.loc[idx] = kind
    return df, labels.values


def temporal_split(ts, fraction=TRAIN_FRACTION):
    cut = ts.min() + fraction * (ts.max() - ts.min())
    return ts <= cut


def metrics(y_true, proba, threshold, benign_hours):
    y_pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "threshold": threshold,
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "false_positive_rate": round(fp / max(fp + tn, 1), 5),
        "false_alarms_per_hour": round(fp / benign_hours, 2) if benign_hours else None,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def fit(X_benign, X_train, y_train):
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=SEED)
    X_benign, X_train = np.asarray(X_benign, dtype=float), np.asarray(X_train, dtype=float)
    iso.fit(X_benign)
    stacked = np.column_stack([X_train, iso.decision_function(X_train)])
    rf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=SEED)
    rf.fit(stacked, y_train)
    return iso, rf


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--baseline", default=os.path.join(LOG_DIR, "baseline.log"))
    ap.add_argument("--attack", default=os.path.join(LOG_DIR, "test_attack.log"))
    args = ap.parse_args()

    for path in (args.baseline, args.attack):
        if not os.path.exists(path):
            logging.error(f"{path} not found. Record the captures first (see README).")
            sys.exit(1)

    benign_raw = parse_zeek_log(args.baseline)
    attack_raw, attack_type = label_attack_phases(parse_zeek_log(args.attack))
    if attack_raw["id.orig_h"].nunique() > 1:
        logging.warning("The attack capture contains more than one source IP: "
                        "benign connections in it would be labelled as attacks.")

    benign = build_features(benign_raw).assign(label=0, attack_type="benign")
    attack = build_features(attack_raw).assign(label=1, attack_type=attack_type)

    benign["train"] = temporal_split(benign["ts"]).values
    attack["train"] = temporal_split(attack["ts"]).values
    data = pd.concat([benign, attack], ignore_index=True)
    train, test = data[data["train"]], data[~data["train"]]

    benign_test_hours = (benign.loc[~benign["train"], "ts"].max() - benign.loc[~benign["train"], "ts"].min()) / 3600

    logging.info(f"Connections: {len(benign)} benign, {len(attack)} attack "
                 f"({', '.join(f'{k}={v}' for k, v in attack['attack_type'].value_counts().items())})")
    logging.info(f"Temporal split: train {len(train)} rows, test {len(test)} rows")

    # --- Main model: temporal split -------------------------------------------------
    iso, rf = fit(train.loc[train.label == 0, FEATURES], train[FEATURES], train["label"])
    proba, anomaly = score(iso, rf, test[FEATURES])
    report = {
        "unit": f"one Zeek connection, features over a {WINDOW_SIZE:.0f}s sliding window per source IP",
        "dataset": {
            "benign_connections": int(len(benign)),
            "attack_connections": int(len(attack)),
            "attack_types": {k: int(v) for k, v in attack["attack_type"].value_counts().items()},
            "train_rows": int(len(train)),
            "test_rows": int(len(test)),
            "benign_test_hours": round(benign_test_hours, 3),
        },
        "temporal_split": {
            "alert": metrics(test["label"], proba, ALERT_THRESHOLD, benign_test_hours),
            "block": metrics(test["label"], proba, BLOCK_THRESHOLD, benign_test_hours),
            "recall_by_attack_type": {
                t: round(float((proba[(test["attack_type"] == t).values] >= ALERT_THRESHOLD).mean()), 4)
                for t in sorted(test.loc[test.label == 1, "attack_type"].unique())
            },
            "isolation_forest_only_recall": round(float((anomaly[(test["label"] == 1).values] < 0).mean()), 4),
            "isolation_forest_only_fpr": round(float((anomaly[(test["label"] == 0).values] < 0).mean()), 4),
        },
    }

    # --- Trivial baseline: a single threshold rule, no ML --------------------------
    # If this already scores as well as the model, the dataset is too easy to say
    # anything about the model itself.
    rule = (test["conn_count"] >= 3).astype(float).values
    report["trivial_rule_conn_count_ge_3"] = metrics(test["label"], rule, 0.5, benign_test_hours)

    # --- For comparison only: random split (optimistic, leaks neighbouring windows) --
    tr, te = train_test_split(data, test_size=1 - TRAIN_FRACTION, random_state=SEED, stratify=data["label"])
    iso_r, rf_r = fit(tr.loc[tr.label == 0, FEATURES], tr[FEATURES], tr["label"])
    p_r, _ = score(iso_r, rf_r, te[FEATURES])
    report["random_split_for_comparison"] = metrics(te["label"], p_r, ALERT_THRESHOLD, None)

    # --- Leave-one-attack-out ---------------------------------------------------------
    loao = {}
    benign_train = data[(data.label == 0) & data["train"]]
    benign_test = data[(data.label == 0) & ~data["train"]]
    for t in sorted(attack["attack_type"].unique()):
        others = data[(data.label == 1) & (data.attack_type != t)]
        held_out = data[data.attack_type == t]
        tr_l = pd.concat([benign_train, others])
        iso_l, rf_l = fit(benign_train[FEATURES], tr_l[FEATURES], tr_l["label"])
        p_h, a_h = score(iso_l, rf_l, held_out[FEATURES])
        p_b, _ = score(iso_l, rf_l, benign_test[FEATURES])
        loao[t] = {
            "connections": int(len(held_out)),
            "recall_hybrid": round(float((p_h >= ALERT_THRESHOLD).mean()), 4),
            "recall_isolation_forest_only": round(float((a_h < 0).mean()), 4),
            "benign_fpr": round(float((p_b >= ALERT_THRESHOLD).mean()), 5),
        }
    report["leave_one_attack_out"] = loao

    # --- Save -----------------------------------------------------------------------
    manifest = save_models(iso, rf, {
        "features": FEATURES,
        "window_size_s": WINDOW_SIZE,
        "alert_threshold": ALERT_THRESHOLD,
        "block_threshold": BLOCK_THRESHOLD,
        "trained_on": {"baseline": os.path.basename(args.baseline), "attack": os.path.basename(args.attack)},
    })
    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(os.path.join(REPORT_DIR, "metrics.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(REPORT_DIR, "evaluation.md"), "w") as f:
        f.write(render_markdown(report))

    logging.info(json.dumps(report, indent=2))
    logging.info(f"Models saved to {HERE} (hashes in model_manifest.json: {list(manifest['sha256'])})")
    logging.info(f"Reports written to {REPORT_DIR}")


def render_markdown(r):
    d, ts = r["dataset"], r["temporal_split"]
    lines = [
        "# NetInfect – evaluation report",
        "",
        "Generated by `src/ml_pipeline/train_ids.py`. Unit: " + r["unit"] + ".",
        "",
        "## Dataset",
        "",
        f"- Benign connections: {d['benign_connections']} · attack connections: {d['attack_connections']}",
        "- Attack types: " + ", ".join(f"{k} ({v})" for k, v in d["attack_types"].items()),
        f"- Temporal split: {d['train_rows']} train rows, {d['test_rows']} test rows "
        f"({d['benign_test_hours'] * 60:.0f} minutes of benign test traffic)",
        "",
        "## Temporal split (main result)",
        "",
        "| Level | Threshold | Precision | Recall | F1 | FPR | False alarms / hour | TP | FP | FN | TN |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name in ("alert", "block"):
        m = ts[name]
        c = m["confusion_matrix"]
        lines.append(f"| {name} | {m['threshold']} | {m['precision']} | {m['recall']} | {m['f1']} | "
                     f"{m['false_positive_rate']} | {m['false_alarms_per_hour']} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} |")
    lines += [
        "",
        "Recall by attack type (alert threshold): "
        + ", ".join(f"{k} {v}" for k, v in ts["recall_by_attack_type"].items()),
        "",
        f"Isolation Forest alone (score < 0): recall {ts['isolation_forest_only_recall']}, "
        f"FPR {ts['isolation_forest_only_fpr']}.",
        "",
        "## Trivial baseline: `conn_count >= 3` in the window, no ML",
        "",
        f"F1 {r['trivial_rule_conn_count_ge_3']['f1']}, recall {r['trivial_rule_conn_count_ge_3']['recall']}, "
        f"precision {r['trivial_rule_conn_count_ge_3']['precision']}. When a one-line rule scores almost as well as the model, "
        "the dataset is too easy to judge the model: the simulated benign users open at most 2 connections every 2 seconds, "
        "while almost every attack is a burst.",
        "",
        "## Random split (for comparison only)",
        "",
        f"F1 {r['random_split_for_comparison']['f1']}, recall {r['random_split_for_comparison']['recall']}, "
        f"precision {r['random_split_for_comparison']['precision']}. A random split puts neighbouring windows of "
        "the same attack in both train and test, so it overstates performance.",
        "",
        "## Leave-one-attack-out (attack type never seen in training)",
        "",
        "| Held-out attack | Connections | Recall (hybrid) | Recall (Isolation Forest only) | Benign FPR |",
        "|---|---|---|---|---|",
    ]
    for t, m in r["leave_one_attack_out"].items():
        lines.append(f"| {t} | {m['connections']} | {m['recall_hybrid']} | {m['recall_isolation_forest_only']} | {m['benign_fpr']} |")
    lines += [
        "",
        "## Caveats",
        "",
        "- Both benign and attack traffic are synthetic and generated by this project's scripts; "
        "results describe this lab, not a real network.",
        "- The attack capture contains three runs of the same attack script, so the test set is small "
        "and very similar to the training set.",
        "- web_attack is an L7 attack: at the connection level it looks like normal browsing. It is caught here "
        "mostly because the same source IP was scanning and brute-forcing in the same 2-second window; "
        "on its own it is the WAF's job.",
        "- The Isolation Forest alone flags a large share of benign traffic; the Random Forest is what makes "
        "the alerts precise.",
        "",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
