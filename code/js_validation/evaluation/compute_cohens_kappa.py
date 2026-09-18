"""
JS LLM justification evaluation helper.

What it does:
1. Loads the two human label sets from human_labeling_all.csv
2. Computes Cohen's kappa in two ways:
   - exact multi-label string agreement
   - macro-average binary kappa across labels A-U
3. Creates a disagreement file for manual adjudication
4. Evaluates every model result JSON against the `gold` column when it exists
   (fallbacks: agreed/h1/h2 modes for older files)

Outputs are written next to this script.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

from sklearn.metrics import cohen_kappa_score

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

ALL_LABELS = list("ABCDEFGHIJKLMNOPQRSTU")


def parse_labels(raw: str) -> Set[str]:
    return {part.strip() for part in raw.split(",") if part.strip()}


def canonical_label(raw: str) -> str:
    labels = sorted(parse_labels(raw))
    return ", ".join(labels)


def load_human_labels(path: Path) -> List[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build_gold(rows: List[dict], mode: str) -> Tuple[Dict[int, Set[str]], List[dict], dict]:
    gold: Dict[int, Set[str]] = {}
    disagreements: List[dict] = []

    h1 = []
    h2 = []
    labels_seen = set()

    for row in rows:
        rid = int(row["id"])
        h1_raw = canonical_label(row["h1_label"])
        h2_raw = canonical_label(row["h2_label"])
        h1.append(h1_raw)
        h2.append(h2_raw)
        labels_seen.update(parse_labels(h1_raw))
        labels_seen.update(parse_labels(h2_raw))

        if h1_raw != h2_raw:
            disagreements.append(
                {
                    "id": rid,
                    "h1_label": h1_raw,
                    "h2_label": h2_raw,
                }
            )

        if "gold" in row and row["gold"].strip():
            gold[int(row["id"])] = parse_labels(row["gold"])
            continue

        if mode == "agreed":
            if h1_raw == h2_raw:
                gold[rid] = parse_labels(h1_raw)
        elif mode == "h1":
            gold[rid] = parse_labels(h1_raw)
        elif mode == "h2":
            gold[rid] = parse_labels(h2_raw)
        else:
            raise ValueError(f"Unsupported gold mode: {mode}")

    exact_string_kappa = cohen_kappa_score(h1, h2)

    per_label_kappa = {}
    for lbl in sorted(labels_seen):
        y1 = [int(lbl in parse_labels(v)) for v in h1]
        y2 = [int(lbl in parse_labels(v)) for v in h2]
        per_label_kappa[lbl] = round(cohen_kappa_score(y1, y2), 6)

    summary = {
        "n_samples": len(rows),
        "exact_agreement": sum(1 for a, b in zip(h1, h2) if a == b),
        "exact_agreement_rate": round(sum(1 for a, b in zip(h1, h2) if a == b) / len(rows), 6),
        "exact_string_kappa": round(exact_string_kappa, 6),
        "macro_binary_kappa": round(sum(per_label_kappa.values()) / len(per_label_kappa), 6),
        "per_label_kappa": per_label_kappa,
        "n_labels": len(labels_seen),
    }

    return gold, disagreements, summary


def load_model_predictions(path: Path) -> Dict[int, Set[str]]:
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    return {int(item["id"]): set(item.get("all_labels_code", [])) for item in data}


def compute_multilabel_metrics(gold: Dict[int, Set[str]], pred: Dict[int, Set[str]]) -> dict:
    ids = sorted(set(gold) & set(pred))
    n = len(ids)
    if n == 0:
        raise ValueError("No overlapping ids between gold labels and model predictions.")

    exact_match = sum(1 for idx in ids if gold[idx] == pred[idx]) / n
    hamming_accuracy = sum(
        int((lbl in gold[idx]) == (lbl in pred[idx]))
        for idx in ids
        for lbl in ALL_LABELS
    ) / (n * len(ALL_LABELS))
    jaccard = sum(
        (len(gold[idx] & pred[idx]) / len(gold[idx] | pred[idx])) if (gold[idx] | pred[idx]) else 1.0
        for idx in ids
    ) / n

    per_label = {}
    macro_p = macro_r = macro_f1 = 0.0
    micro_tp = micro_fp = micro_fn = 0

    for lbl in ALL_LABELS:
        tp = sum(1 for idx in ids if lbl in gold[idx] and lbl in pred[idx])
        fp = sum(1 for idx in ids if lbl not in gold[idx] and lbl in pred[idx])
        fn = sum(1 for idx in ids if lbl in gold[idx] and lbl not in pred[idx])

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

        per_label[lbl] = {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
            "support": sum(1 for idx in ids if lbl in gold[idx]),
        }

        macro_p += precision
        macro_r += recall
        macro_f1 += f1
        micro_tp += tp
        micro_fp += fp
        micro_fn += fn

    macro_p /= len(ALL_LABELS)
    macro_r /= len(ALL_LABELS)
    macro_f1 /= len(ALL_LABELS)
    micro_p = micro_tp / (micro_tp + micro_fp) if (micro_tp + micro_fp) else 0.0
    micro_r = micro_tp / (micro_tp + micro_fn) if (micro_tp + micro_fn) else 0.0
    micro_f1 = 2 * micro_p * micro_r / (micro_p + micro_r) if (micro_p + micro_r) else 0.0

    return {
        "n_samples": n,
        "exact_match_accuracy": round(exact_match, 6),
        "hamming_accuracy": round(hamming_accuracy, 6),
        "jaccard_similarity": round(jaccard, 6),
        "macro_precision": round(macro_p, 6),
        "macro_recall": round(macro_r, 6),
        "macro_f1": round(macro_f1, 6),
        "micro_precision": round(micro_p, 6),
        "micro_recall": round(micro_r, 6),
        "micro_f1": round(micro_f1, 6),
        "per_label": per_label,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--human-labels",
        type=Path,
        default=BASE_DIR / "data" / "js_validation" / "human_labels.csv",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=BASE_DIR / "results" / "js_validation" / "model_outputs",
    )
    parser.add_argument(
        "--gold-mode",
        choices=["gold", "agreed", "h1", "h2"],
        default="gold",
        help="Use the gold column when available, otherwise fall back to a human-label mode.",
    )
    args = parser.parse_args()

    rows = load_human_labels(args.human_labels)
    if args.gold_mode == "gold" and "gold" not in rows[0]:
        args.gold_mode = "agreed"

    gold, disagreements, human_summary = build_gold(rows, args.gold_mode)

    out_dir = BASE_DIR / "results" / "js_validation" / "metrics"
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "human_agreement_summary.json").write_text(
        json.dumps(human_summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    with (out_dir / "human_disagreements.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "h1_label", "h2_label"])
        writer.writeheader()
        writer.writerows(disagreements)

    model_files = sorted(
        p for p in glob.glob(str(args.results_dir / "results_*.json")) if "_metrics" not in p
    )

    model_scores = {}
    for model_path in model_files:
        model_name = Path(model_path).stem.replace("results_", "")
        pred = load_model_predictions(Path(model_path))
        model_scores[model_name] = compute_multilabel_metrics(gold, pred)

    (out_dir / "js_evaluation_summary.json").write_text(
        json.dumps(model_scores, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(json.dumps(human_summary, ensure_ascii=False, indent=2))
    print(f"\nSaved: {out_dir / 'human_agreement_summary.json'}")
    print(f"Saved: {out_dir / 'human_disagreements.csv'}")
    print(f"Saved: {out_dir / 'js_evaluation_summary.json'}")


if __name__ == "__main__":
    main()
