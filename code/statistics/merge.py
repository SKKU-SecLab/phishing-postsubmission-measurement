#!/usr/bin/env python3
"""
Merges rq3_static/dynamic_exfil_targets.csv + rq3_static/dynamic_server_actions.csv
into a single table grouped by Credential Exfiltration channel.

- exfil_targets: classifies the exfil_target string per row and sums static/dynamic counts
- server_actions: mail->Email, fwrite->Local File Logging, telegram->Telegram,
  curl->Custom Web Panel / HTTP outbound
- curl (exfil): telegram.org -> Telegram; geoplugin / api.ip.sb geo -> excluded;
  everything else (internal variables such as $url, etc.) -> Custom Web Panel / HTTP outbound

Usage:
  python merge.py --out-dir results/statistics
"""

from __future__ import annotations

import argparse
import csv
import os
import re
from collections import Counter
from typing import Dict, Optional, Tuple

# Output row order
CHANNEL_ORDER = [
    "Email-based Exfiltration",
    "Messaging APIs (Telegram)",
    "Custom Web Panel / HTTP outbound",
    "Local File Logging",
]

# IP / Geo lookup -- excluded from collection (applies only to curl: entries in exfil_targets)
_GEO_EXCLUDE_SUBSTR = (
    "geoplugin.net",
    "api.ip.sb/geoip",
    "api.ip.sb/",
)


def _norm_exfil(s: str) -> str:
    s = (s or "").strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        s = s[1:-1]
    return s.strip()


def classify_exfil_target(exfil_target: str) -> Optional[str]:
    """
    Returns canonical channel name, or None if excluded (IP/Geo),
    or None if unclassified (should not happen for top rows).
    """
    raw = _norm_exfil(exfil_target)
    low = raw.lower()

    if low.startswith("email:"):
        return "Email-based Exfiltration"

    if low.startswith("telegram:"):
        return "Messaging APIs (Telegram)"

    if low.startswith("curl:"):
        rest = low[5:]
        if "api.telegram.org" in rest:
            return "Messaging APIs (Telegram)"
        for sub in _GEO_EXCLUDE_SUBSTR:
            if sub in rest:
                return None  # excluded
        # curl: + internal variable / other URL (e.g., postmark)
        return "Custom Web Panel / HTTP outbound"

    # legacy form with just an email address, no "email:" prefix
    if re.search(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b", raw, re.I) and "email" in low[:80]:
        return "Email-based Exfiltration"

    return "Email-based Exfiltration" if low.startswith("email") else None


def load_exfil_csv(path: str) -> Counter:
    """channel -> count"""
    by_ch = Counter()
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            t = row.get("exfil_target") or ""
            c = int((row.get("count") or "0").strip() or 0)
            ch = classify_exfil_target(t)
            if ch:
                by_ch[ch] += c
    return by_ch


def load_server_actions_csv(path: str) -> Dict[str, int]:
    """action_type -> count"""
    out: Dict[str, int] = {}
    with open(path, newline="", encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            at = (row.get("action_type") or "").strip().lower()
            if not at:
                continue
            out[at] = int((row.get("count") or "0").strip() or 0)
    return out


def map_server_action_to_channel(action_type: str) -> Optional[str]:
    m = {
        "mail": "Email-based Exfiltration",
        "fwrite": "Local File Logging",
        "telegram": "Messaging APIs (Telegram)",
        "curl": "Custom Web Panel / HTTP outbound",
    }
    return m.get(action_type.lower())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-dir",
        default="results/statistics",
        help="Output directory from statistics.py (must contain the rq3_*.csv files it produced)",
    )
    ap.add_argument(
        "--output",
        default="",
        help="Default: out-dir/credential_exfiltration_channels.csv",
    )
    args = ap.parse_args()

    base = args.out_dir
    paths = {
        "static_exfil": os.path.join(base, "rq3_static_exfil_targets.csv"),
        "dynamic_exfil": os.path.join(base, "rq3_dynamic_exfil_targets.csv"),
        "static_sa": os.path.join(base, "rq3_static_server_actions.csv"),
        "dynamic_sa": os.path.join(base, "rq3_dynamic_server_actions.csv"),
    }

    for k, p in paths.items():
        if not os.path.isfile(p):
            raise SystemExit(f"missing file: {p}")

    static_exfil = load_exfil_csv(paths["static_exfil"])
    dynamic_exfil = load_exfil_csv(paths["dynamic_exfil"])

    static_sa = load_server_actions_csv(paths["static_sa"])
    dynamic_sa = load_server_actions_csv(paths["dynamic_sa"])

    static_tot = Counter(static_exfil)
    dynamic_tot = Counter(dynamic_exfil)

    for at, cnt in static_sa.items():
        ch = map_server_action_to_channel(at)
        if ch:
            static_tot[ch] += cnt

    for at, cnt in dynamic_sa.items():
        ch = map_server_action_to_channel(at)
        if ch:
            dynamic_tot[ch] += cnt

    out_path = args.output or os.path.join(base, "credential_exfiltration_channels.csv")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)

    rows = []
    for ch in CHANNEL_ORDER:
        s = static_tot.get(ch, 0)
        d = dynamic_tot.get(ch, 0)
        rows.append(
            {
                "channel": ch,
                "static_count": s,
                "dynamic_count": d,
                "combined": s + d,
            }
        )

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=["channel", "static_count", "dynamic_count", "combined"],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"[OK] {len(rows)} rows -> {out_path}")
    for row in rows:
        print(f"     {row['channel']}: static={row['static_count']} dynamic={row['dynamic_count']} combined={row['combined']}")


if __name__ == "__main__":
    main()
