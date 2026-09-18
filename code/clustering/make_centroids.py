import json
import numpy as np
from pathlib import Path
from collections import defaultdict

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent
EMB_PATH = BASE_DIR / "results" / "clustering" / "embeddings_codebert.npy"
IDS_PATH = BASE_DIR / "results" / "clustering" / "embeddings_ids.json"
INPUT_PATH = BASE_DIR / "results" / "clustering" / "all_functions.json"
LABEL_PATH = BASE_DIR / "results" / "clustering" / "labels.npy"

OUT_PATH = BASE_DIR / "results" / "clustering" / "cluster_centroids.json"
OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

# Load
embeddings = np.load(EMB_PATH)
labels = np.load(LABEL_PATH)

with open(IDS_PATH) as f:
    gt_ids = json.load(f)

with open(INPUT_PATH, encoding="utf-8") as f:
    all_data = json.load(f)["items"]

id_to_item = {item["gt_id"]: item for item in all_data}

# Build clusters
clusters = defaultdict(list)
for idx, (label, gid) in enumerate(zip(labels, gt_ids)):
    if label == -1:
        continue
    clusters[label].append((idx, gid))

# Extract representative sample based on centroid
centroid_samples = []

for cluster_id, members in clusters.items():
    idxs = [idx for idx, _ in members]

    X = embeddings[idxs]
    centroid = X.mean(axis=0)

    # Find the sample closest to the centroid
    dists = np.linalg.norm(X - centroid, axis=1)
    best_idx = idxs[np.argmin(dists)]

    gid = gt_ids[best_idx]
    item = id_to_item[gid].copy()

    item["cluster_id"] = int(cluster_id)
    item["cluster_size"] = len(members)

    centroid_samples.append(item)

print(f"Number of representative samples: {len(centroid_samples)}")

# Save
with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump({"items": centroid_samples}, f, indent=2, ensure_ascii=False)

print(f"Save complete: {OUT_PATH}")
