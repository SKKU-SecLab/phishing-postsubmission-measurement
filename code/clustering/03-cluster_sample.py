import json
import numpy as np
import random
import time
from pathlib import Path
from sklearn.preprocessing import normalize
from sklearn.metrics import silhouette_score
from collections import defaultdict
from itertools import product

# GPU HDBSCAN (cuML) -> CPU fallback on failure
try:
    from cuml.cluster import HDBSCAN as cuHDBSCAN
    from cuml.metrics import trustworthiness
    import cupy as cp
    USE_GPU = True
    print("Using cuML GPU HDBSCAN")
except ImportError:
    import hdbscan
    USE_GPU = False
    print("cuML not found -> CPU HDBSCAN fallback")

BASE_DIR   = Path(__file__).resolve().parent.parent.parent
INPUT_PATH = BASE_DIR / "results" / "clustering" / "all_functions.json"
EMB_PATH   = BASE_DIR / "results" / "clustering" / "embeddings_codebert.npy"
IDS_PATH   = BASE_DIR / "results" / "clustering" / "embeddings_ids.json"
OUT_PATH   = BASE_DIR / "results" / "clustering" / "sampled_clustered.json"
STAT_PATH  = BASE_DIR / "results" / "clustering" / "cluster_stats.json"
TUNE_PATH  = BASE_DIR / "results" / "clustering" / "tuning_results.json"
LABEL_PATH = BASE_DIR / "results" / "clustering" / "labels.npy"

OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

SAMPLES_PER_CLUSTER = 15
RANDOM_SEED         = 60

random.seed(RANDOM_SEED)
np.random.seed(RANDOM_SEED)

# -- Data loading ----------------------------------------------------
print("Loading data...")
embeddings_np = normalize(np.load(EMB_PATH)).astype(np.float32)

with open(IDS_PATH) as f:
    gt_ids = json.load(f)

with open(INPUT_PATH, encoding="utf-8") as f:
    all_data = json.load(f)["items"]

id_to_item = {item["gt_id"]: item for item in all_data}
print(f"Loaded {len(embeddings_np)} embeddings total\n")


# -- HDBSCAN execution function ----------------------------------------------
def run_hdbscan(embeddings_np, min_cluster_size, min_samples):
    if USE_GPU:
        X_gpu = cp.asarray(embeddings_np)
        clusterer = cuHDBSCAN(
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
            metric="cosine",
        )
        labels = clusterer.fit_predict(X_gpu)
        return cp.asnumpy(labels)
    else:
        clusterer = hdbscan.HDBSCAN(
            min_cluster_size=min_cluster_size,
            min_samples=min_samples,
            metric="cosine",
            core_dist_n_jobs=-1,   # CPU parallelism
        )
        return clusterer.fit_predict(embeddings_np)


def compute_silhouette(embeddings_np, labels):
    """Compute silhouette score, excluding noise (-1)"""
    mask = labels != -1
    if mask.sum() < 2 or len(set(labels[mask])) < 2:
        return -1.0
    # Memory savings: compute using at most 10000 samples
    idxs = np.where(mask)[0]
    if len(idxs) > 10000:
        idxs = np.random.choice(idxs, 10000, replace=False)
    return silhouette_score(
        embeddings_np[idxs],
        labels[idxs],
        metric="cosine",
        sample_size=min(5000, len(idxs)),
        random_state=RANDOM_SEED,
    )


# -- Parameter tuning --------------------------------------------------
PARAM_GRID = {
    "min_cluster_size": [10, 20, 30, 50, 100],
    "min_samples":      [3, 5, 10],
}

print("=== Starting parameter tuning ===")
print(f"Combinations to search: {len(PARAM_GRID['min_cluster_size']) * len(PARAM_GRID['min_samples'])}\n")

tuning_results = []
best_score     = -1.0
best_params    = None
best_labels    = None

for mcs, ms in product(PARAM_GRID["min_cluster_size"], PARAM_GRID["min_samples"]):
    if ms >= mcs:   # require min_samples < min_cluster_size
        continue

    t0     = time.time()
    labels = run_hdbscan(embeddings_np, mcs, ms)
    elapsed = time.time() - t0

    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise    = int(np.sum(labels == -1))
    noise_pct  = n_noise / len(labels) * 100

    sil = compute_silhouette(embeddings_np, labels)

    result = {
        "min_cluster_size": mcs,
        "min_samples":      ms,
        "n_clusters":       n_clusters,
        "n_noise":          n_noise,
        "noise_pct":        round(noise_pct, 2),
        "silhouette":       round(float(sil), 4),
        "elapsed_sec":      round(elapsed, 1),
    }
    tuning_results.append(result)

    print(
        f"mcs={mcs:4d} ms={ms:3d} | "
        f"clusters={n_clusters:4d} | "
        f"noise={noise_pct:5.1f}% | "
        f"silhouette={sil:.4f} | "
        f"{elapsed:.1f}s"
    )

    if sil > best_score:
        best_score  = sil
        best_params = (mcs, ms)
        best_labels = labels.copy()

# Save tuning results
tuning_results.sort(key=lambda x: x["silhouette"], reverse=True)
with open(TUNE_PATH, "w") as f:
    json.dump(tuning_results, f, indent=2)

print(f"\n=== Best parameters ===")
print(f"min_cluster_size={best_params[0]}, min_samples={best_params[1]}")
print(f"silhouette score: {best_score:.4f}")
print(f"Tuning results saved: {TUNE_PATH}\n")


# -- Use clustering results with optimal parameters --------------------------
labels = best_labels
np.save(LABEL_PATH, labels)

n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
n_noise    = int(np.sum(labels == -1))

print(f"=== Final clustering results ===")
print(f"Number of clusters: {n_clusters}")
print(f"Noise points:       {n_noise} ({n_noise/len(labels)*100:.1f}%)")
print(f"Clustered points:   {len(labels)-n_noise}")

# Group by cluster
clusters = defaultdict(list)
noise    = []
for idx, (label, gid) in enumerate(zip(labels, gt_ids)):
    if label == -1:
        noise.append((idx, gid))
    else:
        clusters[label].append((idx, gid))

# Print cluster sizes
print(f"\nCluster sizes (top 30):")
sorted_clusters = sorted(clusters.items(), key=lambda x: len(x[1]), reverse=True)
for k, members in sorted_clusters[:30]:
    print(f"  cluster {k:4d}: {len(members):6d}")
if len(sorted_clusters) > 30:
    print(f"  ... and {len(sorted_clusters)-30} more clusters")

# Save statistics
stats = {
    "best_params": {
        "min_cluster_size": best_params[0],
        "min_samples":      best_params[1],
    },
    "best_silhouette": round(best_score, 4),
    "n_total":    len(embeddings_np),
    "n_clusters": n_clusters,
    "n_noise":    n_noise,
    "clusters":   {str(k): len(v) for k, v in sorted_clusters},
}
with open(STAT_PATH, "w") as f:
    json.dump(stats, f, indent=2)
print(f"\nStats saved: {STAT_PATH}")


# -- Sampling per cluster ----------------------------------------------
sampled = []

for k, members in clusters.items():
    n = min(SAMPLES_PER_CLUSTER, len(members))

    idxs   = [idx for idx, _ in members]
    center = embeddings_np[idxs].mean(axis=0)
    center_norm = center / np.linalg.norm(center)
    dists  = [1.0 - np.dot(embeddings_np[idx], center_norm) for idx, _ in members]
    sorted_m = [m for _, m in sorted(zip(dists, members))]

    n_center = n // 2
    n_rand   = n - n_center
    selected = sorted_m[:n_center]
    rest     = sorted_m[n_center:]
    selected += random.sample(rest, min(n_rand, len(rest)))

    for idx, gid in selected:
        item = id_to_item[gid].copy()
        item["cluster_id"]   = int(k)
        item["cluster_size"] = len(members)
        sampled.append(item)

# Additional sampling from noise
if noise:
    noise_sample = random.sample(noise, min(20, len(noise)))
    for idx, gid in noise_sample:
        item = id_to_item[gid].copy()
        item["cluster_id"]   = -1
        item["cluster_size"] = 1
        sampled.append(item)
    print(f"Additional samples from noise: {len(noise_sample)}")

print(f"\nFinal sample count: {len(sampled)}")

with open(OUT_PATH, "w", encoding="utf-8") as f:
    json.dump({"items": sampled}, f, indent=2, ensure_ascii=False)

print(f"Saved: {OUT_PATH}")