# When You Click Submit: Characterizing Post-Submission Behaviors in Phishing Infrastructure

When You Click Submit: Characterizing Post-Submission Behaviors in Phishing Infrastructure<br>Yerim Kim∗, Jaehwan Park†, Doowon Kim†, and Hyoungshick Kim∗

Sungkyunkwan University∗, University of Tennessee, Knoxville†

## Abstract

Phishing detection has been extensively studied at the upstream stages of an attack, including domain registration, hosting, visual similarity, and blocklist propagation, but the moment a victim submits credentials and the pipeline that delivers them to the adversary has received comparatively limited empirical attention. We argue this post-submission phase is a uniquely stable measurement vantage point, since every credential phishing site must contain a harvesting surface on the client and a transport mechanism on the server. We instrument the complete submission flow across 4,409 phishing kits collected over 45 months, capturing client-side JavaScript, network transmission, and server-side exfiltration sinks, and compare against the official authentication portals of the 15 most spoofed brands. The classified credential-entry JavaScript concentrates on input-processing routines---validation, masking, and event filtering---with exfiltration-specific code appearing comparatively infrequently. Phishing infrastructure systematically lacks the response security headers (CSP, X-Frame-Options, X-Content-Type-Options) that legitimate portals consistently deploy, and forced browsing exposes sensitive data on 27.7\% of kits, 8.2\% with plaintext credential dumps, 10.7\% with leaked .git repositories. Fusing operational identifiers (email, Telegram tokens) with developmental artifacts leaked through OpSec failures (Git author identities, repository URLs) clusters 606 kits into 150 threat campaigns with a median lifespan of 109 days, two orders of magnitude longer than the 5.46-hour median lifespan of individual phishing sites.

## Project Structure

```text
.
├── code
│   ├── clustering
│   │   ├── 01-extract_functions.py
│   │   ├── 02-embed_codebert.py
│   │   ├── 03-cluster_sample.py
│   │   └── make_centroids.py
│   │
│   ├── dynamic_analysis_blackwidow
│   │   ├── README.md
│   │   ├── crawl.py
│   │   ├── analyze_network.py
│   │   ├── FormAnalyzer.py
│   │   ├── Functions.py
│   │   ├── static_analyzer.py
│   │   ├── extractors
│   │   └── js
│   │
│   ├── js_validation
│   │   ├── evaluation
│   │   │   └── compute_cohens_kappa.py
│   │   └── request_models
│   │       └── run_inference_tuned.py
│   │
│   ├── probing
│   │   ├── README.md
│   │   ├── kit_backend_exposure_scanner.py
│   │   └── threat_actor_clustering.py
│   │
│   ├── statistics
│   │   ├── README.md
│   │   ├── statistics.py
│   │   └── merge.py
│   │
│   └── hash_value.py
│
├── data
│   └── js_validation
│       ├── functions_200.csv
│       └── human_labels.csv
│
├── docs
│   ├── ETHICS.md
│   ├── EVALUATION.md
│   ├── LICENSE
│   └── PROVENANCE.md
│
├── results
│   ├── clustering
│   │   ├── README.md
│   │   ├── cluster_centroids.json
│   │   ├── cluster_stats.json
│   │   └── labels.npy
│   │
│   ├── dynamic_analysis_blackwidow
│   │   ├── README.md
│   │   ├── analysis_results
│   │   ├── analysis_results_network
│   │   ├── legit_results
│   │   └── paper_reference_summary.json
│   │
│   ├── js_validation
│   │   ├── README.md
│   │   ├── metrics
│   │   └── model_outputs
│   │
│   ├── probing
│   │   ├── README.md
│   │   ├── cluster_summary.csv
│   │   └── clustering_summary.json
│   │
│   └── statistics
│       ├── README.md
│       └── credential_exfiltration_channels.csv
│
├── scripts
│   └── install.sh
│
├── requirements.txt
└── README.md
```

## Dataset

Due to privacy and security concerns, the complete phishing-kit dataset is not publicly distributed.

During artifact preparation, we identified that the raw phishing kits and their per-kit dynamic-analysis outputs may contain sensitive credentials, security-sensitive identifiers, authentication material, live infrastructure references, and potentially unsafe executable components.

This repository therefore provides a sanitized evaluation subset of 100 phishing kits' dynamic-analysis outputs, including:

```text
results/dynamic_analysis_blackwidow/
├── analysis_results/
└── analysis_results_network/
```

The evaluation subset is intended to exercise the released analysis pipeline and cover the major behaviors analyzed in the paper. Statistics obtained from this subset are not expected to exactly match the full-dataset statistics reported in the paper.

Personally identifiable information and other sensitive values have been redacted from the publicly released evaluation data.

Qualified researchers may request access to the complete phishing-kit dataset and full per-kit analysis outputs for legitimate research purposes:

Dataset Access Request: https://docs.google.com/forms/d/e/1FAIpQLSeNrz7nHNJ8TnGXNuQVrKkunt3E5jsCI1y8z9Zihgf1xiQMxA/viewform?usp=sharing&ouid=114006743748593344949

## Public Evaluation Data Structure

The raw phishing-kit dataset used as input to the dynamic-analysis pipeline is not included in the public artifact.

Instead, we provide sanitized dynamic-analysis outputs for 100 sampled phishing kits so that downstream analysis stages can be inspected and evaluated without redistributing the underlying phishing kits.

The released outputs are organized as follows:

```text
results/dynamic_analysis_blackwidow/
├── analysis_results/
│   ├── analysis_results_<kit_id>.json
│   └── ...
│
├── analysis_results_network/
│   ├── analysis_results_network_<kit_id>.json
│   └── ...
│
└── legit_results/
    └── ...
```

- `analysis_results/` contains per-kit dynamic client-side and server-side analysis results.
- `analysis_results_network/` contains the corresponding network and credential-transmission measurements.
- `legit_results/` contains the legitimate-site baseline measurements used in the paper.


## Prerequisites

- Python 3.9+
- Google Chrome or Chromium
- Selenium 4.6+
- Optional: NVIDIA GPU and CUDA with RAPIDS cuML/cuPy for GPU-accelerated clustering

The clustering pipeline automatically falls back to the CPU hdbscan package when RAPIDS is unavailable.

## Installation

### 1. Clone the repository:

```bash
git clone https://github.com/SKKU-SecLab/phishing-postsubmission-measurement.git
cd phishing-postsubmission-measurement
```

### 2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

The dynamic-analysis pipeline uses Selenium with Chrome DevTools Protocol (CDP). With Selenium 4.6 or later, ChromeDriver is resolved automatically through Selenium Manager as long as Chrome or Chromium is installed.

## Usage
The public artifact contains the analysis code and a sanitized subset of dynamic-analysis outputs for 100 sampled phishing kits.

Because the original phishing-kit dataset is not publicly distributed, some stages that require raw phishing-kit files cannot be rerun from scratch using only the public artifact.

The sections below distinguish between analyses that can be exercised with the publicly released artifact and analyses that require access to the restricted dataset.

### 1. Dynamic analysis

The BlackWidow-based dynamic-analysis pipeline takes an unpacked phishing kit as input.

```bash
python3 code/dynamic_analysis_blackwidow/crawl.py \
    --analyze \
    --kit-path /path/to/kit \
    --headless
```

The raw phishing-kit dataset is not included in the public artifact.
Therefore, this stage cannot be rerun from scratch using only the publicly released files.

Instead, sanitized dynamic-analysis outputs for 100 sampled phishing kits are provided under:

```text
results/dynamic_analysis_blackwidow/
├── analysis_results/
└── analysis_results_network/
```

These files are provided as inputs for downstream analysis and for inspection of the dynamic-analysis output format.

See `code/dynamic_analysis_blackwidow/README.md` for details.

### 2. Statistics aggregation

These scripts do not parse phishing-kit source code themselves; they aggregate the statistics from the released dynamic-analysis outputs (which already embed static-source-code-derived fields alongside dynamically-observed ones) and can be exercised using the public evaluation subset.

```bash
python3 code/statistics/statistics.py \
    --results-dir results/dynamic_analysis_blackwidow/analysis_results \
    --out-dir results/statistics

python3 code/statistics/merge.py \
    --out-dir results/statistics
```

Because the public artifact contains only a 100-kit evaluation subset, the resulting statistics are sample-level results and are not expected to exactly match the full-dataset statistics reported in the paper.

See `code/statistics/README.md` and `results/statistics/README.md` for details.

### 3. JavaScript Function Clustering
The JavaScript-function clustering pipeline consists of function extraction, CodeBERT embedding, HDBSCAN clustering, and centroid selection.

Run the clustering pipeline in the following order:

```bash
python3 code/clustering/01-extract_functions.py
python3 code/clustering/02-embed_codebert.py
python3 code/clustering/03-cluster_sample.py
python3 code/clustering/make_centroids.py
```

The corresponding intermediate and final clustering outputs are provided under:

```text
results/clustering/
```

See `results/clustering/README.md` for the input/output mapping of each
stage.

### 4. JavaScript Classification Validation (LLM validation)

The artifact includes the validation data used to evaluate the JavaScript-function classification procedure.

The validation set consists of 200 sampled functions independently labeled by two researchers. The corresponding validation data are provided under:

```text
data/js_validation/
```

Stored responses from the six evaluated language models are provided under:

```text
results/js_validation/model_outputs/
```

Human-label agreement can be recomputed with:

```bash
python3 code/js_validation/evaluation/compute_cohens_kappa.py
```

The stored model responses can be used to recompute the reported model evaluation metrics without querying external services.

Model responses can optionally be regenerated using:

```bash
python3 code/js_validation/request_models/run_inference_tuned.py \
    --api <provider> \
    --api_key <your-key>
```

Re-querying external models is not required to reproduce the reported validation metrics. Stored model responses are provided because hosted models may require paid API access and their outputs may change over time.

See `results/js_validation/README.md` for details.

### 5. Backend Exposure Analysis

The backend-exposure scanner operates directly on unpacked phishing-kit directories.

```bash
python3 code/probing/kit_backend_exposure_scanner.py \
    --dataset /path/to/phishing_kits \
    --json-out results/probing/hunt_results.json \
    --csv-out results/probing/hunt_results.csv
```

Because this analysis requires the original phishing-kit dataset, it cannot be rerun from scratch using only the public artifact.

The source code is provided for methodological transparency, while released results are available under:

```text
results/probing/
```

See `code/probing/README.md` and `results/probing/README.md` for details.

### 6. Campaign Clustering

Campaign clustering is implemented in:

```text
code/probing/threat_actor_clustering.py
```

The script can combine multiple input sources:

1. per-kit dynamic-analysis JSON files,
2. backend-exposure analysis results, and
3. raw phishing-kit files and Git metadata.

For a scaled-down run using only the publicly released dynamic-analysis subset:

```bash
python3 code/probing/threat_actor_clustering.py \
    --results-dir results/dynamic_analysis_blackwidow/analysis_results \
    --out-dir results/probing/sample_clustering
```

This public run exercises the identifier-extraction and Union-Find clustering logic using the released sample.

However, reproducing the full campaign-clustering results reported in the paper requires additional inputs from the complete dataset, including full per-kit outputs and raw phishing-kit artifacts.

The full-data analysis used additional sources such as:

```bash
python3 code/probing/threat_actor_clustering.py \
    --results-dir /path/to/full/analysis_results \
    --kit-base-dir /path/to/phishing_kits \
    --hunt-results /path/to/hunt_results.json \
    --out-dir /path/to/output
```

The complete phishing-kit dataset and full per-kit outputs are available only through controlled access.

See `code/probing/README.md` and `results/probing/README.md` for details.

## Configuration

### API Keys

`code/js_validation/request_models/run_inference_tuned.py` requires an API key when querying hosted models.

For example:

```bash
--api openai --api_key <your-key>
```

API keys are not stored in this repository.

### GPU clustering
`code/clustering/03-cluster_sample.py` uses RAPIDS cuML/cuPy for GPU-accelerated HDBSCAN when available.

If RAPIDS is unavailable, the script automatically falls back to the CPU hdbscan implementation.

### License

This project is licensed under the [GNU General Public License v3.0] ( `/docs/LICENSE`).

This artifact builds upon Black Widow (https://github.com/SecuringWeb/BlackWidow) 
by Eriksson et al., which includes components originally authored by 
Constantin Tschuertz (Copyright © 2015).