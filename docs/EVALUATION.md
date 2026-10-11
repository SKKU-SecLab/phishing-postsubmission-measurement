# Artifact Evaluation

This document describes the evaluation procedures for the main claims supported by the public artifact.

The public artifact contains a sanitized evaluation subset of dynamic-analysis outputs for 100 sampled phishing kits. The complete phishing-kit dataset and full per-kit outputs are restricted due to privacy and security concerns.

Accordingly, some evaluations are scaled-down versions of the full-study experiments. Sample-level numerical results are not expected to exactly match the full-dataset statistics reported in the paper.

## Installation

Clone the repository and enter its root directory:

```bash
git clone https://github.com/SKKU-SecLab/phishing-postsubmission-measurement.git
cd phishing-postsubmission-measurement
```

Install the Python environment:

```bash
bash scripts/install.sh
source .venv/bin/activate
```

Successful installation ends with:

```bash
[artifact] Installation completed successfully.
```

## Claim 1: Credential Transmission and Exfiltration Analysis

### Claim

The released analysis pipeline identifies the credential-transmission mechanisms and server-side exfiltration channels characterized in the paper.

### Artifact Components

- `results/dynamic_analysis_blackwidow/analysis_results/`
- `results/dynamic_analysis_blackwidow/analysis_results_network/`
- `code/statistics/statistics.py`
- `code/statistics/merge.py`
- `results/statistics/`

### Evaluation

Run:

```bash
python3 code/statistics/statistics.py \
    --results-dir results/dynamic_analysis_blackwidow/analysis_results \
    --out-dir results/statistics

python3 code/statistics/merge.py \
    --out-dir results/statistics
```

### Expected Outcome

The analysis should successfully process the released evaluation subset and identify the exfiltration mechanisms represented in the sample.

The generated sample-level counts are not expected to exactly match the full-dataset statistics reported in the paper.

Aggregate results from the full study are provided separately where they can be safely released.

## Claim 2: JavaScript Classification Validation

### Claim

The JavaScript-function classification procedure was validated against independent human annotations, with high inter-rater agreement and strong performance of the selected language model against the consensus labels.

### Artifact Components

- `data/js_validation/functions_200.csv`
- `data/js_validation/human_labels.csv`
- `results/js_validation/model_outputs/`
- `results/js_validation/metrics/`
- `code/js_validation/evaluation/compute_cohens_kappa.py`

### Evaluation

Recompute human inter-rater agreement:

```bash
python3 code/js_validation/evaluation/compute_cohens_kappa.py
```

The stored model responses under `results/js_validation/model_outputs/` can be evaluated against the human consensus labels without querying external APIs.

Re-querying the six language models is optional.

### Expected Outcome

The human-label agreement should reproduce a Cohen's kappa of approximately 0.919.

The stored GPT-5.4 responses should reproduce a macro-F1 of approximately 0.927 under the provided evaluation procedure.

Stored responses for the other evaluated models are also included for comparison.

## Claim 3: Campaign Clustering

### Claim

Deterministic operational and developmental identifiers extracted from phishing-kit artifacts can be combined to associate multiple kits with common threat campaigns.

### Artifact Components

- `code/probing/threat_actor_clustering.py`
- `results/dynamic_analysis_blackwidow/analysis_results/`
- `results/probing/`
- `code/probing/README.md`

### Scaled-Down Evaluation

The released 100-kit dynamic-analysis subset can be used to exercise the identifier-extraction and Union-Find clustering logic:

```bash
python3 code/probing/threat_actor_clustering.py \
    --results-dir results/dynamic_analysis_blackwidow/analysis_results \
    --out-dir results/probing/sample_clustering
```

### Expected Outcome

The script should extract available identifiers from the released sample and group kits that share identifiers.

The resulting sample-level number of campaigns is not expected to match the full-study result.

The full paper result was produced using additional inputs, including the complete per-kit analysis outputs and raw phishing-kit artifacts. These restricted inputs are not part of the public artifact.
