# probing/

## Probing and Campaign Clustering

This directory contains the code used for backend-exposure analysis and campaign clustering.

## Components

### `kit_backend_exposure_scanner.py`

This script analyzes unpacked phishing-kit directories for exposed resources, backend misconfigurations, credential-dump files, secret material, Git metadata, and related security-relevant artifacts.

The script requires the original phishing-kit dataset as input through:

```bash
--dataset /path/to/phishing_kits
```

Because the raw phishing-kit dataset is not publicly distributed, this analysis cannot be rerun from scratch using only the public artifact.

The source code is nevertheless released to provide transparency into the methodology and implementation used in the study.

### `threat_actor_clustering.py`

This script extracts deterministic forensic identifiers and clusters phishing kits that share identifiers using Union-Find.

It can use up to three data sources:

1. per-kit dynamic-analysis JSON files,
2. backend-exposure scan results, and
3. raw phishing-kit files and Git metadata.

The public artifact includes a sanitized 100-kit subset of the dynamic-analysis JSON files. Therefore, the clustering pipeline can be partially exercised on the released sample.

However, reproducing the full campaign-clustering results reported in the paper requires the complete per-kit analysis outputs and/or the original phishing-kit dataset, both of which are available only through controlled access.

## Availability and Reproducibility

The public artifact is designed to support inspection and scaled-down evaluation of the analysis pipeline.

Some probing stages require the restricted phishing-kit dataset and therefore cannot be fully rerun using the public artifact alone.

We release all analysis code to provide transparency into the methodology and implementation used in the study. Where possible, sanitized sampling outputs and aggregate paper results are provided under `results/probing/`.