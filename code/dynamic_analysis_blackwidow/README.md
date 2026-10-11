# dynamic_analysis_blackwidow/

## Dynamic Analysis

This directory contains the BlackWidow-based dynamic-analysis pipeline
used in the study to instrument phishing kits and collect client-side,
form-submission, and network behaviors.

### Input

The pipeline takes an unpacked phishing kit as input.

The complete phishing-kit dataset used in the study is not included in
the public artifact because it may contain sensitive credentials,
security-sensitive identifiers, live infrastructure references, and
potentially unsafe executable components.

Qualified researchers may request access to the original dataset through
the dataset access procedure described in the repository's main README.

### Public Evaluation Data

Because the raw phishing-kit inputs are not publicly distributed, the
full dynamic-analysis pipeline cannot be rerun from scratch using only
the public artifact.

Instead, we provide sanitized dynamic-analysis outputs for 100 sampled
phishing kits under:

```text
results/dynamic_analysis_blackwidow/
├── analysis_results/
└── analysis_results_network/
```

These outputs can be used by downstream analysis components included in
this artifact.

### Usage

If access to the phishing-kit dataset has been granted, the pipeline can
be executed as follows:

```bash
python3 code/dynamic_analysis_blackwidow/crawl.py \
    --analyze \
    --kit-path /path/to/kit \
    --headless
```

See --help for additional options.