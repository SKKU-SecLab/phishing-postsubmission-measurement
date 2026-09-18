# statistics/

## Static-vs-Dynamic Exfiltration Statistics

This directory does not parse phishing-kit source code itself. It
aggregates the statistics reported in the paper from the
already-produced dynamic-analysis outputs, contrasting exfiltration
channels detected via static source-code analysis (performed earlier by
`code/dynamic_analysis_blackwidow/static_analyzer.py` during the crawl,
and embedded in each result as the `static_action_analysis` field)
against channels observed dynamically at runtime.

### Input

The pipeline takes the per-kit dynamic-analysis JSON outputs as input:

```text
results/dynamic_analysis_blackwidow/analysis_results/
```

The complete phishing-kit dataset used in the study is not included in
the public artifact. Only a sanitized 100-kit evaluation subset of this
directory is publicly released; qualified researchers may request access
to the full dataset through the dataset access procedure described in
the repository's main README.

### Public Evaluation Data

Because the full dynamic-analysis dataset is restricted, the released
statistics are computed from the sanitized 100-kit sample rather than the
complete 4,409-kit corpus. Sample-level results are provided under:

```text
results/statistics/
└── credential_exfiltration_channels.csv
```

and, as a top-level aggregate summary, under:

```text
results/dynamic_analysis_blackwidow/
└── paper_reference_summary.json
```

Statistics obtained from the sample are not expected to exactly match the
full-dataset statistics reported in the paper.

### Usage

Run `statistics.py` followed by `merge.py`:

```bash
python3 code/statistics/statistics.py \
    --results-dir results/dynamic_analysis_blackwidow/analysis_results \
    --out-dir results/statistics

python3 code/statistics/merge.py \
    --out-dir results/statistics
```

See --help for additional options.
