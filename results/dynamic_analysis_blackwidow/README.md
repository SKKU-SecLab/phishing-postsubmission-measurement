# dynamic_analysis_blackwidow/

## 1. Source
- `analysis_results/`, `analysis_results_network/`, `legit_results/` — see the README inside each subdirectory.
- `paper_reference_summary.json` — the aggregate-statistics summary produced by `code/statistics/statistics.py` when run with `--results-dir results/dynamic_analysis_blackwidow/analysis_results`.

## 2. Next-step input
`paper_reference_summary.json` is a terminal aggregate output used directly for paper-level statistics; it is not consumed by another script. The three subdirectories feed the clustering, statistics, and probing pipelines — see their individual READMEs for details.
