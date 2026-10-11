# js_validation/

## JS-Function Behavior Classification Validation

This directory validates the JS-function behavior-classification scheme
used in the paper: querying LLMs to classify credential-entry event
handlers into behavior categories, then scoring those model responses
against independent human annotations.

`evaluation/compute_cohens_kappa.py` does more than its filename
suggests -- despite the name, it does not only compute Cohen's kappa
between the two human annotators. It is the single evaluation script for
this whole pipeline: it also scores every stored model response against
the human gold labels (exact-match accuracy, Jaccard similarity,
macro/micro-averaged precision/recall/F1, and per-label precision/recall/
F1/support for each of the six evaluated models).

### request_models/

`run_inference_tuned.py` generates model responses for the fixed
200-function evaluation set.

- Input: `data/js_validation/functions_200.csv` (the functions to
  classify) and `data/js_validation/human_labels.csv` (used for the
  optional `--metrics_only` pass).
- Output: `results/js_validation/model_outputs/results_<model_name>.json`
  (one file per evaluated model).
- Supports two inference paths: a hosted API (`--api openai` or
  `--api deepseek`, requires `--api_key`) or a local Hugging Face
  `transformers` model loaded by path/name via `--model`.

### evaluation/

`compute_cohens_kappa.py` is the evaluation script for the pipeline.

- Input: `data/js_validation/human_labels.csv` (human gold labels from
  two annotators, `h1_label`/`h2_label`/`gold` columns) and every
  `results_*.json` file under `results/js_validation/model_outputs/`.
- Output, written to `results/js_validation/metrics/`:
  - `human_agreement_summary.json` -- Cohen's kappa (exact-string and
    per-label macro-averaged) between the two human annotators.
  - `human_disagreements.csv` -- rows where the two annotators disagreed,
    for manual adjudication.
  - `js_evaluation_summary.json` -- per-model classification metrics
    (macro-F1, micro-F1, Jaccard similarity, per-label precision/recall/
    F1/support) scored against the gold labels. This is the file that
    supports the paper's reported model-comparison numbers (e.g. GPT-5.4
    macro-F1).

### Usage

```bash
python3 code/js_validation/evaluation/compute_cohens_kappa.py
```

Re-running `request_models/run_inference_tuned.py` to regenerate model
responses is optional -- the stored responses under
`results/js_validation/model_outputs/` are sufficient to recompute the
reported metrics without querying external APIs. See --help on either
script for the full option list.
