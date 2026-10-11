import re
import gc
import os
import csv
import json
import argparse
from pathlib import Path
from collections import defaultdict

# ----------------------------- paths -------------------------------

BASE_DIR   = Path(__file__).resolve().parent.parent.parent.parent
INPUT_CSV  = str(BASE_DIR / "data" / "js_validation" / "functions_200.csv")
GT_CSV     = str(BASE_DIR / "data" / "js_validation" / "human_labels.csv")
RESULT_DIR = str(BASE_DIR / "results" / "js_validation" / "model_outputs")

# ------------------------ category scheme --------------------------

CATEGORIES = {
    "A": "input-validation",
    "B": "state-validation",
    "C": "validation-reset",
    "D": "form-error-clearance",
    "E": "custom-validity-manip.",
    "F": "event-dispatching",
    "G": "event-delegation",
    "H": "event-proxying",
    "I": "event-forwarding",
    "J": "keypress-delegation",
    "K": "event-filtering",
    "L": "event-dispatch-filter",
    "M": "event-propagation-control",
    "N": "execution-guard",
    "O": "input-masking",
    "P": "value-formatting",
    "Q": "caret-positioning",
    "R": "caret-position-mgmt",
    "S": "form-state-management",
    "T": "input-event-handler",
    "U": "obfuscated",
}
VALID_CODES = set(CATEGORIES.keys())

# ---------------------------- prompts ------------------------------

SYSTEM_PROMPT = """\
You must output ONLY a JSON object. No explanation, no reasoning, no extra text.

You are a JavaScript behavior analyst. Given a JavaScript event handler extracted
from a real-world phishing kit, classify its behavior into one or more of the
predefined categories below.

=== CATEGORY DEFINITIONS ===

--- (1) Validation ---
A  input-validation        - Checks the input value itself (regex, length, trim, format, emptiness, equality, parseable numeric/date checks). Use A when the code reads or transforms the value itself, even if the action later affects UI.
B  state-validation        - Checks form or UI state such as disabled, checked, dirty, touched, visible, active step, or submit-readiness flags. Use B only when the code inspects or updates component/form state, not when it is just checking the current input value.
C  validation-reset        - Resets validation state, invalid flags, or validation messages.
D  form-error-clearance    - Removes form error messages, error classes, or error indicators.
E  custom-validity-manip.   - Overrides browser native validation feedback (for example setCustomValidity).

--- (2) Event routing ---
F  event-dispatching       - Fires or dispatches an event. Common pattern: dispatch.apply(...).
G  event-delegation        - A parent element handles child events. Common pattern: e.target checks.
H  event-proxying          - Intercepts an event and re-wraps it before forwarding.
I  event-forwarding        - Simply passes to another element or function via trigger() or dispatchEvent().
J  keypress-delegation     - A keypress/keydown/keyup handler directly triggers an action from a specific key.

--- (3) Event control ---
K  event-filtering         - Lets only specific keys or conditions pass and blocks the rest. Example: if (keyCode !== X) return.
L  event-dispatch-filter   - Decides mid-dispatch whether to block or suppress the event.
M  event-propagation-control - Explicit stopPropagation() or preventDefault() call.
N  execution-guard         - Conditionally guards the function body. Example: if (!initialized) return.

--- (4) Input formatting ---
O  input-masking           - Masks or formats input in place (card number, phone number, date).
P  value-formatting        - Applies visual formatting such as separators, units, spaces, or display formatting.
Q  caret-positioning       - Calculates or moves the cursor position.
R  caret-position-mgmt     - Manages caret position state, including save/restore logic.

--- (5) Form / state mgmt ---
S  form-state-management   - Manages overall form state such as submit readiness, button enabled/disabled state, multi-step progress, or cached form data.
T  input-event-handler     - A generic handler for a specific input event with no more specific category.

--- others ---
U  obfuscated              - Function is obfuscated or too indirect to classify confidently.

=== DISAMBIGUATION RULES ===
- F vs G: F fires an event; G receives or delegates events on behalf of children.
- F vs H: F dispatches; H re-wraps or proxies the event object before forwarding.
- F vs I: F uses dispatch.apply(...); I uses trigger() or dispatchEvent().
- A vs B: A checks the input value itself; B checks form, UI, or interaction state.
- A vs B:
  - A = the code inspects or validates the input value itself, including length/format/empty checks or transforms based on the value.
  - B = the code inspects or updates the form/widget state itself, such as disabled/checked/active/readiness flags.
  - If the code says `value.length`, `trim()`, `replace(...)`, or similar on the current field value, prefer A unless the surrounding logic clearly targets form state.
  - If the code only checks whether a control is disabled, checked, ready, or visible, prefer B.
- C vs E: C resets or clears validation state; E overrides native browser validity feedback.
- K vs L vs M vs N:
  - K = filters specific keys or conditions and returns early for non-matching input.
  - L = decides whether an in-flight dispatch should continue or be suppressed.
  - M = explicitly calls preventDefault() or stopPropagation().
  - N = guards the whole function body with a condition.
- J vs K:
  - K applies when the code only filters keys or conditions, even if that includes Enter.
  - J applies when a specific key directly triggers an action such as submit, click, navigation, or another explicit side effect.
  - Do not upgrade a thin wrapper/helper call to J unless the body makes the side effect explicit.
  - If the code only does `if (keyCode !== 13) return;`, classify it as K only.
  - If the code does `if (keyCode === 13) submitForm();`, classify it as K and J.
- S vs T:
  - T = a generic handler for an input-related event when no stronger category fits.
  - S = code that updates higher-level form state, submit readiness, step state, cached form values, or enabled/disabled controls.
  - If an input handler both processes the event and changes form state, assign both S and T.
  - Thin wrapper/helper calls from an input event should stay T unless the code itself explicitly shows validation, state management, filtering, dispatching, or submit behavior.
- K vs T:
  - Prefer K whenever a key or event filter causes an early return.
  - If the handler only processes a value in response to an input event and no stronger behavior can be recovered, use T.
- U:
  - Use U only when the code is genuinely too obfuscated or indirect to classify with confidence.
  - Do not use U for simple forwarding wrappers, short helper calls, or recognizable validation/state logic.
  - Do not use U just because the function is short, minified, or uses aliases if the behavior is still recoverable from surrounding calls.
  - If the body is mostly opaque wrapper code and the real behavior depends on hidden helper chains, prefer U over speculative labels.
- Multi-label guidance:
  - Assign every category that is clearly present.
  - Do not assign T if a more specific category applies.
- Confidence rule:
  - When a category is only weakly suggested, prefer the safer, more specific label set rather than adding a speculative label.

=== CLASSIFICATION RULES ===
1. Multi-label is allowed -- assign all categories whose behavior is clearly present.
2. Base classification on what the code actually does, not just its name.
   However, you MAY infer from a clear function name (e.g. numberValidation -> A).
3. Assign U only when the code is obfuscated and nothing can be determined with confidence.
4. Do NOT assign T if a more specific category applies.

=== EXAMPLES ===
Example 1:
  fn_phase: typing_keyup
  code: function onkeyup(event) { return numberValidation(event) }
  -> {"all_labels": ["A"], "primary": "A"}

Example 2:
  fn_phase: typing_input
  code: var newVal = p.getMasked(); p.val(newVal); setCaret(p, pos);
  -> {"all_labels": ["O", "Q"], "primary": "O"}

Example 3:
  fn_phase: typing_keypress
  code: function(e){return typeof x===i||e&&x.event.triggered===e.type?t:x.event.dispatch.apply(f.elem,arguments)}
  -> {"all_labels": ["F", "L"], "primary": "F"}

Example 4:
  fn_phase: typing_keydown
  code: if (event.keyCode !== 13 && event.keyCode !== 8) { event.preventDefault(); return false; }
  -> {"all_labels": ["K", "M"], "primary": "K"}

Example 5 (K only):
  code: if (e.keyCode !== 13) return;
  -> {"all_labels": ["K"], "primary": "K"}
  Reason: The code only filters out non-Enter keys. There is no direct action, so J must not be added.

Example 6 (J + K):
  code: if (e.keyCode !== 13) return; Login.submitLoginRequest();
  -> {"all_labels": ["K", "J"], "primary": "J"}
  Reason: The handler filters out every key except Enter (K), then directly triggers a submit action (J).

Example 7 (T only):
  code: function onkeypress(event) { return submitenter(this, event) }
  -> {"all_labels": ["T"], "primary": "T"}
  Reason: The body only delegates to a helper. The actual action is not explicit enough to justify J.

Example 8 (J + K):
  code: function onkeypress(event) { return postOnReturn(event) }
  -> {"all_labels": ["K", "J"], "primary": "J"}
  Reason: The helper name clearly signals Enter-submit behavior, so the explicit key action is J, with K for the Enter filter if present.

Example 9 (B only):
  code: function onkeyup(event) { checkFilled() }
  -> {"all_labels": ["B"], "primary": "B"}
  Reason: The function checks whether the relevant fields are filled, which is state-validation.

Example 10 (S only):
  code: function onchange(event) { $Login.changeLogin('') }
  -> {"all_labels": ["S"], "primary": "S"}
  Reason: The handler updates higher-level login/form state in response to the change event.

Example 11 (O only):
  code: function onkeypress(event) { MascaraTelefone(this) }
  -> {"all_labels": ["O"], "primary": "O"}
  Reason: The helper name indicates input masking/formatting, not a generic input handler.

Example 12 (P only):
  code: function () { space(this, 4); }
  -> {"all_labels": ["P"], "primary": "P"}
  Reason: The helper applies spacing/visual formatting, which is value-formatting rather than masking.

Example 13 (I only):
  code: function(e){n._messageBus.publish(pe.StandardInputEvent,e)}
  -> {"all_labels": ["I"], "primary": "I"}
  Reason: The event is forwarded through a message bus to another component, which is event-forwarding.

Example 14 (S + T):
  code: function oninput(e) { ... if (valid) btn.removeAttribute('disabled'); else btn.setAttribute('disabled','disabled'); }
  -> {"all_labels": ["S", "T"], "primary": "S"}
  Reason: It is an input event handler (T) that also manages submit-related UI state (S).

Example 15 (C + E):
  code: function oninput(event) { setCustomValidity('') }
  -> {"all_labels": ["C", "E"], "primary": "C"}
  Reason: It clears validation state (C) and manipulates native browser validity feedback (E).

=== OUTPUT FORMAT (STRICT) ===
Return ONLY this JSON (no markdown, no extra keys):
{"all_labels": ["X", ...], "primary": "X"}

"primary" = the single most representative label from all_labels.
"""


def make_user_prompt(item: dict) -> str:
    return (
        "=== INPUT ===\n"
        f"fn_phase:     {item.get('fn_phase', '')}\n"
        "\ncode:\n"
        "```javascript\n"
        f"{str(item.get('code', ''))[:3000]}\n"
        "```\n"
        '\nReturn ONLY: {"all_labels": ["X", ...], "primary": "X"}'
    )


# ------------------------ output parsing ---------------------------

def parse_output(raw: str) -> tuple[list[str], str, str]:
    all_labels, primary, error_msg = [], "U", ""
    try:
        clean = re.sub(r"<think>.*?</think>", "", raw, flags=re.DOTALL)
        clean = re.sub(r"Thinking Process:.*?(?=\{)", "", clean, flags=re.DOTALL)
        if "```" in clean:
            for part in clean.split("```"):
                part = part.strip().lstrip("json").strip()
                if part.startswith("{"):
                    clean = part
                    break
        match = re.search(r"\{.*\}", clean, re.DOTALL)
        clean = match.group() if match else clean
        parsed     = json.loads(clean)
        all_labels = [l for l in parsed.get("all_labels", []) if l in VALID_CODES]
        primary    = parsed.get("primary", "U")
        if primary not in VALID_CODES:
            primary = "U"
        if all_labels and primary not in all_labels:
            primary = all_labels[0]
        if not all_labels:
            error_msg = f"all_labels empty | raw: {repr(raw[:200])}"
    except json.JSONDecodeError as e:
        error_msg = f"JSON error: {e} | raw: {repr(raw[:200])}"
    return all_labels, primary, error_msg


# -------------------------- data loading ---------------------------

def load_input_csv(path: str) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_gt_csv(path: str) -> dict[int, list[str]]:
    gt = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            rid = int(row["id"])
            gold_raw = row.get("gold", "").strip()
            if gold_raw:
                source = gold_raw
            else:
                source = row.get("h1_label", "")
            codes = [c.strip() for c in re.findall(r"[A-U]", source)
                     if c.strip() in VALID_CODES]
            gt[rid] = codes
    return gt


# ----------------------------- metrics -----------------------------

def compute_metrics(results: list[dict], gt: dict[int, list[str]]) -> dict:
    exact_match = 0
    tp_per = defaultdict(int)
    fp_per = defaultdict(int)
    fn_per = defaultdict(int)
    evaluated = 0

    for r in results:
        rid = r["id"]
        if rid not in gt:
            continue
        evaluated += 1
        pred_set = set(r["all_labels_code"])
        true_set = set(gt[rid])
        if pred_set == true_set:
            exact_match += 1
        for c in VALID_CODES:
            p, t = c in pred_set, c in true_set
            if p and t:       tp_per[c] += 1
            elif p and not t: fp_per[c] += 1
            elif not p and t: fn_per[c] += 1

    per_cat = {}
    for c in VALID_CODES:
        tp, fp, fn = tp_per[c], fp_per[c], fn_per[c]
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1   = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
        per_cat[c] = {"precision": prec, "recall": rec, "f1": f1, "support": tp + fn}

    active   = [c for c in VALID_CODES if per_cat[c]["support"] > 0]
    macro_p  = sum(per_cat[c]["precision"] for c in active) / len(active) if active else 0
    macro_r  = sum(per_cat[c]["recall"]    for c in active) / len(active) if active else 0
    macro_f1 = sum(per_cat[c]["f1"]        for c in active) / len(active) if active else 0

    return {
        "evaluated": evaluated,
        "exact_match": exact_match,
        "exact_match_acc": exact_match / evaluated if evaluated else 0,
        "macro_precision": macro_p,
        "macro_recall":    macro_r,
        "macro_f1":        macro_f1,
        "per_category":    per_cat,
    }


def print_metrics(metrics: dict, model_name: str):
    print(f"\n{'='*62}")
    print(f"  {model_name}")
    print(f"{'='*62}")
    print(f"  Evaluated        : {metrics['evaluated']}")
    print(f"  Exact-match acc. : {metrics['exact_match_acc']:.3f}  ({metrics['exact_match']}/{metrics['evaluated']})")
    print(f"  Macro Precision  : {metrics['macro_precision']:.3f}")
    print(f"  Macro Recall     : {metrics['macro_recall']:.3f}")
    print(f"  Macro F1         : {metrics['macro_f1']:.3f}")
    print(f"\n  {'Code':<4} {'Name':<28} {'P':>6} {'R':>6} {'F1':>6} {'Sup':>5}")
    print(f"  {'-'*57}")
    for c, v in metrics["per_category"].items():
        if v["support"] == 0:
            continue
        print(f"  {c:<4} {CATEGORIES[c]:<28} {v['precision']:>6.3f} {v['recall']:>6.3f} {v['f1']:>6.3f} {v['support']:>5}")
    print()


# ---------------- transformers inference (local) -------------------

def run_transformers(model_path: str, input_rows: list[dict],
                     done_ids: set, results: list, result_path: str):
    import torch
    from transformers import AutoTokenizer, AutoModelForCausalLM

    print(f"Loading {Path(model_path).name} with transformers ...")

    tokenizer = AutoTokenizer.from_pretrained(model_path, trust_remote_code=True)

    load_kwargs = dict(
        torch_dtype=torch.bfloat16 if torch.cuda.is_available() else torch.float32,
        device_map="auto",
        trust_remote_code=True,
        low_cpu_mem_usage=True,
    )
    if torch.cuda.is_available():
        n_gpus = torch.cuda.device_count()
        free_mem = {
            i: f"{int(torch.cuda.get_device_properties(i).total_memory * 0.85 / 1024**3)}GiB"
            for i in range(n_gpus)
        }
        load_kwargs["max_memory"] = free_mem
        print(f"GPU(s): {free_mem}")

    model = AutoModelForCausalLM.from_pretrained(model_path, **load_kwargs)
    model.eval()
    print("Model loaded.\n")

    remaining = [r for r in input_rows if int(r["id"]) not in done_ids]
    print(f"Remaining: {len(remaining)} samples\n")

    for item in remaining:
        rid = int(item["id"])

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": make_user_prompt(item)},
        ]

        try:
            text = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=False,
            )
        except TypeError:
            text = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
            )

        inputs = tokenizer(text, return_tensors="pt").to(model.device)

        with torch.no_grad():
            output_ids = model.generate(
                **inputs,
                max_new_tokens=256,
                temperature=None,       # greedy
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )

        new_tokens = output_ids[0][inputs["input_ids"].shape[1]:]
        raw = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()

        print(f"[id={rid}] {repr(raw[:120])}")
        all_labels, primary, error_msg = parse_output(raw)

        if error_msg:
            print(f"  ERROR: {error_msg}")
        else:
            print(f"  -> {all_labels}  primary={primary}")

        results.append({
            "id": rid,
            "all_labels": [CATEGORIES[l] for l in all_labels],
            "all_labels_code": all_labels,
            "primary": CATEGORIES.get(primary, "unknown"),
            "primary_code": primary,
            "raw_response": raw,
            "error": error_msg,
        })

        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        del inputs, output_ids
        gc.collect()
        torch.cuda.empty_cache()

    print(f"Done -> {result_path}\n")


# ----------------------- API inference ----------------------------

def run_api(provider: str, model_name: str, api_key: str,
            input_rows: list[dict], done_ids: set,
            results: list, result_path: str):
    from openai import OpenAI

    if provider == "deepseek":
        client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
        api_model = "deepseek-chat"
    else:
        client = OpenAI(api_key=api_key)
        api_model = model_name

    remaining = [r for r in input_rows if int(r["id"]) not in done_ids]
    print(f"API inference ({provider} / {api_model}): {len(remaining)} samples\n")

    for item in remaining:
        rid = int(item["id"])
        try:
            token_param = (
                {"max_completion_tokens": 256}
                if "gpt" in api_model.lower()
                else {"max_tokens": 256}
            )
            resp = client.chat.completions.create(
                model=api_model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user",   "content": make_user_prompt(item)},
                ],
                temperature=0.0,
                **token_param,
            )
            raw = resp.choices[0].message.content.strip()
        except Exception as e:
            raw = ""
            print(f"[id={rid}] API error: {e}")

        print(f"[id={rid}] {repr(raw[:120])}")
        all_labels, primary, error_msg = parse_output(raw)
        if error_msg:
            print(f"  ERROR: {error_msg}")
        else:
            print(f"  -> {all_labels}  primary={primary}")

        results.append({
            "id": rid,
            "all_labels": [CATEGORIES[l] for l in all_labels],
            "all_labels_code": all_labels,
            "primary": CATEGORIES.get(primary, "unknown"),
            "primary_code": primary,
            "raw_response": raw,
            "error": error_msg,
        })

        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"API done -> {result_path}\n")


# ---------------------------- main ---------------------------------

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--model",        required=True,
                   help="Local model path OR api model name")
    p.add_argument("--api",          default=None, choices=["openai", "deepseek"])
    p.add_argument("--api_key",      default=None)
    p.add_argument("--input_csv",    default=INPUT_CSV)
    p.add_argument("--gt_csv",       default=GT_CSV)
    p.add_argument("--result_dir",   default=RESULT_DIR)
    p.add_argument("--metrics_only", action="store_true")
    return p.parse_args()


def main():
    args = parse_args()
    os.makedirs(args.result_dir, exist_ok=True)

    model_name  = Path(args.model).name
    result_path = str(Path(args.result_dir) / f"results_{model_name}.json")

    gt = load_gt_csv(args.gt_csv)
    print(f"GT loaded: {len(gt)} samples")

    # -- metrics only --
    if args.metrics_only:
        if not Path(result_path).exists():
            raise FileNotFoundError(result_path)
        with open(result_path, encoding="utf-8") as f:
            results = json.load(f)
        metrics = compute_metrics(results, gt)
        print_metrics(metrics, model_name)
        return

    # -- resume --
    results, done_ids = [], set()
    if Path(result_path).exists():
        with open(result_path, encoding="utf-8") as f:
            results = json.load(f)
        done_ids = {r["id"] for r in results}
        print(f"Resuming -- already done: {len(done_ids)}")

    input_rows = load_input_csv(args.input_csv)
    print(f"Input: {len(input_rows)} rows | Remaining: {len(input_rows)-len(done_ids)}")

    # -- inference --
    if args.api:
        if not args.api_key:
            raise ValueError("--api_key required")
        run_api(args.api, args.model, args.api_key,
                input_rows, done_ids, results, result_path)
    else:
        run_transformers(model_path=args.model,
                         input_rows=input_rows,
                         done_ids=done_ids,
                         results=results,
                         result_path=result_path)

    # -- metrics --
    metrics = compute_metrics(results, gt)
    print_metrics(metrics, model_name)

    metrics_path = result_path.replace(".json", "_metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"Metrics -> {metrics_path}")


if __name__ == "__main__":
    main()
