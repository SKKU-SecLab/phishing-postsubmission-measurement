import json
import os
from pathlib import Path
from tqdm import tqdm

BASE_DIR   = Path(__file__).resolve().parent.parent.parent
INPUT_DIR  = BASE_DIR / "results" / "dynamic_analysis_blackwidow" / "analysis_results"
OUTPUT     = BASE_DIR / "results" / "clustering" / "all_functions.json"
ERRORS_OUT = BASE_DIR / "results" / "clustering" / "extract_errors.json"

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

def extract_triggered(obj, results, source_file):
    if isinstance(obj, dict):
        if "triggeredFunctions" in obj:
            for fn in obj["triggeredFunctions"]:
                handlers_concat = ""
                jq = fn.get("jquery_context") or {}
                handlers = jq.get("handlers") or []
                if handlers:
                    parts = []
                    for h in handlers:
                        name = h.get("name", "(anonymous)")
                        src  = h.get("source", "")
                        if src.strip():
                            parts.append(f"/* handler: {name} */\n{src}")
                    handlers_concat = "\n\n---\n\n".join(parts)

                results.append({
                    "source_file":            source_file,
                    "event_type":             fn.get("eventType", ""),
                    "fn_phase":               fn.get("phase", ""),
                    "function_name":          fn.get("functionName", ""),
                    "element_xpath":          fn.get("elementXPath", ""),
                    "function_source":        fn.get("functionSource", ""),
                    "jquery_handlers_concat": handlers_concat,
                    "body_hash":              fn.get("bodyHash", ""),
                    "is_default":             fn.get("isDefault", False),
                })
        for v in obj.values():
            extract_triggered(v, results, source_file)

    elif isinstance(obj, list):
        for item in obj:
            extract_triggered(item, results, source_file)


def main():
    json_files = list(Path(INPUT_DIR).rglob("*.json"))
    print(f"Number of JSON files: {len(json_files)}")

    all_results = []
    errors      = []

    for jf in tqdm(json_files, desc="Processing files"):
        try:
            with open(jf, encoding="utf-8", errors="replace") as f:
                data = json.load(f)
            extract_triggered(data, all_results, str(jf))
        except Exception as e:
            errors.append({"file": str(jf), "error": str(e)})

    # Assign gt_id
    for i, item in enumerate(all_results, start=1):
        item["gt_id"] = i

    print(f"Total extracted: {len(all_results)}")
    print(f"Error files: {len(errors)}")

    with open(OUTPUT, "w", encoding="utf-8") as f:
        json.dump({"items": all_results}, f, ensure_ascii=False)

    if errors:
        with open(ERRORS_OUT, "w") as f:
            json.dump(errors, f, indent=2, ensure_ascii=False)

    print(f"done: {OUTPUT}")


if __name__ == "__main__":
    main()