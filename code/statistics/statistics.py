#!/usr/bin/env python3
"""
statistics.py
statistics aggregation

JSON structure (actual confirmed format):
  {
    url, timestamp, mode, kit_path,
    forms: [ { action, method, xpath, fields, submit_log,
               overall_classification, static_action_analysis, page_url } ],
    pages: [ { page_url, forms: [...] } ],   <- same content as forms (duplicate)
    visited_urls, static_analysis
  }

  form.submit_log: { enter_key_test, enter_key_logs, submit_click_logs, submit_detail }
  form.submit_log.submit_click_logs: { networkReqs: [{type, url, resolved_server: {actions, exfil}}] }
  form.static_action_analysis: { server_file, receives_fields, actions: [{type,target,line}], exfil }
  form.overall_classification: string (e.g. "Case B: Server Round-trip (AJAX)")

Usage:
  python3 statistics.py \
    --results-dir results/dynamic_analysis_blackwidow/analysis_results \
    --out-dir results/statistics
"""

import argparse
import csv
import hashlib
import json
import os
import re
from collections import Counter, defaultdict
from urllib.parse import urlparse


_FN_EXAMPLE_SKIP_CATEGORIES = frozenset({"native_opaque"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def iter_result_files(results_dir):
    for name in sorted(os.listdir(results_dir)):
        if name.startswith("analysis_results_") and name.endswith(".json"):
            yield os.path.join(results_dir, name)


def extract_kit_name(data, filepath):
    kit_path = data.get("kit_path") or ""
    if kit_path:
        parts = re.split(r"[/\\]", kit_path.rstrip("/\\"))
        date_part = next(
            (p for p in reversed(parts) if re.search(r"\d{4}-\d{2}-\d{2}", p)), None
        )
        return date_part if date_part else (parts[-1] if parts else "")
    base = os.path.basename(filepath)
    stem = base[:-5] if base.endswith(".json") else base
    stem = stem[len("analysis_results_"):] if stem.startswith("analysis_results_") else stem
    m = re.search(r"_(\d+\.\d+|\d+)$", stem)
    kit_name = stem[:m.start()] if m else stem
    if re.fullmatch(r"[\d.]+", kit_name):
        kit_name = os.path.basename(filepath)
    return kit_name


def is_same_origin(url, base_origin):
    try:
        p = urlparse(url)
        if not p.scheme:  # relative URL
            return True
        return (p.scheme + "://" + p.netloc) == base_origin
    except Exception:
        return False



def parse_urlencoded_body(body_str):
    from urllib.parse import unquote_plus
    result = {}
    for pair in (body_str or "").split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            result[unquote_plus(k)] = unquote_plus(v)
        elif pair.strip():
            result[unquote_plus(pair.strip())] = ""
    return result


def submit_xhr_is_instrumented(submit_reqs, submit_detail):
    detail_fields = submit_detail.get("fields") or {}
    detail_keys   = set(detail_fields.keys())

    for req in (submit_reqs or []):
        if (req.get("type") or "").lower() != "xhr":
            continue

        # Signal 1 (strong): compare requestBody key set
        request_body = req.get("requestBody") or ""
        if request_body:
            body_keys = set(parse_urlencoded_body(request_body).keys())
            if detail_keys and body_keys == detail_keys:
                # Key sets match exactly -> the interceptor converted FormData directly to XHR
                return True
            if body_keys and body_keys != detail_keys:
                # Key sets differ -> the kit JS built the body separately -> kit-native
                return False

        # Signal 2 (secondary): if Content-Type is JSON/multipart it must be kit-native
        # (the interceptor always uses only application/x-www-form-urlencoded)
        ct = (req.get("requestHeaders") or {}).get("Content-Type", "")
        if "application/json" in ct or "multipart" in ct:
            return False

    # No requestBody and Content-Type is ambiguous -> cannot determine
    return None


def has_kit_native_ajax_fallback(submit_click_logs):
    """Secondary heuristic used when submit_xhr_is_instrumented() returns None.

    Only for cases with no requestBody (older kits, empty forms, etc.),
    infer whether the AJAX call is kit-native based on triggeredFunctions.

    Signal A: isDefault=False + categorize_function -> "custom_logic"
    Signal C: functionSource directly contains an AJAX keyword

    Returns True  -> judged as kit-native XHR
            False -> judged as interceptor conversion (conservative default)
    """
    ajax_kw = ("xmlhttprequest", "$.ajax", "$.post", "$.get", "fetch(")
    for fn in (submit_click_logs.get("triggeredFunctions") or []):
        if fn.get("isDefault") is not False:
            continue
        # Signal A
        if categorize_function(fn) in (
            "network_exfiltration",
            "tracking_analytics",
            "redirect_navigation",
            "identity_storage",
            "other_custom_logic",
        ):
            return True
        # Signal C
        src = (fn.get("functionSource") or "").lower()
        if any(k in src for k in ajax_kw):
            return True
    return False


def classify_transmission(has_fetch, has_xhr, submit_detail,
                           submit_click_logs, static_analysis, form,
                           submit_reqs=None):
    """Precisely classify the transmission method.

    Determination priority:
      1. fetch -> "fetch"
      2. has_xhr -> 3-way determination via submit_xhr_is_instrumented()
           True  (instrumentation confirmed) -> classify based on form.method
           False (kit-native confirmed) -> "xhr"
           None  (cannot determine) -> decided by has_kit_native_ajax_fallback() result
      3. submitted=True (no XHR, form submitted directly) -> classify based on form.method

    Returns (method_key: str | None, is_observed: bool)
    """
    if has_fetch:
        return "fetch", True

    if has_xhr:
        form_method = (form.get("method") or
                       submit_detail.get("method") or "post").upper()
        fallback_key = f"form_{form_method.lower()}" if form_method else "form_other"

        verdict = submit_xhr_is_instrumented(submit_reqs, submit_detail)

        if verdict is True:
            # requestBody == submit_detail.fields -> interceptor conversion
            return fallback_key, True

        if verdict is False:
            # key set mismatch or JSON Content-Type -> kit-native XHR
            return "xhr", True

        # verdict is None (no requestBody) -> fall back to triggeredFunctions signal
        if has_kit_native_ajax_fallback(submit_click_logs):
            return "xhr", True
        return fallback_key, True

    if submit_detail.get("submitted") is True:
        method = (submit_detail.get("method") or "").upper()
        key = f"form_{method.lower()}" if method else "form_other"
        return key, True

    return None, False


def classify_overall(classification_str):
    """Map the overall_classification string to an RQ2 category."""
    s = (classification_str or "").lower()
    if "ajax" in s or "xhr" in s or "round-trip" in s:
        return "ajax_xhr"
    if "fetch" in s:
        return "fetch"
    if "form" in s and ("post" in s or "submission" in s or "get" in s):
        return "standard_form"
    if "client-side" in s or "event handler" in s:
        return "client_side_only"
    return "other"


def _build_fn_blob(fn, include_jq_handlers=True):
    """Build a string blob used for classification."""
    name = (fn.get("functionName") or "").lower()
    src = (fn.get("source") or "").lower()
    evt = (fn.get("eventType") or "").lower()
    body = (fn.get("functionSource") or "").lower()
    parts = [name, src, evt, body]
    if include_jq_handlers:
        jq_ctx = fn.get("jquery_context") or {}
        for h in (jq_ctx.get("handlers") or []):
            parts += [
                str(h.get("name") or ""),
                str(h.get("selector") or ""),
                str(h.get("origType") or ""),
                str(h.get("source") or ""),
            ]
    return " ".join(parts).lower()


def is_jquery_router_wrapper(fn):
    """Whether this is jQuery's internal dispatch wrapper.

    When the instrumentation hooks addEventListener, sometimes the wrapper
    gets captured while the real handler ends up attached under
    fn.jquery_context.handlers instead.
    """
    body = (fn.get("functionSource") or "").lower()
    if "event.dispatch.apply" not in body:
        return False
    handlers = ((fn.get("jquery_context") or {}).get("handlers") or [])
    return len(handlers) > 0


def expand_effective_functions(fn):
    """Expand one triggeredFunctions entry into the actual functions to analyze.

    - Regular function: [fn]
    - jQuery router wrapper: expand jquery_context.handlers[*] into virtual
      functions (the wrapper itself is not counted)
    """
    if not is_jquery_router_wrapper(fn):
        return [fn]

    out = []
    handlers = ((fn.get("jquery_context") or {}).get("handlers") or [])
    for h in handlers:
        hsrc = (h.get("source") or "").strip()
        if not hsrc:
            continue
        # Exclude further dispatch-wrapper handlers (nested noise)
        if "event.dispatch.apply" in hsrc.lower():
            continue
        out.append({
            "functionName": h.get("name") or fn.get("functionName") or "",
            "eventType": h.get("origType") or fn.get("eventType") or "",
            "functionSource": hsrc,
            "source": "jquery_context_handler",
            # The real handler inside the wrapper (isDefault=True) may be
            # kit-specific, so conservatively set default=False here.
            "isDefault": False,
            "bodyHash": "",
            "jquery_context": {},
        })
    return out or [fn]


def _subcategorize_keyboard(evt, body, blob):
    """Replacement for key_handler: split key event handlers by purpose.

    The phase in rq1_phase_* (keydown / keyup / enter_key ...) only
    distinguishes "when"; here we split by "what it does" based on the
    function body.
    """
    # 1) Enter -> submit / login / form transmission
    if re.search(r"(keycode|which)\s*(===|==)\s*13\b", body) or re.search(
        r"\bkey\s*(===|==)\s*['\"]enter['\"]", body
    ):
        if any(
            k in blob
            for k in [
                "submit",
                ".submit",
                "form",
                "requestsubmit",
                "submitlogin",
                "loginrequest",
                "formsubmit",
                "lava(",
                "blur",
                "doc_keypress",
            ]
        ):
            return "keyboard_enter_submit"
    if any(
        k in blob
        for k in ["submitenter", "submitloginrequest", "submitlogin", "formsubmit"]
    ):
        return "keyboard_enter_submit"
    if "keycode" in blob and "13" in body and "submit" in blob:
        return "keyboard_enter_submit"

    # 2) Per-key mask / allowed-character filter -- before capture_suspect
    #    (prevents misclassification from the "buffer" keyword)
    if any(
        k in blob
        for k in [
            "restrictnumeric",
            "okchars",
            "isinararray",
            "clearbuffer",
            "writebuffer",
            "seeknext",
            "seekprev",
            "inputmask",
            "caret(",
        ]
    ):
        return "keyboard_input_mask"
    if any(k in blob for k in ["isnumberkey", "isnumber(", "isnumber ", "isnumeric"]) and evt in (
        "keypress",
        "keydown",
        "keyup",
    ):
        return "keyboard_input_mask"
    if any(k in blob for k in ["isinputnumber", "isnumberkey", "isnumber("]):
        return "keyboard_input_mask"
    if (
        "fromcharcode" in blob
        and ("which" in blob or "charcode" in blob)
        and any(k in blob for k in ["test", "regex", "match", "/[", "digit"])
    ):
        return "keyboard_input_mask"
    # Numeric/character filter via charCode / which range comparison (e.g., charCode >= 48 && charCode <= 57)
    if re.search(r"(charcode|\.which)\s*(>=|>)\s*\d+", body) and re.search(
        r"(charcode|\.which)\s*(<=|<)\s*(57|90|122|127)\b", body
    ):
        return "keyboard_input_mask"

    # 3) Suspected keylogging/capture -- only when no mask pattern matched (order matters)
    if any(k in blob for k in ["keylog", "keystroke", "keylogger"]):
        return "keyboard_capture_suspect"
    if "fromcharcode" in blob and ("which" in blob or "keycode" in blob):
        if any(k in blob for k in [".push(", "+=", "buffer", "concat"]):
            return "keyboard_capture_suspect"

    # 4) Esc/arrow keys/Tab etc. UI/focus/modal (not Enter-submit)
    if re.search(r"(keycode|which)\s*(===|==)\s*27\b", body) or re.search(
        r"\b27\s*===\s*\w+\.keycode", body
    ):
        return "keyboard_ui_shortcut"
    if re.search(r"\b(9|37|38|39|40)\s*\)===\s*\w+\.which", body):
        return "keyboard_ui_shortcut"
    if any(k in blob for k in ["combobox", "clickmod"]):
        if "which" in blob or "keycode" in blob:
            return "keyboard_ui_shortcut"

    # 5) Real-time input handling (value/error message/class update right after keypress)
    if evt in ("keyup", "keydown", "keypress"):
        if any(k in blob for k in [".val()", "this.value", "target.value"]) and any(
            k in blob
            for k in [
                "error",
                "validation",
                "err_div",
                "has_err",
                "haserror",
                "please enter",
                "invalid",
                "fadeout",
                "removeclass",
                "addclass",
            ]
        ):
            return "keyboard_realtime_typing"

    return "keyboard_generic"


def categorize_function(fn):
    """
    Fine-grained categorization of JS functions by purpose (v2.0).

    Summary of v2.0 changes:
      - The jQuery event.dispatch wrapper is now checked **before** the key
        event type (prevents keyboard sub-category misclassification).
      - The Geolocation API check now comes before UI rules like `.style`.
      - Angular digest (`$apply`, `$$phase`, etc.) is separated from
        `keyboard_*` into its own `spa_framework_binding` category.
      - Key-level validation such as numeric-only input now goes to
        `input_validation` (relaxing the single key-only bucket).

    Keyboard sub-categories (v2.1, `key_handler` removed):
      - keyboard_enter_submit     : Enter(13) -> submit/login/request, etc.
      - keyboard_input_mask       : per-key numeric/character filter, mask plugins (caret/buffer, etc.)
      - keyboard_capture_suspect  : keystroke buffer / suspected keylogging pattern
      - keyboard_realtime_typing  : immediate value/error UI update on key event
      - keyboard_ui_shortcut      : Esc/arrow keys/Tab etc. UI/focus/modal shortcuts
      - keyboard_generic          : key handlers that match none of the above

    Main categories:
      - jquery_wrapper, jquery_ui_widget
      - geolocation_access, spa_framework_binding
      - tracking_analytics, network_exfiltration, redirect_navigation, identity_storage
      - input_validation, input_masking, length_limit
      - ui_animation, focus_modal
      - native_opaque (body is just [native code] -- still counted in aggregates, excluded from example CSV)
      - payment_card_detection, input_email_pattern, input_phone_pattern, input_value_normalization
      - keyboard_* (above), other_custom_logic
    """
    evt = (fn.get("eventType") or "").lower()
    src_raw = (fn.get("functionSource") or fn.get("body") or "").strip()
    body = src_raw.lower()
    blob = _build_fn_blob(fn, include_jq_handlers=False)

    # Browser-native / bound function -- no source -> separate bucket (prevents misclassification into keyboard/other)
    if "[native code]" in body:
        return "native_opaque"

    # --- 1) Tracking / transmission / redirect / storage ---------------------
    if any(
        k in blob
        for k in [
            "rapidbeacon", "sendbeacon", "beaconclick", "parsedataylk",
            "data-ylk", "data_ylk", "ylk",
            "ga(", "gtag(", "pixel", "omniture", "trackevent",
            "analytics", "mixpanel", "segment",
        ]
    ):
        return "tracking_analytics"

    if any(
        k in blob
        for k in [
            "xmlhttprequest",
            "fetch(",
            "$.ajax",
            "axios",
            ".post(",
            "$.get(",
            "formdata(",
            ".send(",
        ]
    ):
        return "network_exfiltration"

    if any(
        k in blob
        for k in [
            "location.href",
            "window.location",
            "window.open(",
            "location.assign(",
            "location.replace(",
            "document.location",
        ]
    ):
        return "redirect_navigation"

    if any(k in blob for k in ["document.cookie", "localstorage", "sessionstorage"]):
        return "identity_storage"

    # --- 2) Geolocation (before UI style/toast rules) -------------------------
    if any(
        k in blob
        for k in [
            "navigator.geolocation",
            "getcurrentposition",
            "watchposition",
            "geolocation",
            "position.coords",
            "coords.latitude",
            "coords.longitude",
            "current location",
            "your location",
            "fetching your",
        ]
    ) or re.search(r"\bgetlocation\b", blob):
        return "geolocation_access"

    # --- 3) jQuery internal dispatch wrapper (**must** come before keydown/keyup type check) ---
    # minified: r.event.dispatch.apply(a,arguments) + event.triggered
    if "event.dispatch.apply" in body:
        return "jquery_wrapper"
    if "event.triggered" in body and ".event.dispatch" in body:
        return "jquery_wrapper"
    if re.search(r"\w+\.event\.dispatch\.apply", body):
        return "jquery_wrapper"
    if any(k in blob for k in ["n.event.dispatch", "delegatedhandler"]):
        return "jquery_wrapper"
    if re.search(r"jquery\.event\.dispatch|j\.event\.dispatch", blob):
        return "jquery_wrapper"
    if "jquery" in blob and any(
        k in blob for k in ["event.dispatch", "event.handle", "event.trigger"]
    ):
        return "jquery_wrapper"

    # --- 4) SPA / Angular-like digest bridge ----------------------------------
    if any(
        k in blob
        for k in [
            "$$phase",
            "$evalasync",
            "$$watchers",
            "$digest",
        ]
    ) or re.search(r"\$apply\s*\(", body):
        return "spa_framework_binding"

    # --- 4b) jQuery Validate plugin's internal delegation wrapper -------------
    # e.g., $.data(this.form, "validator") / validator.settings.submitHandler
    if re.search(r"\$\.data\s*\([^)]*[\"']validator[\"']", body) or (
        "validator.settings" in blob and "$.data" in blob
    ):
        return "jquery_wrapper"
    if re.search(r"validator\s*=\s*\$\.data\s*\(", body):
        return "jquery_wrapper"

    # --- 5) Field semantic classification (payment / email / phone / normalization) ---
    # Placed before the standalone "validate" match so that validateEmail etc.
    # don't fall straight through to input_validation only.
    if any(
        k in blob
        for k in [
            "$.payment",
            ".payment.",
            "payment.cardtype",
            "jquery.payment",
            "setcardtype",
            "payment.card",
            "luhn",
            "cleave(",
            "imask(",
        ]
    ) or re.search(r"\.payment\.\w+", blob):
        return "payment_card_detection"

    if any(
        k in blob
        for k in [
            "validateemail",
            "isemail",
            "emailregex",
            "checkemail",
            "emailvalid",
            "validemail",
            "mailformat",
            "emailpattern",
            "emailformat",
            "emailcheck",
        ]
    ) or re.search(r"\b(isemail|validateemail|emailcheck|checkemail)\b", body):
        return "input_email_pattern"
    if "email" in blob and any(k in blob for k in ["@", "indexof", "regex", "pattern", ".test("]) and any(
        k in blob for k in ["test", "regex", "match", "pattern", "split", "indexof"]
    ):
        return "input_email_pattern"

    if any(
        k in blob
        for k in [
            "validatephone",
            "phonevalid",
            "phoneregex",
            "telregex",
            "mobilevalid",
            "intl-tel",
            "intltel",
            "parsephone",
            "libphonenumber",
        ]
    ):
        return "input_phone_pattern"
    if ("phone" in blob or "tel" in blob or "mobile" in blob) and any(
        k in blob for k in ["regex", "replace", "pattern", "mask", "format"]
    ):
        if "email" not in blob:
            return "input_phone_pattern"

    # Value-only replacement/normalization in oninput/onchange, etc. (e.g., digits/decimal point only)
    if re.search(r"\.value\.replace\s*\(\s*/", body) or re.search(
        r"this\.value\s*=\s*[^;]{0,200}\.replace\s*\(\s*/", body
    ):
        return "input_value_normalization"

    # --- 6) Input validation / masking / length -------------------------------
    if any(
        k in blob
        for k in [
            "validate",
            "checkvalidity",
            "pattern",
            "required",
            "regex",
            "setcustomvalidity",
            "validity.",
            # Numeric-only validation invoked from key events
            "isinputnumber",
            "inputnumber",
            "onlynumber",
            "numericonly",
            "allowonlynumbers",
            "isnumeric",
        ]
    ):
        return "input_validation"

    if any(k in blob for k in [
        "mask", "formatter", "format", "creditcard", "cardnumber",
        "okchars", "caret(", "writebuffer", "clearbuffer", "seeknext", "seekprev",
        "inputmask", "restrictnumeric",
    ]):
        return "input_masking"

    # Mark/color/class feedback based on password length/strength (input event, etc.)
    if "password" in blob and (
        ".val().length" in body
        or "val().length" in body
        or any(k in blob for k in ["mark password", "password green", "password red", "inp_text error"])
    ):
        return "input_validation"

    if any(k in blob for k in ["maxlength", "minlength"]):
        return "length_limit"
    if re.search(r"\.length\s*(==|===|>=|>|<|<=)\s*\d", body):
        return "length_limit"

    # --- 7) UI state / style ---------------------------------------------------
    # Even with classList manipulation, prefer input_validation if in a submit/check/valid context
    if any(k in blob for k in ["classlist.add", "classlist.remove", "classlist.toggle",
                                "dom.addclass", "dom.removeclass"]):
        if any(k in blob for k in ["valid", "invalid", "error", "success",
                                    "checkvalidity", "setcustomvalidity", "was-validated"]):
            return "input_validation"

    if any(
        k in blob
        for k in [
            "animationname",
            "originalevent.animationname",
            "onautofill",
            "autofill",
            "backgroundcolor",
            "bordercolor",
            ".style.",
            "style.background",
            "classlist.add",
            "classlist.remove",
            "classlist.toggle",
            "dom.addclass",
            "dom.removeclass",
        ]
    ):
        return "ui_animation"

    if any(
        k in blob
        for k in [
            "ui-state-disabled",
            "ui-state-",
            "ui-tooltip",
            "ui-dialog",
            "jquery.ui",
            ".widget(",
            "jquery.widget",
            "datepicker",
            "draggable",
            "droppable",
        ]
    ):
        return "jquery_ui_widget"

    # --- 8) Keyboard (v2.1: key_handler removed -> broken out into purpose-specific keyboard_*) ---
    if evt in ("keydown", "keyup", "keypress") or any(
        k in blob
        for k in [
            "keydown",
            "keyup",
            "keypress",
            "keycode",
            "charcode",
            "which ===",
            "which ==",
            "key ===",
            "key ==",
        ]
    ):
        return _subcategorize_keyboard(evt, body, blob)
    if "enter" in blob and re.search(
        r'(keycode|which|key)\s*(===|==)\s*(13|["\']enter["\'])', body
    ):
        return _subcategorize_keyboard(evt, body, blob)

    if any(k in blob for k in ["animate(", "fade", "slide", "transition"]):
        return "ui_animation"

    if any(k in blob for k in ["modal", "trap", "overlay", "dialog"]):
        return "focus_modal"

    if any(
        k in blob
        for k in [
            "parseint(",
            "parsefloat(",
            "parsedate",
            "date.parse",
            "dayjs(",
            "moment(",
        ]
    ):
        return "input_structured_parse"

    # --- 9) Length check + error/success CSS toggle -> input_validation -------
    if re.search(r"\.length\s*(==|===|>=|>|<|<=)\s*\d", body) and any(
        k in blob for k in ["error", "valid", "invalid", "success", "has-error",
                             "classlist", "addclass", "removeclass"]
    ):
        return "input_validation"

    return "other_custom_logic"


def to_coarse_category(detail_cat):
    """Map a fine-grained category to its parent (coarse) bucket (v2.0)."""
    if detail_cat in ("native_opaque",):
        return "native_opaque"
    if detail_cat in ("jquery_wrapper",):
        return "jquery_wrapper"
    if detail_cat in ("jquery_ui_widget",):
        return "jquery_ui_widget"
    if detail_cat in ("geolocation_access",):
        return "geolocation_access"
    if detail_cat in ("spa_framework_binding",):
        return "spa_framework_binding"
    if detail_cat in ("payment_card_detection",):
        return "payment_card_detection"
    if detail_cat in ("input_email_pattern",):
        return "input_email_pattern"
    if detail_cat in ("input_phone_pattern",):
        return "input_phone_pattern"
    if detail_cat in ("input_value_normalization",):
        return "input_value_normalization"
    if detail_cat in ("input_structured_parse",):
        return "input_structured_parse"
    if detail_cat in ("input_validation",):
        return "input_validation"
    if detail_cat in ("input_masking",):
        return "input_masking"
    if detail_cat in ("length_limit",):
        return "length_limit"
    if detail_cat in (
        "keyboard_enter_submit",
        "keyboard_input_mask",
        "keyboard_capture_suspect",
        "keyboard_realtime_typing",
        "keyboard_ui_shortcut",
        "keyboard_generic",
    ):
        return "keyboard"
    if detail_cat in ("focus_modal", "ui_animation"):
        return "focus_modal"
    if detail_cat in (
        "network_exfiltration",
        "redirect_navigation",
        "identity_storage",
        "tracking_analytics",
        "other_custom_logic",
    ):
        return "custom_logic"
    return "custom_logic"


def classify_event_trigger(evt_type):
    evt = (evt_type or "").lower()
    if evt in ("keydown", "input"):
        return "immediate_typing_intervention"
    if evt in ("blur", "change"):
        return "on_leave_field_intervention"
    if evt in ("click", "submit"):
        return "final_submit_intervention"
    return "other_event"


def write_csv(path, headers, rows):
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


def process_triggered_functions(lg, kit_name, base_origin,
                                rq1_total_calls, rq1_kits_with_js_calls,
                                rq1_cat_calls, rq1_cat_unique_hashes,
                                rq1_default_calls_ref, rq1_custom_calls_ref,
                                rq1_event_trigger_counts, rq1_event_trigger_kits,
                                rq2_realtime_kits,
                                rq1_fn_examples=None,
                                phase=None,                 # NEW
                                rq1_phase_cat_calls=None,   # NEW
                                rq1_phase_total_calls=None,  # NEW
                                rq2_realtime_first_file=None,
                                result_file=None,
                                ):   # NEW param
    """Process triggeredFunctions from one typing/backspace log entry."""
    fn_count = 0
    if lg.get("triggeredFunctions"):
        for fn in lg["triggeredFunctions"]:
            effective_fns = expand_effective_functions(fn)
            for efn in effective_fns:
                rq1_total_calls[0] += 1
                fn_count += 1
                rq1_kits_with_js_calls.add(kit_name)
                cat = categorize_function(efn)
                rq1_cat_calls[cat] += 1
                h = efn.get("bodyHash") or ""
                if not h:
                    seed = (
                        (efn.get("functionName") or "") + "||" +
                        (efn.get("eventType") or "") + "||" +
                        (efn.get("functionSource") or "")
                    )
                    h = hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()
                if h:
                    rq1_cat_unique_hashes[cat].add(h)
                if efn.get("isDefault") is True:
                    rq1_default_calls_ref[0] += 1
                else:
                    rq1_custom_calls_ref[0] += 1
                for ev in (lg.get("firedEvents") or []):
                    trigger = classify_event_trigger(ev.get("eventType"))
                    rq1_event_trigger_counts[trigger] += 1
                    rq1_event_trigger_kits[trigger].add(kit_name)
                # NEW: phase x category cross-tabulation
                if phase and rq1_phase_cat_calls is not None:
                    rq1_phase_cat_calls[(phase, cat)] += 1
                if phase and rq1_phase_total_calls is not None:
                    rq1_phase_total_calls[phase] += 1
                # Collect a function example per category (native_opaque etc. excluded since they have no body)
                if rq1_fn_examples is not None and h and cat not in _FN_EXAMPLE_SKIP_CATEGORIES:
                    src = (efn.get("functionSource") or efn.get("body") or "").strip()
                    name = (efn.get("functionName") or "").strip()
                    evt = (efn.get("eventType") or "").strip()
                    is_def = efn.get("isDefault", False)
                    if h not in rq1_fn_examples[cat]:
                        rq1_fn_examples[cat][h] = {
                            "name":       name,
                            "eventType":  evt,
                            "isDefault":  is_def,
                            "source":     src[:800],   # limited to 800 chars
                            "kits":       set(),
                            "call_count": 0,
                        }
                    rq1_fn_examples[cat][h]["kits"].add(kit_name)
                    rq1_fn_examples[cat][h]["call_count"] += 1

    # real-time network req during typing
    if lg.get("networkReqs"):
        for req in lg["networkReqs"]:
            req_url = req.get("url") or ""
            if req_url.startswith("/"):
                req_url = base_origin + req_url
            if base_origin and req_url and not is_same_origin(req_url, base_origin):
                continue
            rq2_realtime_kits.add(kit_name)
            if rq2_realtime_first_file is not None and result_file:
                rq2_realtime_first_file.setdefault(kit_name, result_file)

    return fn_count


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="RQ1-RQ4 statistics aggregation v2")
    parser.add_argument("--results-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    files = list(iter_result_files(args.results_dir))
    print(f"[Info] Found {len(files)} JSON files")

    # -----------------------------------------------------------------------
    # Counters
    # -----------------------------------------------------------------------
    # RQ1
    rq1_total_calls     = [0]   # mutable ref
    rq1_default_calls   = [0]
    rq1_custom_calls    = [0]
    rq1_kits_with_js_calls  = set()
    rq1_cat_calls           = Counter()
    rq1_cat_unique_hashes   = defaultdict(set)
    rq1_event_trigger_counts = Counter()
    rq1_event_trigger_kits   = defaultdict(set)
    rq1_validation_type_counts = Counter()
    rq1_validation_type_kits   = defaultdict(set)
    rq1_field_type_counts   = Counter()
    rq1_enter_key_dispatched  = 0
    rq1_enter_key_prevented   = 0
    # NEW: collect function examples per category
    # {cat: {bodyHash: {"name": str, "source": str, "kits": set, "call_count": int}}}
    rq1_fn_examples = defaultdict(dict)

    # NEW: phase x category cross-tabulation
    # phase: keydown / keypress / input / keyup / backspace_keydown / backspace_input
    #        backspace_keyup / submit / enter_key
    # Counter key: (phase, category)
    rq1_phase_cat_calls   = Counter()   # (phase, cat) -> call count
    rq1_phase_total_calls = Counter()   # phase -> total fn calls (all categories)

    # RQ2
    rq2_overall_class_counter  = Counter()   # distribution of overall_classification
    rq2_dynamic_method_counter = Counter()   # xhr/fetch/form_post (corrected)
    rq2_old_method_counter     = Counter()   # pre-correction (for comparison)
    rq2_verdict_counter        = Counter()   # determination path: instrumented/kit_native/fallback_native/fallback_form
    rq2_verdict_rows           = []          # per-form verdict -> CSV for manual verification (result_file, form_index, ...)
    rq2_realtime_kits          = set()
    rq2_realtime_first_file    = {}          # kit_name -> path of the first observed analysis_results JSON
    rq2_total_submit_obs       = 0
    rq2_form_action_origin     = Counter()
    rq2_submit_status_counter  = Counter()

    # RQ3 - static (static_action_analysis from all forms)
    rq3_static_action_counter  = Counter()
    rq3_static_exfil_targets   = Counter()
    rq3_static_action_evidence = defaultdict(list)
    # RQ3 - dynamic (networkReqs.resolved_server after submit, confirms actual execution)
    rq3_dynamic_action_counter = Counter()
    rq3_dynamic_exfil_targets  = Counter()

    # Aggregate receives_post field names (form-level + global PHP scan)
    # form-level: form.static_action_analysis.receives_fields
    # global:     data.static_analysis.php_files[*].receives_post
    rp_form_field_counter   = Counter()   # based on form action (linked to dynamic analysis)
    rp_global_field_counter = Counter()   # based on all PHP files (higher coverage)
    rp_form_kits            = defaultdict(set)   # field_name -> kit set
    rp_global_kits          = defaultdict(set)

    # Kit-level
    kit_rows    = []
    monthly     = defaultdict(lambda: Counter())
    success_kits = 0   # kits that have forms
    fail_kits    = 0
    total_forms  = 0

    # -----------------------------------------------------------------------
    # Per-file processing
    # -----------------------------------------------------------------------
    for fp in files:
        data = safe_read_json(fp)
        if not data:
            continue

        kit_name  = extract_kit_name(data, fp)
        base_url  = data.get("url") or ""
        p         = urlparse(base_url)
        base_origin = f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else ""

        date_m    = re.search(r"(\d{4}-\d{2}-\d{2})", kit_name)
        date_str  = date_m.group(1) if date_m else ""
        month_str = date_str[:7] if date_str else ""

        # top-level forms (flat, same content as pages[i].forms)
        forms = data.get("forms") or []
        total_forms += len(forms)

        has_forms = bool(forms)
        if has_forms:
            success_kits += 1
        else:
            fail_kits += 1

        kit_fn_calls    = 0
        kit_net_submit  = 0
        kit_server_acts = 0

        for form_index, form in enumerate(forms):
            submit_log        = form.get("submit_log") or {}
            submit_click_logs = submit_log.get("submit_click_logs") or {}
            submit_reqs       = submit_click_logs.get("networkReqs") or []
            submit_detail     = submit_log.get("submit_detail") or {}

            # ------------------------------------------------------------------
            # RQ1: Enter key analysis
            # ------------------------------------------------------------------
            enter_test = submit_log.get("enter_key_test") or {}
            if enter_test.get("dispatched"):
                rq1_enter_key_dispatched += 1
            if enter_test.get("defaultPrevented"):
                rq1_enter_key_prevented += 1

            # ------------------------------------------------------------------
            # RQ2: overall_classification (combined static+dynamic classification)
            # ------------------------------------------------------------------
            oc = form.get("overall_classification") or ""
            rq2_overall_class_counter[oc] += 1

            # RQ2: form action origin
            form_action = form.get("action") or ""
            if form_action and base_origin:
                if is_same_origin(form_action, base_origin):
                    rq2_form_action_origin["same_origin"] += 1
                else:
                    rq2_form_action_origin["cross_origin"] += 1
            else:
                rq2_form_action_origin["unknown"] += 1

            # RQ2: submit HTTP status
            status = submit_detail.get("status")
            if status:
                rq2_submit_status_counter[str(status)] += 1

            # RQ2: dynamic transmission method -- corrected classification
            # (fixes the misclassification where the interceptor converts a form POST to XHR)
            has_xhr   = False
            has_fetch = False
            for req in submit_reqs:
                rtype   = (req.get("type") or "").lower()
                req_url = req.get("url") or ""
                if req_url and not req_url.startswith("http"):
                    req_url = base_origin + "/" + req_url.lstrip("/")
                if base_origin and req_url and not is_same_origin(req_url, base_origin):
                    continue
                if rtype == "xhr":
                    has_xhr = True
                elif rtype == "fetch":
                    has_fetch = True

            static_analysis = data.get("static_analysis") or {}
            method_key, is_obs = classify_transmission(
                has_fetch, has_xhr, submit_detail,
                submit_click_logs, static_analysis, form,
                submit_reqs=submit_reqs,
            )
            if is_obs:
                rq2_dynamic_method_counter[method_key] += 1
                rq2_total_submit_obs += 1
                kit_net_submit += 1

                # Tally the determination path (for debugging + describing the paper's methodology)
                verdict_bucket = ""
                if has_xhr:
                    verdict = submit_xhr_is_instrumented(submit_reqs, submit_detail)
                    if verdict is True:
                        rq2_verdict_counter["body_match_instrumented"] += 1
                        verdict_bucket = "body_match_instrumented"
                    elif verdict is False:
                        rq2_verdict_counter["body_match_kit_native"] += 1
                        verdict_bucket = "body_match_kit_native"
                    else:
                        # fallback to triggeredFunctions
                        if has_kit_native_ajax_fallback(submit_click_logs):
                            rq2_verdict_counter["fallback_triggeredfn_native"] += 1
                            verdict_bucket = "fallback_triggeredfn_native"
                        else:
                            rq2_verdict_counter["fallback_triggeredfn_form"] += 1
                            verdict_bucket = "fallback_triggeredfn_form"
                elif has_fetch:
                    rq2_verdict_counter["fetch"] += 1
                    verdict_bucket = "fetch"
                else:
                    rq2_verdict_counter["no_xhr_direct_submit"] += 1
                    verdict_bucket = "no_xhr_direct_submit"

                if has_fetch:
                    old_m = "fetch"
                elif has_xhr:
                    old_m = "xhr"
                elif submit_detail.get("submitted") is True:
                    _om = (submit_detail.get("method") or "").upper()
                    old_m = f"form_{_om.lower()}" if _om else "form_other"
                else:
                    old_m = ""

                rq2_verdict_rows.append([
                    fp,
                    kit_name,
                    form_index,
                    str(has_xhr).lower(),
                    str(has_fetch).lower(),
                    method_key,
                    old_m,
                    verdict_bucket,
                ])

            # For before/after comparison -- also tally with the original logic in parallel
            if has_fetch:
                rq2_old_method_counter["fetch"] += 1
            elif has_xhr:
                rq2_old_method_counter["xhr"] += 1
            elif submit_detail.get("submitted") is True:
                _m = (submit_detail.get("method") or "").upper()
                rq2_old_method_counter[f"form_{_m.lower()}" if _m else "form_other"] += 1

            # ------------------------------------------------------------------
            # RQ3 - static: form.static_action_analysis
            # ------------------------------------------------------------------
            saa = form.get("static_action_analysis") or {}
            for act in (saa.get("actions") or []):
                atype = (act.get("type") or "").lower()
                if atype:
                    rq3_static_action_counter[atype] += 1
                    kit_server_acts += 1
                    ev_str = f"{saa.get('server_file','')}::L{act.get('line','')}::{atype}::{act.get('target','')}"
                    if len(rq3_static_action_evidence[atype]) < 20:
                        rq3_static_action_evidence[atype].append(ev_str)
            for exfil in (saa.get("exfil") or []):
                rq3_static_exfil_targets[exfil] += 1

            # ------------------------------------------------------------------
            # receives_post (form-level): static_action_analysis.receives_fields
            # ------------------------------------------------------------------
            for field_name in (saa.get("receives_fields") or []):
                fname = field_name.strip().lower()
                if fname:
                    rp_form_field_counter[fname] += 1
                    rp_form_kits[fname].add(kit_name)

            # ------------------------------------------------------------------
            # RQ3 - dynamic: networkReqs[i].resolved_server
            # ------------------------------------------------------------------
            for req in submit_reqs:
                resolved = req.get("resolved_server") or {}
                for act in (resolved.get("actions") or []):
                    atype = (act.get("type") or "").lower()
                    if atype:
                        rq3_dynamic_action_counter[atype] += 1
                for exfil in (resolved.get("exfil") or []):
                    rq3_dynamic_exfil_targets[exfil] += 1

            # ------------------------------------------------------------------
            # RQ1: iterate over fields (typing_log / backspace_log)
            # ------------------------------------------------------------------
            for field in (form.get("fields") or []):
                ftype = (field.get("type") or "unknown").lower()
                rq1_field_type_counts[ftype] += 1

                has_html5_val   = False
                has_custom_js   = False

                for char_entry in (field.get("typing_log") or []):
                    for phase in ("keydown", "keypress", "input", "keyup"):
                        lg = char_entry.get(phase) or {}
                        if not lg:
                            continue
                        if lg.get("html5Validation"):
                            has_html5_val = True
                        n = process_triggered_functions(
                            lg, kit_name, base_origin,
                            rq1_total_calls, rq1_kits_with_js_calls,
                            rq1_cat_calls, rq1_cat_unique_hashes,
                            rq1_default_calls, rq1_custom_calls,
                            rq1_event_trigger_counts, rq1_event_trigger_kits,
                            rq2_realtime_kits,
                            rq1_fn_examples,
                            phase=phase,
                            rq1_phase_cat_calls=rq1_phase_cat_calls,
                            rq1_phase_total_calls=rq1_phase_total_calls,
                            rq2_realtime_first_file=rq2_realtime_first_file,
                            result_file=fp,
                        )
                        if n > 0:
                            has_custom_js = True
                        kit_fn_calls += n

                b = field.get("backspace_log") or {}
                for phase in ("keydown", "input", "keyup"):
                    lg = b.get(phase) or {}
                    if not lg:
                        continue
                    if lg.get("html5Validation"):
                        has_html5_val = True
                    n = process_triggered_functions(
                        lg, kit_name, base_origin,
                        rq1_total_calls, rq1_kits_with_js_calls,
                        rq1_cat_calls, rq1_cat_unique_hashes,
                        rq1_default_calls, rq1_custom_calls,
                        rq1_event_trigger_counts, rq1_event_trigger_kits,
                        rq2_realtime_kits,
                        rq1_fn_examples,
                        phase=f"backspace_{phase}",
                        rq1_phase_cat_calls=rq1_phase_cat_calls,
                        rq1_phase_total_calls=rq1_phase_total_calls,
                        rq2_realtime_first_file=rq2_realtime_first_file,
                        result_file=fp,
                    )
                    if n > 0:
                        has_custom_js = True
                    kit_fn_calls += n

                cls = (field.get("classification") or "").lower()
                if any(k in cls for k in ("custom", "js", "javascript", "ajax", "input_validation")):
                    has_custom_js = True

                if has_html5_val and has_custom_js:
                    vtype = "hybrid_html5_and_custom_js"
                elif has_html5_val:
                    vtype = "native_html5_only"
                elif has_custom_js:
                    vtype = "custom_js_only"
                else:
                    vtype = "no_validation_observed"
                rq1_validation_type_counts[vtype] += 1
                rq1_validation_type_kits[vtype].add(kit_name)

            # submit phase events
            for ev in (submit_click_logs.get("firedEvents") or []):
                trigger = classify_event_trigger(ev.get("eventType"))
                rq1_event_trigger_counts[trigger] += 1
                rq1_event_trigger_kits[trigger].add(kit_name)

            # submit phase triggeredFunctions
            # BUG FIX: added isDefault branch (missing in the previous version, causing total != default+custom)
            for fn_entry in (submit_click_logs.get("triggeredFunctions") or []):
                for efn in expand_effective_functions(fn_entry):
                    rq1_total_calls[0] += 1
                    kit_fn_calls += 1
                    rq1_kits_with_js_calls.add(kit_name)
                    cat = categorize_function(efn)
                    rq1_cat_calls[cat] += 1
                    if efn.get("isDefault") is True:
                        rq1_default_calls[0] += 1
                    else:
                        rq1_custom_calls[0] += 1

                    h = efn.get("bodyHash") or ""
                    if not h:
                        seed = (
                            (efn.get("functionName") or "") + "||" +
                            (efn.get("eventType") or "") + "||" +
                            (efn.get("functionSource") or "")
                        )
                        h = hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()
                    if h:
                        rq1_cat_unique_hashes[cat].add(h)
                        if rq1_fn_examples is not None and cat not in _FN_EXAMPLE_SKIP_CATEGORIES:
                            src = (efn.get("functionSource") or efn.get("body") or "").strip()
                            name = (efn.get("functionName") or "").strip()
                            evt = (efn.get("eventType") or "").strip()
                            is_def = efn.get("isDefault", False)
                            if h not in rq1_fn_examples[cat]:
                                rq1_fn_examples[cat][h] = {
                                    "name":       name,
                                    "eventType":  evt,
                                    "isDefault":  is_def,
                                    "source":     src[:800],
                                    "kits":       set(),
                                    "call_count": 0,
                                }
                            rq1_fn_examples[cat][h]["kits"].add(kit_name)
                            rq1_fn_examples[cat][h]["call_count"] += 1
                    rq1_phase_cat_calls[("submit", cat)] += 1
                    rq1_phase_total_calls["submit"] += 1

            # enter_key phase triggeredFunctions
            # BUG FIX: added isDefault branch
            enter_key_logs = submit_log.get("enter_key_logs") or {}
            for fn_entry in (enter_key_logs.get("triggeredFunctions") or []):
                for efn in expand_effective_functions(fn_entry):
                    rq1_total_calls[0] += 1
                    kit_fn_calls += 1
                    rq1_kits_with_js_calls.add(kit_name)
                    cat = categorize_function(efn)
                    rq1_cat_calls[cat] += 1
                    if efn.get("isDefault") is True:
                        rq1_default_calls[0] += 1
                    else:
                        rq1_custom_calls[0] += 1

                    h = efn.get("bodyHash") or ""
                    if not h:
                        seed = (
                            (efn.get("functionName") or "") + "||" +
                            (efn.get("eventType") or "") + "||" +
                            (efn.get("functionSource") or "")
                        )
                        h = hashlib.sha256(seed.encode("utf-8", errors="ignore")).hexdigest()
                    if h:
                        rq1_cat_unique_hashes[cat].add(h)
                        if rq1_fn_examples is not None and cat not in _FN_EXAMPLE_SKIP_CATEGORIES:
                            src = (efn.get("functionSource") or efn.get("body") or "").strip()
                            name = (efn.get("functionName") or "").strip()
                            evt = (efn.get("eventType") or "").strip()
                            is_def = efn.get("isDefault", False)
                            if h not in rq1_fn_examples[cat]:
                                rq1_fn_examples[cat][h] = {
                                    "name":       name,
                                    "eventType":  evt,
                                    "isDefault":  is_def,
                                    "source":     src[:800],
                                    "kits":       set(),
                                    "call_count": 0,
                                }
                            rq1_fn_examples[cat][h]["kits"].add(kit_name)
                            rq1_fn_examples[cat][h]["call_count"] += 1
                    rq1_phase_cat_calls[("enter_key", cat)] += 1
                    rq1_phase_total_calls["enter_key"] += 1

        # receives_post (global): data.static_analysis.php_files
        static_analysis = data.get("static_analysis") or {}
        for _php_path, php_info in (static_analysis.get("php_files") or {}).items():
            for field_name in (php_info.get("receives_post") or []):
                fname = field_name.strip().lower()
                if fname:
                    rp_global_field_counter[fname] += 1
                    rp_global_kits[fname].add(kit_name)

        # Monthly
        if month_str:
            monthly[month_str]["kits"] += 1
            monthly[month_str]["kits_with_forms"] += 1 if has_forms else 0
            monthly[month_str]["js_calls"]    += kit_fn_calls
            monthly[month_str]["submit_obs"]  += kit_net_submit
            monthly[month_str]["server_acts"] += kit_server_acts

        kit_rows.append([
            kit_name, date_str,
            1 if has_forms else 0,
            len(forms),
            kit_fn_calls,
            kit_net_submit,
            kit_server_acts,
            data.get("kit_path", ""),
            os.path.basename(fp),
        ])

    # -----------------------------------------------------------------------
    # CSV output
    # -----------------------------------------------------------------------
    total_calls     = max(1, rq1_total_calls[0])
    total_triggers  = max(1, sum(rq1_event_trigger_counts.values()))
    total_val       = max(1, sum(rq1_validation_type_counts.values()))
    total_fields    = max(1, sum(rq1_field_type_counts.values()))
    total_submit    = max(1, rq2_total_submit_obs)
    total_static_acts = max(1, sum(rq3_static_action_counter.values()))

    # RQ1
    # Detailed category (fine-grained)
    write_csv(os.path.join(args.out_dir, "rq1_function_categories.csv"),
              ["category", "unique_functions(bodyHash)", "call_count", "call_pct"],
              [[cat,
                len(rq1_cat_unique_hashes[cat]),
                rq1_cat_calls[cat],
                round(rq1_cat_calls[cat] / total_calls * 100, 2)]
               for cat, _ in rq1_cat_calls.most_common()])

    # Parent category (for backward compatibility)
    rq1_coarse_calls = Counter()
    rq1_coarse_unique = defaultdict(set)
    for cat, cnt in rq1_cat_calls.items():
        coarse = to_coarse_category(cat)
        rq1_coarse_calls[coarse] += cnt
        rq1_coarse_unique[coarse].update(rq1_cat_unique_hashes[cat])
    write_csv(os.path.join(args.out_dir, "rq1_function_categories_coarse.csv"),
              ["category", "unique_functions(bodyHash)", "call_count", "call_pct"],
              [[cat,
                len(rq1_coarse_unique[cat]),
                rq1_coarse_calls[cat],
                round(rq1_coarse_calls[cat] / total_calls * 100, 2)]
               for cat, _ in rq1_coarse_calls.most_common()])

    write_csv(os.path.join(args.out_dir, "rq1_event_triggers.csv"),
              ["trigger_category", "event_count", "pct", "kit_count"],
              [[k, v, round(v / total_triggers * 100, 2), len(rq1_event_trigger_kits[k])]
               for k, v in rq1_event_trigger_counts.most_common()])

    write_csv(os.path.join(args.out_dir, "rq1_validation_types.csv"),
              ["validation_type", "field_count", "pct_of_fields", "kit_count"],
              [[k, v, round(v / total_val * 100, 2), len(rq1_validation_type_kits[k])]
               for k, v in rq1_validation_type_counts.most_common()])

    write_csv(os.path.join(args.out_dir, "rq1_field_type_distribution.csv"),
              ["field_type", "count", "pct"],
              [[k, v, round(v / total_fields * 100, 2)]
               for k, v in rq1_field_type_counts.most_common()])

    write_csv(os.path.join(args.out_dir, "rq1_enter_key_behavior.csv"),
              ["behavior", "count"],
              [["enter_key_dispatched",       rq1_enter_key_dispatched],
               ["enter_key_default_prevented", rq1_enter_key_prevented]])

    # NEW: phase x category cross-tabulation CSV
    # Output order: fixed phase order x fixed category order
    PHASES = ["keydown", "keypress", "input", "keyup",
              "backspace_keydown", "backspace_input", "backspace_keyup",
              "submit", "enter_key"]
    CATS   = [cat for cat, _ in rq1_cat_calls.most_common()]

    # (1) phase x category detail table
    phase_cat_rows = []
    for ph in PHASES:
        ph_total = max(1, rq1_phase_total_calls[ph])
        for cat in CATS:
            cnt = rq1_phase_cat_calls[(ph, cat)]
            phase_cat_rows.append([
                ph, cat, cnt,
                round(cnt / ph_total * 100, 2),          # percentage within the phase
                round(cnt / max(1, rq1_total_calls[0]) * 100, 2),  # percentage of the overall total
            ])
    write_csv(os.path.join(args.out_dir, "rq1_phase_category_calls.csv"),
              ["phase", "category", "call_count",
               "pct_within_phase", "pct_of_total"],
              phase_cat_rows)

    # (2) per-phase totals (for the paper summary)
    phase_total_rows = []
    grand_total = max(1, rq1_total_calls[0])
    for ph in PHASES:
        cnt = rq1_phase_total_calls[ph]
        phase_total_rows.append([
            ph, cnt,
            round(cnt / grand_total * 100, 2),
        ])
    write_csv(os.path.join(args.out_dir, "rq1_phase_totals.csv"),
              ["phase", "total_fn_calls", "pct_of_total"],
              phase_total_rows)

    # NEW: unique function example CSV per category
    # rq1_function_examples.csv -- one row per category x bodyHash, sorted by kit_count descending
    fn_example_rows = []
    for cat, _ in rq1_cat_calls.most_common():
        entries = rq1_fn_examples.get(cat, {})
        # sort by kit_count descending
        sorted_entries = sorted(entries.items(),
                                key=lambda x: len(x[1]["kits"]), reverse=True)
        for body_hash, info in sorted_entries:
            fn_example_rows.append([
                cat,
                body_hash,
                info["name"],
                info["eventType"],
                "default" if info["isDefault"] else "kit_specific",
                len(info["kits"]),
                info["call_count"],
                info["source"].replace("\n", " ").replace("\r", ""),
            ])
    write_csv(os.path.join(args.out_dir, "rq1_function_examples.csv"),
              ["category", "body_hash", "function_name", "event_type",
               "is_default", "kit_count", "call_count", "source_snippet"],
              fn_example_rows)

    # NEW: top-10 summary per category (no source, for the paper)
    fn_top_rows = []
    for cat, _ in rq1_cat_calls.most_common():
        entries = rq1_fn_examples.get(cat, {})
        sorted_entries = sorted(entries.items(),
                                key=lambda x: len(x[1]["kits"]), reverse=True)[:10]
        for rank, (body_hash, info) in enumerate(sorted_entries, 1):
            fn_top_rows.append([
                cat, rank,
                info["name"],
                info["eventType"],
                "default" if info["isDefault"] else "kit_specific",
                len(info["kits"]),
                info["call_count"],
                body_hash[:16],   # only first 16 chars of the hash
                info["source"][:200].replace("\n", " ").replace("\r", ""),
            ])
    write_csv(os.path.join(args.out_dir, "rq1_function_top10_per_category.csv"),
              ["category", "rank", "function_name", "event_type", "is_default",
               "kit_count", "call_count", "body_hash_prefix", "source_preview"],
              fn_top_rows)

    # RQ2
    write_csv(os.path.join(args.out_dir, "rq2_overall_classification.csv"),
              ["overall_classification", "count"],
              rq2_overall_class_counter.most_common())

    write_csv(os.path.join(args.out_dir, "rq2_dynamic_transmission_methods.csv"),
              ["method", "count", "pct"],
              [[k, rq2_dynamic_method_counter[k],
                round(rq2_dynamic_method_counter[k] / total_submit * 100, 2)]
               for k in ["xhr", "fetch", "form_post", "form_get", "form_other"]])

    # Before/after correction comparison CSV
    write_csv(os.path.join(args.out_dir, "rq2_transmission_comparison.csv"),
              ["method", "old_count", "old_pct", "new_count", "new_pct", "delta"],
              [[k,
                rq2_old_method_counter[k],
                round(rq2_old_method_counter[k] / max(1, sum(rq2_old_method_counter.values())) * 100, 2),
                rq2_dynamic_method_counter[k],
                round(rq2_dynamic_method_counter[k] / total_submit * 100, 2),
                rq2_dynamic_method_counter[k] - rq2_old_method_counter[k],
               ]
               for k in ["xhr", "fetch", "form_post", "form_get", "form_other"]])

    # Verdict-path distribution CSV (for methodology verification)
    # body_match_instrumented   : requestBody == submit_detail.fields -> instrumentation confirmed
    # body_match_kit_native     : requestBody != submit_detail.fields or JSON CT -> kit-native confirmed
    # fallback_triggeredfn_native: no requestBody + triggeredFunctions signal present
    # fallback_triggeredfn_form : no requestBody + no triggeredFunctions signal (conservative form classification)
    # fetch / no_xhr_direct_submit: cases with no XHR
    verdict_total = max(1, sum(rq2_verdict_counter.values()))
    write_csv(os.path.join(args.out_dir, "rq2_verdict_distribution.csv"),
              ["verdict", "count", "pct"],
              [[k, rq2_verdict_counter[k],
                round(rq2_verdict_counter[k] / verdict_total * 100, 2)]
               for k in ["body_match_instrumented", "body_match_kit_native",
                         "fallback_triggeredfn_native", "fallback_triggeredfn_form",
                         "fetch", "no_xhr_direct_submit"]])

    # Per-form: matches rq2_verdict_distribution -> manual verification via JSON path + form_index
    write_csv(os.path.join(args.out_dir, "rq2_verdict_per_form.csv"),
              ["result_file", "kit_name", "form_index", "has_xhr", "has_fetch",
               "corrected_method", "old_method", "verdict_bucket"],
              rq2_verdict_rows)

    write_csv(os.path.join(args.out_dir, "rq2_form_action_origin.csv"),
              ["origin_type", "count", "pct"],
              [[k, v, round(v / max(1, sum(rq2_form_action_origin.values())) * 100, 2)]
               for k, v in rq2_form_action_origin.most_common()])

    # List of kits that had a same-origin network request during typing/backspace (kits_with_realtime_typing_requests)
    write_csv(os.path.join(args.out_dir, "rq2_realtime_typing_kits.csv"),
              ["kit_name", "result_file"],
              sorted(rq2_realtime_first_file.items(), key=lambda x: x[0]))

    write_csv(os.path.join(args.out_dir, "rq2_submit_http_status.csv"),
              ["http_status", "count"],
              rq2_submit_status_counter.most_common())

    # RQ3 - static (based on server file analysis, high coverage across all kits)
    write_csv(os.path.join(args.out_dir, "rq3_static_server_actions.csv"),
              ["action_type", "count", "pct", "evidence_samples"],
              [[k, c, round(c / total_static_acts * 100, 2),
                " | ".join(rq3_static_action_evidence[k][:3])]
               for k, c in rq3_static_action_counter.most_common()])

    write_csv(os.path.join(args.out_dir, "rq3_static_exfil_targets.csv"),
              ["exfil_target", "count"],
              rq3_static_exfil_targets.most_common(100))

    # RQ3 - dynamic (only what was actually confirmed after submit execution)
    write_csv(os.path.join(args.out_dir, "rq3_dynamic_server_actions.csv"),
              ["action_type", "count"],
              rq3_dynamic_action_counter.most_common())

    write_csv(os.path.join(args.out_dir, "rq3_dynamic_exfil_targets.csv"),
              ["exfil_target", "count"],
              rq3_dynamic_exfil_targets.most_common(100))

    # receives_post field aggregation CSV
    # (1) form-level: based on the PHP action of forms actually submitted in dynamic analysis
    rp_form_rows = []
    for fname, cnt in rp_form_field_counter.most_common():
        kit_cnt = len(rp_form_kits[fname])
        rp_form_rows.append([fname, cnt, kit_cnt,
                              round(cnt / max(1, sum(rp_form_field_counter.values())) * 100, 2)])
    write_csv(os.path.join(args.out_dir, "rq_receives_post_form_level.csv"),
              ["field_name", "occurrence_count", "kit_count", "pct"],
              rp_form_rows)

    # (2) global: based on static analysis of all PHP files (higher coverage, duplicates included)
    rp_global_rows = []
    for fname, cnt in rp_global_field_counter.most_common():
        kit_cnt = len(rp_global_kits[fname])
        rp_global_rows.append([fname, cnt, kit_cnt,
                                round(cnt / max(1, sum(rp_global_field_counter.values())) * 100, 2)])
    write_csv(os.path.join(args.out_dir, "rq_receives_post_global.csv"),
              ["field_name", "occurrence_count", "kit_count", "pct"],
              rp_global_rows)

    # RQ4
    write_csv(os.path.join(args.out_dir, "rq4_monthly_trends.csv"),
              ["month", "kits", "kits_with_forms", "js_call_count",
               "submit_observations", "server_actions"],
              [[month, monthly[month]["kits"], monthly[month]["kits_with_forms"],
                monthly[month]["js_calls"], monthly[month]["submit_obs"],
                monthly[month]["server_acts"]]
               for month in sorted(monthly.keys())])

    write_csv(os.path.join(args.out_dir, "kit_level_summary.csv"),
              ["dataset_name", "dataset_date", "dynamic_success", "forms_count",
               "js_call_count", "submit_observations", "server_actions",
               "kit_path", "result_file"],
              kit_rows)

    # -----------------------------------------------------------------------
    # Summary JSON
    # -----------------------------------------------------------------------
    summary = {
        "input_files": len(files),
        "total_forms_found": total_forms,
        "dynamic_success_kits": success_kits,
        "dynamic_fail_or_no_form_kits": fail_kits,
        "rq1": {
            "kits_with_js_function_calls": len(rq1_kits_with_js_calls),
            "total_js_function_calls": rq1_total_calls[0],
            "default_function_calls": rq1_default_calls[0],
            "kit_specific_function_calls": rq1_custom_calls[0],
            "enter_key_dispatched": rq1_enter_key_dispatched,
            "enter_key_default_prevented": rq1_enter_key_prevented,
            "field_type_distribution": dict(rq1_field_type_counts.most_common()),
            "validation_type_counts": dict(rq1_validation_type_counts),
            "function_category_calls": dict(rq1_cat_calls),
            "function_category_calls_coarse": dict(rq1_coarse_calls),
            "event_trigger_counts": dict(rq1_event_trigger_counts),
        },
        "rq2": {
            "submission_observations": rq2_total_submit_obs,
            "dynamic_method_counts": dict(rq2_dynamic_method_counter),
            "overall_classification_top10": dict(rq2_overall_class_counter.most_common(10)),
            "kits_with_realtime_typing_requests": len(rq2_realtime_kits),
            "realtime_typing_kit_files": rq2_realtime_first_file,
            "form_action_origin": dict(rq2_form_action_origin),
            "submit_http_status": dict(rq2_submit_status_counter),
            "transmission_verdict_distribution": dict(rq2_verdict_counter),
        },
        "rq3": {
            "static_action_counts": dict(rq3_static_action_counter),
            "dynamic_action_counts": dict(rq3_dynamic_action_counter),
            "top_static_exfil_targets": dict(rq3_static_exfil_targets.most_common(20)),
            "top_dynamic_exfil_targets": dict(rq3_dynamic_exfil_targets.most_common(20)),
        },
        "receives_post": {
            "form_level_top20": dict(rp_form_field_counter.most_common(20)),
            "global_top20":     dict(rp_global_field_counter.most_common(20)),
            "unique_field_names_form":   len(rp_form_field_counter),
            "unique_field_names_global": len(rp_global_field_counter),
        },
        "outputs_dir": args.out_dir,
    }

    with open(os.path.join(args.out_dir, "paper_reference_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[Done!]: {args.out_dir}")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
