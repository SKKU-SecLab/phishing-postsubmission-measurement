#!/usr/bin/env python3
"""
analyze_network.py -- Network analysis summary script
=====================================================
Reads existing analysis_results/*.json files and prints the network
request/response structure in a human-readable format.

Post-processes the JSON without re-running the crawler.

    python analyze_network.py results/dynamic_analysis_blackwidow/analysis_results/analysis_results_*.json
    python analyze_network.py results/dynamic_analysis_blackwidow/analysis_results/analysis_results_*.json --csv
    python analyze_network.py results/dynamic_analysis_blackwidow/analysis_results/analysis_results_*.json --verbose
"""

import json
import sys
import os
import argparse
import csv
from urllib.parse import urlparse
from collections import defaultdict


# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------

def _parse_response_headers(raw):
    """Convert raw header string (key: value\r\n...) to dict."""
    if isinstance(raw, dict):
        return raw
    result = {}
    if not raw:
        return result
    for line in str(raw).splitlines():
        if ':' in line:
            k, _, v = line.partition(':')
            result[k.strip().lower()] = v.strip()
    return result


def _get_header(headers, name):
    if isinstance(headers, dict):
        return (headers.get(name) or headers.get(name.lower()) or
                headers.get(name.title()) or '')
    return ''


def _method_color(method):
    colors = {'POST': '\033[91m', 'GET': '\033[94m', 'PUT': '\033[93m',
              'DELETE': '\033[91m', 'PATCH': '\033[93m'}
    reset = '\033[0m'
    m = (method or '').upper()
    return colors.get(m, '') + m + reset


def _status_color(status):
    reset = '\033[0m'
    if status is None:
        return '???'
    s = int(status)
    if s < 300:
        return '\033[92m' + str(s) + reset   # green
    if s < 400:
        return '\033[93m' + str(s) + reset   # yellow
    return '\033[91m' + str(s) + reset       # red


def _short_url(url, max_len=80):
    if not url or len(url) <= max_len:
        return url
    return url[:max_len - 3] + '...'


def _fmt_ms(val):
    if val is None:
        return '-'
    return '%.1f ms' % float(val)


# ------------------------------------------------------------------------------
# Core extraction from a form-level result dict
# ------------------------------------------------------------------------------

def _extract_js_network_reqs(form_result):
    """Collect JS-intercepted XHR/fetch from all phases of a form."""
    reqs = []
    submit_log = form_result.get('submit_log', {})

    for phase_key, logs in submit_log.items():
        if not isinstance(logs, dict):
            continue
        for req in logs.get('networkReqs', []):
            req = dict(req)
            req['_phase'] = phase_key
            req['_source'] = 'js_xhr'
            reqs.append(req)

    # Also check field typing logs
    for field in form_result.get('fields', []):
        for char_log in field.get('typing_log', []):
            for phase in ('keydown', 'keypress', 'input', 'keyup'):
                for req in char_log.get(phase, {}).get('networkReqs', []):
                    req = dict(req)
                    req['_phase'] = 'typing_%s_%s' % (field.get('name', '?'), phase)
                    req['_source'] = 'js_xhr'
                    reqs.append(req)

    return reqs


def _extract_cdp_network_reqs(form_result):
    """Collect CDP-level network requests from submit phase."""
    reqs = []
    submit_log = form_result.get('submit_log', {})
    for phase_key, logs in submit_log.items():
        if not isinstance(logs, dict):
            continue
        for req in logs.get('cdpNetworkReqs', []):
            req = dict(req)
            req['_phase'] = phase_key
            req['_source'] = 'cdp'
            reqs.append(req)
    return reqs


def _extract_timing_chain(form_result):
    """Extract timing chain from submit_log."""
    submit_log = form_result.get('submit_log', {})
    timing = submit_log.get('submit_timing', {})
    return timing


# ------------------------------------------------------------------------------
# Printing
# ------------------------------------------------------------------------------

SEP = '-' * 72
SEP2 = '=' * 72

def print_request_block(req, source, verbose=False):
    method = req.get('method', '?')
    url = req.get('url', req.get('url', '?'))
    status = req.get('status')
    ts = req.get('timestamp')
    latency = req.get('latencyMs') or req.get('latency_ms')
    ttfb = req.get('ttfbMs')

    print('  +- [%s] %s %s -> %s' % (
        source.upper(), _method_color(method), _short_url(url, 70),
        _status_color(status)
    ))

    # --- Request details ---
    req_headers = req.get('requestHeaders', {})
    if isinstance(req_headers, str):
        req_headers = _parse_response_headers(req_headers)

    content_type = _get_header(req_headers, 'content-type') or req.get('requestContentType', '')
    cookie = _get_header(req_headers, 'cookie')
    has_cookie = req.get('hasCookieHeader', bool(cookie))

    payload = req.get('requestBody') or req.get('postData')

    print('  |  > Request')
    print('  |     Content-Type : %s' % (content_type or '-'))
    print('  |     Cookie       : %s' % ('YES' if has_cookie else 'no'))

    custom_hdrs = req.get('customRequestHeaders', {})
    if custom_hdrs:
        print('  |     Custom Headers: %s' % ', '.join(custom_hdrs.keys()))

    if payload:
        short_payload = str(payload)[:200]
        print('  |     Payload      : %s%s' % (
            short_payload, ' [...]' if len(str(payload)) > 200 else ''))

    if verbose and req_headers:
        print('  |     All Req Headers:')
        for k, v in sorted(req_headers.items()):
            v_str = str(v)[:80]
            print('  |       %s: %s' % (k, v_str))

    # --- Response details ---
    res_headers = req.get('responseHeaders', {})
    if isinstance(res_headers, str):
        res_headers = _parse_response_headers(res_headers)

    res_content_type = (
        _get_header(res_headers, 'content-type')
        or req.get('responseContentType', '')
    )
    set_cookie = _get_header(res_headers, 'set-cookie')
    has_set_cookie = req.get('hasSetCookie', bool(set_cookie))
    redirected = req.get('redirected', False)
    redirect_chain = req.get('redirectChain', [])
    redirect_loc = req.get('redirectLocation', '') or _get_header(res_headers, 'location')
    body_len = req.get('responseBodyLength')
    protocol = req.get('protocol', '')

    print('  |  > Response')
    print('  |     Status       : %s%s' % (
        _status_color(status),
        ' -> %s' % redirect_loc if redirect_loc else ''))
    print('  |     Protocol     : %s' % (protocol or '-'))
    print('  |     Content-Type : %s' % (res_content_type or '-'))
    print('  |     Set-Cookie   : %s' % ('YES' if has_set_cookie else 'no'))
    if body_len is not None:
        print('  |     Body Length  : %d bytes' % body_len)

    if redirected and redirect_chain:
        print('  |     Redirect chain (%d hop):' % len(redirect_chain))
        for hop in redirect_chain:
            print('  |       %s -> %s (Location: %s)' % (
                hop.get('url', '?')[:50],
                hop.get('status', '?'),
                hop.get('location', '?')[:50]))

    if verbose and res_headers:
        print('  |     All Res Headers:')
        for k, v in sorted(res_headers.items()):
            v_str = str(v)[:80]
            print('  |       %s: %s' % (k, v_str))

    # --- Timing ---
    print('  |  > Timing')
    print('  |     Latency (E2E): %s' % _fmt_ms(latency))
    print('  |     TTFB         : %s' % _fmt_ms(ttfb))
    if ts:
        print('  |     JS Timestamp : %s ms (epoch)' % ts)

    # --- Body preview ---
    preview = req.get('responseBodyPreview') or req.get('response', '')
    if preview:
        short = str(preview)[:300].replace('\n', ' ').replace('\r', '')
        print('  |  > Response Preview: %s%s' % (
            short, '[...]' if len(str(preview)) > 300 else ''))

    print('  +' + SEP[2:])


def print_form_network_summary(form_result, verbose=False):
    form_action = form_result.get('action', '?')
    form_method = form_result.get('method', '?').upper()
    page_url = form_result.get('page_url', '?')

    print('\n' + SEP)
    print('FORM  action=%s  method=%s' % (_short_url(form_action, 60), form_method))
    print('PAGE  %s' % _short_url(page_url, 70))
    print(SEP)

    # Classification -- Fix 4: key is 'overall_classification' in FormAnalyzer
    classif = form_result.get('overall_classification',
                              form_result.get('classification', '-'))
    print('Classification: %s' % classif)

    # Native submit observation (real browser, CDP only) -- Fix 1 insight
    native_reqs, form_meta, native_note = _extract_native_submit_cdp(form_result)
    if form_meta or native_reqs:
        print('\n[Native Submit (real browser, CDP only)]')
        if form_meta:
            print('  form action  : %s' % form_meta.get('action', '?'))
            print('  form method  : %s' % form_meta.get('method', '?'))
            print('  enctype      : %s' % form_meta.get('enctype', '?'))
        if native_note:
            print('  note: %s' % native_note)
        for req in native_reqs:
            print('\n  (real Content-Type from browser)')
            print_request_block(req, 'cdp-native', verbose=verbose)
    else:
        print('\n[Native Submit] (not yet captured -- needs re-run with new code)')

    # Static analysis (server side behavior)
    resolved = None
    submit_log = form_result.get('submit_log', {})
    click_logs = submit_log.get('submit_click_logs', {})
    js_nets = click_logs.get('networkReqs', [])
    if js_nets and js_nets[0].get('resolved_server'):
        resolved = js_nets[0]['resolved_server']
    if resolved:
        print('\n[Server-Side Analysis]')
        print('  File    : %s' % resolved.get('server_file', '?'))
        print('  Receives: %s' % resolved.get('receives_fields', []))
        exfil = resolved.get('exfil', [])
        if exfil:
            print('  \033[91mEXFIL\033[0m   : %s' % ', '.join(exfil))
        for act in resolved.get('actions', []):
            print('  Action  : %s (line %s) target=%s' % (
                act.get('type', '?'), act.get('line', '?'), act.get('target', '?')))

    # Timing chain
    timing = _extract_timing_chain(form_result)
    if not timing:
        timing = submit_log.get('submit_timing', {})
    if timing:
        print('\n[Timing Chain]')
        print('  Python click()        : %s ms epoch' % timing.get('python_click_ts_ms', '-'))
        print('  JS trigger event      : %s ms epoch' % timing.get('js_trigger_event_ts_ms', '-'))
        print('  JS XHR send           : %s ms epoch' % timing.get('js_first_req_ts_ms', '-'))
        ev_delta = timing.get('event_to_request_ms')
        if ev_delta is not None:
            print('  event->request delta   : %.1f ms' % ev_delta)
        print('  CDP req count         : %s' % timing.get('cdp_req_count', '-'))

    # JS-level requests (XHR intercepted)
    js_all = _extract_js_network_reqs(form_result)
    if js_all:
        print('\n[JS-Intercepted Requests (%d)]' % len(js_all))
        for req in js_all:
            phase = req.get('_phase', '?')
            print('\n  Phase: %s' % phase)
            print_request_block(req, 'js', verbose=verbose)
    else:
        print('\n[JS-Intercepted Requests] (none captured)')

    # CDP-level requests (browser network stack)
    cdp_all = _extract_cdp_network_reqs(form_result)

    # Also check top-level cdp_network from the full results
    # (passed through if available)
    if cdp_all:
        print('\n[CDP Network Requests (%d)]' % len(cdp_all))
        for req in cdp_all:
            phase = req.get('_phase', '?')
            print('\n  Phase: %s' % phase)
            print_request_block(req, 'cdp', verbose=verbose)
    else:
        print('\n[CDP Network Requests] (none in submit phase -- see top-level cdp_network)')


def print_top_level_cdp(data, verbose=False):
    cdp = data.get('cdp_network', [])
    if not cdp:
        print('\n[Top-Level CDP Network] (empty -- CDP drain may not have captured anything)')
        return
    print('\n' + SEP2)
    print('TOP-LEVEL CDP NETWORK TRACE (%d requests across all pages)' % len(cdp))
    print(SEP2)
    for req in cdp:
        print_request_block(req, 'cdp-global', verbose=verbose)


def _extract_native_submit_cdp(form_result):
    """Extract CDP requests from the native (real browser) submit pass."""
    native = form_result.get('submit_log', {}).get('native_submit', {})
    reqs = []
    for req in native.get('cdp_reqs', []):
        req = dict(req)
        req['_phase'] = 'native_submit'
        req['_source'] = 'cdp-native'
        reqs.append(req)
    return reqs, native.get('form_meta', {}), native.get('note', '')


def print_protocol_summary(forms, top_cdp=None):
    """HTTP communication pattern summary -- uses ALL CDP sources.

    top_cdp: top-level cdp_network list from the full results dict.
    This ensures page-load / resource requests are not excluded.
    """
    print('\n' + SEP2)
    print('PROTOCOL-LEVEL SUMMARY')
    print(SEP2)

    all_js = []
    all_cdp_submit = []    # submit-phase CDP (XHR-intercepted)
    all_cdp_native = []    # native submit CDP (real browser)

    for f in forms:
        all_js.extend(_extract_js_network_reqs(f))
        all_cdp_submit.extend(_extract_cdp_network_reqs(f))
        native_reqs, _, _ = _extract_native_submit_cdp(f)
        all_cdp_native.extend(native_reqs)

    # top-level cdp_network is the authoritative full-session record
    top_cdp = list(top_cdp or [])

    # Deduplicate top-level vs per-phase (by requestId)
    phase_ids = {r.get('requestId') for r in all_cdp_submit + all_cdp_native if r.get('requestId')}
    top_cdp_extra = [r for r in top_cdp if r.get('requestId') not in phase_ids]

    # Full CDP set = native (real) + XHR intercept + anything else from top-level
    all_cdp = all_cdp_native + all_cdp_submit + top_cdp_extra

    all_reqs = all_js + all_cdp

    if not all_reqs:
        print('  No network requests captured.')
        return

    # Dedup by URL+method for unique endpoint count
    seen = set()
    unique = []
    for r in all_reqs:
        key = (r.get('url', ''), r.get('method', ''))
        if key not in seen:
            seen.add(key)
            unique.append(r)

    print('  CDP sources:')
    print('    native submit (real browser)  : %d reqs' % len(all_cdp_native))
    print('    XHR intercept (transformed)   : %d reqs' % len(all_cdp_submit))
    print('    top-level session (other)     : %d reqs' % len(top_cdp_extra))
    print('    JS-level (XHR hook)           : %d reqs' % len(all_js))
    print('  Total requests   : %d (%d unique endpoints)' % (len(all_reqs), len(unique)))

    methods = defaultdict(int)
    statuses = defaultdict(int)
    redirects = 0
    has_cookie = 0
    has_set_cookie = 0
    protocols = defaultdict(int)
    resource_types = defaultdict(int)
    latencies = []
    ttfbs = []

    for r in all_cdp:
        methods[r.get('method', '?').upper()] += 1
        st = r.get('status')
        if st:
            statuses[str(st)] += 1
        if r.get('redirected'):
            redirects += 1
        if r.get('hasCookieHeader'):
            has_cookie += 1
        if r.get('hasSetCookie'):
            has_set_cookie += 1
        p = r.get('protocol', '')
        if p:
            protocols[p] += 1
        rt = r.get('resourceType', '')
        if rt:
            resource_types[rt] += 1
        lat = r.get('latencyMs')
        if lat:
            latencies.append(lat)
        ttfb = r.get('ttfbMs')
        if ttfb:
            ttfbs.append(ttfb)

    # JS-level supplements for any requests CDP missed
    for r in all_js:
        if r.get('method', '?').upper() not in methods:
            methods[r.get('method', '?').upper()] += 1

    print('\n  HTTP Methods:')
    for m, c in sorted(methods.items()):
        print('    %-8s : %d' % (m, c))

    print('\n  Status Codes:')
    for s, c in sorted(statuses.items()):
        print('    %-8s : %d' % (s, c))

    print('\n  Protocol (HTTP version):')
    if protocols:
        for p, c in sorted(protocols.items()):
            print('    %-14s: %d' % (p, c))
    else:
        print('    (CDP not active)')

    print('\n  Resource types:')
    if resource_types:
        for rt, c in sorted(resource_types.items(), key=lambda x: -x[1]):
            print('    %-16s: %d' % (rt, c))

    print('\n  Cookie:')
    if all_cdp:
        print('    Sends Cookie    : %d/%d CDP requests' % (has_cookie, len(all_cdp)))
        print('    Sets Cookie     : %d/%d CDP requests' % (has_set_cookie, len(all_cdp)))
    else:
        print('    (no CDP data)')

    print('\n  Redirects        : %d' % redirects)

    if latencies:
        print('\n  Latency E2E (ms):')
        print('    min=%.1f  max=%.1f  avg=%.1f  n=%d' % (
            min(latencies), max(latencies),
            sum(latencies)/len(latencies), len(latencies)))
    if ttfbs:
        print('  TTFB (ms):')
        print('    min=%.1f  max=%.1f  avg=%.1f  n=%d' % (
            min(ttfbs), max(ttfbs),
            sum(ttfbs)/len(ttfbs), len(ttfbs)))

    # Directionality
    print('\n  Communication direction:')
    post_reqs = [r for r in all_reqs if r.get('method', '').upper() == 'POST']
    response_returned = [r for r in all_cdp if r.get('responseReturned')]
    print('    Client->Server (POST) : %d' % len(post_reqs))
    print('    Server responded     : %d/%d CDP requests' % (len(response_returned), len(all_cdp)))
    if all_cdp and len(response_returned) == len(all_cdp):
        print('    Pattern: Bidirectional (server responded to all)')
    elif len(post_reqs) > 0 and not response_returned:
        print('    Pattern: Unidirectional (sent only, no response captured)')
    else:
        print('    Pattern: Mixed / partial')

    # Real vs transformed submit comparison (Fix 1 insight)
    native_reqs = [r for r in all_cdp_native if r.get('requestContentType') or
                   r.get('postData') or r.get('method')]
    xhr_reqs = [r for r in all_cdp_submit if r.get('requestContentType') or
                r.get('postData') or r.get('method')]
    if native_reqs or xhr_reqs:
        print('\n  Submit method comparison (native vs XHR-intercept):')
        for label, reqs in [('native (real)', native_reqs), ('XHR intercept', xhr_reqs)]:
            for r in reqs[:1]:
                ct = (r.get('requestContentType') or
                      _get_header(r.get('requestHeaders', {}), 'content-type') or '?')
                print('    %-20s: method=%s  Content-Type=%s' % (
                    label, r.get('method', '?'), ct))

    # Destination hosts (full picture)
    hosts = defaultdict(int)
    for r in all_reqs:
        try:
            h = urlparse(r.get('url', '')).hostname or ''
            if h:
                hosts[h] += 1
        except Exception:
            pass
    if hosts:
        print('\n  Destination hosts:')
        for h, c in sorted(hosts.items(), key=lambda x: -x[1]):
            print('    %-40s : %d req' % (h, c))


# ------------------------------------------------------------------------------
# CSV export
# ------------------------------------------------------------------------------

def export_csv(forms, outpath, top_cdp=None):
    headers = [
        'form_action', 'form_method', 'page_url',
        'classification',
        'req_source', 'req_phase',
        'req_url', 'req_method', 'req_content_type',
        'req_payload_preview', 'req_has_cookie', 'req_custom_headers',
        'res_status', 'res_protocol', 'res_content_type',
        'res_has_set_cookie', 'res_redirected', 'res_redirect_to',
        'res_body_length', 'res_body_preview',
        'latency_ms', 'ttfb_ms',
        'event_to_request_ms',
        'server_file', 'server_exfil',
        'is_native_submit',
    ]
    rows = []
    for form in forms:
        form_action = form.get('action', '')
        form_method = form.get('method', '')
        page_url = form.get('page_url', '')
        # Fix 4: correct key
        classif = form.get('overall_classification',
                           form.get('classification', ''))

        timing = _extract_timing_chain(form)
        ev_to_req = timing.get('event_to_request_ms', '')

        submit_log = form.get('submit_log', {})
        click_logs = submit_log.get('submit_click_logs', {})
        js_nets = click_logs.get('networkReqs', [])
        resolved = js_nets[0].get('resolved_server') if js_nets else None
        server_file = resolved.get('server_file', '') if resolved else ''
        server_exfil = '; '.join(resolved.get('exfil', [])) if resolved else ''

        # Fix 3: include native submit CDP + XHR-intercept CDP
        native_reqs, _, _ = _extract_native_submit_cdp(form)
        all_reqs = (
            [dict(r, _source='js',        _native='no') for r in _extract_js_network_reqs(form)] +
            [dict(r, _source='cdp-native',_native='yes') for r in native_reqs] +
            [dict(r, _source='cdp',       _native='no') for r in _extract_cdp_network_reqs(form)]
        )
        if not all_reqs:
            rows.append([form_action, form_method, page_url, classif,
                         '', '', '', '', '', '', '', '',
                         '', '', '', '', '', '', '', '',
                         '', '', ev_to_req, server_file, server_exfil, ''])
            continue

        for req in all_reqs:
            req_headers = req.get('requestHeaders', {})
            if isinstance(req_headers, str):
                req_headers = _parse_response_headers(req_headers)
            res_headers = req.get('responseHeaders', {})
            if isinstance(res_headers, str):
                res_headers = _parse_response_headers(res_headers)

            payload = req.get('requestBody') or req.get('postData') or ''
            redirect_loc = (req.get('redirectLocation', '') or
                            _get_header(res_headers, 'location'))
            custom = req.get('customRequestHeaders', {})

            rows.append([
                form_action, form_method, page_url, classif,
                req.get('_source', ''), req.get('_phase', ''),
                req.get('url', ''), req.get('method', ''),
                (req.get('requestContentType') or
                 _get_header(req_headers, 'content-type')),
                str(payload)[:200],
                'yes' if req.get('hasCookieHeader') else 'no',
                '|'.join(custom.keys()) if custom else '',
                req.get('status', ''),
                req.get('protocol', ''),
                (req.get('responseContentType') or
                 _get_header(res_headers, 'content-type')),
                'yes' if req.get('hasSetCookie') else 'no',
                'yes' if req.get('redirected') else 'no',
                redirect_loc,
                req.get('responseBodyLength', ''),
                str(req.get('responseBodyPreview') or req.get('response') or '')[:200],
                req.get('latencyMs', ''),
                req.get('ttfbMs', ''),
                ev_to_req,
                server_file, server_exfil,
                req.get('_native', 'no'),
            ])

    # Fix 3: append top-level cdp_network rows not tied to any form
    if top_cdp:
        form_phase_ids = {r[-1] for r in rows}  # rough dedup not needed -- use requestId
        phase_ids = set()
        for form in forms:
            for r in _extract_cdp_network_reqs(form) + list(_extract_native_submit_cdp(form)[0]):
                if r.get('requestId'):
                    phase_ids.add(r['requestId'])
        for req in top_cdp:
            if req.get('requestId') in phase_ids:
                continue  # already in a form-level row
            req_headers = req.get('requestHeaders', {})
            res_headers = req.get('responseHeaders', {})
            redirect_loc = (req.get('redirectLocation', '') or
                            _get_header(res_headers, 'location'))
            custom = req.get('customRequestHeaders', {})
            rows.append([
                '', '', '',  # no form context
                'session-level',
                'cdp-session', req.get('resourceType', ''),
                req.get('url', ''), req.get('method', ''),
                req.get('requestContentType', ''),
                str(req.get('postData') or '')[:200],
                'yes' if req.get('hasCookieHeader') else 'no',
                '|'.join(custom.keys()) if custom else '',
                req.get('status', ''),
                req.get('protocol', ''),
                req.get('responseContentType', ''),
                'yes' if req.get('hasSetCookie') else 'no',
                'yes' if req.get('redirected') else 'no',
                redirect_loc,
                req.get('responseBodyLength', ''),
                str(req.get('responseBodyPreview') or '')[:200],
                req.get('latencyMs', ''),
                req.get('ttfbMs', ''),
                '',  # no event_to_request for session-level
                '', '',  # no server_file/exfil
                'no',
            ])

    with open(outpath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    print('[analyze_network] CSV saved: %s (%d rows)' % (outpath, len(rows)))


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Network analysis of FormAnalyzer JSON output')
    parser.add_argument('json_files', nargs='+', help='Path(s) to analysis_results JSON')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print full request/response headers')
    parser.add_argument('--csv', action='store_true',
                        help='Export results as CSV')
    parser.add_argument('--forms-only', action='store_true',
                        help='Skip top-level CDP trace and protocol summary')
    args = parser.parse_args()

    for json_path in args.json_files:
        if not os.path.isfile(json_path):
            print('[ERROR] Not found: %s' % json_path)
            continue

        with open(json_path, encoding='utf-8') as f:
            data = json.load(f)

        print('\n' + SEP2)
        print('TARGET : %s' % data.get('url', '?'))
        print('KIT    : %s' % data.get('kit_path', '-'))
        print('MODE   : %s' % data.get('mode', '?'))
        print('TIME   : %s' % data.get('timestamp', '?'))
        print(SEP2)

        forms = data.get('forms', [])
        print('Forms found: %d' % len(forms))

        # Per-form network breakdown
        for i, form in enumerate(forms):
            print('\n[Form %d/%d]' % (i + 1, len(forms)))
            print_form_network_summary(form, verbose=args.verbose)

        if not args.forms_only:
            # Top-level CDP global trace
            print_top_level_cdp(data, verbose=args.verbose)

            # Protocol summary -- now uses all CDP sources including top-level
            top_cdp = data.get('cdp_network', [])
            print_protocol_summary(forms, top_cdp=top_cdp)

        # CSV export
        if args.csv:
            base = os.path.splitext(json_path)[0]
            csv_path = base + '_network_analysis.csv'
            top_cdp = data.get('cdp_network', [])
            export_csv(forms, csv_path, top_cdp=top_cdp)

    print('\n' + SEP2)
    print('Done.')


if __name__ == '__main__':
    main()