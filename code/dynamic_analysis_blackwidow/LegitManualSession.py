"""LegitManualSession.py -- Manual interaction mode for anti-bot / SSO-protected sites.

The tool sets up CDP monitoring and JS instrumentation, then yields control
to the human.  Phase boundaries are marked via terminal prompts; the tool
collects signals at each boundary without touching the browser itself.

Sync vs async detection works even for manual submit:
  Synchronous  (native form) : page navigates -> CDP resourceType=Document,
                                sec-fetch-dest=document, current_url changes.
  Asynchronous (XHR/fetch)   : page stays    -> CDP resourceType=XHR/Fetch,
                                JS hook captures in window.__fa.networkReqs.
  Mixed                      : JS intercepted native submit and re-sent as XHR.
"""

import json
import logging
import os
import time
from urllib.parse import urlparse

from Functions import (
    drain_cdp_network_logs,
    init_cdp_network_monitoring,
    reset_cdp_network_monitoring,
)

# Known analytics / telemetry / bot-sensor domains to filter from signal data.
# These generate noise that would pollute listener/AJAX classification.
_ANALYTICS_DOMAINS = (
    'google-analytics.com', 'googletagmanager.com', 'googlesyndication.com',
    'omtrdc.net', 'demdex.net', 'doubleclick.net', '2mdn.net',
    'facebook.net', 'connect.facebook.net',
    'scorecardresearch.com', 'quantserve.com',
    'hotjar.com', 'fullstory.com', 'mixpanel.com',
    'segment.io', 'segment.com', 'amplitude.com',
    'newrelic.com', 'nr-data.net', 'datadog-browser-agent.com',
    'securemetrics.apple.com', 'mdt.apple.com',   # Apple Analytics
    'graffiti-tags.apple.com',                     # Apple tag mgmt
)


def _is_analytics(url):
    try:
        host = urlparse(url).netloc.lower()
        return any(d in host for d in _ANALYTICS_DOMAINS)
    except Exception:
        return False


class LegitManualSession:
    """
    Manual-drive session recorder for sites that defeat automation.

    Usage:
        python crawl.py --legit --manual --url https://appleid.apple.com

    Workflow:
        1. Tool opens browser, injects CDP + JS hooks, navigates to URL.
        2. Human interacts (dismiss banners, fill fields, submit).
        3. Human marks phase boundaries via terminal commands.
        4. Tool collects signals at each boundary and saves JSON.
    """

    _HELP = """
  Commands (type letter + Enter in this terminal):
    f      Field -- collect signals after finishing with ONE field
    s      Submit -- clear buffers, you click submit, tool collects
    p      Post-submit -- collect redirect / cookie / challenge signals
    b      Baseline -- collect current state (e.g. after page load)
    n      Note -- attach free-text annotation to the last phase
    r      Reset -- discard accumulated JS/CDP buffer (noise cleanup)
    ?      Show this help
    d      Done -- save results and exit
"""

    def __init__(self, driver, url, output_dir=None):
        self.driver = driver
        self.url = url
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'results', 'dynamic_analysis_blackwidow', 'legit_results'
        )
        os.makedirs(self.output_dir, exist_ok=True)

        self.session = {
            'url': url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'mode': 'manual',
            'page_load': {},
            'phases': [],
            'errors': [],
        }

    # ------------------------------------------------------------------ #
    #  Public entry point
    # ------------------------------------------------------------------ #

    def run(self):
        _banner("LEGIT MANUAL SESSION -- Anti-bot / SSO mode")
        print("  Tool : CDP monitor + JS hooks (passive)")
        print("  You  : navigate, interact, submit in browser")
        print("  Goal : structured signal collection at phase boundaries")
        _banner()

        try:
            self._setup()
            self._phase_loop()
        except KeyboardInterrupt:
            print("\n[Manual] Session interrupted.")
        except Exception as exc:
            msg = "Unhandled error: %s" % exc
            logging.exception(msg)
            print("[Manual] ERROR: %s" % msg)
            self.session['errors'].append(msg)
        finally:
            self._save()
            self._print_final_report()

    # ------------------------------------------------------------------ #
    #  Setup -- CDP + JS hooks + initial navigation
    # ------------------------------------------------------------------ #

    def _setup(self):
        init_cdp_network_monitoring(self.driver)
        reset_cdp_network_monitoring(self.driver)

        print("[Manual] Navigating -> %s" % self.url)
        try:
            self.driver.get(self.url)
        except Exception as exc:
            # Page may still load despite timeout/warning
            print("[Manual] Navigation note (continuing): %s" % exc)

        time.sleep(1.5)

        page_cdp = drain_cdp_network_logs(self.driver)
        summarized = self._summarize_cdp(page_cdp)
        self.session['page_load'] = {
            'requests': summarized,
            'initial_cookies_set': [r for r in summarized if r['hasSetCookie']],
        }
        print("[Manual] Page load  : %d request(s) captured" % len(page_cdp))
        print("[Manual] Current URL: %s" % self._current_url())
        print()
        print(self._HELP)

    # ------------------------------------------------------------------ #
    #  Interactive phase loop
    # ------------------------------------------------------------------ #

    def _phase_loop(self):
        phase_idx = 0
        while True:
            try:
                cmd = input("[Manual] Phase %d > " % phase_idx).strip().lower()
            except EOFError:
                break

            if cmd == '?':
                print(self._HELP)

            elif cmd == 'r':
                self._clear_logs()
                print("[Manual] Buffers cleared -- fresh window starts now.")

            elif cmd == 'n':
                note = input("[Manual]   Note: ").strip()
                if self.session['phases']:
                    self.session['phases'][-1].setdefault('notes', []).append(note)
                    print("[Manual]   Attached to phase %d." % (phase_idx - 1))
                else:
                    print("[Manual]   No phase yet -- discarded.")

            elif cmd == 'b':
                phase = self._collect_phase('baseline')
                self.session['phases'].append(phase)
                self._print_phase_summary(phase)
                phase_idx += 1

            elif cmd == 'f':
                name = input("[Manual]   Field name (e.g. email, password, search): ").strip()
                phase = self._collect_phase('field_%s' % (name or 'unknown'))
                self.session['phases'].append(phase)
                self._print_phase_summary(phase)
                phase_idx += 1

            elif cmd == 's':
                phase_idx = self._run_submit_phase(phase_idx)

            elif cmd == 'p':
                phase = self._collect_phase('post_submit')
                phase['post_submit'] = self._detect_post_submit(
                    phase.get('_raw_cdp', [])
                )
                phase.pop('_raw_cdp', None)
                self.session['phases'].append(phase)
                self._print_phase_summary(phase)
                phase_idx += 1

            elif cmd == 'd':
                print("[Manual] Finalising session...")
                break

            else:
                print("[Manual] Unknown command. Type ? for help.")

    def _run_submit_phase(self, phase_idx):
        """
        Two-step submit collection:
          Step 1 -- clear buffers -> user clicks submit -> collect submit signals
          Step 2 -- user waits for page to settle -> collect post-submit signals
        """
        print()
        print("  ---- SUBMIT PHASE ------------------------------------")
        print("  Clearing buffers...", end=' ', flush=True)
        self._clear_logs()
        pre_url = self._current_url()
        reset_cdp_network_monitoring(self.driver)
        print("done.")
        print()
        print("  >>> Click the submit button NOW. <<<")
        input("  Press Enter immediately after clicking submit... ")

        # Short wait so async requests have time to fire before we drain
        time.sleep(0.6)

        submit_phase = self._collect_phase('submit')
        post_url = self._current_url()
        submit_phase['pre_submit_url'] = pre_url
        submit_phase['post_submit_url'] = post_url
        submit_phase['submission_method'] = self._classify_submission(
            submit_phase.get('_raw_cdp', []),
            submit_phase.get('js_network_requests', []),
            pre_url,
            post_url,
        )
        submit_phase.pop('_raw_cdp', None)
        self.session['phases'].append(submit_phase)
        self._print_phase_summary(submit_phase)
        phase_idx += 1

        print()
        print("  Wait for the page to fully settle (load / error / redirect).")
        input("  Press Enter when done... ")

        post_phase = self._collect_phase('post_submit')
        # Merge submit CDP + post CDP for complete post_submit analysis
        combined_cdp = (
            self.session['phases'][-2].get('cdp_requests', []) +
            post_phase.get('_raw_cdp', [])
        )
        post_phase['post_submit'] = self._detect_post_submit(combined_cdp)
        post_phase['post_url'] = self._current_url()
        post_phase.pop('_raw_cdp', None)
        self.session['phases'].append(post_phase)
        self._print_phase_summary(post_phase)
        phase_idx += 1

        return phase_idx

    # ------------------------------------------------------------------ #
    #  Signal collection
    # ------------------------------------------------------------------ #

    def _collect_phase(self, label):
        """Drain JS logs + CDP, filter analytics, return structured phase dict."""
        try:
            raw = self.driver.execute_script("return window.__fa_getAndClearLogs()")
            js_logs = json.loads(raw)
        except Exception:
            js_logs = {}

        try:
            cdp_reqs = drain_cdp_network_logs(self.driver)
        except Exception:
            cdp_reqs = []

        signal_cdp = [r for r in cdp_reqs if not _is_analytics(r.get('url', ''))]
        noise_count = len(cdp_reqs) - len(signal_cdp)

        js_nets = js_logs.get('networkReqs', [])
        signal_js = [r for r in js_nets if not _is_analytics(r.get('url', ''))]

        fired      = js_logs.get('firedEvents', [])
        triggered  = js_logs.get('triggeredFunctions', [])
        dom_chg    = js_logs.get('domChanges', [])
        html5_val  = js_logs.get('html5Validation', [])

        # De-duplicate preserving order
        listener_events = list(dict.fromkeys(
            e.get('type') or e.get('eventType') or ''
            for e in fired if e.get('type') or e.get('eventType')
        ))
        triggered_fns = list(dict.fromkeys(
            f.get('functionName') or f.get('name') or ''
            for f in triggered
            if f.get('functionName') or f.get('name')
        ))

        return {
            'label':                    label,
            'timestamp':                time.strftime('%H:%M:%S'),
            'current_url':              self._current_url(),
            # Field-level interaction signals
            'listener_events':          listener_events,
            'triggered_function_names': triggered_fns,
            'dom_change_count':         len(dom_chg),
            'html5_validation':         bool(html5_val),
            # Network signals (analytics filtered)
            'js_network_requests': [
                {
                    'method':          r.get('method', ''),
                    'url':             r.get('url', ''),
                    'request_headers': r.get('requestHeaders', {}),
                }
                for r in signal_js
            ],
            'cdp_requests':                  self._summarize_cdp(signal_cdp),
            'analytics_requests_filtered':   noise_count,
            # Keep raw for internal use (post_submit / classify); stripped before save
            '_raw_cdp':                      signal_cdp,
        }

    def _clear_logs(self):
        try:
            self.driver.execute_script("window.__fa_getAndClearLogs()")
        except Exception:
            pass
        try:
            drain_cdp_network_logs(self.driver)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Sync / async classifier
    # ------------------------------------------------------------------ #

    def _classify_submission(self, cdp_reqs, js_nets, pre_url, post_url):
        """
        Classify submit as sync/async from CDP signals alone.
        Works regardless of who triggered the submit (human or script).

        Key signals:
          resourceType=Document + sec-fetch-dest=document -> synchronous navigation
          resourceType=XHR/Fetch                          -> asynchronous
          Both present                                    -> mixed (JS intercepted)
          current_url changed                             -> navigation happened
        """
        navigated = bool(pre_url and post_url and pre_url != post_url)

        doc_reqs = [
            r for r in cdp_reqs
            if r.get('resourceType') == 'Document'
            or (r.get('requestHeaders', {}).get('sec-fetch-dest') == 'document'
                and r.get('method') in ('POST', 'GET'))
        ]
        async_reqs = [
            r for r in cdp_reqs
            if r.get('resourceType') in ('XHR', 'Fetch', 'fetch', 'xhr')
            or r.get('initiatorType') in ('xmlhttprequest', 'fetch')
        ]
        post_reqs = [
            r for r in cdp_reqs
            if r.get('method') in ('POST', 'PUT', 'PATCH')
        ]

        has_nav   = navigated or bool(doc_reqs)
        has_async = bool(async_reqs) or bool(js_nets)

        if has_nav and has_async:
            return ('Mixed: native form submit + async re-send '
                    '(JS intercepted and forwarded as XHR/fetch)')
        if has_nav:
            return 'Synchronous: native form navigation (page URL changed)'
        if has_async:
            return 'Asynchronous: XHR/fetch only (page stayed, no navigation)'
        if post_reqs:
            return ('Asynchronous (inferred): POST without navigation '
                    '-- resourceType unclear (may be service worker or preflighted)')
        return 'Undetermined: no network activity in submit window'

    # ------------------------------------------------------------------ #
    #  Post-submit analysis
    # ------------------------------------------------------------------ #

    def _detect_post_submit(self, cdp_reqs):
        redirect_chain = []
        cookies_set    = []
        challenge      = 'none'
        response_status = None

        for r in cdp_reqs:
            status       = r.get('status')
            resp_headers = r.get('responseHeaders', {})

            if r.get('redirected') or status in (301, 302, 303, 307, 308):
                loc = r.get('redirectLocation') or resp_headers.get('location', '')
                if loc:
                    redirect_chain.append({'status': status, 'location': loc})

            if r.get('hasSetCookie'):
                parsed = self._parse_set_cookie(resp_headers.get('set-cookie', ''))
                if parsed:
                    cookies_set.append(parsed)

            if challenge == 'none':
                body = r.get('responseBodyPreview', '') or ''
                if resp_headers.get('sec-challenge') or status == 428:
                    challenge = 'bot_challenge'
                elif status == 429:
                    challenge = 'rate_limit'
                elif status in (401, 403):
                    challenge = 'auth_required'
                elif 'captcha' in body.lower():
                    challenge = 'captcha'
                elif 'otp' in body.lower() or '2fa' in body.lower():
                    challenge = 'mfa_otp'

            if response_status is None and status:
                response_status = status

        return {
            'redirect_chain':      redirect_chain,
            'cookies_set':         cookies_set,
            'challenge_type':      challenge,
            'session_established': any(c.get('httponly') for c in cookies_set),
            'response_status':     response_status,
        }

    def _parse_set_cookie(self, header_value):
        if not header_value:
            return None
        parts = [p.strip() for p in header_value.split(';')]
        if not parts:
            return None
        name_val = parts[0].split('=', 1)
        result = {'name': name_val[0].strip(), 'httponly': False, 'secure': False}
        for part in parts[1:]:
            pl = part.lower()
            if pl == 'httponly':
                result['httponly'] = True
            elif pl == 'secure':
                result['secure'] = True
            elif pl.startswith('samesite='):
                result['samesite'] = part.split('=', 1)[1].strip()
            elif pl.startswith('path='):
                result['path'] = part.split('=', 1)[1].strip()
            elif pl.startswith('domain='):
                result['domain'] = part.split('=', 1)[1].strip()
        return result

    # ------------------------------------------------------------------ #
    #  CDP helpers
    # ------------------------------------------------------------------ #

    def _summarize_cdp(self, cdp_reqs):
        out = []
        for r in cdp_reqs:
            out.append({
                'url':                r.get('url', ''),
                'method':             r.get('method', ''),
                'status':             r.get('status'),
                'resourceType':       r.get('resourceType', ''),
                'initiatorType':      r.get('initiatorType', ''),
                'protocol':           r.get('protocol', ''),
                'requestHeaders':     r.get('requestHeaders', {}),
                'responseHeaders':    r.get('responseHeaders', {}),
                'requestBody':        (r.get('postData') or '')[:500],
                'hasSetCookie':       r.get('hasSetCookie', False),
                'hasCookieHeader':    r.get('hasCookieHeader', False),
                'redirected':         r.get('redirected', False),
                'redirectChain':      r.get('redirectChain', []),
                'redirectLocation':   r.get('redirectLocation', ''),
                'latencyMs':          r.get('latencyMs'),
                'ttfbMs':             r.get('ttfbMs'),
                'responseBodyPreview': (r.get('responseBodyPreview') or '')[:300],
            })
        return out

    def _current_url(self):
        try:
            return self.driver.current_url
        except Exception:
            return ''

    # ------------------------------------------------------------------ #
    #  Output
    # ------------------------------------------------------------------ #

    def _save(self):
        # Strip internal _raw_cdp keys before saving (already consumed)
        for ph in self.session.get('phases', []):
            ph.pop('_raw_cdp', None)

        domain = urlparse(self.url).netloc.replace('.', '_').replace(':', '_')
        ts     = time.strftime('%Y%m%d_%H%M%S')
        path   = os.path.join(self.output_dir, 'manual_%s_%s.json' % (domain, ts))
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(self.session, fh, indent=2, ensure_ascii=False)
        print("\n[Manual] Results saved -> %s" % path)

    def _print_phase_summary(self, phase):
        label = phase.get('label', '?')
        print()
        print("  +- [%s]  %s" % (label, phase.get('timestamp', '')))
        print("  |  url: %s" % (phase.get('current_url') or '')[:70])

        if phase.get('listener_events'):
            print("  |  listener_events     : %s" % ', '.join(phase['listener_events']))
        if phase.get('triggered_function_names'):
            print("  |  triggered_functions : %s" % ', '.join(
                phase['triggered_function_names'][:8]))
        print("  |  dom_changes         : %d   html5_val: %s" % (
            phase.get('dom_change_count', 0), phase.get('html5_validation', False)))

        js_nets = phase.get('js_network_requests', [])
        if js_nets:
            print("  |  JS-visible requests : %d" % len(js_nets))
            for r in js_nets[:3]:
                print("  |    %s  %s" % (r.get('method', '?'), r.get('url', '')[:68]))

        cdp = phase.get('cdp_requests', [])
        print("  |  CDP requests        : %d  (analytics noise filtered: %d)" % (
            len(cdp), phase.get('analytics_requests_filtered', 0)))
        for r in cdp[:6]:
            flags = ''
            if r.get('hasSetCookie'):    flags += ' [Set-Cookie]'
            if r.get('hasCookieHeader'): flags += ' [Cookie]'
            print("  |    %-6s %-4s %-8s %s%s" % (
                r.get('method', '?'), r.get('status', '?'),
                r.get('resourceType', '?')[:8],
                r.get('url', '')[:52], flags))

        sm = phase.get('submission_method')
        if sm:
            print("  |")
            print("  |  * SYNC/ASYNC       : %s" % sm)
            print("  |    pre_url  : %s" % phase.get('pre_submit_url', '')[:68])
            print("  |    post_url : %s" % phase.get('post_submit_url', '')[:68])

        ps = phase.get('post_submit')
        if ps:
            print("  |")
            print("  |  [Post-submit]")
            print("  |    challenge_type      : %s" % ps.get('challenge_type', '?'))
            print("  |    session_established : %s" % ps.get('session_established'))
            print("  |    response_status     : %s" % ps.get('response_status', '?'))
            for hop in ps.get('redirect_chain', []):
                print("  |    redirect -> %s  %s" % (
                    hop.get('status', '?'), hop.get('location', '')[:58]))
            for c in ps.get('cookies_set', []):
                print("  |    cookie  : %-20s httponly=%-5s secure=%s" % (
                    c.get('name', '?')[:20], c.get('httponly'), c.get('secure')))

        print("  +" + "-" * 66)
        print()

    def _print_final_report(self):
        _banner("MANUAL SESSION REPORT")
        print("  URL   : %s" % self.session.get('url', ''))
        print("  Phases: %d" % len(self.session.get('phases', [])))
        print()
        for ph in self.session.get('phases', []):
            evts = ', '.join(ph.get('listener_events', [])) or '--'
            print("  [%-20s]  events=%-25s  cdp=%2d  ajax=%2d  domΔ=%d" % (
                ph.get('label', '?')[:20], evts[:25],
                len(ph.get('cdp_requests', [])),
                len(ph.get('js_network_requests', [])),
                ph.get('dom_change_count', 0),
            ))
            sm = ph.get('submission_method')
            if sm:
                print("    -> %s" % sm)
            ps = ph.get('post_submit', {})
            if ps:
                print("    challenge=%-15s  session=%s  status=%s" % (
                    ps.get('challenge_type', '?'),
                    ps.get('session_established', '?'),
                    ps.get('response_status', '?')))
        print()
        if self.session.get('errors'):
            print("  Errors:")
            for e in self.session['errors']:
                print("    ! %s" % e)
        _banner()


def _banner(text=''):
    line = '=' * 68
    print(line)
    if text:
        print('  ' + text)
        print(line)
