"""LegitAnalyzer.py -- Header-aware form submission analyzer for legitimate websites.

Header visibility by layer:
  CDP layer  : ALL browser-generated request headers (Cookie, Authorization,
               Referer, Origin, Host, Content-Length) + ALL response headers
               (Set-Cookie, Location, HSTS, CSP).  Not subject to CORS.
  JS layer   : Only headers JS explicitly set via setRequestHeader() or
               fetch(init.headers).  Forbidden headers (Cookie, Authorization,
               Referer, Origin) are silently dropped by the browser before
               the request is sent, so they never appear in __fa.networkReqs.
               Response headers: only CORS-safelisted ones for cross-origin.
               Same-origin responses expose all headers to JS.
"""

import json
import logging
import os
import time
from urllib.parse import urlparse

from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import (
    ElementNotInteractableException,
    StaleElementReferenceException,
    NoSuchElementException,
)

from Functions import (
    drain_cdp_network_logs,
    init_cdp_network_monitoring,
    reset_cdp_network_monitoring,
)

FORBIDDEN_HEADERS = frozenset({
    'cookie', 'authorization', 'referer', 'origin',
    'host', 'content-length', 'connection',
    'accept-encoding', 'user-agent', 'sec-fetch-site',
    'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user',
    'upgrade-insecure-requests',
})

_USERNAME_PATTERNS = ('email', 'user', 'username', 'login', 'account', 'uid', 'mail', 'id')
_PASSWORD_PATTERNS = ('pass', 'password', 'pwd', 'secret')

# Text content patterns that indicate a submit/search/action button
_SUBMIT_TEXT_PATTERNS = (
    'track', 'search', 'find', 'submit', 'continue', 'next',
    'go', 'send', 'login', 'sign in', 'log in', 'verify',
    'confirm', 'proceed', 'check', 'get', 'start',
)

# CSS selectors tried in order to find cookie consent accept buttons
_COOKIE_ACCEPT_SELECTORS = [
    '#onetrust-accept-btn-handler',          # OneTrust
    '#accept-recommended-btn-handler',       # OneTrust alternative
    '.evidon-barrier-acceptbutton',          # Evidon
    '#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll',  # Cookiebot
    '[data-testid="cookie-accept"]',
    '[data-testid="accept-cookies"]',
    '[data-cy="accept-all-cookies"]',
    '.cookie-accept',
    '.cookie-consent__accept',
    '.js-cookie-accept',
    '#cookie-accept',
    'button[aria-label*="accept" i]',
    'button[aria-label*="agree" i]',
    'button[id*="accept" i]',
    'button[class*="accept" i]',
]


class LegitAnalyzer:
    """
    Dual-phase form submission analyzer for external (legitimate) websites.

    Phase A -- native browser submit:
        Real browser submit, CDP captures ground-truth headers including
        Cookie, Authorization, Set-Cookie, Location.  Page navigates; JS context
        is destroyed but CDP logs survive the navigation.

    Phase B -- XHR-intercepted submit:
        e.preventDefault() + XHR resend.  form_analyzer.js wrappers capture
        what JS can observe: headers JS set explicitly, CORS-permitted response
        headers.  Diffing A vs B shows headers hidden from page JavaScript.
    """

    def __init__(self, driver, url, username=None, password=None,
                 delay=2, output_dir=None):
        self.driver = driver
        self.url = url
        self.username = username
        self.password = password
        self.delay = delay
        self.output_dir = output_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'results', 'dynamic_analysis_blackwidow', 'legit_results'
        )
        os.makedirs(self.output_dir, exist_ok=True)

        self.results = {
            'url': url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'page_load': {},
            'forms': [],
            'errors': [],
        }

    # ------------------------------------------------------------------ #
    #  Public entry point
    # ------------------------------------------------------------------ #

    def run(self):
        """Main entry point. Errors are logged but never raise -- browser stays open."""
        print("[Legit] Target: %s" % self.url)
        try:
            self._run_inner()
        except KeyboardInterrupt:
            print("[Legit] Interrupted by user.")
        except Exception as e:
            msg = "Unhandled error in run(): %s" % e
            logging.exception(msg)
            print("[Legit] ERROR: %s" % msg)
            self.results['errors'].append(msg)
            # Save partial results so we don't lose what was captured
            try:
                self._save()
            except Exception:
                pass

    def _run_inner(self):
        init_cdp_network_monitoring(self.driver)
        reset_cdp_network_monitoring(self.driver)

        self.driver.get(self.url)
        self._wait_for_dom_stable(timeout=12)

        # Cookie/GDPR consent banners block all interaction -- dismiss first
        self._dismiss_overlays()
        time.sleep(0.8)

        page_load_cdp = drain_cdp_network_logs(self.driver)
        self.results['page_load'] = {
            'requests': self._summarize_cdp(page_load_cdp),
            'initial_cookies_set': [
                r for r in self._summarize_cdp(page_load_cdp) if r['hasSetCookie']
            ],
        }
        print("[Legit] Page load: %d request(s) captured" % len(page_load_cdp))

        self._fa_start()

        forms = self._discover_inputs()
        print("[Legit] Input groups found: %d" % len(forms))

        if not forms:
            print("[Legit] WARNING: No input groups found. Page may require manual interaction.")
            self.results['errors'].append('No forms or input groups discovered on page.')

        for idx, group in enumerate(forms):
            print("\n[Legit] --- Input group %d/%d ---" % (idx + 1, len(forms)))
            try:
                form_result = self._analyze_group(group, idx)
                self.results['forms'].append(form_result)
            except Exception as e:
                msg = "Error analyzing group %d: %s" % (idx, e)
                logging.exception(msg)
                print("[Legit]   ERROR: %s" % msg)
                self.results['errors'].append(msg)

        self._save()
        self._print_report()

    # ------------------------------------------------------------------ #
    #  Overlay / cookie consent dismissal
    # ------------------------------------------------------------------ #

    def _dismiss_overlays(self):
        """
        Attempt to dismiss cookie consent banners and GDPR modals.

        Tries in order:
          1. Known cookie consent framework selectors
          2. Any visible button whose text contains accept/agree/allow
          3. Escape key for modal dialogs
        """
        # Attempt 1: known selectors
        for sel in _COOKIE_ACCEPT_SELECTORS:
            try:
                btn = self.driver.find_element('css selector', sel)
                if btn.is_displayed() and btn.is_enabled():
                    self.driver.execute_script("arguments[0].scrollIntoView(true);", btn)
                    btn.click()
                    print("[Legit] Cookie banner dismissed via selector: %s" % sel)
                    time.sleep(0.8)
                    return
            except (NoSuchElementException, ElementNotInteractableException):
                continue
            except Exception:
                continue

        # Attempt 2: text-based heuristic on all visible buttons
        try:
            dismissed = self.driver.execute_script("""
                var keywords = ['accept all', 'accept cookies', 'allow all',
                                'agree', 'i accept', 'okay', 'got it',
                                'accept', 'allow'];
                var buttons = document.querySelectorAll(
                    'button, [role="button"], a[class*="cookie"], a[id*="cookie"]'
                );
                for (var i = 0; i < buttons.length; i++) {
                    var btn = buttons[i];
                    var txt = (btn.innerText || btn.textContent || '').toLowerCase().trim();
                    var rect = btn.getBoundingClientRect();
                    var visible = rect.width > 0 && rect.height > 0 &&
                                  window.getComputedStyle(btn).visibility !== 'hidden';
                    if (!visible) continue;
                    for (var k = 0; k < keywords.length; k++) {
                        if (txt.indexOf(keywords[k]) !== -1) {
                            btn.click();
                            return txt;
                        }
                    }
                }
                return null;
            """)
            if dismissed:
                print("[Legit] Cookie banner dismissed via text heuristic: '%s'" % dismissed)
                time.sleep(0.8)
                return
        except Exception as e:
            logging.debug("Text-based overlay dismiss failed: %s", e)

        # Attempt 3: Escape key (closes some modal-style overlays)
        try:
            self.driver.find_element('css selector', 'body').send_keys(Keys.ESCAPE)
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Input group discovery
    # ------------------------------------------------------------------ #

    def _discover_inputs(self):
        """
        Return a list of input group dicts, each representing one form/action unit.

        Approach:
          1. Standard <form> elements -- existing behaviour
          2. Inputs inside a <form> but also grab non-form inputs as a group
          3. Standalone inputs/buttons not inside any <form> (SPA, React widgets)

        Each group is a dict:
          {
            'form_el':   Selenium element or None,
            'action':    str,
            'method':    str,
            'enctype':   str,
            'inputs':    [{'el': el, 'type': str, 'name': str, 'placeholder': str}],
            'submit_candidates': [el, ...],
          }
        """
        groups = []
        seen_inputs = set()  # track element IDs to avoid duplicates

        # -- Standard <form> elements ------------------------------------
        try:
            form_els = self.driver.find_elements('css selector', 'form')
            for fel in form_els:
                try:
                    if not fel.is_displayed():
                        continue
                except StaleElementReferenceException:
                    continue

                action = (fel.get_attribute('action') or '').strip() or self.driver.current_url
                method = (fel.get_attribute('method') or 'GET').upper()
                enctype = fel.get_attribute('enctype') or 'application/x-www-form-urlencoded'

                inputs = []
                for inp in fel.find_elements('css selector', 'input, textarea, select'):
                    try:
                        itype = (inp.get_attribute('type') or 'text').lower()
                        if itype in ('hidden', 'image'):
                            continue
                        if not inp.is_displayed():
                            continue
                        inp_id = inp.id
                        if inp_id in seen_inputs:
                            continue
                        seen_inputs.add(inp_id)
                        inputs.append({
                            'el': inp,
                            'type': itype,
                            'name': inp.get_attribute('name') or '',
                            'placeholder': inp.get_attribute('placeholder') or '',
                        })
                    except StaleElementReferenceException:
                        continue

                # Submit candidates within this form
                submits = self._find_submit_buttons_in(fel)
                # Also accept type=button with submit-like text
                submits += self._find_text_buttons_in(fel)

                if inputs or submits:
                    groups.append({
                        'form_el': fel,
                        'action': action,
                        'method': method,
                        'enctype': enctype,
                        'inputs': inputs,
                        'submit_candidates': submits,
                    })
        except Exception as e:
            logging.warning("[Legit] <form> discovery error: %s", e)

        # -- Standalone inputs not inside any <form> (SPA / React widgets) --
        try:
            all_inputs = self.driver.find_elements(
                'css selector',
                'input:not([type=hidden]):not([type=submit])'
                ':not([type=button]):not([type=reset]):not([type=image]),'
                'textarea'
            )
            orphan_inputs = []
            for inp in all_inputs:
                try:
                    if inp.id in seen_inputs:
                        continue
                    if not inp.is_displayed():
                        continue
                    # Check if inside a <form>
                    try:
                        inp.find_element('xpath', 'ancestor::form')
                        continue  # already captured via form discovery
                    except NoSuchElementException:
                        pass
                    seen_inputs.add(inp.id)
                    orphan_inputs.append({
                        'el': inp,
                        'type': (inp.get_attribute('type') or 'text').lower(),
                        'name': inp.get_attribute('name') or '',
                        'placeholder': inp.get_attribute('placeholder') or '',
                    })
                except StaleElementReferenceException:
                    continue

            if orphan_inputs:
                # Find submit-like buttons also not inside a <form>
                orphan_submits = []
                try:
                    btns = self.driver.find_elements(
                        'css selector',
                        'button, [role="button"], input[type=button], input[type=submit]'
                    )
                    for b in btns:
                        try:
                            if not b.is_displayed():
                                continue
                            try:
                                b.find_element('xpath', 'ancestor::form')
                                continue
                            except NoSuchElementException:
                                pass
                            orphan_submits.append(b)
                        except StaleElementReferenceException:
                            continue
                except Exception:
                    pass

                groups.append({
                    'form_el': None,
                    'action': self.driver.current_url,
                    'method': 'POST',
                    'enctype': 'application/x-www-form-urlencoded',
                    'inputs': orphan_inputs,
                    'submit_candidates': orphan_submits,
                })
        except Exception as e:
            logging.warning("[Legit] Orphan input discovery error: %s", e)

        return groups

    def _find_submit_buttons_in(self, container):
        """Return submit/image type buttons inside container."""
        btns = []
        for sel in ('input[type=submit]', 'button[type=submit]',
                    'button:not([type])', 'input[type=image]'):
            try:
                for b in container.find_elements('css selector', sel):
                    if b.is_displayed() and b.is_enabled():
                        btns.append(b)
            except Exception:
                pass
        return btns

    def _find_text_buttons_in(self, container):
        """Return type=button elements whose text matches submit-action keywords."""
        btns = []
        try:
            candidates = container.find_elements(
                'css selector', 'button[type=button], input[type=button], [role=button]'
            )
            for b in candidates:
                try:
                    if not b.is_displayed():
                        continue
                    txt = (b.text or b.get_attribute('value') or
                           b.get_attribute('aria-label') or '').lower()
                    if any(p in txt for p in _SUBMIT_TEXT_PATTERNS):
                        btns.append(b)
                except Exception:
                    continue
        except Exception:
            pass
        return btns

    # ------------------------------------------------------------------ #
    #  Single group analysis
    # ------------------------------------------------------------------ #

    def _analyze_group(self, group, idx):
        page_url = self.driver.current_url
        field_names = [i['name'] or i['placeholder'] or i['type']
                       for i in group['inputs']]
        print("[Legit]   Fields: %s" % field_names)
        print("[Legit]   Submit buttons: %d" % len(group['submit_candidates']))

        result = {
            'form_index': idx,
            'action': group['action'],
            'method': group['method'],
            'enctype': group['enctype'],
            'is_login': any(i['type'] == 'password' for i in group['inputs']),
            'fields': field_names,
            'has_form_tag': group['form_el'] is not None,
            'field_analysis': [],
            'post_submit': {},
            'phase_a_native': {},
            'phase_b_xhr': {},
            'header_comparison': {},
            'submission_method_classification': '',
        }

        # -- Pre-submit: per-field keystroke analysis --------------------
        print("[Legit]   Pre-submit field analysis")
        for inp in group['inputs']:
            itype = inp['type']
            if itype in ('submit', 'button', 'reset', 'image', 'file',
                         'checkbox', 'radio', 'hidden'):
                continue
            test_value = self._pick_value(inp)
            try:
                fa = self._analyze_field_legit(inp, test_value)
                result['field_analysis'].append(fa)
            except Exception as exc:
                logging.warning("[Legit] field analysis failed for %s: %s",
                                inp['name'], exc)
                result['field_analysis'].append({
                    'name': inp['name'] or inp['placeholder'] or itype,
                    'type': itype,
                    'error': str(exc),
                })

        # -- Phase A: native submit --------------------------------------
        print("[Legit]   Phase A: native submit -> CDP capture")
        result['phase_a_native'] = self._phase_a(group, page_url)
        # _raw_cdp_reqs is a temp key holding raw CDP list for post_submit analysis
        raw_cdp = result['phase_a_native'].pop('_raw_cdp_reqs', [])
        result['post_submit'] = self._detect_post_submit(raw_cdp)

        # Reload + re-dismiss overlays for clean Phase B
        self.driver.get(page_url)
        self._wait_for_dom_stable(timeout=12)
        self._dismiss_overlays()
        time.sleep(0.5)
        self._fa_start()

        # -- Phase B: XHR-intercepted ------------------------------------
        print("[Legit]   Phase B: XHR-intercepted -> JS header capture")
        # Re-discover inputs after reload (elements are stale)
        groups_reloaded = self._discover_inputs()
        group_b = groups_reloaded[idx] if idx < len(groups_reloaded) else group
        result['phase_b_xhr'] = self._phase_b(group_b)

        result['header_comparison'] = self._compare(
            result['phase_a_native'].get('request_headers_cdp', {}),
            result['phase_b_xhr'].get('request_headers_js', {}),
        )
        result['submission_method_classification'] = self._classify(result)
        return result

    # ------------------------------------------------------------------ #
    #  Phase A -- native browser submit, CDP capture
    # ------------------------------------------------------------------ #

    def _phase_a(self, group, page_url):
        out = {
            'request_headers_cdp': {},
            'response_headers_cdp': {},
            'request_body': '',
            'content_type': '',
            'method': '',
            'action_url': '',
            'status': None,
            'protocol': '',
            'redirect_chain': [],
            'has_set_cookie': False,
            'has_cookie_header': False,
            'login_success_signals': {},
            'all_requests': [],
            'fill_results': [],
            '_raw_cdp_reqs': [],   # temp; popped in _analyze_group after _detect_post_submit
            'error': '',
        }

        fill_results = self._fill_group(group)
        out['fill_results'] = fill_results
        time.sleep(0.3)
        reset_cdp_network_monitoring(self.driver)

        submitted = self._click_best_submit(group)
        if not submitted:
            out['error'] = 'no submit button found or clickable'
            return out

        self._wait_for_navigation(page_url, timeout=8)

        cdp_reqs = drain_cdp_network_logs(self.driver)
        out['all_requests'] = self._summarize_cdp(cdp_reqs)
        out['_raw_cdp_reqs'] = cdp_reqs

        req = self._find_submit_req(cdp_reqs, group['action'])
        if not req:
            out['error'] = 'submit request not identified in CDP log (%d reqs captured)' % len(cdp_reqs)
            return out

        out['request_headers_cdp'] = req.get('requestHeaders', {})
        out['response_headers_cdp'] = req.get('responseHeaders', {})
        out['request_body'] = (req.get('postData') or '')[:1000]
        out['content_type'] = req.get('requestContentType', '')
        out['method'] = req.get('method', '')
        out['action_url'] = req.get('url', '')
        out['status'] = req.get('status')
        out['protocol'] = req.get('protocol', '')
        out['redirect_chain'] = req.get('redirectChain', [])
        out['has_set_cookie'] = req.get('hasSetCookie', False)
        out['has_cookie_header'] = req.get('hasCookieHeader', False)
        out['login_success_signals'] = self._detect_login_success(req)
        out['latency_ms'] = req.get('latencyMs')
        out['ttfb_ms'] = req.get('ttfbMs')
        return out

    # ------------------------------------------------------------------ #
    #  Phase B -- XHR-intercepted submit
    # ------------------------------------------------------------------ #

    def _phase_b(self, group):
        out = {
            'request_headers_js': {},
            'response_headers_js': {},
            'request_body': '',
            'content_type': '',
            'method': '',
            'action_url': '',
            'status': None,
            'response_preview': '',
            'cdp_during_xhr': [],
            'fill_results': [],
            'error': '',
        }

        fill_results = self._fill_group(group)
        out['fill_results'] = fill_results
        time.sleep(0.3)
        reset_cdp_network_monitoring(self.driver)
        self._install_interceptor()

        self._click_best_submit(group)
        time.sleep(self.delay)

        try:
            js_nets = self.driver.execute_script(
                "return window.__fa ? window.__fa.networkReqs : []"
            ) or []
        except Exception:
            js_nets = []

        cdp_reqs = drain_cdp_network_logs(self.driver)
        out['cdp_during_xhr'] = self._summarize_cdp(cdp_reqs)

        if js_nets:
            req = js_nets[-1]
            out['request_headers_js'] = req.get('requestHeaders', {})
            out['response_headers_js'] = req.get('responseHeaders', {})
            out['request_body'] = (req.get('requestBody') or '')[:1000]
            out['content_type'] = req.get('requestContentType', '')
            out['method'] = req.get('method', '')
            out['action_url'] = req.get('url', '')
            out['status'] = req.get('status')
            out['response_preview'] = (req.get('response') or '')[:500]
        else:
            try:
                meta = self.driver.execute_script("return window.__fa_submitResult")
                if meta:
                    out['method'] = meta.get('method', '')
                    out['action_url'] = meta.get('action', '')
                    out['status'] = meta.get('status')
                    out['error'] = '__fa networkReqs empty; __fa_submitResult fallback used'
                else:
                    out['error'] = 'no JS network data captured (form may use fetch/async handler)'
            except Exception as e:
                out['error'] = 'JS read failed: %s' % e

        return out

    # ------------------------------------------------------------------ #
    #  Input filling -- JS-native setter (React/Vue compatible)
    # ------------------------------------------------------------------ #

    def _fill_group(self, group):
        """
        Fill each input in the group.

        Strategy (tried in order per field):
          1. JS native setter + dispatchEvent -- compatible with React/Vue controlled inputs
          2. Selenium send_keys() -- fallback for traditional inputs
          3. ActionChains click + send_keys -- for inputs that need focus first

        Returns a list of fill result dicts for debugging.
        """
        results = []
        for inp in group['inputs']:
            itype = inp['type']
            if itype in ('submit', 'button', 'reset', 'image', 'file', 'checkbox', 'radio'):
                continue
            value = self._pick_value(inp)
            if not value:
                continue
            el = inp['el']
            method_used = None
            try:
                method_used = self._fill_input_js(el, value)
            except Exception as e:
                logging.debug("JS fill failed for %s: %s", inp['name'], e)
            if not method_used:
                try:
                    el.clear()
                    el.send_keys(value)
                    method_used = 'send_keys'
                except ElementNotInteractableException:
                    try:
                        ActionChains(self.driver).move_to_element(el).click().send_keys(value).perform()
                        method_used = 'action_chains'
                    except Exception as e2:
                        logging.debug("ActionChains fill failed for %s: %s", inp['name'], e2)
                except StaleElementReferenceException:
                    logging.debug("Stale element for %s -- skipping", inp['name'])

            actual = None
            try:
                actual = el.get_attribute('value')
            except Exception:
                pass

            results.append({
                'field': inp['name'] or inp['placeholder'] or itype,
                'type': itype,
                'intended_value': value[:30] if value else '',
                'actual_value': (actual or '')[:30],
                'method': method_used or 'failed',
                'success': bool(actual and value and actual == value),
            })

            if results[-1]['success']:
                print("[Legit]     fill OK  : %-20s = %s (via %s)" % (
                    results[-1]['field'][:20], results[-1]['actual_value'][:20], method_used))
            else:
                print("[Legit]     fill FAIL: %-20s (intended=%s actual=%s via %s)" % (
                    results[-1]['field'][:20], value[:20],
                    (actual or '')[:20], method_used or 'none'))

        return results

    def _fill_input_js(self, el, value):
        """
        Set an input value using the native property setter.

        This triggers React/Vue synthetic onChange events because React
        overrides the value property descriptor but listens on the native
        setter via Object.getOwnPropertyDescriptor.
        """
        script = """
            var el = arguments[0];
            var value = arguments[1];
            var nativeSetter = Object.getOwnPropertyDescriptor(
                el.tagName === 'TEXTAREA'
                    ? HTMLTextAreaElement.prototype
                    : HTMLInputElement.prototype,
                'value'
            );
            if (nativeSetter && nativeSetter.set) {
                nativeSetter.set.call(el, value);
            } else {
                el.value = value;
            }
            el.dispatchEvent(new Event('input',  {bubbles: true, cancelable: true}));
            el.dispatchEvent(new Event('change', {bubbles: true, cancelable: true}));
            el.dispatchEvent(new KeyboardEvent('keydown',  {bubbles: true, key: 'a'}));
            el.dispatchEvent(new KeyboardEvent('keypress', {bubbles: true, key: 'a'}));
            el.dispatchEvent(new KeyboardEvent('keyup',    {bubbles: true, key: 'a'}));
            return el.value;
        """
        result = self.driver.execute_script(script, el, value)
        if result == value:
            return 'js_native_setter'
        return None

    def _pick_value(self, inp):
        """Choose the value to fill for a given input field."""
        itype = inp['type']
        name_l = (inp['name'] + ' ' + inp['placeholder']).lower()

        if itype == 'password':
            return self.password or 'TestPass123!'
        if itype == 'email':
            return self.username if (self.username and '@' in self.username) else 'test@example.com'
        if any(p in name_l for p in _PASSWORD_PATTERNS):
            return self.password or 'TestPass123!'
        if any(p in name_l for p in _USERNAME_PATTERNS):
            return self.username or 'testuser'
        # Heuristic: tracking number inputs
        if any(kw in name_l for kw in ('track', 'waybill', 'parcel', 'shipment', 'awb', 'number')):
            return '1234567890'
        if itype in ('number', 'tel'):
            return '1234567890'
        if itype in ('search', 'text', 'textarea', ''):
            return 'test'
        return 'test'

    # ------------------------------------------------------------------ #
    #  Submit button selection
    # ------------------------------------------------------------------ #

    def _click_best_submit(self, group):
        """
        Click the most appropriate submit button from the group's candidates.

        Priority:
          1. Candidates already found during discovery (type=submit, type=button with text)
          2. Page-wide submit button search
          3. JS click on form.submit() / button near inputs
        """
        # Try pre-discovered candidates
        for btn in group.get('submit_candidates', []):
            try:
                if btn.is_displayed() and btn.is_enabled():
                    self.driver.execute_script(
                        "arguments[0].scrollIntoView({block:'center'});", btn)
                    time.sleep(0.2)
                    btn.click()
                    print("[Legit]     submit click: %s ('%s')" % (
                        btn.tag_name,
                        (btn.text or btn.get_attribute('value') or '')[:30]))
                    return True
            except StaleElementReferenceException:
                continue
            except ElementNotInteractableException:
                try:
                    self.driver.execute_script("arguments[0].click();", btn)
                    return True
                except Exception:
                    continue
            except Exception:
                continue

        # Page-wide search by type
        for sel in ('[type="submit"]', 'button[type="submit"]', 'button:not([type])'):
            try:
                btn = self.driver.find_element('css selector', sel)
                if btn.is_displayed():
                    self.driver.execute_script(
                        "arguments[0].scrollIntoView({block:'center'});", btn)
                    btn.click()
                    return True
            except Exception:
                continue

        # Page-wide search by button text
        try:
            clicked = self.driver.execute_script("""
                var patterns = %s;
                var candidates = document.querySelectorAll(
                    'button, [role="button"], input[type=button], input[type=submit], a[onclick]'
                );
                for (var i = 0; i < candidates.length; i++) {
                    var btn = candidates[i];
                    var txt = (btn.innerText || btn.textContent || btn.value || '').toLowerCase();
                    var rect = btn.getBoundingClientRect();
                    if (rect.width === 0 || rect.height === 0) continue;
                    for (var k = 0; k < patterns.length; k++) {
                        if (txt.indexOf(patterns[k]) !== -1) {
                            btn.scrollIntoView({block:'center'});
                            btn.click();
                            return txt;
                        }
                    }
                }
                return null;
            """ % json.dumps(list(_SUBMIT_TEXT_PATTERNS)))
            if clicked:
                print("[Legit]     submit click (text match): '%s'" % clicked)
                return True
        except Exception as e:
            logging.debug("Text-based submit click failed: %s", e)

        # Last resort: JS form.submit()
        if group.get('form_el'):
            try:
                self.driver.execute_script("arguments[0].submit();", group['form_el'])
                return True
            except Exception:
                pass

        return False

    # ------------------------------------------------------------------ #
    #  Submit interceptor (Phase B)
    # ------------------------------------------------------------------ #

    def _install_interceptor(self):
        """
        Install e.preventDefault() + XHR resend interceptor.

        Works for:
          - Standard <form> submit events
          - HTMLFormElement.submit() calls
          - Does NOT intercept direct fetch()/XHR calls made by app JS
            (those are already captured by form_analyzer.js wrappers).
        """
        self.driver.execute_script("""
            window.__fa_submitResult = null;
            window.__fa_submitIntercepted = false;

            if (!window.__fa_submitIntercepted) {
                window.__fa_submitIntercepted = true;

                document.addEventListener('submit', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    var form = e.target;
                    var action = form.getAttribute('action') || window.location.href;
                    var method = (form.getAttribute('method') || 'GET').toUpperCase();
                    var pairs = [];
                    try {
                        (new FormData(form)).forEach(function(v, k) {
                            pairs.push(encodeURIComponent(k) + '=' + encodeURIComponent(v));
                        });
                    } catch(ex) {}

                    var xhr = new XMLHttpRequest();
                    xhr.open(method, action, true);
                    xhr.setRequestHeader('Content-Type',
                        'application/x-www-form-urlencoded');
                    xhr.onload = function() {
                        window.__fa_submitResult = {
                            action: action, method: method, status: xhr.status,
                            responseContentType: xhr.getResponseHeader('Content-Type') || '',
                            responseBodyLength: (xhr.responseText || '').length,
                            submitted: true,
                        };
                    };
                    xhr.onerror = function() {
                        window.__fa_submitResult = {
                            action: action, method: method,
                            status: 'network_error', submitted: true,
                        };
                    };
                    xhr.send(pairs.join('&'));
                }, true);

                var _orig = HTMLFormElement.prototype.submit;
                HTMLFormElement.prototype.submit = function() {
                    var ev = new Event('submit', {bubbles: true, cancelable: true});
                    if (!this.dispatchEvent(ev)) return;
                    _orig.call(this);
                };
            }
        """)

    # ------------------------------------------------------------------ #
    #  Header comparison
    # ------------------------------------------------------------------ #

    def _compare(self, cdp_headers, js_headers):
        cdp_norm = {k.lower(): v for k, v in cdp_headers.items()}
        js_norm  = {k.lower(): v for k, v in js_headers.items()}

        cdp_keys = set(cdp_norm)
        js_keys  = set(js_norm)

        browser_only = cdp_keys - js_keys
        js_only      = js_keys  - cdp_keys
        shared       = cdp_keys & js_keys

        return {
            'hidden_auth_headers':       {k: cdp_norm[k] for k in browser_only if k in FORBIDDEN_HEADERS},
            'other_browser_only_headers': {k: cdp_norm[k] for k in browser_only if k not in FORBIDDEN_HEADERS},
            'js_set_headers':            {k: js_norm[k]  for k in js_only},
            'shared_headers':            {k: cdp_norm[k] for k in shared},
            'counts': {
                'cdp_total':       len(cdp_keys),
                'js_total':        len(js_keys),
                'hidden_from_js':  len(browser_only),
                'js_only':         len(js_only),
                'shared':          len(shared),
            },
        }

    # ------------------------------------------------------------------ #
    #  Submission method classification
    # ------------------------------------------------------------------ #

    def _classify(self, form_result):
        a = form_result.get('phase_a_native', {})
        b = form_result.get('phase_b_xhr', {})
        a_ok = bool(a.get('method') and not a.get('error'))
        b_ok = bool(b.get('method') and not b.get('error'))
        a_ct = a.get('content_type', '')
        b_ct = b.get('content_type', '')

        if a_ok and b_ok:
            if a_ct != b_ct:
                return ('Async/JS-transformed: JS intercepts and changes Content-Type '
                        '%s (browser) -> %s (XHR)' % (a_ct, b_ct))
            return 'Native HTML form submit'
        if a_ok and not b_ok:
            return 'Native HTML form submit (no JS interception)'
        if not a_ok and b_ok:
            return 'Pure async/JS submit (%s -> %s)' % (b.get('method', '?'), b.get('action_url', '?'))
        return 'Undetermined -- check fill_results and errors'

    # ------------------------------------------------------------------ #
    #  Login success detection
    # ------------------------------------------------------------------ #

    def _detect_login_success(self, cdp_req):
        signals = {
            'has_set_cookie': bool(cdp_req.get('hasSetCookie')),
            'redirect_away_from_login': False,
            'success_keywords_in_body': False,
        }
        loc = cdp_req.get('redirectLocation') or ''
        if loc:
            signals['redirect_away_from_login'] = not any(
                kw in loc.lower()
                for kw in ('login', 'signin', 'sign-in', 'error', 'fail', 'auth', 'verify')
            )
        body = cdp_req.get('responseBodyPreview') or ''
        signals['success_keywords_in_body'] = any(
            kw in body.lower()
            for kw in ('dashboard', 'welcome', 'logout', 'sign out', 'profile', 'account')
        )
        signals['likely_success'] = sum(1 for v in signals.values() if v) >= 2
        return signals

    # ------------------------------------------------------------------ #
    #  Wait helpers
    # ------------------------------------------------------------------ #

    def _wait_for_dom_stable(self, timeout=12):
        """Poll until visible input count is stable for two consecutive 500 ms ticks."""
        prev = -1
        stable = 0
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.5)
            try:
                curr = self.driver.execute_script(
                    "return document.querySelectorAll("
                    "  'input:not([type=hidden]), select, textarea').length"
                )
            except Exception:
                break
            if curr == prev:
                stable += 1
                if stable >= 2:
                    break
            else:
                stable = 0
            prev = curr

    def _wait_for_navigation(self, original_url, timeout=8):
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.5)
            try:
                if self.driver.current_url != original_url:
                    break
            except Exception:
                break

    # ------------------------------------------------------------------ #
    #  JS instrumentation
    # ------------------------------------------------------------------ #

    def _fa_start(self):
        try:
            self.driver.execute_script("if(window.__fa_start) window.__fa_start(null);")
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    #  Per-keystroke field analysis -- helpers
    # ------------------------------------------------------------------ #

    def _get_xpath(self, el):
        """Return XPath for a Selenium element using getXPath() from form_analyzer.js."""
        return self.driver.execute_script("return getXPath(arguments[0]);", el)

    def _clear_logs(self):
        """Clear JS event log arrays and drain CDP buffer (discarded -- phase boundary reset)."""
        try:
            self.driver.execute_script("window.__fa_getAndClearLogs()")
        except Exception:
            pass
        try:
            drain_cdp_network_logs(self.driver)
        except Exception:
            pass

    def _collect_logs_legit(self):
        """Snapshot + clear JS logs, drain CDP, return combined dict."""
        try:
            raw = self.driver.execute_script("return window.__fa_getAndClearLogs()")
            logs = json.loads(raw)
        except Exception:
            logs = {}
        try:
            cdp_logs = drain_cdp_network_logs(self.driver)
        except Exception:
            cdp_logs = []
        logs['cdpNetworkReqs'] = cdp_logs
        return logs

    def _type_chars_legit(self, xpath, value, delay_ms=50):
        """Type value char by char (keydown->keypress->input->keyup) with delay_ms between steps.

        Returns aggregated signals dict instead of full per-char log.
        """
        delay = delay_ms / 1000.0
        ajax_triggered = False
        ajax_first_at_char_index = None
        ajax_endpoints = []
        dom_change_on_input = False
        triggered_fn_names = []
        current_value = ''

        for char_idx, char in enumerate(value):
            char_code = ord(char)

            # keydown
            self.driver.execute_script("window.__fa_setPhase('typing_keydown')")
            self.driver.execute_script("window.__fa_incrementStep()")
            self._clear_logs()
            self.driver.execute_script(
                "window.__fa_dispatchKeyEvent(arguments[0],'keydown',"
                "arguments[1],arguments[2],0)", xpath, char, char_code)
            time.sleep(delay)

            # keypress
            self.driver.execute_script("window.__fa_setPhase('typing_keypress')")
            self.driver.execute_script("window.__fa_incrementStep()")
            self._clear_logs()
            self.driver.execute_script(
                "window.__fa_dispatchKeyEvent(arguments[0],'keypress',"
                "arguments[1],arguments[2],arguments[2])", xpath, char, char_code)
            time.sleep(delay)

            # input -- update value and check signals
            self.driver.execute_script("window.__fa_setPhase('typing_input')")
            self.driver.execute_script("window.__fa_incrementStep()")
            self._clear_logs()
            current_value += char
            self.driver.execute_script(
                "window.__fa_updateValueAndInput(arguments[0],arguments[1])",
                xpath, current_value)
            time.sleep(delay)
            logs = self._collect_logs_legit()

            if logs.get('networkReqs') or logs.get('cdpNetworkReqs'):
                if not ajax_triggered:
                    ajax_first_at_char_index = char_idx
                ajax_triggered = True
                for req in (logs.get('networkReqs', []) + logs.get('cdpNetworkReqs', [])):
                    ep = {'method': req.get('method', ''), 'url': req.get('url', '')}
                    if ep not in ajax_endpoints:
                        ajax_endpoints.append(ep)
            if logs.get('domChanges'):
                dom_change_on_input = True
            for fn in logs.get('triggeredFunctions', []):
                name = fn.get('functionName') or fn.get('name') or ''
                if name and name not in triggered_fn_names:
                    triggered_fn_names.append(name)

            # keyup
            self.driver.execute_script("window.__fa_setPhase('typing_keyup')")
            self.driver.execute_script("window.__fa_incrementStep()")
            self._clear_logs()
            self.driver.execute_script(
                "window.__fa_dispatchKeyEvent(arguments[0],'keyup',"
                "arguments[1],arguments[2],0)", xpath, char, char_code)
            time.sleep(delay)

        return {
            'ajax_triggered': ajax_triggered,
            'ajax_first_at_char_index': ajax_first_at_char_index,
            'ajax_endpoints': ajax_endpoints,
            'dom_change_on_input': dom_change_on_input,
            'triggered_fn_names': triggered_fn_names,
            'final_value': current_value,
        }

    def _analyze_field_legit(self, inp, test_value):
        """Per-field keystroke analysis: focus->type->backspace->blur->change.

        Returns a summary dict (not full raw log) with only research-relevant signals.
        """
        el = inp['el']
        field_name = inp['name'] or inp['placeholder'] or inp['type']
        print("[Legit]     field: %-20s value: %s" % (field_name[:20], test_value[:20]))

        try:
            xpath = self._get_xpath(el)
        except Exception as exc:
            logging.warning("[Legit] _get_xpath failed for %s: %s", field_name, exc)
            return {'name': field_name, 'type': inp['type'], 'error': 'xpath: %s' % exc}

        signals = {
            'listener_events': [],
            'triggered_function_names': [],
            'ajax_triggered': False,
            'ajax_first_at_char_index': None,
            'ajax_endpoints': [],
            'dom_change_on_input': False,
            'dom_change_on_blur': False,
            'html5_validation': False,
            'blur_triggers_network': False,
        }

        try:
            self.driver.execute_script(
                "window.__fa_instrumentOnHandlers(arguments[0])", xpath)
        except Exception:
            pass

        # Focus phase
        self.driver.execute_script("window.__fa_setPhase('focus')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script("window.__fa_dispatchFocus(arguments[0])", xpath)
        time.sleep(0.05)
        focus_logs = self._collect_logs_legit()
        for ev in focus_logs.get('firedEvents', []):
            evt = ev.get('type') or ev.get('eventType') or ''
            if evt and evt not in signals['listener_events']:
                signals['listener_events'].append(evt)
        for fn in focus_logs.get('triggeredFunctions', []):
            name = fn.get('functionName') or fn.get('name') or ''
            if name and name not in signals['triggered_function_names']:
                signals['triggered_function_names'].append(name)

        # Typing phase
        typing = self._type_chars_legit(xpath, test_value)
        signals['ajax_triggered'] = typing['ajax_triggered']
        signals['ajax_first_at_char_index'] = typing['ajax_first_at_char_index']
        signals['ajax_endpoints'] = typing['ajax_endpoints']
        signals['dom_change_on_input'] = typing['dom_change_on_input']
        for name in typing['triggered_fn_names']:
            if name not in signals['triggered_function_names']:
                signals['triggered_function_names'].append(name)
        current_value = typing['final_value']

        # Backspace phase
        delay = 0.05
        self.driver.execute_script("window.__fa_setPhase('backspace_keydown')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchBackspace(arguments[0],'keydown')", xpath)
        time.sleep(delay)

        self.driver.execute_script("window.__fa_setPhase('backspace_input')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        trimmed = current_value[:-1] if current_value else ''
        self.driver.execute_script(
            "window.__fa_updateValueAndInput(arguments[0],arguments[1])", xpath, trimmed)
        time.sleep(delay)

        self.driver.execute_script("window.__fa_setPhase('backspace_keyup')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchBackspace(arguments[0],'keyup')", xpath)
        time.sleep(delay)

        # Blur phase
        self.driver.execute_script("window.__fa_setPhase('blur')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script("window.__fa_dispatchBlur(arguments[0])", xpath)
        time.sleep(0.05)
        blur_logs = self._collect_logs_legit()
        if blur_logs.get('networkReqs') or blur_logs.get('cdpNetworkReqs'):
            signals['blur_triggers_network'] = True
        if blur_logs.get('domChanges'):
            signals['dom_change_on_blur'] = True
        if blur_logs.get('html5Validation'):
            signals['html5_validation'] = True
        for ev in blur_logs.get('firedEvents', []):
            evt = ev.get('type') or ev.get('eventType') or ''
            if evt and evt not in signals['listener_events']:
                signals['listener_events'].append(evt)
        for fn in blur_logs.get('triggeredFunctions', []):
            name = fn.get('functionName') or fn.get('name') or ''
            if name and name not in signals['triggered_function_names']:
                signals['triggered_function_names'].append(name)

        # Change phase
        self.driver.execute_script("window.__fa_setPhase('change')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script("window.__fa_dispatchChange(arguments[0])", xpath)
        time.sleep(0.05)
        change_logs = self._collect_logs_legit()
        if change_logs.get('networkReqs') or change_logs.get('cdpNetworkReqs'):
            signals['ajax_triggered'] = True
        if change_logs.get('html5Validation'):
            signals['html5_validation'] = True
        for fn in change_logs.get('triggeredFunctions', []):
            name = fn.get('functionName') or fn.get('name') or ''
            if name and name not in signals['triggered_function_names']:
                signals['triggered_function_names'].append(name)

        try:
            self.driver.execute_script(
                "window.__fa_restoreOnHandlers(arguments[0])", xpath)
        except Exception:
            pass

        classification = self._classify_field_legit(signals)
        print("[Legit]       -> %s" % classification)

        return {
            'name': field_name,
            'type': inp['type'],
            'test_value': test_value,
            'listener_events': signals['listener_events'],
            'triggered_function_names': signals['triggered_function_names'],
            'validation': {
                'ajax_triggered': signals['ajax_triggered'],
                'ajax_first_at_char_index': signals['ajax_first_at_char_index'],
                'ajax_endpoints': signals['ajax_endpoints'],
                'dom_change_on_input': signals['dom_change_on_input'],
                'dom_change_on_blur': signals['dom_change_on_blur'],
                'html5_validation': signals['html5_validation'],
                'blur_triggers_network': signals['blur_triggers_network'],
            },
            'classification': classification,
        }

    def _classify_field_legit(self, signals):
        """Map collected signals to a classification string (mirrors FormAnalyzer logic)."""
        if signals['ajax_triggered']:
            return 'Case B: Server Round-trip (AJAX)'
        if signals['html5_validation']:
            if signals['dom_change_on_input'] or signals['triggered_function_names']:
                return 'Mixed: HTML5 + Client-side JS'
            return 'Case C: HTML5 Validation'
        if signals['dom_change_on_input'] or signals['dom_change_on_blur']:
            return 'Case A: Pure Client-side JS'
        if signals['triggered_function_names']:
            return 'Case A: Pure Client-side JS (triggered functions detected)'
        if signals['listener_events']:
            return 'Case A: Pure Client-side JS (event handlers only)'
        return 'None: No validation detected'

    # ------------------------------------------------------------------ #
    #  Post-submit analysis
    # ------------------------------------------------------------------ #

    def _detect_post_submit(self, cdp_reqs):
        """Analyse CDP requests captured during Phase A for redirect/cookie/challenge signals."""
        redirect_chain = []
        cookies_set = []
        challenge = 'none'
        response_status = None

        for r in cdp_reqs:
            status = r.get('status')
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
                elif 'captcha' in body.lower():
                    challenge = 'captcha'
                elif 'otp' in body.lower() or '2fa' in body.lower():
                    challenge = 'mfa_otp'

            if response_status is None and status:
                response_status = status

        try:
            post_url = self.driver.current_url
        except Exception:
            post_url = ''

        return {
            'redirect_chain': redirect_chain,
            'cookies_set': cookies_set,
            'challenge_type': challenge,
            'session_established': any(c.get('httponly') for c in cookies_set),
            'post_url': post_url,
            'response_status': response_status,
        }

    def _parse_set_cookie(self, header_value):
        """Parse a Set-Cookie header string into an attribute dict."""
        if not header_value:
            return None
        parts = [p.strip() for p in header_value.split(';')]
        if not parts:
            return None
        name_val = parts[0].split('=', 1)
        result = {'name': name_val[0].strip(), 'httponly': False, 'secure': False}
        for part in parts[1:]:
            part_l = part.lower()
            if part_l == 'httponly':
                result['httponly'] = True
            elif part_l == 'secure':
                result['secure'] = True
            elif part_l.startswith('samesite='):
                result['samesite'] = part.split('=', 1)[1].strip()
            elif part_l.startswith('path='):
                result['path'] = part.split('=', 1)[1].strip()
            elif part_l.startswith('domain='):
                result['domain'] = part.split('=', 1)[1].strip()
        return result

    # ------------------------------------------------------------------ #
    #  CDP helpers
    # ------------------------------------------------------------------ #

    def _summarize_cdp(self, cdp_reqs):
        out = []
        for r in cdp_reqs:
            out.append({
                'url':              r.get('url', ''),
                'method':           r.get('method', ''),
                'status':           r.get('status'),
                'protocol':         r.get('protocol', ''),
                'contentType':      r.get('requestContentType', ''),
                'requestHeaders':   r.get('requestHeaders', {}),
                'responseHeaders':  r.get('responseHeaders', {}),
                'requestBody':      (r.get('postData') or '')[:500],
                'hasSetCookie':     r.get('hasSetCookie', False),
                'hasCookieHeader':  r.get('hasCookieHeader', False),
                'customRequestHeaders': r.get('customRequestHeaders', {}),
                'redirected':       r.get('redirected', False),
                'redirectChain':    r.get('redirectChain', []),
                'redirectLocation': r.get('redirectLocation', ''),
                'latencyMs':        r.get('latencyMs'),
                'ttfbMs':           r.get('ttfbMs'),
                'initiatorType':    r.get('initiatorType', ''),
                'resourceType':     r.get('resourceType', ''),
            })
        return out

    def _find_submit_req(self, cdp_reqs, action_url):
        if not cdp_reqs:
            return None
        action_host = urlparse(action_url).netloc if action_url else ''

        for r in cdp_reqs:
            if r.get('method') in ('POST', 'PUT', 'PATCH'):
                if not action_host or urlparse(r.get('url', '')).netloc == action_host:
                    return r
        for r in cdp_reqs:
            if r.get('method') in ('POST', 'PUT', 'PATCH'):
                return r
        return cdp_reqs[0] if cdp_reqs else None

    # ------------------------------------------------------------------ #
    #  Output
    # ------------------------------------------------------------------ #

    def _save(self):
        domain = urlparse(self.url).netloc.replace('.', '_').replace(':', '_')
        ts = time.strftime('%Y%m%d_%H%M%S')
        path = os.path.join(self.output_dir, 'legit_%s_%s.json' % (domain, ts))
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(self.results, fh, indent=2, ensure_ascii=False)
        print("\n[Legit] Results saved -> %s" % path)

    def _print_report(self):
        SEP = '=' * 72
        print('\n' + SEP)
        print('LEGIT ANALYZER -- HEADER CAPTURE REPORT')
        print('URL: %s' % self.url)
        print(SEP)

        if self.results.get('errors'):
            print('\n[Errors during run]')
            for e in self.results['errors']:
                print('  ! %s' % e)

        pl_reqs = self.results.get('page_load', {}).get('requests', [])
        print('\n[Page Load] %d request(s)' % len(pl_reqs))
        for r in pl_reqs[:5]:
            print('  %s %-60s -> %s%s' % (
                r['method'], r['url'][:60], r['status'],
                '  *Set-Cookie' if r['hasSetCookie'] else ''))
        if len(pl_reqs) > 5:
            print('  ... (+%d more)' % (len(pl_reqs) - 5))

        for form_res in self.results.get('forms', []):
            print('\n' + '-' * 72)
            print('[Input group %d]  action=%-38s  method=%s' % (
                form_res['form_index'], form_res['action'][:38], form_res['method']))
            print('  Fields   : %s' % ', '.join(form_res.get('fields', [])))
            print('  Has <form>: %s' % form_res.get('has_form_tag'))
            print('  Login?   : %s' % form_res.get('is_login'))
            print('  Submit?  : %s' % form_res.get('submission_method_classification', ''))

            fa_list = form_res.get('field_analysis', [])
            if fa_list:
                print('\n  [Pre-submit Field Analysis]')
                for fa in fa_list:
                    if fa.get('error'):
                        print('    %-20s  ERROR: %s' % (fa['name'][:20], fa['error']))
                        continue
                    v = fa.get('validation', {})
                    print('    %-20s  [%s]  %s' % (
                        fa['name'][:20], fa['type'][:8], fa['classification']))
                    if fa.get('listener_events'):
                        print('      listeners   : %s' % ', '.join(fa['listener_events']))
                    if fa.get('triggered_function_names'):
                        print('      JS functions: %s' % ', '.join(
                            fa['triggered_function_names'][:5]))
                    if v.get('ajax_triggered'):
                        idx_c = v.get('ajax_first_at_char_index')
                        print('      AJAX at char: %s' % (
                            str(idx_c) if idx_c is not None else '?'))
                        for ep in v.get('ajax_endpoints', [])[:3]:
                            print('      endpoint    : %s %s' % (ep['method'], ep['url'][:60]))

            ps = form_res.get('post_submit', {})
            if ps:
                print('\n  [Post-submit]')
                print('    challenge_type    : %s' % ps.get('challenge_type', '?'))
                print('    session_established: %s' % ps.get('session_established', False))
                print('    response_status   : %s' % ps.get('response_status', '?'))
                print('    post_url          : %s' % (ps.get('post_url') or '')[:70])
                for hop in ps.get('redirect_chain', []):
                    print('    redirect          : %s -> %s' % (
                        hop.get('status', '?'), hop.get('location', '')[:60]))
                for c in ps.get('cookies_set', []):
                    print('    cookie            : %-20s  httponly=%s secure=%s' % (
                        c.get('name', '?')[:20], c.get('httponly'), c.get('secure')))

            # Fill diagnostics
            a_fills = form_res.get('phase_a_native', {}).get('fill_results', [])
            if a_fills:
                print('\n  [Fill diagnostics (Phase A)]')
                for f in a_fills:
                    ok = 'OK' if f.get('success') else 'FAIL'
                    print('    %s %-20s -> %-20s via %s' % (
                        ok, f['field'][:20], f['actual_value'][:20], f['method']))

            a = form_res.get('phase_a_native', {})
            print('\n  [Phase A -- CDP ground truth]')
            if a.get('error'):
                print('    ERROR: %s' % a['error'])
            print('    Method/URL    : %s %s' % (a.get('method', ''), a.get('action_url', '')))
            print('    Status        : %s  Protocol: %s' % (a.get('status', ''), a.get('protocol', '')))
            print('    Content-Type  : %s' % a.get('content_type', ''))
            print('    Cookie sent?  : %s   Set-Cookie? %s' % (
                a.get('has_cookie_header', False), a.get('has_set_cookie', False)))
            print('    Latency       : %s ms' % a.get('latency_ms', '?'))
            for hop in (a.get('redirect_chain') or []):
                print('    Redirect      : %s -> %s' % (hop.get('status', '?'), hop.get('location', '')))
            lss = a.get('login_success_signals', {})
            if lss:
                print('    Login likely? : %s' % lss.get('likely_success', False))

            print('\n    Request headers (CDP):')
            for k, v in sorted(a.get('request_headers_cdp', {}).items()):
                print('      %-34s %s' % (k + ':', _mask(k, str(v))[:80]))

            print('\n    Response headers (CDP):')
            for k, v in sorted(a.get('response_headers_cdp', {}).items()):
                print('      %-34s %s' % (k + ':', _mask(k, str(v))[:80]))

            b = form_res.get('phase_b_xhr', {})
            print('\n  [Phase B -- JS-visible only]')
            if b.get('error'):
                print('    Note: %s' % b['error'])
            print('    Method/Status : %s  %s' % (b.get('method', ''), b.get('status', '')))
            print('\n    Request headers JS could set:')
            for k, v in sorted(b.get('request_headers_js', {}).items()):
                print('      %-34s %s' % (k + ':', str(v)[:80]))

            cmp = form_res.get('header_comparison', {})
            counts = cmp.get('counts', {})
            print('\n  [Header Comparison: CDP vs JS]')
            print('    CDP: %d  JS: %d  Shared: %d  Hidden from JS: %d' % (
                counts.get('cdp_total', 0), counts.get('js_total', 0),
                counts.get('shared', 0), counts.get('hidden_from_js', 0)))

            hidden = cmp.get('hidden_auth_headers', {})
            if hidden:
                print('\n    *** Forbidden headers (server sees, JS cannot): ***')
                for k, v in sorted(hidden.items()):
                    print('      %-34s %s' % (k + ':', _mask(k, str(v))[:80]))

            other = cmp.get('other_browser_only_headers', {})
            if other:
                print('\n    Browser-generated (non-forbidden):')
                for k, v in sorted(other.items()):
                    print('      %-34s %s' % (k + ':', str(v)[:80]))

        print('\n' + SEP)


def _mask(header_name, value):
    if header_name.lower() in ('cookie', 'authorization', 'set-cookie') \
            and len(value) > 10:
        return value[:6] + '...' + value[-4:]
    return value
