# FormAnalyzer.py
# Dynamic form behavior analysis: traces JS function calls, DOM changes,
# network requests, and HTML5 validation per keystroke to classify
# whether validation logic is client-side JS, server-side AJAX, or HTML5.

import json
import csv
import time
import random
import string
import logging
import os
import re
import hashlib
import traceback
from urllib.parse import urlparse, quote, urlunparse

try:
    from static_analyzer import StaticCodeAnalyzer, DynamicResolver
except ImportError:
    StaticCodeAnalyzer = None
    DynamicResolver = None

from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    StaleElementReferenceException,
    WebDriverException,
    NoAlertPresentException,
    UnexpectedAlertPresentException,
    TimeoutException,
)

# BlackWidow core (Graph, edge types, extractors, navigation)
from Classes import Graph, Request, CrawlEdge
from extractors.Urls import extract_urls
from extractors.Forms import extract_forms
from extractors.Events import extract_events
from extractors.Iframes import extract_iframes
from extractors.Ui_forms import extract_ui_forms
from Functions import (
    follow_edge, allow_edge, check_edge, remove_alerts, linkrank,
    drain_cdp_network_logs, reset_cdp_network_monitoring,
)


class FormAnalyzer:
    """Orchestrates per-field, per-keystroke form behavior analysis."""

    # Input types that accept text and are worth analysing
    ANALYSABLE_TYPES = {
        'text', 'email', 'password', 'number', 'tel', 'url', 'search',
        'textarea',
    }

    # Interactive field types that can also be analysed (click-based)
    INTERACTIVE_TYPES = {
        'select', 'checkbox', 'radio',
    }

    # File extensions considered web-accessible for whitebox scanning
    WEB_EXTENSIONS = {'.php', '.html', '.htm', '.phtml', '.shtml', '.asp', '.aspx', '.jsp'}

    # Directories to skip during kit scanning
    SKIP_DIRS = {
        '__pycache__', '.git', '.svn', 'node_modules', 'vendor',
        '.idea', '.vscode', '.cursor',
    }

    # Directories that contain backend/processing files, not user-facing
    # form pages. Files inside these are skipped during whitebox seeding.
    BACKEND_DIRS = {
        'xbalti', 'send', 'antibots', 'antbots', 'antbot', 'antibotes',
        'panel', 'cpanel', 'log', 'logs', 'data', 'tmp',
        'includes', 'include', 'inc', 'lib', 'config', 'cfg',
        '__macosx', 'wp-content', 'wp-includes', 'wp-admin',
        'node_modules', 'vendor', 'bower_components', 'bots', 'bot',
    }

    # File name patterns that are backend processing, not form pages.
    BACKEND_FILES = {
        'antibots.php', 'antibots.html', 'antibot.php',
        'email.php', 'mail.php', 'mailer.php',
        'robots.txt', '.htaccess', 'error_log',
    }

    # Prefixes of backend file names (send_login.php, get_ip.php, etc.)
    BACKEND_FILE_PREFIXES = (
        'send_', 'get_', 'check_', 'recv_', 'save_',
    )

    # Cap whitebox seed URLs to prevent huge cloned kits from exploding
    # the graph (e.g. thousands of duplicated HTML/PHP copies).
    MAX_SEED_URLS = 150
    # Cap event edges added per page to prevent edge explosion on
    # utility-heavy templates (search/admin pages with many click hooks).
    MAX_EVENT_EDGES_NOFORM = 8
    MAX_EVENT_EDGES_WITH_FORM = 30

    def __init__(self, driver, url, delay=30, network_only=False,
                 kit_path=None, hash_db=None, max_pages=0):
        self.driver = driver
        self.url = url
        self.delay = delay  # seconds between each sub-event
        self.network_only = network_only
        self.network_wait = 0.5 if network_only else delay
        self.kit_path = kit_path  # whitebox: local phishing kit directory
        self.hash_db = None if network_only else hash_db

        self.results = {
            'url': url,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'mode': 'whitebox' if kit_path else 'blackbox',
            'kit_path': kit_path or '',
            'pages': [],           # per-page results with forms
            'forms': [],           # flat list of all form results
            'visited_urls': [],    # all visited URLs (for debugging)
            'cdp_network': [],     # flattened CDP-backed request/response traces
        }
        self.session_ts = str(time.time())
        self._cdp_network_index = {}

        # Ensure output directory exists.
        # --network-only runs get their own subdirectory so results don't mix.
        _subdir = 'analysis_results_network' if network_only else 'analysis_results'
        _repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.output_dir = os.path.join(_repo_root, 'results', 'dynamic_analysis_blackwidow', _subdir)
        os.makedirs(self.output_dir, exist_ok=True)

        # ---- Graph-based crawl state (mirrors Crawler in Classes.py) ----
        self.graph = Graph()
        self._root_req = Request("ROOTREQ", "get")
        self.graph.add(self._root_req)
        self.graph.data['urls'] = {}
        self.graph.data['form_urls'] = {}

        # Track which pages we already analysed forms on (avoid re-analysis)
        self._analysed_pages = set()
        # Track analysed form signatures to skip duplicate rendered forms.
        self._analysed_form_sigs = set()
        self._skipped_dup_forms = 0

        # Scope: only follow URLs under the kit's URL prefix to avoid
        # crawling into http://localhost/ or other unrelated pages.
        # e.g. "http://localhost/kits/2021-08-22_FR/FR/" -> prefix is
        # "http://localhost/kits/2021-08-22_FR/"
        self._url_scope = self._compute_url_scope(url)

        # Crawl counters
        self._early_gets = 0
        self._max_early_gets = 100
        self._page_count = 0
        self._loop_iterations = 0
        self._max_loop_iterations = 500  # hard cap to prevent infinite loops
        self._pages_since_last_form = 0
        self._max_pages_without_form = 40  # stop crawling if no forms after N pages
        if max_pages and max_pages > 0:
            self._max_loop_iterations = max_pages
            self._max_pages_without_form = min(40, max_pages)
            self.MAX_SEED_URLS = min(self.MAX_SEED_URLS, max_pages)

        # ---- Static code analysis (whitebox only) ----
        self._code_map = None
        self._resolver = None

        # ---- Hash DB for noise filtering ----
        self._default_hashes = set()
        if self.network_only:
            logging.info("Network-only mode: skipping hash DB load")
        elif self.hash_db and os.path.isdir(self.hash_db):
            self._load_hash_db(self.hash_db)

        logging.info("FormAnalyzer init on %s (delay=%ds, network_only=%s, kit_path=%s)",
                     url, delay, network_only, kit_path)

    # ==================================================================
    # Main entry point
    # ==================================================================

    def start(self):
        print("=" * 60)
        if self.kit_path:
            print("[FormAnalyzer] WHITEBOX mode -- kit: %s" % self.kit_path)
        print("[FormAnalyzer] Starting graph-based crawl from: %s" % self.url)
        if self.network_only:
            print("[FormAnalyzer] Fast network-only mode enabled "
                  "(skip per-field typing and validation waits)")
        cdp_reset_ok = reset_cdp_network_monitoring(self.driver)
        self.results['cdp_monitoring'] = {
            'enabled': bool(cdp_reset_ok),
            'degraded': not bool(cdp_reset_ok),
            'note': ('performance log reset timed out or was disabled; '
                     'CDP-backed network capture may be incomplete')
                    if not cdp_reset_ok else 'ok',
        }
        if not cdp_reset_ok:
            print("[FormAnalyzer] WARNING: performance log reset timed out; "
                  "continuing in degraded mode without reliable CDP drain")
        print("=" * 60)

        driver = self.driver
        graph = self.graph

        # ---- Whitebox: static code analysis ----
        if self.kit_path and StaticCodeAnalyzer:
            print("[StaticAnalysis] Scanning kit source code...")
            sa = StaticCodeAnalyzer(self.kit_path)
            self._code_map = sa.build()
            self._resolver = DynamicResolver(self._code_map)
            n_funcs = len(self._code_map.get('function_index', {}))
            n_php = len(self._code_map.get('php_files', {}))
            n_flows = len(self._code_map.get('data_flow', []))
            print("[StaticAnalysis] Found %d JS functions, %d PHP files, "
                  "%d data flow chains" % (n_funcs, n_php, n_flows))
            self.results['static_analysis'] = {
                'function_count': n_funcs,
                'php_file_count': n_php,
                'data_flow_count': n_flows,
                'data_flows': self._code_map.get('data_flow', []),
                'php_files': {
                    k: {
                        'receives_post': v.get('receives_post', []),
                        'actions': v.get('actions', []),
                        'exfil': v.get('exfil', []),
                    }
                    for k, v in self._code_map.get('php_files', {}).items()
                },
            }
        elif self.kit_path and not StaticCodeAnalyzer:
            print("[StaticAnalysis] static_analyzer.py not found -- "
                  "skipping static analysis")

        # ---- Whitebox: seed graph with file URLs from kit directory ----
        if self.kit_path:
            kit_urls = self._scan_kit_directory()
            n_added = 0
            for file_url in kit_urls:
                req = Request(file_url, "get")
                if graph.add(req):
                    graph.connect(self._root_req, req,
                                  CrawlEdge("get", None, None))
                    n_added += 1
            print("[Whitebox] Scanned kit directory: %d file(s) -> %d new URL(s) seeded"
                  % (len(kit_urls), n_added))
            # In whitebox mode, don't add the bare --url separately if it's
            # a directory URL (ends with /) -- the kit scan already added
            # the actual index file, so visiting the directory would be a
            # duplicate.  If the --url is a specific file, add it normally.
            if not self.url.rstrip('/').split('/')[-1].count('.'):
                # URL looks like a directory (no file extension in last segment)
                print("[Whitebox] Skipping directory URL seed (files already added)")
            else:
                start_req = Request(self.url, "get")
                graph.add(start_req)
                graph.connect(self._root_req, start_req,
                              CrawlEdge("get", None, None))
        else:
            # Blackbox mode: seed with start URL only
            start_req = Request(self.url, "get")
            graph.add(start_req)
            graph.connect(self._root_req, start_req,
                          CrawlEdge("get", None, None))

        # ---- Main crawl loop (mirrors Crawler.start + rec_crawl) ----
        still_work = True
        while still_work:
            self._loop_iterations += 1
            if self._loop_iterations > self._max_loop_iterations:
                print("[Crawl] Hit max loop iterations (%d) -- stopping."
                      % self._max_loop_iterations)
                break

            n_unvisited = sum(1 for e in graph.edges if not e.visited)
            print("\n" + "-" * 50)
            print("[Crawl] Edges left: %d" % n_unvisited)

            try:
                still_work = self._crawl_step()
            except KeyboardInterrupt:
                print("\n[FormAnalyzer] CTRL-C, stopping crawl.")
                break
            except Exception as e:
                logging.error("Crawl step error: %s\n%s", e,
                              traceback.format_exc())
                still_work = any(not ed.visited for ed in graph.edges)

        # ---- Static fallback: when dynamic analysis found 0 forms ----
        if not self.results['forms'] and self._code_map:
            flows = self._code_map.get('data_flow', [])
            if flows:
                print("[FormAnalyzer] Dynamic analysis found 0 forms -- "
                      "including %d static data flow(s) as fallback" % len(flows))
                self.results['static_fallback'] = True
                self.results['static_fallback_reason'] = (
                    'Dynamic crawl visited %d page(s) but found 0 forms. '
                    'Likely cause: server-side bot detection (AntiBOT/fsockopen) '
                    'or flow-gated pages (missing required query params). '
                    'Static analysis data flows are included as reference.'
                    % self._page_count
                )

        if self._skipped_dup_forms > 0:
            print("[FormAnalyzer] Skipped %d duplicate form(s) (same signature)."
                  % self._skipped_dup_forms)
            self.results['skipped_duplicate_forms'] = self._skipped_dup_forms

        # ---- Output ----
        self._output_json()

        print("\n" + "=" * 60)
        print("[FormAnalyzer] Done. Visited %d page(s), analysed %d form(s)."
              % (self._page_count, len(self.results['forms'])))
        print("[FormAnalyzer] Results saved.")

    # ==================================================================
    # URL scope helpers
    # ==================================================================

    @staticmethod
    def _compute_url_scope(start_url):
        """Compute a URL prefix that all crawled URLs must start with.

        For whitebox kits, the start URL is something like:
            http://localhost/kits/2021-08-22_FR/FR/
        We strip the last path component (entry page) and keep the
        kit's top-level directory as the scope.
        """
        from urllib.parse import urlparse
        parsed = urlparse(start_url)
        path = parsed.path.rstrip('/')
        # Keep at least the first two path segments
        # e.g. /kits/2021-08-22_FR/FR -> /kits/2021-08-22_FR
        parts = path.split('/')
        if len(parts) > 2:
            scope_path = '/'.join(parts[:-1]) + '/'
        else:
            scope_path = path + '/'
        scope = '%s://%s%s' % (parsed.scheme, parsed.netloc, scope_path)
        return scope

    def _is_in_scope(self, url):
        """Check if a URL is within the kit's URL scope."""
        if not url or not self._url_scope:
            return True
        return url.startswith(self._url_scope)

    @staticmethod
    def _normalize_page_url(url):
        """Normalize a URL to path-only for deduplication.

        Strips fragment (#...) AND query string (?...) so that e.g.
        login.php, login.php?cngmail=user@x.com, and login.php#hash
        all map to the same canonical URL.  This prevents infinite
        loops when PHP kits redirect back with varying query params.
        """
        if not url:
            return url
        p = urlparse(url)
        path = p.path.rstrip('/') or '/'
        return '%s://%s%s' % (p.scheme, p.netloc, path)

    @staticmethod
    def _is_noise_event(event):
        """Filter obviously noisy/non-actionable events."""
        if not event:
            return True
        evt_name = str(getattr(event, 'event', '') or '').lower()
        evt_addr = str(getattr(event, 'addr', '') or '').lower()

        if evt_name in ('onerror', 'error'):
            return True
        # Browser error-page controls often produce synthetic click loops.
        if 'reload-button' in evt_addr:
            return True
        if 'chrome-error' in evt_addr or 'neterror' in evt_addr:
            return True
        return False

    # ==================================================================
    # One crawl iteration  (mirrors Crawler.rec_crawl)
    # ==================================================================

    def _crawl_step(self):
        """Visit one edge, extract new edges, analyse forms if present.

        Returns True if more work remains, False otherwise.
        """
        driver = self.driver
        graph = self.graph

        # 1. Pick the next edge to follow
        edge = self._next_unvisited_edge()
        if edge is None:
            print("[Crawl] No more edges to visit.")
            return False

        request = edge.n2.value
        graph.visit_node(request)
        graph.visit_edge(edge)
        self._page_count += 1

        current_url = request.url
        print("[Crawl %d] Following edge: %s" % (self._page_count, edge))

        # Log the visited URL (and actual landed URL) for debugging
        actual_url = driver.current_url
        self.results['visited_urls'].append({
            'step': self._page_count,
            'requested_url': current_url,
            'actual_url': actual_url,
            'method': edge.value.method,
        })

        # Optimisation: don't GET the same destination twice
        if edge.value.method == "get":
            for e in graph.edges:
                if (edge.n2 == e.n2) and (edge != e) and \
                   (e.value.method == "get"):
                    graph.visit_edge(e)

        # 2. Wait for async scripts (need_to_wait from lib.js)
        self._wait_for_async()

        # 3. Execute pending timeouts (from timing_wrapper.js)
        self._execute_timeouts()

        # 4. Extract everything from the current page
        try:
            reqs = extract_urls(driver)
        except Exception:
            reqs = set()
        try:
            forms = extract_forms(driver)
        except Exception:
            forms = set()
        try:
            events = extract_events(driver)
        except Exception:
            events = set()
        try:
            iframes = extract_iframes(driver)
        except Exception:
            iframes = set()
        try:
            ui_forms = extract_ui_forms(driver)
        except Exception:
            ui_forms = []

        n_before = len(graph.edges)
        cookies = driver.get_cookies()

        # 5. Add findings to the graph as new edges
        for req in reqs:
            # Normalise: strip URL fragment (#...) to avoid treating
            # "index.html" and "index.html#" as different pages
            clean_url = req.url.split('#')[0] if req.url else req.url
            # For GET requests, also strip query string so that e.g. login.php
            # and login.php?cngmail=user@example.com are treated as the same
            # page (avoids loops when kits redirect back with varying query params).
            if req.method == "get" and clean_url:
                p = urlparse(clean_url)
                path_only = p.path.rstrip('/') or '/'
                clean_url = f"{p.scheme}://{p.netloc}{path_only}"
            if clean_url != req.url:
                req = Request(clean_url, req.method)
            # Skip self-referencing links (href="#")
            current_clean = request.url.split('#')[0].rstrip('/')
            if req.method == "get":
                p_cur = urlparse(current_clean)
                p_dest = urlparse(clean_url)
                current_path = (p_cur.path or '/').rstrip('/') or '/'
                dest_path = (p_dest.path or '/').rstrip('/') or '/'
                if clean_url and current_path == dest_path and p_cur.netloc == p_dest.netloc:
                    continue
            elif clean_url and clean_url.rstrip('/') == current_clean:
                continue
            # Scope check: skip URLs outside the kit's directory
            if not self._is_in_scope(clean_url):
                continue
            new_edge = graph.create_edge(
                request, req, CrawlEdge(req.method, None, cookies), edge)
            if allow_edge(graph, new_edge):
                graph.add(req)
                graph.connect(request, req,
                              CrawlEdge(req.method, None, cookies), edge)

        # Optimise event edge generation for analyse mode.
        # Pages WITH forms: keep ALL event edges (any interaction may
        #   trigger validation or reveal hidden form steps).
        # Pages WITHOUT forms: keep only 'click' events -- clicks are
        #   the most likely to reveal hidden modals/forms (e.g. XBALTIV3
        #   admin/index.php shows its login form after a touchstart/click).
        #   Suppress non-click events (touchstart, keydown, keyup, etc.)
        #   on formless pages to avoid edge explosion (e.g. NewOreo's 37
        #   utility PHP files each generating reload-button events).
        page_has_forms = bool(forms) or self._count_visible_forms() > 0
        event_budget = (self.MAX_EVENT_EDGES_WITH_FORM
                        if page_has_forms else self.MAX_EVENT_EDGES_NOFORM)
        event_added = 0
        for event in events:
            if self._is_noise_event(event):
                continue
            if not page_has_forms:
                # On formless pages, only keep click-like events that
                # could plausibly reveal a hidden form or modal.
                evt_name = getattr(event, 'event', '') if event else ''
                if 'click' not in str(evt_name).lower() \
                        and 'touch' not in str(evt_name).lower():
                    continue
            if event_added >= event_budget:
                break
            req2 = Request(request.url, "event")
            new_edge = graph.create_edge(
                request, req2, CrawlEdge("event", event, cookies), edge)
            if allow_edge(graph, new_edge):
                graph.add(req2)
                graph.connect(request, req2,
                              CrawlEdge("event", event, cookies), edge)
                event_added += 1

        for iframe in iframes:
            req3 = Request(iframe.src, "iframe")
            new_edge = graph.create_edge(
                request, req3, CrawlEdge("iframe", iframe, cookies), edge)
            if allow_edge(graph, new_edge):
                graph.add(req3)
                graph.connect(request, req3,
                              CrawlEdge("iframe", iframe, cookies), edge)

        for ui_form in ui_forms:
            req4 = Request(driver.current_url, "ui_form")
            new_edge = graph.create_edge(
                request, req4, CrawlEdge("ui_form", ui_form, cookies), edge)
            if allow_edge(graph, new_edge):
                graph.add(req4)
                graph.connect(request, req4,
                              CrawlEdge("ui_form", ui_form, cookies), edge)

        # NOTE: We intentionally do NOT add "form" edges here.
        # BlackWidow adds form edges to submit forms for page discovery,
        # but in analyze mode we inspect forms in-place instead.

        n_new = len(graph.edges) - n_before
        print("[Crawl %d] +%d new edge(s) (total %d)"
              % (self._page_count, n_new, len(graph.edges)))

        remove_alerts(driver)

        # Early-abort: if we've visited many pages without finding any
        # forms, the kit is likely blocking us (AntiBOT) or requires
        # a specific entry flow we can't satisfy automatically.
        self._pages_since_last_form += 1
        if (self._pages_since_last_form > self._max_pages_without_form
                and not self.results['forms']):
            print("[Crawl] Visited %d page(s) without finding any forms -- "
                  "aborting crawl (possible AntiBOT or flow-gated kit)"
                  % self._pages_since_last_form)
            return False

        # 6. If this page has forms, analyse them
        page_url = driver.current_url
        page_url_normalised = self._normalize_page_url(page_url)
        if page_url_normalised not in self._analysed_pages:
            form_count = self._count_visible_forms()
            if form_count > 0:
                print("[Crawl %d] Found %d form(s) -- starting analysis"
                      % (self._page_count, form_count))
                self._analyse_forms_on_page(page_url, form_count)
                self._analysed_pages.add(page_url_normalised)
                self._pages_since_last_form = 0

        # 6b. After a click event, wait for DOM to settle and re-scan
        #     for forms that may have been revealed (e.g. hidden modals
        #     or overlays toggled by a button like #login-button).
        is_click_event = (
            edge.value.method == "event"
            and hasattr(edge.value, 'method_data')
            and edge.value.method_data is not None
            and "click" in str(getattr(edge.value.method_data, 'event', '')).lower()
        )
        if is_click_event:
            time.sleep(1.0)
            new_visible = self._count_visible_forms()
            if new_visible > 0 and page_url_normalised not in self._analysed_pages:
                print("[Crawl %d] After click: found %d visible form(s) -- starting analysis"
                      % (self._page_count, new_visible))
                self._analyse_forms_on_page(page_url, new_visible)
                self._analysed_pages.add(page_url_normalised)
                self._pages_since_last_form = 0

        return True

    # ==================================================================
    # Edge priority selection  (mirrors Crawler.next_unvisited_edge)
    # ==================================================================

    def _next_unvisited_edge(self):
        """Pick the next unvisited edge to follow, using BlackWidow-style
        priority: iframe > early GETs > random(form/get/event) > fallback.
        """
        driver = self.driver
        graph = self.graph

        # Priority 1: iframes (always first)
        candidates = [e for e in graph.edges
                      if e.value.method == "iframe" and not e.visited]
        if candidates:
            return self._try_follow(candidates)

        # Priority 2: early GET exploration
        if self._early_gets < self._max_early_gets:
            candidates = [e for e in graph.edges
                          if e.value.method == "get" and not e.visited]
            candidates = linkrank(candidates, graph.data['urls'])
            if candidates:
                self._early_gets += 1
                return self._try_follow(candidates)

        # Priority 3: random mix of get / event
        rand = random.randint(0, 100)
        if rand < 60:
            candidates = [e for e in graph.edges
                          if e.value.method == "get" and not e.visited]
            candidates = linkrank(candidates, graph.data['urls'])
        elif rand < 90:
            candidates = [e for e in graph.edges
                          if e.value.method == "event"
                          and "click" in e.value.method_data.event
                          and not e.visited]
            if not candidates:
                candidates = [e for e in graph.edges
                              if e.value.method == "event" and not e.visited]
        else:
            candidates = [e for e in graph.edges
                          if e.value.method == "ui_form" and not e.visited]

        if candidates:
            return self._try_follow(candidates)

        # Priority 4: GET fallback
        candidates = [e for e in graph.edges
                      if e.value.method == "get" and not e.visited]
        candidates = linkrank(candidates, graph.data['urls'])
        if candidates:
            return self._try_follow(candidates)

        # Priority 5: any unvisited edge
        candidates = [e for e in graph.edges if not e.visited]
        if candidates:
            return self._try_follow(candidates)

        return None

    def _try_follow(self, candidates):
        """Try to follow edges in order; return the first successful one."""
        graph = self.graph
        driver = self.driver

        for edge in candidates:
            if edge.visited:
                continue
            if not check_edge(driver, graph, edge):
                logging.info("check_edge rejected: %s", edge)
                edge.visited = True
                continue

            graph.data['prev_edge'] = edge
            try:
                successful = follow_edge(driver, graph, edge)
            except Exception as e:
                # If follow_edge throws (e.g. find_state -> execute_event
                # fails on AntiBOT pages), mark edge as visited so we don't
                # retry the same broken edge indefinitely.
                logging.warning("follow_edge exception, marking visited: %s -- %s",
                                edge, e)
                edge.visited = True
                continue
            if successful:
                return edge
            # follow_edge marks edge as visited on failure

        return None

    # ==================================================================
    # Analyse all forms on the current page
    # ==================================================================

    def _count_visible_forms(self):
        """Count forms on the current page, preferring only visible ones."""
        try:
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            visible = []
            for f in forms:
                try:
                    if f.is_displayed():
                        visible.append(f)
                except Exception:
                    visible.append(f)
            return len(visible) if visible else len(forms)
        except Exception:
            return 0

    def _analyse_forms_on_page(self, page_url, form_count):
        """Reload the page per form to avoid stale refs, then analyse."""
        page_result = {
            'page_url': page_url,
            'forms': [],
        }

        for idx in range(form_count):
            print("-" * 50)
            print("[FormAnalyzer] Analysing form %d/%d on %s"
                  % (idx + 1, form_count, page_url))
            try:
                try:
                    self.driver.get(page_url)
                except TimeoutException:
                    print("[FormAnalyzer]   Page load timeout -- using partial DOM")
                time.sleep(3)
                self._dismiss_alert()

                # After reload, the page may have redirected (e.g.
                # pass.php?cngmail=true -> login.php?cngmail=xx).
                # Check if the *actual* landed page was already analysed.
                actual_url = self.driver.current_url
                actual_normalised = self._normalize_page_url(actual_url)
                if actual_normalised in self._analysed_pages:
                    print("[FormAnalyzer]   Skipping -- redirected to "
                          "already-analysed page: %s" % actual_normalised)
                    continue
                # Also mark the redirected URL to prevent future re-analysis
                self._analysed_pages.add(actual_normalised)

                form_elements = self.driver.find_elements(
                    By.TAG_NAME, "form")
                if idx >= len(form_elements):
                    logging.warning(
                        "Form index %d out of range after reload", idx)
                    continue

                form_el = form_elements[idx]
                form_xpath = self._get_xpath(form_el)

                # Form-level dedup: same structure across cloned directories.
                form_sig = self._compute_form_signature(form_el)
                if form_sig and form_sig in self._analysed_form_sigs:
                    self._skipped_dup_forms += 1
                    print("[FormAnalyzer]   Skipping duplicate form "
                          "(signature already analysed, dup #%d)"
                          % self._skipped_dup_forms)
                    continue
                if form_sig:
                    self._analysed_form_sigs.add(form_sig)

                # Start instrumentation scoped to this specific form
                self.driver.execute_script(
                    "window.__fa_start(arguments[0])", form_xpath)

                form_result = self._analyze_form(form_el, page_url=page_url)
                form_result['page_url'] = page_url
                page_result['forms'].append(form_result)
                self.results['forms'].append(form_result)
            except StaleElementReferenceException:
                logging.warning("Form %d went stale, skipping", idx)
            except Exception as e:
                logging.error("Error analysing form %d: %s", idx, e)

        try:
            self.driver.execute_script("window.__fa_stop()")
        except Exception:
            pass

        self.results['pages'].append(page_result)

    def _compute_form_signature(self, form_el):
        """Compute a signature for form-level deduplication."""
        try:
            action = form_el.get_attribute('action') or ''
            action_base = action.rstrip('/').rsplit('/', 1)[-1] if action else ''
            fields = form_el.find_elements(By.CSS_SELECTOR, 'input, select, textarea')
            names = []
            types = []
            for f in fields:
                ftype = (f.get_attribute('type') or f.tag_name).lower()
                if ftype in ('hidden', 'submit', 'image', 'button'):
                    continue
                names.append(f.get_attribute('name') or '')
                types.append(ftype)
            return (action_base, tuple(sorted(names)), tuple(sorted(types)))
        except Exception:
            return None

    # ==================================================================
    # Async / timeout helpers (from lib.js / timing_wrapper.js)
    # ==================================================================

    def _wait_for_async(self):
        """Wait if lib.js flagged an outstanding XHR."""
        try:
            raw = self.driver.execute_script(
                "return JSON.stringify(need_to_wait)")
            if json.loads(raw):
                time.sleep(1)
        except UnexpectedAlertPresentException:
            self._dismiss_alert()
            try:
                raw = self.driver.execute_script(
                    "return JSON.stringify(need_to_wait)")
                if json.loads(raw):
                    time.sleep(1)
            except Exception:
                pass
        except Exception:
            pass

    def _execute_timeouts(self):
        """Execute pending JS timeouts collected by timing_wrapper.js."""
        try:
            raw = self.driver.execute_script(
                "return JSON.stringify(timeouts)")
            for t in json.loads(raw):
                try:
                    if t.get('function_name'):
                        self.driver.execute_script(
                            t['function_name'] + "()")
                except Exception:
                    pass
        except Exception:
            pass

    # ==================================================================
    # Whitebox: Kit directory scanning
    # ==================================================================

    def _scan_kit_directory(self):
        """Walk the local phishing kit directory and build URLs for every
        web-accessible file (PHP, HTML, etc.).

        The --url and --kit-path may point to different directory levels.
        For example:
            --url       http://localhost/kits/2021/apple/home
            --kit-path  /var/www/html/kits/2021/

        In this case the URL already includes 'apple/home' but kit_path
        is two levels above.  We auto-detect this overlap by comparing
        the URL path tail with the kit directory structure, and compute
        the correct web root so that file URLs are not doubled.

        Returns a list of absolute URLs.
        """
        kit_path = os.path.realpath(self.kit_path)
        if not os.path.isdir(kit_path):
            logging.error("Kit path does not exist or is not a directory: %s",
                          kit_path)
            return []

        # --- Compute base URL for kit_path ---
        # Strategy: find the longest suffix of kit_path segments that
        # matches a prefix of the URL path segments.  This tells us
        # which URL corresponds to kit_path.
        #
        # Example:
        #   kit_path = /var/www/html/.../apple
        #   URL      = http://localhost/.../apple/home/index.html
        #   -> kit_base_url = http://localhost/.../apple/
        #   -> file at kit_path/home/fr.html -> .../apple/home/fr.html (ok)
        #   -> file at kit_path/block.php    -> .../apple/block.php    (ok)

        parsed = urlparse(self.url)
        url_path = parsed.path.rstrip('/')
        # Strip filename if URL points to a file
        url_basename = url_path.rsplit('/', 1)[-1] if '/' in url_path else url_path
        if '.' in url_basename:
            url_dir_path = url_path.rsplit('/', 1)[0]
        else:
            url_dir_path = url_path
        url_dir_segments = [s for s in url_dir_path.strip('/').split('/') if s]

        kit_segments = [s for s in kit_path.rstrip(os.sep).split(os.sep) if s]

        # Find longest common match between kit_path tail and URL path head
        # We compare decoded segments (URL segments may be percent-encoded).
        from urllib.parse import unquote
        url_dir_segments_decoded = [unquote(s) for s in url_dir_segments]

        kit_base_url = None
        for n in range(min(len(kit_segments), len(url_dir_segments_decoded)), 0, -1):
            if kit_segments[-n:] == url_dir_segments_decoded[:n]:
                kit_base_url = (parsed.scheme + '://' + parsed.netloc
                                + '/' + '/'.join(url_dir_segments[:n]) + '/')
                break

        if kit_base_url is None:
            kit_base_url = (parsed.scheme + '://' + parsed.netloc
                            + '/' + '/'.join(url_dir_segments) + '/')
            logging.warning("Could not align kit-path with URL, using fallback base: %s",
                            kit_base_url)

        print("[Whitebox] kit-path  : %s" % kit_path)
        print("[Whitebox] kit-base  : %s" % kit_base_url)

        urls = []
        skipped_backend = 0
        skipped_dup_dir = 0
        skipped_dup_file = 0

        # Phase 1: detect duplicate first-level subdirectories by content
        dir_fingerprints = {}
        duplicate_dirs = set()
        first_level_dirs = []
        try:
            first_level_dirs = sorted(
                d for d in os.listdir(kit_path)
                if os.path.isdir(os.path.join(kit_path, d))
                and d not in self.SKIP_DIRS and not d.startswith('.')
                and d.lower() not in self.BACKEND_DIRS
            )
        except Exception:
            pass

        for subdir in first_level_dirs:
            subdir_path = os.path.join(kit_path, subdir)
            file_sigs = []
            for dp, dns, fns in os.walk(subdir_path):
                dns[:] = [d for d in dns
                          if d not in self.SKIP_DIRS and not d.startswith('.')
                          and d.lower() not in self.BACKEND_DIRS]
                for fn in sorted(fns):
                    _, ext = os.path.splitext(fn)
                    if ext.lower() not in self.WEB_EXTENSIONS:
                        continue
                    fp = os.path.join(dp, fn)
                    rel = os.path.relpath(fp, subdir_path)
                    try:
                        with open(fp, 'rb') as fh:
                            h = hashlib.md5(fh.read(16384)).hexdigest()
                        file_sigs.append((rel.lower(), h))
                    except Exception:
                        file_sigs.append((rel.lower(), ''))
            if not file_sigs:
                continue
            fp_hash = hashlib.md5(str(sorted(file_sigs)).encode()).hexdigest()
            if fp_hash in dir_fingerprints:
                duplicate_dirs.add(subdir)
                skipped_dup_dir += 1
            else:
                dir_fingerprints[fp_hash] = subdir

        # Phase 2: collect URLs while skipping duplicate dirs/files
        seen_file_hashes = set()
        for dirpath, dirnames, filenames in os.walk(kit_path):
            # Prune directories we don't want to descend into
            dirnames[:] = [d for d in dirnames
                           if d not in self.SKIP_DIRS and not d.startswith('.')
                           and d.lower() not in self.BACKEND_DIRS]

            rel_to_kit = os.path.relpath(dirpath, kit_path)
            first_level = rel_to_kit.split(os.sep)[0] if rel_to_kit != '.' else ''
            if first_level in duplicate_dirs:
                continue

            for fname in filenames:
                if fname.startswith('.'):
                    continue

                _, ext = os.path.splitext(fname)
                if ext.lower() not in self.WEB_EXTENSIONS:
                    continue

                fname_lower = fname.lower()
                if fname_lower in self.BACKEND_FILES:
                    skipped_backend += 1
                    continue
                if any(fname_lower.startswith(p) for p in self.BACKEND_FILE_PREFIXES):
                    skipped_backend += 1
                    continue

                full_path = os.path.join(dirpath, fname)
                try:
                    with open(full_path, 'rb') as fh:
                        content_hash = hashlib.md5(fh.read(16384)).hexdigest()
                    file_key = fname_lower + ':' + content_hash
                    if file_key in seen_file_hashes:
                        skipped_dup_file += 1
                        continue
                    seen_file_hashes.add(file_key)
                except Exception:
                    pass
                rel_path = os.path.relpath(full_path, kit_path)
                rel_path = rel_path.replace(os.sep, '/')

                # URL-encode each path segment to handle spaces and
                # special characters in directory/file names.
                encoded_segments = '/'.join(
                    quote(seg, safe='') for seg in rel_path.split('/')
                )
                file_url = kit_base_url + encoded_segments
                urls.append(file_url)

                # NOTE: We intentionally do NOT add directory URLs
                # (e.g. ".../home/") because they resolve to the same page
                # as the index file (e.g. ".../home/index.html"), causing
                # duplicate analysis of the same form.

        # Sort for deterministic ordering (shallow paths first)
        urls.sort(key=lambda u: (u.count('/'), u))

        if len(urls) > self.MAX_SEED_URLS:
            print("[Whitebox] Capping seed URLs: %d -> %d (skipping deepest paths)"
                  % (len(urls), self.MAX_SEED_URLS))
            urls = urls[:self.MAX_SEED_URLS]

        if skipped_backend or skipped_dup_dir or skipped_dup_file:
            print("[Whitebox] Filtered: %d backend file(s), %d duplicate dir(s), %d duplicate file(s)"
                  % (skipped_backend, skipped_dup_dir, skipped_dup_file))

        print("[Whitebox] Found %d web-accessible file(s) under %s"
              % (len(urls), kit_path))
        for u in urls:
            print("  -> %s" % u)

        return urls

    # ------------------------------------------------------------------
    # Form-level analysis
    # ------------------------------------------------------------------

    def _analyze_form(self, form_el, page_url=None):
        form_xpath = self._get_xpath(form_el)
        form_action = form_el.get_attribute('action') or ''
        form_method = (form_el.get_attribute('method') or 'get').lower()

        form_result = {
            'action': form_action,
            'method': form_method,
            'xpath': form_xpath,
            'registered_handlers': [],
            'fields': [],
            'submit_log': {},
            'overall_classification': '',
        }

        # Collect registered handlers scoped to this form
        try:
            handlers_json = self.driver.execute_script(
                "return window.__fa_getRegisteredHandlers(arguments[0])",
                form_xpath)
            form_result['registered_handlers'] = json.loads(handlers_json)
        except Exception as e:
            logging.warning("Could not get registered handlers: %s", e)

        # Discover fields
        fields = self._discover_fields(form_el)
        visible_fields = 0
        for f in fields:
            try:
                if f.get('element') is not None and f['element'].is_displayed():
                    visible_fields += 1
            except Exception:
                pass
        hidden_fields = max(0, len(fields) - visible_fields)
        form_result['field_stats'] = {
            'dom_analysable': len(fields),
            'visible_now': visible_fields,
            'hidden_or_collapsed': hidden_fields,
        }
        print("[FormAnalyzer]   Analysable fields: DOM=%d, visible=%d, hidden=%d"
              % (len(fields), visible_fields, hidden_fields))

        if self.network_only:
            form_result['fields'] = [
                self._make_minimal_field_result(field_info) for field_info in fields
            ]
            print("[FormAnalyzer]   Network-only mode: skipping per-field typing analysis")
        else:
            for field_info in fields:
                field_info['form_xpath'] = form_xpath
                print("[FormAnalyzer]   Field: %s (%s)" % (
                    field_info['name'], field_info['type']))
                field_result = self._analyze_field(field_info)
                form_result['fields'].append(field_result)

        # Submit analysis -- always attempt, even without a visible submit button
        submit_btn = self._find_submit_button(form_el)
        if submit_btn:
            btn_tag = submit_btn.tag_name
            btn_type = submit_btn.get_attribute("type") or ''
            btn_text = (submit_btn.text or submit_btn.get_attribute("value") or '')[:50]
            print("[FormAnalyzer]   Submit button found: <%s type='%s'> \"%s\""
                  % (btn_tag, btn_type, btn_text))
        else:
            print("[FormAnalyzer]   No explicit submit button -- will use JS fallback")
        form_result['submit_log'] = self._analyze_submit(
            form_el, submit_btn, fields, page_url=page_url,
            form_xpath=form_xpath)

        # Static analysis enrichment (resolve anonymous functions + server behavior)
        if self._resolver:
            self._resolver.enrich_form_result(form_result)

        # Classification
        form_result['overall_classification'] = self._classify_form(
            form_result)

        return form_result

    # ------------------------------------------------------------------
    # Field-level analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _make_minimal_field_result(field_info):
        return {
            'name': field_info['name'],
            'type': field_info['type'],
            'xpath': field_info['xpath'],
            'typing_log': [],
            'backspace_log': {},
            'other_log': {},
            'classification': '',
        }

    def _prime_fields_for_submit(self, fields):
        """Populate fields once so submit-oriented network traces have data."""
        for field_info in fields:
            xpath = field_info['xpath']
            field_type = field_info.get('type', '')
            try:
                if field_info.get('interactive'):
                    if field_type == 'select':
                        self.driver.execute_script("""
                            var el = document.evaluate(arguments[0], document, null,
                                XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                            if (el && el.options && el.options.length > 0) {
                                el.selectedIndex = Math.min(1, el.options.length - 1);
                                el.dispatchEvent(new Event('change', {bubbles: true}));
                            }
                        """, xpath)
                    elif field_type in ('checkbox', 'radio'):
                        self.driver.execute_script("""
                            var el = document.evaluate(arguments[0], document, null,
                                XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                            if (el && !el.checked) { el.click(); }
                        """, xpath)
                    continue

                test_val = self._generate_input(field_info)
                self.driver.execute_script(
                    "window.__fa_updateValueAndInput(arguments[0], arguments[1])",
                    xpath, test_val)
                self.driver.execute_script("""
                    var el = document.evaluate(arguments[0], document, null,
                        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                    if (el) { el.dispatchEvent(new Event('change', {bubbles: true})); }
                """, xpath)
            except Exception as e:
                logging.debug("Field priming failed for %s: %s", xpath, e)

    def _analyze_field(self, field_info):
        xpath = field_info['xpath']
        form_xpath = field_info.get('form_xpath', '')
        is_interactive = field_info.get('interactive', False)

        field_result = {
            'name': field_info['name'],
            'type': field_info['type'],
            'xpath': xpath,
            'typing_log': [],
            'backspace_log': {},
            'other_log': {},
            'classification': '',
        }

        # Instrument on* property handlers on the field and parent form
        # so we can track which page-defined function fires per action.
        # (addEventListener callbacks are already wrapped at registration time.)
        try:
            n_field = self.driver.execute_script(
                "return window.__fa_instrumentOnHandlers(arguments[0])", xpath)
            n_form = 0
            if form_xpath:
                n_form = self.driver.execute_script(
                    "return window.__fa_instrumentOnHandlers(arguments[0])",
                    form_xpath)
            if n_field or n_form:
                print("[FormAnalyzer]     Instrumented %d on* handler(s) "
                      "(field=%d, form=%d)" % (n_field + n_form, n_field, n_form))
        except Exception as e:
            logging.warning("Handler instrumentation failed: %s", e)

        # -- Phase 1: Focus --
        self.driver.execute_script("window.__fa_setPhase('focus')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()  # clear stale
        self.driver.execute_script(
            "window.__fa_dispatchFocus(arguments[0])", xpath)
        time.sleep(self.delay)
        focus_logs = self._collect_logs()

        if is_interactive:
            # For select/checkbox/radio: simulate click + change instead of
            # char-by-char typing which doesn't apply.
            click_log = self._do_click_interaction(xpath, field_info['type'])
            field_result['typing_log'] = []  # not applicable
            field_result['other_log']['click_interaction'] = click_log
        else:
            # -- Phase 2: Typing (char by char) --
            test_chars = self._generate_input(field_info)
            current_value = ''
            for char in test_chars:
                char_log = self._type_single_char(xpath, char, current_value)
                current_value += char
                field_result['typing_log'].append(char_log)

            # -- Phase 3: Backspace --
            field_result['backspace_log'] = self._do_backspace(
                xpath, current_value)

        # -- Phase 4: Other interactions (blur, change) --
        other = field_result.get('other_log', {})

        # Blur
        self.driver.execute_script("window.__fa_setPhase('blur')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchBlur(arguments[0])", xpath)
        time.sleep(self.delay)
        other['blur'] = self._collect_logs()

        # Change
        self.driver.execute_script("window.__fa_setPhase('change')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchChange(arguments[0])", xpath)
        time.sleep(self.delay)
        other['change'] = self._collect_logs()

        other['focus'] = focus_logs
        field_result['other_log'] = other

        # Restore original on* handlers
        try:
            self.driver.execute_script(
                "window.__fa_restoreOnHandlers(arguments[0])", xpath)
            if form_xpath:
                self.driver.execute_script(
                    "window.__fa_restoreOnHandlers(arguments[0])", form_xpath)
        except Exception:
            pass

        # Field-level classification
        field_result['classification'] = self._classify_field(field_result)

        return field_result

    # ------------------------------------------------------------------
    # Typing simulation helpers
    # ------------------------------------------------------------------

    def _type_single_char(self, xpath, char, current_value):
        """Simulate KeyDown -> KeyPress -> Input -> KeyUp with 30s delays."""
        char_code = ord(char)
        char_log = {'char': char}

        # 1. KeyDown
        self.driver.execute_script("window.__fa_setPhase('typing_keydown')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchKeyEvent(arguments[0], 'keydown', "
            "arguments[1], arguments[2], 0)",
            xpath, char, char_code)
        time.sleep(self.delay)
        char_log['keydown'] = self._collect_logs()

        # 2. KeyPress
        self.driver.execute_script("window.__fa_setPhase('typing_keypress')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchKeyEvent(arguments[0], 'keypress', "
            "arguments[1], arguments[2], arguments[2])",
            xpath, char, char_code)
        time.sleep(self.delay)
        char_log['keypress'] = self._collect_logs()

        # 3. Input (update value + dispatch input event)
        self.driver.execute_script("window.__fa_setPhase('typing_input')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        new_value = current_value + char
        self.driver.execute_script(
            "window.__fa_updateValueAndInput(arguments[0], arguments[1])",
            xpath, new_value)
        time.sleep(self.delay)
        char_log['input'] = self._collect_logs()

        # 4. KeyUp
        self.driver.execute_script("window.__fa_setPhase('typing_keyup')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchKeyEvent(arguments[0], 'keyup', "
            "arguments[1], arguments[2], 0)",
            xpath, char, char_code)
        time.sleep(self.delay)
        char_log['keyup'] = self._collect_logs()

        return char_log

    def _do_backspace(self, xpath, current_value):
        """Simulate Backspace: KeyDown -> value update + Input -> KeyUp."""
        result = {}

        # KeyDown(Backspace)
        self.driver.execute_script("window.__fa_setPhase('backspace_keydown')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchBackspace(arguments[0], 'keydown')", xpath)
        time.sleep(self.delay)
        result['keydown'] = self._collect_logs()

        # Value update + Input event
        self.driver.execute_script("window.__fa_setPhase('backspace_input')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        trimmed = current_value[:-1] if current_value else ''
        self.driver.execute_script(
            "window.__fa_updateValueAndInput(arguments[0], arguments[1])",
            xpath, trimmed)
        time.sleep(self.delay)
        result['input'] = self._collect_logs()

        # KeyUp(Backspace)
        self.driver.execute_script("window.__fa_setPhase('backspace_keyup')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()
        self.driver.execute_script(
            "window.__fa_dispatchBackspace(arguments[0], 'keyup')", xpath)
        time.sleep(self.delay)
        result['keyup'] = self._collect_logs()

        return result

    # ------------------------------------------------------------------
    # Click interaction for select/checkbox/radio
    # ------------------------------------------------------------------

    def _do_click_interaction(self, xpath, field_type):
        """Simulate a click on interactive elements (select/checkbox/radio)."""
        result = {}

        self.driver.execute_script("window.__fa_setPhase('click_interaction')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()

        # Dispatch a click event via JS
        self.driver.execute_script("""
            var el = document.evaluate(arguments[0], document, null,
                XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
            if (el) { el.click(); }
        """, xpath)
        time.sleep(self.delay)
        result['click'] = self._collect_logs()

        # For selects, also dispatch change after option switch
        if field_type == 'select':
            self.driver.execute_script("window.__fa_setPhase('select_change')")
            self.driver.execute_script("window.__fa_incrementStep()")
            self._clear_logs()
            self.driver.execute_script("""
                var el = document.evaluate(arguments[0], document, null,
                    XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
                if (el && el.options && el.options.length > 1) {
                    el.selectedIndex = 1;
                    el.dispatchEvent(new Event('change', {bubbles: true}));
                }
            """, xpath)
            time.sleep(self.delay)
            result['select_change'] = self._collect_logs()

        return result

    # ------------------------------------------------------------------
    # Submit analysis
    # ------------------------------------------------------------------

    def _observe_native_submit(self, fields, page_url):
        """Run ONE native browser submit to capture the REAL request structure.

        Unlike the XHR-interception path this does NOT call e.preventDefault().
        The browser sends exactly what it would send to a real server:
        - Correct Content-Type (multipart/form-data for file inputs, etc.)
        - All browser-generated headers (Referer, Cookie, Origin, …)
        - Correct enctype from the form element

        Because the page navigates after submit the JS context is destroyed,
        so we rely entirely on CDP performance logs (which survive navigation)
        for capture.  The result is stored under result['native_submit'].

        Returns a dict with:
          form_meta   - action, method, enctype read from DOM before submit
          cdp_reqs    - list of CDP request entries (real network stack)
          note        - human-readable annotation
        """
        result = {'form_meta': {}, 'cdp_reqs': [], 'note': ''}

        # 1. Snapshot form metadata before anything changes
        try:
            form_meta = self.driver.execute_script("""
                var form = document.querySelector('form');
                if (!form) return null;
                return {
                    action:  form.getAttribute('action') || window.location.href,
                    method:  (form.getAttribute('method') || 'GET').toUpperCase(),
                    enctype: form.getAttribute('enctype') || form.enctype ||
                             'application/x-www-form-urlencoded',
                    id:      form.id || '',
                    name:    form.name || ''
                };
            """)
            result['form_meta'] = form_meta or {}
        except Exception as e:
            logging.debug("Native submit: form_meta read failed: %s", e)

        # 2. Fill fields with test data (same as XHR path)
        self._prime_fields_for_submit(fields)
        time.sleep(0.3)

        # 3. Reset CDP buffer so we capture only this submit's traffic
        cdp_reset_ok = reset_cdp_network_monitoring(self.driver)
        if not cdp_reset_ok:
            result['note'] = (
                'performance log reset timed out before native submit; '
                'native CDP capture may be incomplete'
            )

        # 4. Click the real submit button -- NO interception installed
        submit_ts_ms = int(time.time() * 1000)
        submitted = False
        try:
            btn = self._find_submit_button_by_page()
            if btn:
                btn.click()
                submitted = True
        except Exception as e:
            logging.debug("Native submit: click failed: %s", e)

        if not submitted:
            result['note'] = 'submit button not found -- native submit skipped'
            return result

        # 5. Wait briefly.  The page may navigate immediately.
        #    CDP logs persist at the driver level across page transitions.
        try:
            import selenium.common.exceptions as _sce
            self.driver.implicitly_wait(0)
            for _ in range(6):          # up to ~3 s
                time.sleep(0.5)
                try:
                    current = self.driver.current_url
                    if current != page_url:
                        break           # navigation happened
                except _sce.WebDriverException:
                    break
        except Exception:
            time.sleep(1.5)

        # 6. Drain CDP logs immediately -- before more requests pile up
        try:
            cdp_reqs = drain_cdp_network_logs(self.driver)
            # Annotate each req so readers know this is the native path
            for req in cdp_reqs:
                req['_native_submit'] = True
                req['_submit_trigger_ts_ms'] = submit_ts_ms
            result['cdp_reqs'] = cdp_reqs
            # Also roll into global index
            self._record_cdp_requests(cdp_reqs)
        except Exception as e:
            logging.debug("Native submit: CDP drain failed: %s", e)

        result['note'] = ('native browser submit observed via CDP only; '
                          'JS context may have been destroyed by navigation')
        return result

    def _analyze_submit(self, form_el, submit_btn, fields, page_url=None,
                        form_xpath=None):
        result = {}
        reload_url = page_url or self.driver.current_url

        if self.network_only:
            result['enter_key_test'] = {'skipped': True, 'reason': 'network_only'}
            result['enter_key_logs'] = {}
            # Prime fields for the upcoming native submit pass
            self._prime_fields_for_submit(fields)
        else:
            # 1. Enter key prevention test
            self.driver.execute_script("window.__fa_setPhase('submit_enter_test')")
            self.driver.execute_script("window.__fa_incrementStep()")
            self._clear_logs()

            # Pick the first text field to test Enter on
            text_fields = [f for f in fields if not f.get('interactive')]
            if text_fields:
                enter_result = self.driver.execute_script(
                    "return window.__fa_dispatchEnterKey(arguments[0])",
                    text_fields[0]['xpath'])
                result['enter_key_test'] = enter_result
            time.sleep(self.delay)
            result['enter_key_logs'] = self._collect_logs()

            # 2. Reload page state for clean submit test
            #    (Enter key might have triggered submit / page navigation)
            self.driver.get(reload_url)
            time.sleep(3)
            self._dismiss_alert()
            self.driver.execute_script(
                "window.__fa_start(arguments[0])", form_xpath)

            # Re-fill text fields with test data so submit has content
            self._prime_fields_for_submit(fields)
            time.sleep(0.5)

        # -- Phase A: Native submit (real browser, CDP only) -------------
        # Run BEFORE the XHR interception so we capture the actual
        # Content-Type, enctype, headers the browser would really send.
        # Page may navigate; we reload afterward for the XHR pass.
        try:
            native = self._observe_native_submit(fields, reload_url)
            result['native_submit'] = native
        except Exception as e:
            logging.warning("Native submit observation failed: %s", e)
            result['native_submit'] = {'note': 'observation failed: %s' % e,
                                       'cdp_reqs': [], 'form_meta': {}}

        # Reload for clean XHR-interception pass
        try:
            self.driver.get(reload_url)
            time.sleep(2)
            self._dismiss_alert()
            self.driver.execute_script(
                "window.__fa_start(arguments[0])", form_xpath)
            self._prime_fields_for_submit(fields)
            time.sleep(0.3)
        except Exception as e:
            logging.warning("Reload before XHR pass failed: %s", e)

        # -- Phase B: XHR-intercepted submit (JS hooks, response body) ---
        # 3. Intercept form submission and submit via XHR instead of
        #    browser navigation.  A normal form POST causes page navigation
        #    which destroys our JS context, so networkReqs would be empty.
        #    We prevent the default submit, capture the action/method/body,
        #    send it via XHR (which our hooks capture), then record the result.
        #    NOTE: this changes Content-Type to application/x-www-form-urlencoded
        #    and strips file uploads -- use native_submit.cdp_reqs for real structure.
        self.driver.execute_script("window.__fa_setPhase('submit_click')")
        self.driver.execute_script("window.__fa_incrementStep()")
        self._clear_logs()

        # Install form submit interceptor
        self.driver.execute_script("""
            window.__fa_submitResult = null;
            // Intercept all form submissions to prevent page navigation
            if (!window.__fa_submitIntercepted) {
                window.__fa_submitIntercepted = true;
                document.addEventListener('submit', function(e) {
                    e.preventDefault();
                    var form = e.target;
                    var formData = new FormData(form);
                    // IMPORTANT: use getAttribute() instead of form.action
                    // because <input name="action"> inside the form shadows
                    // form.action, returning the HTMLElement instead of the URL.
                    var action = form.getAttribute('action')
                                 || window.location.href;
                    var method = (form.getAttribute('method') || 'GET')
                                 .toUpperCase();

                    // Record what would be submitted
                    var fields = {};
                    formData.forEach(function(value, key) {
                        fields[key] = value;
                    });

                    // Send via XHR so our hooks capture it
                    var xhr = new XMLHttpRequest();
                    xhr.open(method, action, true);
                    xhr.setRequestHeader('Content-Type',
                        'application/x-www-form-urlencoded');

                    // Build URL-encoded body
                    var pairs = [];
                    formData.forEach(function(value, key) {
                        pairs.push(encodeURIComponent(key) + '=' +
                                   encodeURIComponent(value));
                    });
                    var body = pairs.join('&');

                    xhr.onload = function() {
                        window.__fa_submitResult = {
                            action: action,
                            method: method,
                            fields: fields,
                            status: xhr.status,
                            responseLength: (xhr.responseText || '').length,
                            responseContentType:
                                xhr.getResponseHeader('Content-Type') || '',
                            submitted: true
                        };
                    };
                    xhr.onerror = function() {
                        window.__fa_submitResult = {
                            action: action, method: method, fields: fields,
                            status: 'error', submitted: true
                        };
                    };
                    xhr.send(body);
                }, true);

                // Also intercept form.submit() calls
                var origSubmit = HTMLFormElement.prototype.submit;
                HTMLFormElement.prototype.submit = function() {
                    var evt = new Event('submit', {bubbles: true, cancelable: true});
                    if (!this.dispatchEvent(evt)) return;
                    origSubmit.call(this);
                };
            }
        """)

        submitted = False
        submit_trigger_ts_ms = int(time.time() * 1000)  # Python wall-clock before click
        try:
            new_btn = self._find_submit_button_by_page()
            if new_btn:
                new_btn.click()
                submitted = True
        except Exception as e:
            logging.warning("Submit button click failed: %s", e)

        if not submitted:
            try:
                self.driver.execute_script("""
                    var f = document.querySelector('form');
                    if (f) {
                        var candidates = f.querySelectorAll(
                            'input[type="button"], input[type="image"], ' +
                            'div[onclick], a[onclick], span[onclick], ' +
                            '[role="button"], [class*="btn"], [class*="submit"]');
                        if (candidates.length > 0) {
                            candidates[0].click();
                        } else {
                            // Dispatch submit event (intercepted above)
                            var evt = new Event('submit',
                                {bubbles: true, cancelable: true});
                            f.dispatchEvent(evt);
                        }
                    }
                """)
            except Exception as e:
                logging.warning("JS submit fallback failed: %s", e)

        # Wait for submit action + any async AJAX (jQuery $.ajax, etc.)
        time.sleep(self.network_wait)

        # Poll briefly for late-arriving network responses (jQuery AJAX
        # may fire asynchronously after the click handler returns)
        for _ in range(3):
            try:
                pending = self.driver.execute_script("""
                    var reqs = window.__fa.networkReqs;
                    for (var i = 0; i < reqs.length; i++) {
                        if (reqs[i].status === null) return true;
                    }
                    return false;
                """)
                if not pending:
                    break
            except Exception:
                break
            time.sleep(self.network_wait)

        # Collect logs (now networkReqs should contain the XHR submit)
        try:
            result['submit_click_logs'] = self._collect_logs()
        except Exception:
            result['submit_click_logs'] = {}

        # Timing chain analysis: event -> request -> response
        result['submit_trigger_ts_ms'] = submit_trigger_ts_ms
        try:
            logs = result.get('submit_click_logs', {})
            js_nets = logs.get('networkReqs', [])
            cdp_nets = logs.get('cdpNetworkReqs', [])
            fired_events = logs.get('firedEvents', [])

            # Find earliest submit/click event fired in JS (ms epoch)
            trigger_event_ts = None
            for ev in fired_events:
                et = ev.get('eventType', '')
                if et in ('submit', 'click'):
                    ts = ev.get('timestamp')
                    if ts and (trigger_event_ts is None or ts < trigger_event_ts):
                        trigger_event_ts = ts

            # First JS-level network request timestamp (ms epoch)
            first_js_req_ts = js_nets[0].get('timestamp') if js_nets else None

            timing_chain = {
                'python_click_ts_ms': submit_trigger_ts_ms,
                'js_trigger_event_ts_ms': trigger_event_ts,
                'js_first_req_ts_ms': first_js_req_ts,
            }
            # event -> request delta (both from JS Date.now() -> directly comparable)
            if trigger_event_ts and first_js_req_ts:
                timing_chain['event_to_request_ms'] = first_js_req_ts - trigger_event_ts

            # Enrich cdpNetworkReqs with latency (already computed in drain)
            for req in cdp_nets:
                # CDP latencyMs already computed in drain_cdp_network_logs
                # Add initiator label for readability
                req.setdefault('_timing_summary', {
                    'latencyMs': req.get('latencyMs'),
                    'ttfbMs': req.get('ttfbMs'),
                    'protocol': req.get('protocol', ''),
                    'redirected': req.get('redirected', False),
                    'redirectChain': req.get('redirectChain', []),
                    'status': req.get('status'),
                    'hasCookieHeader': req.get('hasCookieHeader', False),
                    'hasSetCookie': req.get('hasSetCookie', False),
                })

            timing_chain['cdp_req_count'] = len(cdp_nets)
            result['submit_timing'] = timing_chain
        except Exception as e:
            logging.debug("Timing analysis failed: %s", e)
            result['submit_timing'] = {}

        # Also capture the submit result metadata
        try:
            submit_meta = self.driver.execute_script(
                "return window.__fa_submitResult")
            if submit_meta:
                submit_meta['cdp_network'] = (
                    result.get('submit_click_logs', {}).get('cdpNetworkReqs', [])[:10]
                )
                result['submit_detail'] = submit_meta
        except Exception:
            pass

        return result

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _classify_field(self, field_result):
        """Classify a single field based on its collected logs."""
        has_network = False
        has_dom_change = False
        has_html5 = False
        has_js_event = False
        has_triggered_fn = False

        # Check all typing logs
        for char_log in field_result.get('typing_log', []):
            for phase in ('keydown', 'keypress', 'input', 'keyup'):
                logs = char_log.get(phase, {})
                if logs.get('networkReqs') or logs.get('cdpNetworkReqs'):
                    has_network = True
                if logs.get('domChanges'):
                    has_dom_change = True
                if logs.get('html5Validation'):
                    has_html5 = True
                if logs.get('firedEvents'):
                    has_js_event = True
                if logs.get('triggeredFunctions'):
                    has_triggered_fn = True

        # Check backspace logs
        for phase in ('keydown', 'input', 'keyup'):
            logs = field_result.get('backspace_log', {}).get(phase, {})
            if logs.get('networkReqs') or logs.get('cdpNetworkReqs'):
                has_network = True
            if logs.get('domChanges'):
                has_dom_change = True
            if logs.get('triggeredFunctions'):
                has_triggered_fn = True

        # Check other logs
        for phase_name, logs in field_result.get('other_log', {}).items():
            if isinstance(logs, dict):
                if logs.get('networkReqs') or logs.get('cdpNetworkReqs'):
                    has_network = True
                if logs.get('domChanges'):
                    has_dom_change = True
                if logs.get('triggeredFunctions'):
                    has_triggered_fn = True

        # Classification logic
        if has_network and has_dom_change:
            return 'Case B: Server Round-trip (AJAX)'
        elif has_network:
            return 'Case B: Server Round-trip (AJAX)'
        elif has_html5:
            if has_dom_change or has_js_event or has_triggered_fn:
                return 'Mixed: HTML5 + Client-side JS'
            return 'Case C: HTML5 Validation'
        elif has_dom_change:
            return 'Case A: Pure Client-side JS'
        elif has_triggered_fn:
            return 'Case A: Pure Client-side JS (triggered functions detected)'
        elif has_js_event:
            return 'Case A: Pure Client-side JS (event handlers only)'
        else:
            return 'None: No validation detected'

    def _classify_form(self, form_result):
        """Derive overall classification from field-level classifications."""
        classifications = set()
        for field in form_result.get('fields', []):
            c = field.get('classification', '')
            if c:
                classifications.add(c)

        # Check submit logs for additional signals
        submit_logs = form_result.get('submit_log', {})
        submit_click = submit_logs.get('submit_click_logs', {})
        if submit_click.get('networkReqs') or submit_click.get('cdpNetworkReqs'):
            classifications.add('Case B: Server Round-trip (AJAX)')
        if submit_click.get('html5Validation'):
            classifications.add('Case C: HTML5 Validation')

        if len(classifications) == 0:
            return 'None: No validation detected'
        elif len(classifications) == 1:
            return classifications.pop()
        else:
            return 'Mixed: ' + ' + '.join(sorted(classifications))

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    @staticmethod
    def _json_safe_default(obj):
        """Fallback serializer for objects that json can't handle.

        Prevents 'WebElement is not JSON serializable' crashes by
        converting unknown types to a safe string representation.
        """
        # Selenium WebElement
        if hasattr(obj, 'tag_name'):
            try:
                return '<WebElement:%s id=%s>' % (obj.tag_name,
                                                   obj.get_attribute('id'))
            except Exception:
                return '<WebElement>'
        # Anything else
        try:
            return str(obj)
        except Exception:
            return '<non-serializable:%s>' % type(obj).__name__

    def _output_json(self):
        prefix = self._result_name_prefix()
        name_prefix = 'analysis_results_network' if self.network_only else 'analysis_results'
        filename = "%s_%s_%s.json" % (name_prefix, prefix, self.session_ts)
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False,
                      default=self._json_safe_default)
        print("[FormAnalyzer] JSON saved: %s" % filepath)

    # ------------------------------------------------------------------
    # CSV helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_network_info(logs):
        """Extract structured network request+response info from a log dict.

        Returns a dict with:
            net_names:  semicolon-separated file names  (e.g. "ajax.php")
            net_urls:   semicolon-separated full paths
            net_methods: semicolon-separated methods     (e.g. "POST")
            net_count:  number of requests
            req_content_types: semicolon-separated request content types
            req_has_cookie:    semicolon-separated booleans
            req_custom_headers: semicolon-separated custom header names
            res_statuses:      semicolon-separated status codes  (e.g. "200; 302")
            res_redirected:    semicolon-separated redirect flags
            res_response_returned: semicolon-separated response-returned flags
            res_body_lengths:  semicolon-separated body lengths  (e.g. "0; 1234")
            res_content_types: semicolon-separated content types
            res_has_set_cookie: semicolon-separated Set-Cookie flags
            res_body_previews: semicolon-separated truncated response body previews
        """
        reqs = logs.get('cdpNetworkReqs') or logs.get('networkReqs', [])
        if not reqs:
            return {
                'net_names': '', 'net_urls': '', 'net_methods': '',
                'net_count': 0,
                'req_content_types': '', 'req_has_cookie': '',
                'req_custom_headers': '',
                'res_statuses': '', 'res_body_lengths': '',
                'res_content_types': '', 'latencies_ms': '',
                'res_redirected': '', 'res_response_returned': '',
                'res_has_set_cookie': '', 'res_body_previews': '',
            }

        names = []
        urls = []
        methods = []
        req_content_types = []
        req_has_cookie = []
        req_custom_headers = []
        statuses = []
        redirected = []
        response_returned = []
        body_lengths = []
        content_types = []
        latencies = []
        has_set_cookie = []
        body_previews = []
        for req in reqs:
            url = req.get('url', '')
            urls.append(url)
            methods.append(req.get('method', ''))
            try:
                from urllib.parse import urlparse as _urlparse
                parsed = _urlparse(url)
                path = parsed.path if parsed.path else url
            except Exception:
                path = url
            basename = path.rstrip('/').rsplit('/', 1)[-1] if path else url
            names.append(basename or url)

            req_content_types.append(req.get('requestContentType') or '')
            req_has_cookie.append(str(bool(req.get('hasCookieHeader'))))
            custom_headers = req.get('customRequestHeaders') or {}
            req_custom_headers.append('|'.join(sorted(custom_headers.keys())))
            statuses.append(str(req.get('status', '')))
            redirected.append(str(bool(req.get('redirected'))))
            response_returned.append(str(bool(req.get('responseReturned'))))
            bl = req.get('responseBodyLength')
            if bl is None and req.get('response') is not None:
                try:
                    bl = len(req.get('response') or '')
                except Exception:
                    bl = None
            body_lengths.append(str(bl) if bl is not None else '')
            content_types.append(req.get('responseContentType') or '')
            lat = req.get('latencyMs')
            latencies.append(str(lat) if lat is not None else '')
            has_set_cookie.append(str(bool(req.get('hasSetCookie'))))
            preview = (
                req.get('responseBodyPreview')
                if req.get('responseBodyPreview') is not None
                else req.get('response')
            )
            preview = str(preview or '').replace('\r', ' ').replace('\n', ' ')[:160]
            body_previews.append(preview)

        return {
            'net_names': '; '.join(names),
            'net_urls': '; '.join(urls),
            'net_methods': '; '.join(methods),
            'net_count': len(reqs),
            'req_content_types': '; '.join(req_content_types),
            'req_has_cookie': '; '.join(req_has_cookie),
            'req_custom_headers': '; '.join(req_custom_headers),
            'res_statuses': '; '.join(statuses),
            'res_body_lengths': '; '.join(body_lengths),
            'res_content_types': '; '.join(content_types),
            'latencies_ms': '; '.join(latencies),
            'res_redirected': '; '.join(redirected),
            'res_response_returned': '; '.join(response_returned),
            'res_has_set_cookie': '; '.join(has_set_cookie),
            'res_body_previews': '; '.join(body_previews),
        }

    @staticmethod
    def _count_meaningful_events(logs):
        """Count fired events excluding mouse noise (mouseover/mouseout/mousemove)."""
        noise_types = {'mouseover', 'mouseout', 'mousemove'}
        events = logs.get('firedEvents', [])
        total = len(events)
        meaningful = sum(1 for e in events if e.get('eventType') not in noise_types)
        return (meaningful, total)

    @staticmethod
    def _extract_triggered_functions(logs):
        """Extract triggered function names and sources from a log dict.

        Returns:
            fn_names:  semicolon-separated function names
            fn_detail: semicolon-separated "name (source)" strings
            fn_count:  number of triggered functions
        """
        fns = logs.get('triggeredFunctions', [])
        if not fns:
            return ('', '', 0)

        names = []
        details = []
        for fn in fns:
            name = fn.get('functionName', '(anonymous)')
            src = fn.get('source', '')  # 'addEventListener' or 'on-property'
            evt = fn.get('eventType', '')
            names.append(name)
            details.append('%s [%s/%s]' % (name, src, evt))

        return (
            '; '.join(names),
            '; '.join(details),
            len(fns),
        )

    def _output_csv(self):
        prefix = self._result_name_prefix()
        name_prefix = 'analysis_results_network' if self.network_only else 'analysis_results'
        filename = "%s_%s_%s.csv" % (name_prefix, prefix, self.session_ts)
        filepath = os.path.join(self.output_dir, filename)

        headers = [
            'page_url',
            'form_action', 'form_method', 'field_name', 'field_type',
            'phase', 'step', 'event_type',
            'dom_changes_count',
            'network_reqs_count', 'network_req_names', 'network_req_urls',
            'network_req_methods',
            'req_content_types', 'req_has_cookie', 'req_custom_headers',
            'res_statuses', 'res_body_lengths', 'res_content_types',
            'latencies_ms', 'res_redirected', 'res_response_returned',
            'res_has_set_cookie', 'res_body_previews',
            'html5_validation_count',
            'fired_events_meaningful', 'fired_events_total',
            'triggered_fn_count', 'triggered_fn_names', 'triggered_fn_detail',
            'classification',
        ]

        rows = []
        for form in self.results.get('forms', []):
            page_url = form.get('page_url', self.url)
            for field in form.get('fields', []):
                classification = field.get('classification', '')

                # Typing logs
                for char_entry in field.get('typing_log', []):
                    char = char_entry.get('char', '')
                    for phase in ('keydown', 'keypress', 'input', 'keyup'):
                        logs = char_entry.get(phase, {})
                        ni = self._extract_network_info(logs)
                        evt_meaningful, evt_total = self._count_meaningful_events(logs)
                        fn_names, fn_detail, fn_count = self._extract_triggered_functions(logs)
                        rows.append([
                            page_url,
                            form['action'], form['method'],
                            field['name'], field['type'],
                            'typing_' + phase,
                            logs.get('step', ''),
                            'typing_' + phase + '_' + char,
                            len(logs.get('domChanges', [])),
                            ni['net_count'], ni['net_names'], ni['net_urls'],
                            ni['net_methods'],
                            ni['req_content_types'], ni['req_has_cookie'],
                            ni['req_custom_headers'],
                            ni['res_statuses'], ni['res_body_lengths'],
                            ni['res_content_types'], ni['latencies_ms'],
                            ni['res_redirected'], ni['res_response_returned'],
                            ni['res_has_set_cookie'], ni['res_body_previews'],
                            len(logs.get('html5Validation', [])),
                            evt_meaningful, evt_total,
                            fn_count, fn_names, fn_detail,
                            classification,
                        ])

            submit_logs = form.get('submit_log', {})
            for submit_phase in ('enter_key_logs', 'submit_click_logs'):
                logs = submit_logs.get(submit_phase, {})
                if isinstance(logs, dict) and logs:
                    ni = self._extract_network_info(logs)
                    evt_meaningful, evt_total = self._count_meaningful_events(logs)
                    fn_names, fn_detail, fn_count = self._extract_triggered_functions(logs)
                    rows.append([
                        page_url,
                        form['action'], form['method'],
                        '__form_submit__', '',
                        submit_phase,
                        logs.get('step', ''),
                        submit_phase,
                        len(logs.get('domChanges', [])),
                        ni['net_count'], ni['net_names'], ni['net_urls'],
                        ni['net_methods'],
                        ni['req_content_types'], ni['req_has_cookie'],
                        ni['req_custom_headers'],
                        ni['res_statuses'], ni['res_body_lengths'],
                        ni['res_content_types'], ni['latencies_ms'],
                        ni['res_redirected'], ni['res_response_returned'],
                        ni['res_has_set_cookie'], ni['res_body_previews'],
                        len(logs.get('html5Validation', [])),
                        evt_meaningful, evt_total,
                        fn_count, fn_names, fn_detail,
                        form.get('overall_classification', ''),
                    ])

                # Backspace logs
                for phase in ('keydown', 'input', 'keyup'):
                    logs = field.get('backspace_log', {}).get(phase, {})
                    if logs:
                        ni = self._extract_network_info(logs)
                        evt_meaningful, evt_total = self._count_meaningful_events(logs)
                        fn_names, fn_detail, fn_count = self._extract_triggered_functions(logs)
                        rows.append([
                            page_url,
                            form['action'], form['method'],
                            field['name'], field['type'],
                            'backspace_' + phase,
                            logs.get('step', ''),
                            'backspace',
                            len(logs.get('domChanges', [])),
                            ni['net_count'], ni['net_names'], ni['net_urls'],
                            ni['net_methods'],
                            ni['req_content_types'], ni['req_has_cookie'],
                            ni['req_custom_headers'],
                            ni['res_statuses'], ni['res_body_lengths'],
                            ni['res_content_types'], ni['latencies_ms'],
                            ni['res_redirected'], ni['res_response_returned'],
                            ni['res_has_set_cookie'], ni['res_body_previews'],
                            len(logs.get('html5Validation', [])),
                            evt_meaningful, evt_total,
                            fn_count, fn_names, fn_detail,
                            classification,
                        ])

                # Other logs
                for phase_name, logs in field.get('other_log', {}).items():
                    if isinstance(logs, dict) and logs:
                        ni = self._extract_network_info(logs)
                        evt_meaningful, evt_total = self._count_meaningful_events(logs)
                        fn_names, fn_detail, fn_count = self._extract_triggered_functions(logs)
                        rows.append([
                            page_url,
                            form['action'], form['method'],
                            field['name'], field['type'],
                            phase_name,
                            logs.get('step', ''),
                            phase_name,
                            len(logs.get('domChanges', [])),
                            ni['net_count'], ni['net_names'], ni['net_urls'],
                            ni['net_methods'],
                            ni['req_content_types'], ni['req_has_cookie'],
                            ni['req_custom_headers'],
                            ni['res_statuses'], ni['res_body_lengths'],
                            ni['res_content_types'], ni['latencies_ms'],
                            ni['res_redirected'], ni['res_response_returned'],
                            ni['res_has_set_cookie'], ni['res_body_previews'],
                            len(logs.get('html5Validation', [])),
                            evt_meaningful, evt_total,
                            fn_count, fn_names, fn_detail,
                            classification,
                        ])

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)

        print("[FormAnalyzer] CSV saved: %s" % filepath)

    def _result_name_prefix(self):
        """Build a stable, filesystem-safe prefix for output file names.

        Priority:
        1) kit_path basename (whitebox mode, most reliable)
        2) URL path basename
        3) URL host
        """
        candidate = ""
        if self.kit_path:
            candidate = os.path.basename(os.path.normpath(self.kit_path))
        if not candidate and self.url:
            parsed = urlparse(self.url)
            path_base = os.path.basename(parsed.path.rstrip('/'))
            candidate = path_base or parsed.netloc
        if not candidate:
            candidate = "unknown_kit"

        # Keep letters/numbers/._- only; replace everything else with "_"
        safe = re.sub(r'[^A-Za-z0-9._-]+', '_', candidate)
        return safe.strip('._-') or "unknown_kit"

    def _record_cdp_requests(self, requests):
        """Keep a deduplicated global view of CDP-backed network traces."""
        for req in requests or []:
            request_id = req.get('requestId')
            if not request_id:
                continue
            self._cdp_network_index[request_id] = req
        self.results['cdp_network'] = sorted(
            self._cdp_network_index.values(),
            key=lambda x: (
                x.get('sequence', 0),
                x.get('lastEventTs', 0),
                x.get('requestId', ''),
            ),
        )

    def _clear_logs(self):
        """Clear browser-side JS logs and drain CDP perf events into the
        global index (so page-load / resource requests are NOT lost).

        Previously drain_cdp_network_logs() was called and its return value
        thrown away, which caused document/script/img/XHR requests that fired
        before a phase boundary to disappear from cdp_network entirely.
        """
        try:
            self.driver.execute_script("window.__fa_getAndClearLogs()")
        except Exception:
            pass
        try:
            cdp_logs = drain_cdp_network_logs(self.driver)
            # Accumulate into top-level index -- never discard
            self._record_cdp_requests(cdp_logs)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _collect_logs(self):
        """Retrieve and clear browser-side logs.

        If a hash DB is loaded, automatically tags triggeredFunctions
        as 'default' (library/noise) or 'kit-specific'.
        """
        # Ensure optional jQuery provenance hooks are installed before
        # collecting logs so dispatch metadata can be captured in the same phase.
        self._ensure_jquery_provenance_hooks()

        try:
            raw = self.driver.execute_script(
                "return window.__fa_getAndClearLogs()")
            logs = json.loads(raw)
        except Exception as e:
            logging.warning("Failed to collect logs: %s", e)
            logs = {}

        cdp_logs = []
        try:
            cdp_logs = drain_cdp_network_logs(self.driver)
        except Exception as e:
            logging.debug("Failed to drain CDP logs: %s", e)
        logs['cdpNetworkReqs'] = cdp_logs
        self._record_cdp_requests(cdp_logs)

        # Merge jQuery dispatch provenance logs (if available).
        try:
            jq_raw = self.driver.execute_script(
                "return (window.__fa_getAndClearJqueryDispatchLogs && "
                "window.__fa_getAndClearJqueryDispatchLogs()) || '[]'")
            jq_logs = json.loads(jq_raw)
            logs['jqueryDispatchLogs'] = jq_logs
        except Exception:
            logs['jqueryDispatchLogs'] = []

        # Attach nearest jQuery dispatch context to triggered functions.
        self._enrich_triggered_functions_with_jquery_context(logs)

        # Tag triggered functions with hash-based noise detection
        if self._default_hashes:
            for fn in logs.get('triggeredFunctions', []):
                fn_source = fn.get('functionSource', '')
                fn_hash = self._hash_function_body(fn_source)
                fn['bodyHash'] = fn_hash
                fn['isDefault'] = fn_hash in self._default_hashes

        return logs

    def _ensure_jquery_provenance_hooks(self):
        """Install runtime hooks to capture jQuery dispatch provenance.

        We cannot always map anonymous wrappers to attacker-authored logic
        from function name alone. This hook records dispatch-time handler
        metadata (handler names/selectors/source snippets), allowing
        post-analysis to explain *why* jQuery dispatch fired.
        """
        try:
            self.driver.execute_script(r"""
                (function () {
                  if (window.__fa_jq_hook_installed) return true;
                  if (!window.jQuery || !window.jQuery.event) return false;

                  var $ = window.jQuery;
                  window.__fa_jq_dispatch_logs = window.__fa_jq_dispatch_logs || [];

                  function getXPath(el) {
                    try {
                      if (!el || el.nodeType !== 1) return "";
                      if (el.id) return '//*[@id="' + el.id + '"]';
                      var parts = [];
                      while (el && el.nodeType === 1) {
                        var ix = 1, sib = el.previousSibling;
                        while (sib) {
                          if (sib.nodeType === 1 && sib.nodeName === el.nodeName) ix++;
                          sib = sib.previousSibling;
                        }
                        parts.unshift(el.nodeName.toLowerCase() + "[" + ix + "]");
                        el = el.parentNode;
                      }
                      return "/" + parts.join("/");
                    } catch (e) {
                      return "";
                    }
                  }

                  var origAdd = $.event.add;
                  $.event.add = function (elem, types, handler, data, selector) {
                    try {
                      if (typeof handler === "function") {
                        if (!handler.__faRegMeta) {
                          handler.__faRegMeta = {
                            registeredTypes: String(types || ""),
                            selector: String(selector || ""),
                            name: String(handler.name || "(anonymous)"),
                            source: (handler.toString ? String(handler.toString()) : "").slice(0, 800),
                            registeredAt: ((new Error()).stack || "").slice(0, 1200)
                          };
                        }
                      }
                    } catch (e) {}
                    return origAdd.apply(this, arguments);
                  };

                  var origDispatch = $.event.dispatch;
                  $.event.dispatch = function (nativeEvent) {
                    try {
                      var e = nativeEvent || window.event || {};
                      var t = String(e.type || "");
                      var target = e.target || this;
                      var eventsObj = null;
                      var handlersArr = [];
                      try {
                        eventsObj = ($._data && $._data(this, "events")) ? $._data(this, "events") : null;
                        if (eventsObj && eventsObj[t]) handlersArr = eventsObj[t];
                      } catch (_e) {}

                      var handlers = [];
                      for (var i = 0; i < handlersArr.length && i < 12; i++) {
                        var h = handlersArr[i] || {};
                        var fn = h.handler || h.origHandler || null;
                        var meta = (fn && fn.__faRegMeta) ? fn.__faRegMeta : {};
                        handlers.push({
                          name: String((fn && fn.name) || meta.name || "(anonymous)"),
                          selector: String(h.selector || meta.selector || ""),
                          namespace: String(h.namespace || ""),
                          origType: String(h.origType || ""),
                          guid: h.guid || (fn && fn.guid) || null,
                          registeredTypes: String(meta.registeredTypes || ""),
                          source: String(meta.source || ((fn && fn.toString) ? fn.toString() : "")).slice(0, 800)
                        });
                      }

                      window.__fa_jq_dispatch_logs.push({
                        timestamp: Date.now(),
                        eventType: t,
                        currentTargetXPath: getXPath(this),
                        targetXPath: getXPath(target),
                        handlerCount: handlersArr.length || 0,
                        handlers: handlers
                      });

                      if (window.__fa_jq_dispatch_logs.length > 5000) {
                        window.__fa_jq_dispatch_logs.splice(
                          0,
                          window.__fa_jq_dispatch_logs.length - 5000
                        );
                      }
                    } catch (e) {}
                    return origDispatch.apply(this, arguments);
                  };

                  window.__fa_getAndClearJqueryDispatchLogs = function () {
                    try {
                      var out = window.__fa_jq_dispatch_logs || [];
                      window.__fa_jq_dispatch_logs = [];
                      return JSON.stringify(out);
                    } catch (e) {
                      return "[]";
                    }
                  };

                  window.__fa_jq_hook_installed = true;
                  return true;
                })();
            """)
        except Exception:
            pass

    @staticmethod
    def _enrich_triggered_functions_with_jquery_context(logs):
        """Map triggered functions to nearest jQuery dispatch metadata."""
        fns = logs.get('triggeredFunctions', []) or []
        jq_logs = logs.get('jqueryDispatchLogs', []) or []
        if not fns or not jq_logs:
            return

        # Sort once for deterministic nearest-time matching.
        jq_sorted = sorted(
            jq_logs, key=lambda x: x.get('timestamp') or 0
        )
        for fn in fns:
            evt = str(fn.get('eventType') or '').lower()
            fx = str(fn.get('elementXPath') or '')
            ft = fn.get('timestamp') or 0

            candidates = []
            for j in jq_sorted:
                je = str(j.get('eventType') or '').lower()
                if evt and je and evt != je:
                    continue
                j_target = str(j.get('targetXPath') or '')
                j_cur = str(j.get('currentTargetXPath') or '')
                # Prefer same target/currentTarget, but allow same-event fallback.
                score = 0
                if fx and (fx == j_target or fx == j_cur):
                    score += 2
                jt = j.get('timestamp') or 0
                dt = abs((ft or 0) - jt)
                candidates.append((score, -dt, j))

            if not candidates:
                continue

            # Highest score, then nearest timestamp.
            candidates.sort(reverse=True, key=lambda x: (x[0], x[1]))
            best = candidates[0][2]
            fn['jquery_context'] = {
                'handlerCount': best.get('handlerCount', 0),
                'targetXPath': best.get('targetXPath', ''),
                'currentTargetXPath': best.get('currentTargetXPath', ''),
                'handlers': best.get('handlers', [])[:5],
            }

    # ------------------------------------------------------------------
    # Hash DB helpers
    # ------------------------------------------------------------------

    def _load_hash_db(self, hash_db_path):
        """Load default function hashes from a directory of hash files.

        The hash DB directory is expected to contain files named
        <sha256_hash>.txt (as produced by 01_add_hash_value.py).
        """
        count = 0
        for fname in os.listdir(hash_db_path):
            if len(fname) == 68 and fname.endswith('.txt'):
                # filename = <64-char hash>.txt
                self._default_hashes.add(fname[:-4])
                count += 1
        if count > 0:
            print("[HashDB] Loaded %d default function hashes from %s"
                  % (count, hash_db_path))
        else:
            logging.warning("Hash DB directory has no hash files: %s",
                            hash_db_path)

    @staticmethod
    def _hash_function_body(fn_source):
        """Compute SHA-256 hash of a function body, matching the
        normalisation used by 01_add_hash_value.py:
        strip whitespace, wrap in braces.
        """
        if not fn_source:
            return ''
        # Extract body between first { and matching }
        start = fn_source.find('{')
        if start == -1:
            body = fn_source
        else:
            body = fn_source[start:]
        # Remove all whitespace (same as remove_whitespace in 01_add_hash_value.py)
        normalised = re.sub(r'\s+', '', body)
        if not normalised.startswith('{'):
            normalised = '{' + normalised + '}'
        return hashlib.sha256(normalised.encode()).hexdigest()

    def _get_xpath(self, element):
        try:
            return self.driver.execute_script(
                "return getXPath(arguments[0])", element)
        except Exception:
            return 'unknown'

    def _discover_fields(self, form_el):
        """Find all analysable fields within a form element.

        Includes text-type inputs, textareas, and interactive elements
        (select, checkbox, radio) so that their event handlers can also
        be observed.
        """
        fields = []
        try:
            inputs = form_el.find_elements(By.TAG_NAME, "input")
            for inp in inputs:
                inp_type = (inp.get_attribute("type") or "text").lower()
                if inp_type in self.ANALYSABLE_TYPES:
                    fields.append({
                        'element': inp,
                        'type': inp_type,
                        'name': inp.get_attribute("name") or '',
                        'xpath': self._get_xpath(inp),
                        'minlength': inp.get_attribute("minlength") or '',
                        'maxlength': inp.get_attribute("maxlength") or '',
                        'pattern': inp.get_attribute("pattern") or '',
                    })
                elif inp_type in self.INTERACTIVE_TYPES:
                    fields.append({
                        'element': inp,
                        'type': inp_type,
                        'name': inp.get_attribute("name") or '',
                        'xpath': self._get_xpath(inp),
                        'interactive': True,
                    })

            textareas = form_el.find_elements(By.TAG_NAME, "textarea")
            for ta in textareas:
                fields.append({
                    'element': ta,
                    'type': 'textarea',
                    'name': ta.get_attribute("name") or '',
                    'xpath': self._get_xpath(ta),
                    'minlength': ta.get_attribute("minlength") or '',
                    'maxlength': ta.get_attribute("maxlength") or '',
                    'pattern': ta.get_attribute("pattern") or '',
                })

            selects = form_el.find_elements(By.TAG_NAME, "select")
            for sel in selects:
                fields.append({
                    'element': sel,
                    'type': 'select',
                    'name': sel.get_attribute("name") or '',
                    'xpath': self._get_xpath(sel),
                    'interactive': True,
                })
        except StaleElementReferenceException:
            logging.warning("Stale element while discovering fields")

        return fields

    def _find_submit_button(self, form_el):
        """Find a submit button within a form element.

        Phishing kits often use non-standard submit patterns:
        - <input type="button"> or <input type="image">
        - <div onclick="..."> styled as a button
        - <a href="#"> styled as a button
        - Last <input> in a <div> that looks like a button
        We search broadly and pick the best candidate.
        """
        # Priority 1: standard submit elements
        selectors_priority = [
            "input[type='submit']",
            "button[type='submit']",
            "button:not([type])",
            # Priority 2: common phishing kit patterns
            "input[type='button']",
            "input[type='image']",
            "button",
            # Priority 3: clickable elements with submit-like attributes
            "[onclick*='submit']",
            "[onclick*='Submit']",
            "a[onclick]",
            "div[onclick]",
            "span[onclick]",
        ]
        for selector in selectors_priority:
            try:
                btns = form_el.find_elements(By.CSS_SELECTOR, selector)
                if btns:
                    return btns[0]
            except Exception:
                continue

        # Priority 4: last input/div/a in the form that isn't a text field
        # (phishing kits often put the submit element at the end)
        try:
            all_inputs = form_el.find_elements(By.TAG_NAME, "input")
            for inp in reversed(all_inputs):
                inp_type = (inp.get_attribute("type") or "").lower()
                if inp_type not in self.ANALYSABLE_TYPES and inp_type != 'hidden':
                    return inp
        except Exception:
            pass

        # Priority 5: any div/a/span that looks like a button (by class/role)
        try:
            candidates = form_el.find_elements(
                By.CSS_SELECTOR,
                "[role='button'], [class*='btn'], [class*='button'], "
                "[class*='submit'], [class*='login'], [class*='sign']")
            if candidates:
                return candidates[0]
        except Exception:
            pass

        return None

    def _find_submit_button_by_page(self):
        """Find a submit button anywhere on the current page (after reload)."""
        selectors = [
            "input[type='submit']",
            "button[type='submit']",
            "button:not([type])",
            "input[type='button']",
            "input[type='image']",
            "[onclick*='submit']",
            "[role='button']",
            "[class*='btn'], [class*='button'], [class*='submit']",
        ]
        for selector in selectors:
            try:
                btns = self.driver.find_elements(By.CSS_SELECTOR, selector)
                if btns:
                    return btns[0]
            except Exception:
                continue

        # Fallback: last non-text input in any form
        try:
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            if forms:
                all_inputs = forms[0].find_elements(By.TAG_NAME, "input")
                for inp in reversed(all_inputs):
                    inp_type = (inp.get_attribute("type") or "").lower()
                    if inp_type not in self.ANALYSABLE_TYPES and inp_type != 'hidden':
                        return inp
        except Exception:
            pass

        return None

    @staticmethod
    def _safe_int(value, default):
        try:
            if value is None or value == '':
                return default
            return int(value)
        except Exception:
            return default

    def _generate_input(self, field_info):
        """Generate test characters appropriate for the field type.

        Returns a full valid-ish string so that HTML5 validation and
        server-side checks can be properly triggered.
        """
        if isinstance(field_info, dict):
            field_type = field_info.get('type', '')
            minlength = self._safe_int(field_info.get('minlength'), 0)
            maxlength = self._safe_int(field_info.get('maxlength'), 64)
            pattern = field_info.get('pattern', '') or ''
        else:
            field_type = field_info
            minlength = 0
            maxlength = 64
            pattern = ''

        maxlength = max(1, maxlength)
        minlength = min(max(0, minlength), maxlength)

        if field_type == 'email':
            # Generate a realistic email that passes both HTML5 validation
            # and common regex filters (e.g. TLD must be 2-4 chars).
            user_len = max(4, minlength, 4)
            user_len = min(user_len, max(4, maxlength - 9))
            user = ''.join(random.choice(string.ascii_lowercase)
                          for _ in range(user_len))
            return '%s@tesq.com' % user
        elif field_type in ('number', 'tel'):
            low = max(3, minlength)
            high = max(low, min(maxlength, 8))
            length = random.randint(low, high)
            return ''.join(random.choice(string.digits) for _ in range(length))
        elif field_type == 'url':
            return 'http://t.co'
        elif field_type == 'password':
            # Mix letters and digits so common password-strength validators
            # produce observable reactions.
            low = max(5, minlength)
            high = max(low, min(maxlength, 12))
            length = random.randint(low, high)
            if pattern == r'.{5,50}' and length < 5:
                length = 5
            return ''.join(random.choice(string.ascii_letters + string.digits)
                           for _ in range(length))
        else:
            low = max(3, minlength)
            high = max(low, min(maxlength, 12))
            length = random.randint(low, high)
            return ''.join(
                random.choice(string.ascii_lowercase) for _ in range(length))

    def _dismiss_alert(self):
        try:
            alert = self.driver.switch_to.alert
            alert.dismiss()
        except NoAlertPresentException:
            pass
        except Exception:
            pass
