from selenium import webdriver
from selenium.webdriver.remote.webdriver import WebDriver
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.chrome.service import Service
import argparse
import os
import sys
import time
import atexit
from urllib.parse import quote

from Classes import *

parser = argparse.ArgumentParser(description='Crawler')
parser.add_argument("--debug", action='store_true',  help="Dont use path deconstruction and recon scan. Good for testing single URL")
parser.add_argument("--url", help="Custom URL to crawl")
parser.add_argument("--analyze", action='store_true', help="Form dynamic behavior analysis mode: traces JS calls, DOM changes, network requests per keystroke")
parser.add_argument("--delay", type=int, default=30, help="Delay in seconds between each sub-event in analyze mode (default: 30)")
parser.add_argument("--network-only", action='store_true', help="Fast analyze mode: skip per-field typing/validation and collect submit-centered network traces only")
parser.add_argument("--kit-path", help="(Whitebox) Local path to phishing kit directory. Scans all PHP/HTML files and generates URLs to visit, so hidden pages not linked from the landing page are also analysed.")
parser.add_argument("--headless", action='store_true', help="Run Chrome in headless mode (for Linux servers without a display)")
parser.add_argument("--chrome-bin", help="Path to Chrome/Chromium binary (e.g. /usr/bin/chromium-browser)")
parser.add_argument("--hash-db", help="Path to default function hash DB directory (from 01_add_hash_value.py) for noise filtering")
parser.add_argument("--max-pages", type=int, default=0, help="Max number of pages to visit per kit (0 = use built-in defaults). Useful for large kits with thousands of files.")

# Legit mode arguments
parser.add_argument("--legit", action='store_true', help="Legitimate website analysis mode: dual-phase header capture (CDP ground truth + JS-visible layer) for external sites without a local kit")
parser.add_argument("--username", help="Username or email to inject into login forms in --legit mode")
parser.add_argument("--password", help="Password to inject into login forms in --legit mode")
parser.add_argument("--crawl-delay", type=float, default=2.0, help="Seconds to wait between page visits in --legit mode (default: 2). Reduces bot-detection risk on real sites.")
parser.add_argument("--manual", action='store_true', help="Manual interaction mode for --legit: tool sets up CDP+JS hooks, human drives the browser. Use for anti-bot / SSO / MFA-protected sites.")

# Batch mode arguments
parser.add_argument("--batch-root", help="Root directory containing multiple phishing kits. Each subdirectory (recursively) that contains index.html/index.php is treated as one kit. Requires --analyze.")
parser.add_argument("--web-root", help="Local web server document root (e.g. /var/www/html). Used with --batch-root to compute URLs from file paths.")
parser.add_argument("--base-url", default="http://localhost", help="Base URL of the local web server (default: http://localhost)")
parser.add_argument("--num", type=int, default=0, help="Max number of kits to process in batch mode (0 = all)")
parser.add_argument("--skip", type=int, default=0, help="Skip the first N kits in batch mode (for resuming)")
args = parser.parse_args()

# Clean form_files/dynamic
root_dirname = os.path.dirname(__file__)
dynamic_path = os.path.join(root_dirname, 'form_files', 'dynamic')
if os.path.isdir(dynamic_path):
    for f in os.listdir(dynamic_path):
        os.remove(os.path.join(dynamic_path, f))


# ---- Tee: duplicate stdout/stderr to command_logs.txt ----
class _Tee:
    """Write to both the original stream and a log file."""
    def __init__(self, stream, logfile):
        self._stream = stream
        self._logfile = logfile

    def write(self, data):
        self._stream.write(data)
        try:
            self._logfile.write(data)
            self._logfile.flush()
        except Exception:
            pass

    def flush(self):
        self._stream.flush()
        try:
            self._logfile.flush()
        except Exception:
            pass

    def fileno(self):
        return self._stream.fileno()

    def isatty(self):
        return self._stream.isatty()

_results_subdir = 'analysis_results_network' if args.network_only else 'analysis_results'
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
output_dir = os.path.join(_repo_root, 'results', 'dynamic_analysis_blackwidow', _results_subdir)
os.makedirs(output_dir, exist_ok=True)
_log_path = os.path.join(output_dir, 'command_logs.txt')
_driver_log_path = os.path.join(output_dir, 'chromedriver.log')
_log_fh = open(_log_path, 'a', encoding='utf-8')
_log_fh.write("\n" + "=" * 60 + "\n")
_log_fh.write("[Session] %s\n" % time.strftime('%Y-%m-%d %H:%M:%S'))
_log_fh.write("[Args] %s\n" % ' '.join(sys.argv))
_log_fh.write("[DriverLog] %s\n" % _driver_log_path)
_log_fh.write("=" * 60 + "\n")
sys.stdout = _Tee(sys.__stdout__, _log_fh)
sys.stderr = _Tee(sys.__stderr__, _log_fh)
print("[Log] Terminal output is being saved to: %s" % _log_path)
print("[Log] ChromeDriver log is being saved to: %s" % _driver_log_path)


WebDriver.add_script = add_script


chrome_options = webdriver.ChromeOptions()
# --disable-web-security is needed for Phase B XHR interception in automated legit
# mode and for accessing local phishing kit pages.  Skip it in --manual mode so the
# browser fingerprint looks like a normal user's browser (anti-bot detects this flag).
if not args.manual:
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--disable-xss-auditor")

# Incognito mode for --legit: no cached cookies/storage from prior sessions
# that could bias per-keystroke AJAX validation or session establishment signals.
if args.legit:
    chrome_options.add_argument("--incognito")

# Anti-bot detection evasion: hide Selenium/automation fingerprints
chrome_options.add_argument("--disable-blink-features=AutomationControlled")
chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
chrome_options.add_experimental_option("useAutomationExtension", False)
chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})

# "eager" page load: DOM ready is enough, don't wait for external
# CSS/JS/images.  Cloned phishing pages often reference 50-100+ CDN
# resources (optimum.net, facebook.net, etc.) that timeout in offline
# environments, causing driver.get() to stall for minutes.
chrome_options.page_load_strategy = 'eager'

# Realistic User-Agent: many phishing kits block UAs containing
# "HeadlessChrome", "bot", "crawl", "python", "selenium", etc.
chrome_options.add_argument(
    "user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

# Headless mode for Linux servers without a display
if args.headless:
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--window-size=1920,1080")

# Custom Chrome/Chromium binary path
if args.chrome_bin:
    chrome_options.binary_location = args.chrome_bin

# ==================================================================
# Helper functions
# ==================================================================

def load_analyze_scripts(drv, js_directory):
    """Load JavaScript scripts needed for --analyze mode."""
    for fname in ["lib.js", "property_obs.js", "md5.js",
                   "addeventlistener_wrapper.js", "timing_wrapper.js",
                   "window_wrapper.js", "forms.js", "form_analyzer.js",
                   "remove_alerts.js"]:
        drv.add_script(open(os.path.join(js_directory, fname), "r").read())


def create_driver(opts):
    """Create a fresh Chrome WebDriver with the given options."""
    service = Service(
        log_output=_driver_log_path,
        service_args=["--verbose"],
    )
    drv = webdriver.Chrome(service=service, options=opts)

    # Prevent external-resource stalls from blocking the crawl.
    # 30s is generous for local pages; external CDN refs will simply fail.
    drv.set_page_load_timeout(30)
    drv.set_script_timeout(15)

    # Mask navigator.webdriver and other automation fingerprints.
    # This runs before any page script, hiding Selenium from JS detection.
    drv.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {"source": """
        // Hide navigator.webdriver
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

        // Hide chrome.runtime (sometimes checked by anti-bot scripts)
        if (window.chrome) {
            window.chrome.runtime = undefined;
        }

        // Mask permissions query for notifications
        const origQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (params) =>
            params.name === 'notifications'
                ? Promise.resolve({state: Notification.permission})
                : origQuery(params);

        // Override navigator.plugins to look like a real browser
        Object.defineProperty(navigator, 'plugins', {
            get: () => [1, 2, 3, 4, 5]
        });
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en']
        });

        // Prevent window.open() from creating new tabs.  Cloned sites
        // (e.g. casas bahia) embed Google Ads iframes whose click handlers
        // call window.open(googleads.g.doubleclick.net/..., '_blank'),
        // spawning dozens of dead tabs in an offline environment.
        window.open = function() { return null; };

        // Prevent print dialogs from blocking Selenium execution.
        // Some kits bind footer/header links to window.print(), which opens
        // a native modal the driver cannot reliably dismiss.
        window.print = function() { return false; };
    """})

    # Enable CDP network events so request/response metadata can be
    # drained phase-by-phase from Selenium performance logs.
    try:
        drv.execute_cdp_cmd("Page.enable", {})
    except Exception:
        pass
    try:
        drv.execute_cdp_cmd("Network.enable", {})
    except Exception:
        pass
    try:
        drv.execute_cdp_cmd("Network.setCacheDisabled", {"cacheDisabled": True})
    except Exception:
        pass

    return drv


def recreate_driver(current_driver, opts, js_directory=None, retries=3, sleep_sec=2, context=""):
    """Best-effort driver recreation with retry/backoff.

    Returns a working driver instance on success, or None on failure.
    """
    try:
        if current_driver is not None:
            current_driver.quit()
    except Exception:
        pass

    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            new_driver = create_driver(opts)
            if js_directory:
                load_analyze_scripts(new_driver, js_directory)
            if attempt > 1:
                print("[Batch] Browser recreated successfully on attempt %d%s"
                      % (attempt, (" (%s)" % context) if context else ""))
            return new_driver
        except Exception as e:
            last_exc = e
            print("[Batch] Browser recreate failed (%d/%d)%s: %s"
                  % (attempt, retries, (" (%s)" % context) if context else "", e))
            if attempt < retries:
                time.sleep(sleep_sec * attempt)

    if last_exc is not None:
        print("[Batch] Browser recreate exhausted retries%s. Last error: %s"
              % ((" (%s)" % context) if context else "", last_exc))
    return None


def discover_kits(batch_root, web_root, base_url):
    """Walk batch_root and discover phishing kit entry points.

    A directory that contains ``index.html`` or ``index.php`` (or, failing
    that, any ``.html``/``.php`` file) is treated as a candidate entry
    point.  Kits are grouped by the first-level subdirectory under
    batch_root (the "kit root").  For each kit only the shallowest
    entry point is kept.

    Returns a sorted list of dicts::

        {'name': str, 'kit_path': str, 'url': str}
    """
    kit_entries = {}  # kit_root_name -> {name, kit_path, url, depth}

    for dirpath, _dirnames, filenames in os.walk(batch_root):
        # --- find an entry file ----
        entry_file = None
        for candidate in ('index.html', 'index.php'):
            if candidate in filenames:
                entry_file = candidate
                break
        if entry_file is None:
            for f in sorted(filenames):
                if f.endswith(('.html', '.php')):
                    entry_file = f
                    break
        if entry_file is None:
            continue

        # --- determine kit root (first level under batch_root) ---
        rel = os.path.relpath(dirpath, batch_root)
        if rel == '.':
            continue  # skip batch_root itself
        parts = rel.split(os.sep)
        kit_name = parts[0]
        kit_path = os.path.join(batch_root, kit_name)
        depth = len(parts)

        if kit_name not in kit_entries or depth < kit_entries[kit_name]['depth']:
            rel_to_web = os.path.relpath(dirpath, web_root)
            # URL-encode each path segment so spaces and special chars
            # (e.g. "1 2.html") become valid URL components ("%201%202.html").
            encoded_path = '/'.join(
                quote(seg, safe='') for seg in rel_to_web.replace(os.sep, '/').split('/')
            )
            url = base_url.rstrip('/') + '/' + encoded_path + '/'
            kit_entries[kit_name] = {
                'name': kit_name,
                'kit_path': kit_path,
                'url': url,
                'depth': depth,
            }

    return sorted(kit_entries.values(), key=lambda k: k['name'])


# ==================================================================
# Launch Chrome
# ==================================================================
driver = recreate_driver(None, chrome_options, retries=3, sleep_sec=2, context="initial startup")
if driver is None:
    raise RuntimeError("Could not start Chrome WebDriver after retries.")


def _cleanup_runtime_resources():
    """Best-effort cleanup to avoid orphan browser processes."""
    global driver
    try:
        if driver is not None:
            driver.quit()
            driver = None
            print("[Cleanup] Browser driver terminated.")
    except Exception:
        pass
    try:
        _log_fh.flush()
        _log_fh.close()
    except Exception:
        pass


atexit.register(_cleanup_runtime_resources)

if args.legit:
    # ----------------------------------------------------------
    # Legit mode: header capture + JS instrumentation for real sites
    # ----------------------------------------------------------
    # Clear any residual disk cache and cookies via CDP so each run
    # starts from a clean state (equivalent to a fresh incognito profile).
    send(driver, "Network.clearBrowserCache", {})
    send(driver, "Network.clearBrowserCookies", {})

    # Loads the same JS scripts as --analyze so form_analyzer.js
    # XHR/fetch wrappers are active for signal collection.
    js_dir = os.path.join(root_dirname, 'js')
    load_analyze_scripts(driver, js_dir)

    if not args.url:
        print("--legit requires --url")
    elif args.manual:
        # -- Manual interaction mode -----------------------------
        # CDP + JS hooks are active; human drives the browser.
        # Use for anti-bot / SSO / MFA-protected sites where
        # automation triggers bot detection or requires live tokens.
        from LegitManualSession import LegitManualSession
        session = LegitManualSession(driver, args.url)
        session.run()
    else:
        # -- Automated mode --------------------------------------
        # Tool fills fields, submits, runs Phase A/B comparison.
        # Use for sites without strong bot protection.
        from LegitAnalyzer import LegitAnalyzer
        analyzer = LegitAnalyzer(
            driver, args.url,
            username=args.username,
            password=args.password,
            delay=args.crawl_delay,
        )
        analyzer.run()

elif args.analyze:
    # ----------------------------------------------------------
    # Analyze mode
    # ----------------------------------------------------------
    js_dir = os.path.join(root_dirname, 'js')
    load_analyze_scripts(driver, js_dir)

    from FormAnalyzer import FormAnalyzer
    import traceback

    if args.batch_root:
        # ======================================================
        # BATCH MODE: process many kits automatically
        # ======================================================
        web_root = args.web_root or '/var/www/html'
        kits = discover_kits(args.batch_root, web_root, args.base_url)
        total_discovered = len(kits)

        start_idx = args.skip
        end_idx = (start_idx + args.num) if args.num > 0 else total_discovered
        kits_to_process = kits[start_idx:end_idx]
        n_process = len(kits_to_process)

        print("=" * 60)
        print("[Batch] Discovered %d kits under %s" % (total_discovered, args.batch_root))
        print("[Batch] Processing %d kits (skip=%d, num=%s)"
              % (n_process, args.skip, args.num if args.num > 0 else 'all'))
        print("=" * 60)

        success = 0
        fail = 0
        failed_kits = []

        for i, kit in enumerate(kits_to_process):
            kit_idx = start_idx + i + 1
            print("\n" + "=" * 60)
            print("[Batch %d/%d] Kit: %s" % (kit_idx, total_discovered, kit['name']))
            print("  kit_path : %s" % kit['kit_path'])
            print("  url      : %s" % kit['url'])
            print("=" * 60)

            # --- Pre-kit cleanup: prevent state leaking between kits ---
            # Verify the browser is alive and responsive.  After a long
            # kit (e.g. WF_IJB with 2167 PHP files taking 2+ hours), the
            # browser may be unresponsive or have accumulated corrupt state.
            browser_ok = False
            for _attempt in range(2):
                try:
                    driver.delete_all_cookies()
                    driver.get("about:blank")
                    # Quick health check: execute a trivial JS expression
                    assert driver.execute_script("return 1+1") == 2
                    browser_ok = True
                    break
                except Exception:
                    print("[Batch] Browser unresponsive, restarting (attempt %d)..."
                          % (_attempt + 1))
                    driver = recreate_driver(
                        driver, chrome_options, js_directory=js_dir,
                        retries=3, sleep_sec=2, context="pre-kit health check"
                    )
                    if driver is None:
                        break

            if not browser_ok:
                print("[Batch] ERROR: Could not get a working browser, skipping kit")
                fail += 1
                failed_kits.append(kit['name'])
                continue

            try:
                analyzer = FormAnalyzer(
                    driver, kit['url'],
                    delay=args.delay,
                    network_only=args.network_only,
                    kit_path=kit['kit_path'],
                    hash_db=args.hash_db,
                    max_pages=args.max_pages)
                analyzer.start()
                success += 1
            except KeyboardInterrupt:
                print("\n[Batch] Interrupted by user. Stopping.")
                break
            except Exception as e:
                fail += 1
                failed_kits.append(kit['name'])
                print("[Batch] ERROR on kit %s: %s" % (kit['name'], e))
                traceback.print_exc()

                # Restart browser to recover from crash
                print("[Batch] Restarting browser...")
                driver = recreate_driver(
                    driver, chrome_options, js_directory=js_dir,
                    retries=3, sleep_sec=2, context="post-kit exception"
                )

            # Periodic browser restart to prevent memory leaks and
            # session corruption during long batch runs.
            if (i + 1) % 20 == 0:
                print("[Batch] Periodic browser restart (every 20 kits)...")
                driver = recreate_driver(
                    driver, chrome_options, js_directory=js_dir,
                    retries=3, sleep_sec=2, context="periodic restart"
                )

            # Progress summary
            done = i + 1
            remaining = n_process - done
            print("[Batch] Progress: %d/%d done  |  success=%d  fail=%d  |  remaining=%d"
                  % (done, n_process, success, fail, remaining))

        # Final summary
        print("\n" + "=" * 60)
        print("[Batch] FINISHED")
        print("  Total kits discovered : %d" % total_discovered)
        print("  Processed             : %d" % (success + fail))
        print("  Success               : %d" % success)
        print("  Failed                : %d" % fail)
        if failed_kits:
            print("  Failed kits:")
            for fk in failed_kits:
                print("    - %s" % fk)
        print("=" * 60)

    elif args.url:
        # ======================================================
        # SINGLE KIT MODE (existing behaviour)
        # ======================================================
        url = args.url
        kit_path = args.kit_path or None
        analyzer = FormAnalyzer(driver, url, delay=args.delay,
                                network_only=args.network_only,
                                kit_path=kit_path,
                                hash_db=args.hash_db,
                                max_pages=args.max_pages)
        analyzer.start()
    else:
        print("Please use --url or --batch-root")

else:
    # ----------------------------------------------------------
    # Default mode: original BlackWidow crawl + XSS attack
    # ----------------------------------------------------------
    # Read scripts and add script which will be executed when the page starts loading
    ## JS libraries from JaK crawler, with minor improvements
    js_dir = os.path.join(root_dirname, 'js')
    driver.add_script( open(os.path.join(js_dir, "lib.js"), "r").read() )
    driver.add_script( open(os.path.join(js_dir, "property_obs.js"), "r").read() )
    driver.add_script( open(os.path.join(js_dir, "md5.js"), "r").read() )
    driver.add_script( open(os.path.join(js_dir, "addeventlistener_wrapper.js"), "r").read() )
    driver.add_script( open(os.path.join(js_dir, "timing_wrapper.js"), "r").read() )
    driver.add_script( open(os.path.join(js_dir, "window_wrapper.js"), "r").read() )
    # Black Widow additions
    driver.add_script( open(os.path.join(js_dir, "forms.js"), "r").read() )
    driver.add_script( open(os.path.join(js_dir, "xss_xhr.js"), "r").read() )
    driver.add_script( open(os.path.join(js_dir, "remove_alerts.js"), "r").read() )

    if args.url:
        url = args.url
        Crawler(driver, url).start(args.debug)
    else:
        print("Please use --url")
