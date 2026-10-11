#!/usr/bin/env python3
"""
Phishing kit brand extractor (HTML/PHP heuristic parser).

Methods:
  1. Rule-based artifact voting:
     title, meta, favicon, logo, form-action, copyright, placeholder,
     visible text, id/class/alt attrs -> brand candidate scoring.

  2. External-domain analysis:
     - External asset/script/link/redirect domains are frequency-counted
       per kit (cross-file); top domains are matched against a curated
       brand->domain map (EXTERNAL_DOMAIN_BRAND_MAP).
     - PHP header("Location: ...") and redirect variables are parsed
       to trace where the kit redirects victims after credential harvest.
     - Unrecognized external domains are token-mined for unknown brand
       candidates (dataset-driven discovery).

Usage:
    python3 brand_extractor_heuristics.py --kit-path /path/to/kit
    python3 brand_extractor_heuristics.py --batch-root /path/to/phishing_kits --num 100 --skip 200
"""

import argparse
import csv
import json
import os
import re
import time
from collections import defaultdict
from html.parser import HTMLParser
from urllib.parse import urlparse


HTML_EXTENSIONS = {".html", ".htm", ".php"}
SKIP_DIRS = {
    ".git", ".svn", "__pycache__", "node_modules", "vendor", ".idea",
    ".vscode", ".cursor", "__MACOSX"
}

MAX_READ_BYTES = 2 * 1024 * 1024

# -----------------------------------------------------------------------------
# Method 1: Canonical brand -> alias patterns (regex-based voting)
# -----------------------------------------------------------------------------
BRAND_PATTERNS = {
    "netflix":        [r"\bnetflix\b", r"nflxext", r"nflximg", r"nflxso"],
    "amazon":         [r"\bamazon\b", r"amzn", r"amazonaws", r"prime.?video", r"\baws\b"],
    "microsoft":      [r"\bmicrosoft\b", r"\boffice365\b", r"\boutlook\b",
                       r"\blive\.com\b", r"\bmsn\b", r"msftauth", r"microsoftonline",
                       r"\bonedrive\b", r"\bsharepoint\b", r"\bazure\b"],
    "apple":          [r"\bapple\b", r"\bicloud\b", r"\bitunes\b", r"\bappleid\b",
                       r"idmsa\.apple"],
    "google":         [r"\bgoogle\b", r"\bgmail\b", r"\bgoogleapis\b", r"\byoutube\b",
                       r"\bgstatic\b"],
    "facebook":       [r"\bfacebook\b", r"\bmeta\b", r"\bfbcdn\b", r"\bfb\.com\b",
                       r"connect\.facebook"],
    "instagram":      [r"\binstagram\b", r"\binsta\b", r"cdninstagram"],
    "paypal":         [r"\bpaypal\b", r"\bvenmo\b", r"paypalobjects"],
    "linkedin":       [r"\blinkedin\b", r"\blicdn\b"],
    "twitter":        [r"\btwitter\b", r"\btwimg\b", r"\bx\.com\b"],
    "whatsapp":       [r"\bwhatsapp\b"],
    "telegram":       [r"\btelegram\b"],
    "dropbox":        [r"\bdropbox\b", r"dropboxstatic"],
    "adobe":          [r"\badobe\b", r"\bacrobat\b", r"\bsign\.adobe\b", r"adobelogin",
                       r"adobeid", r"echosign"],
    "docusign":       [r"\bdocusign\b", r"\bdocucdn\b"],
    "dhl":            [r"\bdhl\b"],
    "ups":            [r"\bups\b", r"\bunited parcel\b"],
    "fedex":          [r"\bfedex\b"],
    "bankofamerica":  [r"bank of america", r"\bbankofamerica\b", r"\bbofa\b"],
    "chase":          [r"\bchase\b", r"\bjpmorgan\b", r"\bjp morgan\b"],
    "wellsfargo":     [r"\bwells[\s_-]?fargo\b"],
    "citibank":       [r"\bciti\b", r"\bcitibank\b"],
    "hsbc":           [r"\bhsbc\b"],
    "santander":      [r"\bsantander\b"],
    "bbva":           [r"\bbbva\b"],
    "caixabank":      [r"\bcaixabank\b"],
    "societegenerale":[r"societe generale", r"soci.t.g.n.rale", r"\bsg\b"],
    "creditagricole": [r"credit agricole", r"cr.dit agricole"],
    "usbank":         [r"\busbank\b", r"u\.s\.?\s*bank", r"us\s*bank"],
    "optus":          [r"\boptus\b"],
    "commbank":       [r"\bcommbank\b", r"commonwealth bank", r"\bnetbank\b"],
    "nab":            [r"\bnab\b", r"national australia bank"],
    "anz":            [r"\banz\b"],
    "ing":            [r"\bing\b", r"\bing direct\b"],
    "scotiabank":     [r"\bscotiabank\b", r"\bscotia\b"],
    "rbc":            [r"\brbc\b", r"royal bank of canada", r"rbcroyalbank"],
    "tdbank":         [r"\btd bank\b", r"\btdbank\b"],
}

# -----------------------------------------------------------------------------
# Method 2: External CDN/service domain -> canonical brand
# Used for direct domain matching (highest confidence signal).
# -----------------------------------------------------------------------------
EXTERNAL_DOMAIN_BRAND_MAP = {
    # Microsoft
    "microsoftonline.com":          "microsoft",
    "login.microsoftonline.com":    "microsoft",
    "microsoft.com":                "microsoft",
    "live.com":                     "microsoft",
    "office.com":                   "microsoft",
    "office365.com":                "microsoft",
    "msftauth.net":                 "microsoft",
    "outlook.com":                  "microsoft",
    "outlook.live.com":             "microsoft",
    "msn.com":                      "microsoft",
    "sharepoint.com":               "microsoft",
    "onedrive.com":                 "microsoft",
    "azure.com":                    "microsoft",
    "login.live.com":               "microsoft",
    # Google - identity/login only (CDN/analytics subdomains go to INFRA_DOMAINS)
    "google.com":                   "google",
    "accounts.google.com":          "google",
    "myaccount.google.com":         "google",
    "gmail.com":                    "google",
    "mail.google.com":              "google",
    "youtube.com":                  "google",
    "youtu.be":                     "google",
    # Apple
    "apple.com":                    "apple",
    "icloud.com":                   "apple",
    "appleid.apple.com":            "apple",
    "idmsa.apple.com":              "apple",
    "apple-cloudkit.com":           "apple",
    # Facebook / Meta - identity only (connect.facebook.net = Pixel tracker -> INFRA_DOMAINS)
    "facebook.com":                 "facebook",
    "fbcdn.net":                    "facebook",
    "fb.com":                       "facebook",
    "fbstatic-a.akamaihd.net":      "facebook",
    # Instagram
    "instagram.com":                "instagram",
    "cdninstagram.com":             "instagram",
    # PayPal
    "paypal.com":                   "paypal",
    "paypalobjects.com":            "paypal",
    # Amazon
    "amazon.com":                   "amazon",
    "amazonaws.com":                "amazon",
    "ssl-images-amazon.com":        "amazon",
    "images-amazon.com":            "amazon",
    "amazon-adsystem.com":          "amazon",
    # Netflix
    "netflix.com":                  "netflix",
    "nflxext.com":                  "netflix",
    "nflximg.net":                  "netflix",
    "nflxso.net":                   "netflix",
    # LinkedIn
    "linkedin.com":                 "linkedin",
    "licdn.com":                    "linkedin",
    # Twitter / X
    "twitter.com":                  "twitter",
    "x.com":                        "twitter",
    "twimg.com":                    "twitter",
    # WhatsApp
    "whatsapp.com":                 "whatsapp",
    "whatsapp.net":                 "whatsapp",
    # Telegram
    "telegram.org":                 "telegram",
    "t.me":                         "telegram",
    # Dropbox
    "dropbox.com":                  "dropbox",
    "dropboxstatic.com":            "dropbox",
    # Adobe
    "adobe.com":                    "adobe",
    "adobelogin.com":               "adobe",
    "adobeid.com":                  "adobe",
    "sign.adobe.com":               "adobe",
    "echosign.com":                 "adobe",
    "documentcloud.adobe.com":      "adobe",
    # DocuSign
    "docusign.com":                 "docusign",
    "docusign.net":                 "docusign",
    "docucdn.com":                  "docusign",
    # DHL
    "dhl.com":                      "dhl",
    "dhlparcel.nl":                 "dhl",
    "dhl-global-mail.com":          "dhl",
    # UPS
    "ups.com":                      "ups",
    # FedEx
    "fedex.com":                    "fedex",
    # Bank of America
    "bankofamerica.com":            "bankofamerica",
    # Chase / JPMorgan
    "chase.com":                    "chase",
    "jpmorgan.com":                 "chase",
    # Wells Fargo
    "wellsfargo.com":               "wellsfargo",
    # Citibank
    "citi.com":                     "citibank",
    "citibank.com":                 "citibank",
    # HSBC
    "hsbc.com":                     "hsbc",
    # Santander
    "santander.com":                "santander",
    # BBVA
    "bbva.com":                     "bbva",
    "bbva.es":                      "bbva",
    # CaixaBank
    "caixabank.com":                "caixabank",
    "caixabank.es":                 "caixabank",
    # US Bank
    "usbank.com":                   "usbank",
    "onlinebanking.usbank.com":     "usbank",
    # Optus
    "optus.com.au":                 "optus",
    "optus.net.au":                 "optus",
    # Commonwealth Bank (Australia)
    "commbank.com.au":              "commbank",
    "netbank.com.au":               "commbank",
    # NAB (Australia)
    "nab.com.au":                   "nab",
    # ANZ (Australia)
    "anz.com":                      "anz",
    "anz.com.au":                   "anz",
    # ING
    "ing.com":                      "ing",
    "ing.com.au":                   "ing",
    # Scotiabank
    "scotiabank.com":               "scotiabank",
    # Royal Bank of Canada
    "rbc.com":                      "rbc",
    "rbcroyalbank.com":             "rbc",
    # TD Bank
    "td.com":                       "tdbank",
    "tdbank.com":                   "tdbank",
}

# Local/loopback hosts that should never be counted as external domains
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}

# Domains that are ALWAYS infrastructure/analytics - NEVER brand impersonation signals.
# Phishing kits copy these verbatim from the real site; scoring them causes FP.
# Key examples:
#   - google-analytics.com / googletagmanager.com -> embedded on ANY site, not Google impersonation
#   - connect.facebook.net -> Facebook Pixel tracker, not Facebook impersonation
#   - ajax.googleapis.com -> jQuery CDN (Google deprecated but still used)
#   - fonts.googleapis.com / fonts.gstatic.com -> Google Fonts CDN
#   - bootstrapcdn.com / cdnjs.cloudflare.com / jsdelivr.net / unpkg.com -> generic CDNs
INFRA_DOMAINS = {
    # Google analytics/ads infrastructure
    "google-analytics.com",
    "googletagmanager.com",
    "googleadservices.com",
    "googlesyndication.com",
    "googletagservices.com",
    "doubleclick.net",
    # Google CDN / utility (NOT identity)
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "apis.google.com",
    # Facebook analytics/tracking (NOT identity)
    "connect.facebook.net",
    # Bootstrap / jQuery / generic CDNs
    "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
    "code.jquery.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    # Analytics / telemetry services (third-party, not brand-identity)
    "qualtrics.com",
    "siteintercept.qualtrics.com",
    "appdynamics.com",
    "quantummetric.com",
    "tiqcdn.com",
    "tealiumiq.com",
    "mparticle.com",
    "newrelic.com",
    "nr-data.net",
    "hotjar.com",
    "mouseflow.com",
    "fullstory.com",
    "clarity.ms",
    "iesnare.com",
    "mpsnare.iesnare.com",
    "c3tag.com",
    "glancecdn.net",
    # Cloudflare generic endpoints
    "cloudflare.com",
    "cloudflareinsights.com",
}

# -----------------------------------------------------------------------------
# Source weights (Method 1 artifact voting + Method 2 domain signals)
# -----------------------------------------------------------------------------
SOURCE_WEIGHT = {
    "title":                8,
    "meta":                 7,
    "logo_filename":        8,
    "favicon":              7,
    "copyright":            6,
    "php_redirect":         8,   # Method 2: PHP header Location
    "external_domain":      9,   # Method 2: direct CDN/service domain match
    "external_domain_freq": 7,   # Method 2: cross-file domain frequency
    "form_action":          5,
    "asset_host":           5,
    "placeholder":          4,
    "visible_text":         4,
    "script_or_link":       3,
    "raw_html":             2,
}

UNKNOWN_SOURCE_WEIGHT = {
    "title":         8,
    "meta":          7,
    "logo_filename": 8,
    "favicon":       7,
    "copyright":     6,
    "php_redirect":  6,
    "form_action":   4,
    "asset_host":    8,
    "placeholder":   4,
    "visible_text":  3,
    "script_or_link":4,
    "raw_html":      2,
}

# -----------------------------------------------------------------------------
# Regex patterns
# -----------------------------------------------------------------------------
RE_TITLE        = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
RE_META         = re.compile(r"<meta[^>]+>", re.IGNORECASE)
RE_META_CONTENT = re.compile(r'content\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_META_NAME    = re.compile(r'(?:name|property)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_IMG_SRC      = re.compile(r"<img[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_SCRIPT_SRC   = re.compile(r"<script[^>]+src\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_LINK_HREF    = re.compile(r"<link[^>]+href\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
RE_ATTR_ID_CLASS= re.compile(r'(?:id|class|alt|aria-label)\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
RE_WS           = re.compile(r"\s+")
RE_TOKEN        = re.compile(r"[a-z][a-z0-9]{2,24}", re.IGNORECASE)

# Method 1 - additional artifact regexes
RE_FAVICON = re.compile(
    r'<link[^>]+rel\s*=\s*["\'][^"\']*(?:shortcut\s+)?icon[^"\']*["\'][^>]+href\s*=\s*["\']([^"\']+)["\']'
    r'|<link[^>]+href\s*=\s*["\']([^"\']+)["\'][^>]+rel\s*=\s*["\'][^"\']*(?:shortcut\s+)?icon[^"\']*["\']',
    re.IGNORECASE,
)
RE_FORM_ACTION = re.compile(r'<form[^>]+action\s*=\s*["\']([^"\']{3,})["\']', re.IGNORECASE)
RE_COPYRIGHT = re.compile(
    r'(?:&copy;|©|copyright)\s*'
    r'(?:(?:20\d{2}|19\d{2})[-–]?(?:\d{4})?\s*)?'
    r'([A-Za-z][A-Za-z0-9\s\.,&]{2,60}?)'
    r'(?:\.|<|,\s*[Aa]ll|\n|$)',
    re.IGNORECASE,
)
RE_PLACEHOLDER = re.compile(r'placeholder\s*=\s*["\']([^"\']{5,100})["\']', re.IGNORECASE)

# Method 2 - PHP redirect regexes
RE_PHP_LOCATION = re.compile(
    r'header\s*\(\s*["\']Location:\s*([^\s"\']{5,})["\']',
    re.IGNORECASE,
)
RE_PHP_REDIRECT_VAR = re.compile(
    r'(?:redirect|redir|goto|target|return_url|returnurl|back_url|location)\s*'
    r'=\s*["\']([^"\']{10,})["\']',
    re.IGNORECASE,
)

# -----------------------------------------------------------------------------
# Common stopwords
# -----------------------------------------------------------------------------
GENERIC_STOPWORDS = {
    "www", "http", "https", "com", "net", "org", "co", "io", "gov", "edu",
    "html", "htm", "php", "js", "css", "png", "jpg", "jpeg", "svg", "ico", "webp",
    "img", "image", "images", "assets", "static", "media", "cdn", "content",
    "api", "ajax", "script", "scripts", "style", "styles", "font", "fonts",
    "login", "signin", "signup", "account", "secure", "security", "verify",
    "update", "submit", "index", "home", "main", "page", "next", "prev", "new",
    "form", "mail", "email", "password", "username", "user", "auth", "token",
    "session", "redirect", "free", "gift", "card", "service", "support",
    "global", "international", "official", "welcome", "portal", "online",
    "ui", "nf", "country", "select", "option", "item", "link", "name", "code",
    "flag", "clearfix", "wrapper", "container", "header", "footer", "button",
    "input", "label", "modal", "dialog", "layout", "grid", "row", "col",
    "logo", "localhost", "local", "file", "none", "true", "false",
}

GENERIC_HOST_LABELS = {
    "www", "m", "mobile", "cdn", "static", "assets", "img", "images", "api",
    "login", "secure", "auth", "sso", "mail", "portal", "support", "help",
    "content", "media", "js", "css", "fonts", "files", "data",
}


# -----------------------------------------------------------------------------
# HTML visible-text collector
# -----------------------------------------------------------------------------
class TextCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self._skip_tag = None
        self.chunks = []

    def handle_starttag(self, tag, _attrs):
        if tag in ("script", "style", "noscript"):
            self._skip_tag = tag

    def handle_endtag(self, tag):
        if self._skip_tag == tag:
            self._skip_tag = None

    def handle_data(self, data):
        if self._skip_tag:
            return
        txt = data.strip()
        if txt:
            self.chunks.append(txt)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def normalize_text(s):
    return RE_WS.sub(" ", s or "").strip().lower()


def safe_read_text(path):
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ_BYTES)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def compile_brand_regex():
    compiled = {}
    for brand, patterns in BRAND_PATTERNS.items():
        compiled[brand] = [re.compile(p, re.IGNORECASE) for p in patterns]
    return compiled


def build_known_terms():
    known = set(BRAND_PATTERNS.keys())
    for patterns in BRAND_PATTERNS.values():
        for p in patterns:
            plain = re.sub(r"\\b|\\.|\\s|[\^\$\[\]\(\)\?\*\+\|]", " ", p.lower())
            for tok in RE_TOKEN.findall(plain):
                if len(tok) >= 3:
                    known.add(tok)
    return known


def extract_domain_tokens(host):
    host = (host or "").split(":")[0].lower().strip(".")
    if not host:
        return []
    labels = [x for x in host.split(".") if x]
    if not labels:
        return []
    tokens = []
    if len(labels) >= 2:
        sld = labels[-2]
        if len(sld) >= 3 and sld not in GENERIC_HOST_LABELS:
            tokens.append(sld)
    for label in labels:
        if len(label) >= 3 and label not in GENERIC_HOST_LABELS:
            tokens.append(label)
    return tokens


def _is_infra_domain(host):
    """Return True if host is a known analytics/CDN infrastructure domain (not a brand signal)."""
    if host in INFRA_DOMAINS:
        return True
    for infra in INFRA_DOMAINS:
        if host.endswith("." + infra):
            return True
    return False


def match_external_domain(host):
    """Return canonical brand name if host matches EXTERNAL_DOMAIN_BRAND_MAP.

    Returns None for infrastructure/analytics domains even if they share a
    parent domain with a known brand (e.g. ajax.googleapis.com -> None, not google).
    """
    host = (host or "").lower().strip().rstrip(".")
    if not host or host in _LOCAL_HOSTS:
        return None
    # Infrastructure domains are never brand impersonation signals.
    if _is_infra_domain(host):
        return None
    if host in EXTERNAL_DOMAIN_BRAND_MAP:
        return EXTERNAL_DOMAIN_BRAND_MAP[host]
    for domain, brand in EXTERNAL_DOMAIN_BRAND_MAP.items():
        if host.endswith("." + domain):
            return brand
    return None


def score_unknown_tokens(source_name, raw_text, file_relpath, unknown_scores,
                         unknown_evidences, known_terms, file_seen=None):
    text = normalize_text(raw_text).replace("-", " ").replace("_", " ")
    if not text:
        return

    weight = UNKNOWN_SOURCE_WEIGHT.get(source_name, 1)
    seen_local = set()
    for tok in RE_TOKEN.findall(text):
        tok = tok.lower()
        if tok in seen_local:
            continue
        seen_local.add(tok)
        if file_seen is not None and tok in file_seen:
            continue
        if tok in GENERIC_STOPWORDS or tok in known_terms:
            continue
        if tok.isdigit():
            continue
        if len(tok) < 4:
            continue
        unknown_scores[tok] += weight
        if file_seen is not None:
            file_seen.add(tok)
        if len(unknown_evidences[tok]) < 10:
            unknown_evidences[tok].append({
                "source": source_name,
                "file": file_relpath,
                "weight": weight,
                "snippet": tok,
            })


def score_source_text(source_name, text, file_relpath, brand_regex, scores, evidences):
    text_norm = normalize_text(text)
    if not text_norm:
        return

    for brand, regex_list in brand_regex.items():
        for rgx in regex_list:
            if rgx.search(text_norm):
                weight = SOURCE_WEIGHT.get(source_name, 1)
                scores[brand] += weight
                if len(evidences[brand]) < 20:
                    evidences[brand].append({
                        "source": source_name,
                        "file": file_relpath,
                        "weight": weight,
                        "snippet": (text_norm[:180] + "...") if len(text_norm) > 180 else text_norm,
                    })
                break


def extract_host_and_name(asset_url):
    raw = (asset_url or "").strip()
    if not raw:
        return "", ""
    try:
        parsed = urlparse(raw)
    except ValueError:
        sanitized = raw.split("?")[0].split("#")[0]
        return "", os.path.basename(sanitized.lower().strip("/"))

    host = (parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    filename = os.path.basename(path)
    return host, filename


# -----------------------------------------------------------------------------
# Method 2: Cross-file external domain frequency scoring
# -----------------------------------------------------------------------------
def score_external_domains(domain_counter, scores, evidences,
                           unknown_scores, unknown_evidences, known_terms):
    """
    After scanning all files in a kit, rank external domains by how many
    files referenced them and score accordingly.

    - Domains in EXTERNAL_DOMAIN_BRAND_MAP get a strong direct score.
    - Unrecognised domains are token-mined for unknown brand candidates.
    """
    if not domain_counter:
        return

    top_domains = sorted(domain_counter.items(), key=lambda x: x[1], reverse=True)[:50]

    for domain, count in top_domains:
        brand = match_external_domain(domain)
        if brand:
            # Weight increases with how many kit files reference this domain (capped at 10)
            weight = min(10, 3 + count)
            scores[brand] += weight
            if len(evidences[brand]) < 20:
                evidences[brand].append({
                    "source": "external_domain_freq",
                    "file": "[cross_file_domain_analysis]",
                    "weight": weight,
                    "snippet": "%s (referenced in %d file(s))" % (domain, count),
                })
        else:
            for tok in extract_domain_tokens(domain):
                score_unknown_tokens(
                    "asset_host", tok, "[cross_file]",
                    unknown_scores, unknown_evidences, known_terms,
                )


# -----------------------------------------------------------------------------
# Per-file analysis (Methods 1 + 2)
# -----------------------------------------------------------------------------
def analyze_single_file(path, rel_path, brand_regex, scores, evidences,
                        unknown_scores, unknown_evidences, known_terms,
                        domain_counter=None):
    html = safe_read_text(path)
    if len(html) < 20:
        return

    unknown_seen_in_file = set()

    def _score_host(host, fallback_source):
        """Try direct brand map first; fall back to regex/token scoring.

        Infra/analytics domains are silently skipped - they are copied verbatim
        from legitimate sites and cause FP (e.g. googletagmanager.com on a
        USBank phishing kit does NOT mean the kit targets Google).
        """
        if not host or host in _LOCAL_HOSTS:
            return
        if _is_infra_domain(host):
            return  # skip analytics/CDN infra domains entirely
        brand = match_external_domain(host)
        if brand:
            weight = SOURCE_WEIGHT.get("external_domain", 9)
            scores[brand] += weight
            if len(evidences[brand]) < 20:
                evidences[brand].append({
                    "source": "external_domain",
                    "file": rel_path,
                    "weight": weight,
                    "snippet": host,
                })
        else:
            score_source_text(fallback_source, host, rel_path, brand_regex, scores, evidences)
            for tok in extract_domain_tokens(host):
                score_unknown_tokens(fallback_source, tok, rel_path, unknown_scores,
                                     unknown_evidences, known_terms, unknown_seen_in_file)
        # Accumulate in cross-file domain counter (infra already filtered above)
        if domain_counter is not None and "." in host:
            domain_counter[host] += 1

    # -- 1. Title --------------------------------------------------------------
    for m in RE_TITLE.finditer(html):
        title_text = m.group(1)
        score_source_text("title", title_text, rel_path, brand_regex, scores, evidences)
        score_unknown_tokens("title", title_text, rel_path, unknown_scores,
                             unknown_evidences, known_terms, unknown_seen_in_file)

    # -- 2. Meta tags ----------------------------------------------------------
    for meta in RE_META.findall(html):
        m_name = RE_META_NAME.search(meta)
        m_content = RE_META_CONTENT.search(meta)
        if not m_content:
            continue
        name_key = (m_name.group(1).lower() if m_name else "")
        content = m_content.group(1)
        if name_key in ("og:site_name", "application-name",
                        "apple-mobile-web-app-title", "title", "description"):
            score_source_text("meta", content, rel_path, brand_regex, scores, evidences)
            score_unknown_tokens("meta", content, rel_path, unknown_scores,
                                 unknown_evidences, known_terms, unknown_seen_in_file)

    # -- 3. Favicon (Method 1 new artifact) -----------------------------------
    for m in RE_FAVICON.finditer(html):
        href = m.group(1) or m.group(2) or ""
        if not href:
            continue
        host, filename = extract_host_and_name(href)
        if filename:
            score_source_text("favicon", filename, rel_path, brand_regex, scores, evidences)
            score_unknown_tokens("favicon", filename, rel_path, unknown_scores,
                                 unknown_evidences, known_terms, unknown_seen_in_file)
        if host:
            _score_host(host, "favicon")

    # -- 4. Image / logo filenames ---------------------------------------------
    for src in RE_IMG_SRC.findall(html):
        host, filename = extract_host_and_name(src)
        if filename:
            score_source_text("logo_filename", filename, rel_path, brand_regex, scores, evidences)
            score_unknown_tokens("logo_filename", filename, rel_path, unknown_scores,
                                 unknown_evidences, known_terms, unknown_seen_in_file)
        if host:
            _score_host(host, "asset_host")

    # -- 5. Scripts / link hrefs -----------------------------------------------
    for src in RE_SCRIPT_SRC.findall(html):
        host, filename = extract_host_and_name(src)
        if host:
            _score_host(host, "asset_host")
        if filename:
            score_source_text("script_or_link", filename, rel_path, brand_regex, scores, evidences)

    for href in RE_LINK_HREF.findall(html):
        host, filename = extract_host_and_name(href)
        if host:
            _score_host(host, "asset_host")
        if filename:
            score_source_text("script_or_link", filename, rel_path, brand_regex, scores, evidences)

    # -- 6. Form action (Method 1 new artifact) --------------------------------
    for m in RE_FORM_ACTION.finditer(html):
        action = m.group(1).strip()
        host, filename = extract_host_and_name(action)
        if host:
            _score_host(host, "form_action")
        if filename:
            score_source_text("form_action", filename, rel_path, brand_regex, scores, evidences)
            score_unknown_tokens("form_action", filename, rel_path, unknown_scores,
                                 unknown_evidences, known_terms, unknown_seen_in_file)

    # -- 7. Copyright text (Method 1 new artifact) -----------------------------
    for m in RE_COPYRIGHT.finditer(html):
        copy_text = m.group(1).strip()
        if len(copy_text) >= 3:
            score_source_text("copyright", copy_text, rel_path, brand_regex, scores, evidences)
            score_unknown_tokens("copyright", copy_text, rel_path, unknown_scores,
                                 unknown_evidences, known_terms, unknown_seen_in_file)

    # -- 8. Input placeholders (Method 1 new artifact) -------------------------
    for m in RE_PLACEHOLDER.finditer(html):
        placeholder = m.group(1).strip()
        score_source_text("placeholder", placeholder, rel_path, brand_regex, scores, evidences)
        score_unknown_tokens("placeholder", placeholder, rel_path, unknown_scores,
                             unknown_evidences, known_terms, unknown_seen_in_file)

    # -- 9. PHP redirect tracking (Method 2) -----------------------------------
    ext = os.path.splitext(path.lower())[1]
    if ext == ".php":
        for m in RE_PHP_LOCATION.finditer(html):
            url = m.group(1).strip()
            host, _ = extract_host_and_name(url)
            if host:
                brand = match_external_domain(host)
                if brand:
                    weight = SOURCE_WEIGHT.get("php_redirect", 8)
                    scores[brand] += weight
                    if len(evidences[brand]) < 20:
                        evidences[brand].append({
                            "source": "php_redirect",
                            "file": rel_path,
                            "weight": weight,
                            "snippet": url[:180],
                        })
                    if domain_counter is not None and "." in host:
                        domain_counter[host] += 1
                else:
                    score_source_text("php_redirect", host, rel_path, brand_regex, scores, evidences)
                    for tok in extract_domain_tokens(host):
                        score_unknown_tokens("php_redirect", tok, rel_path, unknown_scores,
                                             unknown_evidences, known_terms, unknown_seen_in_file)

        for m in RE_PHP_REDIRECT_VAR.finditer(html):
            url = m.group(1).strip()
            host, _ = extract_host_and_name(url)
            if host:
                brand = match_external_domain(host)
                if brand:
                    weight = SOURCE_WEIGHT.get("php_redirect", 8)
                    scores[brand] += weight
                    if len(evidences[brand]) < 20:
                        evidences[brand].append({
                            "source": "php_redirect",
                            "file": rel_path,
                            "weight": weight,
                            "snippet": url[:180],
                        })

    # -- 10. id / class / alt tokens -------------------------------------------
    for attr_val in RE_ATTR_ID_CLASS.findall(html):
        score_source_text("raw_html", attr_val, rel_path, brand_regex, scores, evidences)

    # -- 11. Visible text ------------------------------------------------------
    parser = TextCollector()
    try:
        parser.feed(html)
    except Exception:
        pass
    if parser.chunks:
        text_blob = " ".join(parser.chunks[:3000])
        score_source_text("visible_text", text_blob, rel_path, brand_regex, scores, evidences)


# -----------------------------------------------------------------------------
# Kit-level file collection
# -----------------------------------------------------------------------------
def collect_candidate_files(kit_path):
    paths = []
    for dirpath, dirnames, filenames in os.walk(kit_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            _, ext = os.path.splitext(name.lower())
            if ext in HTML_EXTENSIONS:
                fpath = os.path.join(dirpath, name)
                paths.append(fpath)
    return paths


# -----------------------------------------------------------------------------
# Main detection entry point
# -----------------------------------------------------------------------------
def detect_brand_for_kit(kit_path, top_k=3, max_files=300,
                         unknown_top_k=10, unknown_min_score=6,
                         promote_unknown_as_brand=False):
    brand_regex = compile_brand_regex()
    known_terms = build_known_terms()
    scores = defaultdict(int)
    evidences = defaultdict(list)
    unknown_scores = defaultdict(int)
    unknown_evidences = defaultdict(list)
    domain_counter = defaultdict(int)   # Method 2: cross-file external domain counter

    files = collect_candidate_files(kit_path)
    files = sorted(files)[:max_files]

    for fp in files:
        rel = os.path.relpath(fp, kit_path)
        analyze_single_file(
            fp, rel, brand_regex, scores, evidences,
            unknown_scores, unknown_evidences, known_terms,
            domain_counter,
        )

    # Method 2: score from cross-file external domain frequency
    score_external_domains(
        domain_counter, scores, evidences,
        unknown_scores, unknown_evidences, known_terms,
    )

    ranked = sorted(scores.items(), key=lambda x: x[1], reverse=True)
    total = sum(score for _, score in ranked)

    top = []
    for brand, score in ranked[:top_k]:
        confidence = round((score / total), 4) if total > 0 else 0.0
        top.append({
            "brand": brand,
            "score": score,
            "confidence": confidence,
            "evidence_count": len(evidences[brand]),
            "evidence_samples": evidences[brand][:5],
        })

    unknown_ranked = sorted(unknown_scores.items(), key=lambda x: x[1], reverse=True)
    unknown_top = []
    for token, score in unknown_ranked:
        if score < unknown_min_score:
            continue
        unknown_top.append({
            "candidate": token,
            "score": score,
            "evidence_count": len(unknown_evidences[token]),
            "evidence_samples": unknown_evidences[token][:5],
        })
        if len(unknown_top) >= unknown_top_k:
            break

    # If no known-brand hit, optionally promote unknown candidates as pseudo labels.
    if promote_unknown_as_brand and not top and unknown_top:
        promoted = []
        total_unknown = sum(item["score"] for item in unknown_top[:top_k])
        for item in unknown_top[:top_k]:
            conf = round((item["score"] / total_unknown), 4) if total_unknown > 0 else 0.0
            promoted.append({
                "brand": "unknown:%s" % item["candidate"],
                "score": item["score"],
                "confidence": conf,
                "evidence_count": item["evidence_count"],
                "evidence_samples": item["evidence_samples"],
            })
        top = promoted

    # Include top external domains for audit/debugging
    top_ext_domains = [
        {"domain": d, "count": c}
        for d, c in sorted(domain_counter.items(), key=lambda x: x[1], reverse=True)[:20]
    ]

    return {
        "kit_path": os.path.realpath(kit_path),
        "files_scanned": len(files),
        "detected": top,
        "unknown_brand_candidates": unknown_top,
        "top_external_domains": top_ext_domains,
    }


# -----------------------------------------------------------------------------
# Batch kit discovery
# -----------------------------------------------------------------------------
def discover_kits(batch_root):
    """Similar to crawl.py: group kits under batch_root by 1-level depth."""
    discovered = {}

    for dirpath, _dirnames, filenames in os.walk(batch_root):
        entry = None
        for candidate in ("index.html", "index.php"):
            if candidate in filenames:
                entry = candidate
                break
        if entry is None:
            for f in sorted(filenames):
                if f.lower().endswith((".html", ".htm", ".php")):
                    entry = f
                    break
        if entry is None:
            continue

        rel = os.path.relpath(dirpath, batch_root)
        if rel == ".":
            continue

        parts = rel.split(os.sep)
        kit_name = parts[0]
        kit_path = os.path.join(batch_root, kit_name)
        depth = len(parts)

        prev = discovered.get(kit_name)
        if prev is None or depth < prev["depth"]:
            discovered[kit_name] = {
                "name": kit_name,
                "kit_path": kit_path,
                "depth": depth,
            }

    return sorted(discovered.values(), key=lambda x: x["name"])


def default_output_path(root_dir):
    ts = int(time.time())
    project_root = os.path.dirname(root_dir)
    out_dir = os.path.join(project_root, "09-brand-html")
    os.makedirs(out_dir, exist_ok=True)
    return os.path.join(out_dir, "brand_targets_%d.json" % ts)


def save_csv(json_results, csv_path):
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "kit_name", "kit_path", "files_scanned", "rank", "brand",
            "score", "confidence", "evidence_count"
        ])
        for row in json_results:
            kit_name = row.get("kit_name", "")
            kit_path = row.get("kit_path", "")
            files_scanned = row.get("files_scanned", 0)
            detected = row.get("detected", [])
            if not detected:
                w.writerow([kit_name, kit_path, files_scanned, 1, "", 0, 0.0, 0])
                continue
            for rank, item in enumerate(detected, start=1):
                w.writerow([
                    kit_name, kit_path, files_scanned, rank,
                    item.get("brand", ""),
                    item.get("score", 0),
                    item.get("confidence", 0.0),
                    item.get("evidence_count", 0),
                ])


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Extract target brand(s) from phishing kits (HTML/PHP heuristic)."
    )
    parser.add_argument("--kit-path", help="Single phishing kit path")
    parser.add_argument("--batch-root", help="Root path containing many kits")
    parser.add_argument("--num", type=int, default=0, help="Max kits for batch mode (0=all)")
    parser.add_argument("--skip", type=int, default=0, help="Skip first N kits")
    parser.add_argument("--top-k", type=int, default=3, help="Number of top brands to keep")
    parser.add_argument("--unknown-top-k", type=int, default=10,
                        help="Number of unknown brand candidates to keep")
    parser.add_argument("--unknown-min-score", type=int, default=6,
                        help="Minimum score threshold for unknown candidates")
    parser.add_argument("--promote-unknown-as-brand", action="store_true",
                        help="If no known brand detected, promote unknown candidates as pseudo labels.")
    parser.add_argument("--max-files", type=int, default=300,
                        help="Max HTML/PHP files scanned per kit")
    parser.add_argument("--output", default=None, help="Output JSON path")
    parser.add_argument("--csv", action="store_true", help="Also save CSV next to JSON output")
    args = parser.parse_args()

    if not args.kit_path and not args.batch_root:
        raise SystemExit("Use --kit-path or --batch-root")

    root_dir = os.path.dirname(os.path.realpath(__file__))
    output_path = args.output or default_output_path(root_dir)

    results = []
    if args.kit_path:
        det = detect_brand_for_kit(
            args.kit_path,
            top_k=args.top_k,
            max_files=args.max_files,
            unknown_top_k=args.unknown_top_k,
            unknown_min_score=args.unknown_min_score,
            promote_unknown_as_brand=args.promote_unknown_as_brand,
        )
        det["kit_name"] = os.path.basename(os.path.realpath(args.kit_path))
        results.append(det)
    else:
        kits = discover_kits(args.batch_root)
        start = args.skip
        end = (start + args.num) if args.num > 0 else len(kits)
        selected = kits[start:end]

        print("=" * 60)
        print("[Brand] Discovered kits: %d" % len(kits))
        print("[Brand] Processing kits: %d (skip=%d, num=%s)" %
              (len(selected), args.skip, args.num if args.num > 0 else "all"))
        print("=" * 60)

        for i, kit in enumerate(selected, start=1):
            print("[Brand %d/%d] %s" % (i, len(selected), kit["name"]))
            det = detect_brand_for_kit(
                kit["kit_path"],
                top_k=args.top_k,
                max_files=args.max_files,
                unknown_top_k=args.unknown_top_k,
                unknown_min_score=args.unknown_min_score,
                promote_unknown_as_brand=args.promote_unknown_as_brand,
            )
            det["kit_name"] = kit["name"]
            results.append(det)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print("[Brand] JSON saved:", output_path)

    if args.csv:
        csv_path = os.path.splitext(output_path)[0] + ".csv"
        save_csv(results, csv_path)
        print("[Brand] CSV saved:", csv_path)

    with_brand = sum(1 for row in results if row.get("detected"))
    print("[Brand] Kits with detected brands: %d/%d" % (with_brand, len(results)))


if __name__ == "__main__":
    main()
