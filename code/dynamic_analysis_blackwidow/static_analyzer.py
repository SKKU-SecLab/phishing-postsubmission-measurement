#!/usr/bin/env python3
"""
Static Code Analyzer for Phishing Kits

Parses HTML/JS/PHP source files to build a "code map" that enriches
BlackWidow's dynamic analysis results.  When the dynamic analysis
reports an (anonymous) function or a network request to "test.php",
the static analyzer can resolve it to a real function name and
tell you what the PHP file does with the submitted data.

Usage (standalone):
    python3 static_analyzer.py --kit-path /path/to/kit

Usage (integrated with FormAnalyzer):
    Automatically invoked when --kit-path is provided to crawl.py --analyze
"""

import os
import re
import json
import argparse
from collections import defaultdict
from html.parser import HTMLParser


# =====================================================================
# Regex patterns
# =====================================================================

# --- JS function definitions ---
RE_FUNC_DECL = re.compile(
    r'function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)\s*\{',
    re.MULTILINE)
RE_FUNC_EXPR = re.compile(
    r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*function\s*\(([^)]*)\)\s*\{',
    re.MULTILINE)
RE_ARROW_FUNC = re.compile(
    r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*(?:\(([^)]*)\)|([a-zA-Z_$][a-zA-Z0-9_$]*))\s*=>',
    re.MULTILINE)

# --- jQuery callback anonymous functions ---
# Matches:  $('selector').click(function(e){ ... })
#           $(document).ready(function(){ ... })
#           $(...).on('event', function(){ ... })
RE_JQUERY_CALLBACK = re.compile(
    r'\$\s*\(\s*(?:["\']([^"\']*)["\']|(\w+))\s*\)\s*\.\s*'
    r'(click|keyup|keydown|keypress|change|submit|focus|blur|input'
    r'|mouseover|mouseout|mousedown|mouseup|ready|load|each)\s*\(\s*'
    r'function\s*(?:(\w+))?\s*\(([^)]*)\)\s*\{',
    re.MULTILINE)

# --- JS event handler registration ---
RE_ADDEVENTLISTENER = re.compile(
    r'\.addEventListener\s*\(\s*["\'](\w+)["\']\s*,\s*'
    r'(?:function\s*(?:(\w+))?\s*\(|(\w+))',
    re.MULTILINE)
RE_JQUERY_ON = re.compile(
    r'\.\s*(?:on|bind)\s*\(\s*["\'](\w+)["\']\s*,\s*'
    r'(?:function\s*(?:(\w+))?\s*\(|(\w+))',
    re.MULTILINE)
RE_JQUERY_SHORTHAND = re.compile(
    r'\.\s*(click|keyup|keydown|keypress|change|submit|focus|blur|input'
    r'|mouseover|mouseout|mousedown|mouseup)\s*\(\s*'
    r'(?:function\s*(?:(\w+))?\s*\(|(\w+))',
    re.MULTILINE)

# --- JS AJAX calls ---
RE_AJAX_JQUERY = re.compile(
    r'\$\s*\.\s*(ajax|post|get)\s*\(\s*["\']([^"\']+)["\']',
    re.MULTILINE | re.IGNORECASE)
RE_AJAX_JQUERY_OBJ = re.compile(
    r'\$\s*\.\s*ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
    re.MULTILINE | re.IGNORECASE | re.DOTALL)
RE_FETCH = re.compile(
    r'fetch\s*\(\s*["\']([^"\']+)["\']',
    re.MULTILINE)
RE_XHR_OPEN = re.compile(
    r'\.open\s*\(\s*["\'](\w+)["\']\s*,\s*["\']([^"\']+)["\']',
    re.MULTILINE)

# --- PHP patterns ---
RE_PHP_POST = re.compile(
    r'\$_POST\s*\[\s*["\'](\w+)["\']\s*\]', re.IGNORECASE)
RE_PHP_GET = re.compile(
    r'\$_GET\s*\[\s*["\'](\w+)["\']\s*\]', re.IGNORECASE)
RE_PHP_REQUEST = re.compile(
    r'\$_REQUEST\s*\[\s*["\'](\w+)["\']\s*\]', re.IGNORECASE)
RE_PHP_MAIL = re.compile(
    r'\bmail\s*\(\s*([^)]+)\)', re.IGNORECASE)
RE_PHP_MAIL_TO = re.compile(
    r'\bmail\s*\(\s*["\']([^"\']+?)["\']', re.IGNORECASE)
RE_PHP_TELEGRAM = re.compile(
    r'api\.telegram\.org/bot([^\s"\'<>]+)', re.IGNORECASE)
RE_PHP_HEADER = re.compile(
    r'header\s*\(\s*["\']Location:\s*([^"\']+)["\']', re.IGNORECASE)
RE_PHP_CURL = re.compile(
    r'CURLOPT_URL\s*,\s*["\']?([^\s"\'<>]+)', re.IGNORECASE)
RE_PHP_FILE_GET = re.compile(
    r'file_get_contents\s*\(\s*["\']?(https?://[^\s"\'<>)]+)',
    re.IGNORECASE)
RE_PHP_FWRITE = re.compile(
    r'fwrite\s*\(\s*\$\w+\s*,', re.IGNORECASE)
RE_PHP_INCLUDE = re.compile(
    r'(?:include|require)(?:_once)?\s*[\(\s]["\']([^"\']+)["\']',
    re.IGNORECASE)

# File extensions
JS_EXTENSIONS = {'.js'}
PHP_EXTENSIONS = {'.php'}
HTML_EXTENSIONS = {'.html', '.htm'}
ALL_EXTENSIONS = JS_EXTENSIONS | PHP_EXTENSIONS | HTML_EXTENSIONS
SKIP_DIRS = {
    '__MACOSX', '.git', '.svn', 'node_modules', '__pycache__',
    '.idea', '.vscode', '.cursor', 'vendor',
}


# =====================================================================
# HTML Parser -- extract forms, inline handlers, embedded scripts
# =====================================================================

class FormHTMLParser(HTMLParser):
    """Parse an HTML file to extract form structure and event handlers."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.inline_handlers = []
        self.scripts = []
        self._current_form = None
        self._in_script = False
        self._script_content = []
        self._current_tag_info = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == 'form':
            self._current_form = {
                'action': attrs_dict.get('action', ''),
                'method': (attrs_dict.get('method', 'get')).lower(),
                'id': attrs_dict.get('id', ''),
                'fields': [],
                'inline_handlers': [],
            }

        if tag == 'input' and self._current_form is not None:
            self._current_form['fields'].append({
                'name': attrs_dict.get('name', ''),
                'type': (attrs_dict.get('type', 'text')).lower(),
                'id': attrs_dict.get('id', ''),
            })

        if tag == 'script':
            self._in_script = True
            self._script_content = []
            return

        # Collect inline event handlers (on any element)
        for attr_name, attr_val in attrs:
            if attr_name.startswith('on') and attr_val:
                handler_info = {
                    'tag': tag,
                    'event': attr_name,
                    'handler_code': attr_val.strip(),
                    'element_id': attrs_dict.get('id', ''),
                    'element_name': attrs_dict.get('name', ''),
                    'element_class': attrs_dict.get('class', ''),
                }
                self.inline_handlers.append(handler_info)
                if self._current_form is not None:
                    self._current_form['inline_handlers'].append(handler_info)

    def handle_endtag(self, tag):
        if tag == 'form' and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None
        if tag == 'script' and self._in_script:
            self._in_script = False
            content = ''.join(self._script_content).strip()
            if content:
                self.scripts.append(content)

    def handle_data(self, data):
        if self._in_script:
            self._script_content.append(data)


# =====================================================================
# JS Analyzer
# =====================================================================

class JSAnalyzer:
    """Parse JavaScript source to extract function definitions and bindings."""

    @staticmethod
    def _strip_js_comments(code):
        """Remove single-line (//) and multi-line (/* */) JS comments.

        Preserves string literals so URLs like 'http://...' are not damaged.
        """
        # State machine: walk the code, track whether we are inside a
        # string ('...', "...", `...`) or a comment, and copy only the
        # non-comment parts.
        result_chars = []
        i = 0
        n = len(code)
        while i < n:
            c = code[i]
            # String literals -- pass through unchanged
            if c in ('"', "'", '`'):
                quote = c
                result_chars.append(c)
                i += 1
                while i < n:
                    ch = code[i]
                    result_chars.append(ch)
                    if ch == '\\' and i + 1 < n:
                        result_chars.append(code[i + 1])
                        i += 2
                        continue
                    if ch == quote:
                        i += 1
                        break
                    i += 1
                continue
            # Single-line comment
            if c == '/' and i + 1 < n and code[i + 1] == '/':
                # Skip to end of line
                while i < n and code[i] != '\n':
                    i += 1
                result_chars.append('\n')  # preserve line count
                continue
            # Multi-line comment
            if c == '/' and i + 1 < n and code[i + 1] == '*':
                i += 2
                while i + 1 < n and not (code[i] == '*' and code[i + 1] == '/'):
                    if code[i] == '\n':
                        result_chars.append('\n')  # preserve line count
                    i += 1
                i += 2  # skip */
                continue
            result_chars.append(c)
            i += 1
        return ''.join(result_chars)

    @staticmethod
    def analyze(content, filename=''):
        """Analyze JS content and return structured data."""
        # Strip JS comments so that commented-out code is not picked up
        content = JSAnalyzer._strip_js_comments(content)

        result = {
            'functions': [],
            'event_bindings': [],
            'ajax_calls': [],
        }

        # --- Function definitions ---
        for m in RE_FUNC_DECL.finditer(content):
            result['functions'].append({
                'name': m.group(1),
                'params': m.group(2).strip(),
                'type': 'declaration',
                'file': filename,
                'offset': m.start(),
                'line': content[:m.start()].count('\n') + 1,
                'body_preview': content[m.start():m.start() + 300],
            })

        for m in RE_FUNC_EXPR.finditer(content):
            result['functions'].append({
                'name': m.group(1),
                'params': m.group(2).strip(),
                'type': 'expression',
                'file': filename,
                'offset': m.start(),
                'line': content[:m.start()].count('\n') + 1,
                'body_preview': content[m.start():m.start() + 300],
            })

        for m in RE_ARROW_FUNC.finditer(content):
            result['functions'].append({
                'name': m.group(1),
                'params': (m.group(2) or m.group(3) or '').strip(),
                'type': 'arrow',
                'file': filename,
                'offset': m.start(),
                'line': content[:m.start()].count('\n') + 1,
                'body_preview': content[m.start():m.start() + 300],
            })

        # jQuery callback anonymous functions
        # e.g. $('#submit-btn').click(function(e){ ... })
        for m in RE_JQUERY_CALLBACK.finditer(content):
            selector = m.group(1) or m.group(2) or ''
            event_type = m.group(3)
            func_name = m.group(4)  # named or None
            params = m.group(5) or ''
            generated_name = func_name or '$(%s).%s' % (selector, event_type)
            result['functions'].append({
                'name': generated_name,
                'params': params.strip(),
                'type': 'jquery-callback',
                'file': filename,
                'offset': m.start(),
                'line': content[:m.start()].count('\n') + 1,
                'body_preview': content[m.start():m.start() + 300],
                'selector': selector,
                'jquery_event': event_type,
            })

        # --- Event handler bindings ---
        for m in RE_ADDEVENTLISTENER.finditer(content):
            result['event_bindings'].append({
                'event': m.group(1),
                'handler': m.group(2) or m.group(3) or '(anonymous)',
                'method': 'addEventListener',
                'file': filename,
                'line': content[:m.start()].count('\n') + 1,
                'context': content[max(0, m.start() - 50):m.end() + 100].strip(),
            })

        for m in RE_JQUERY_ON.finditer(content):
            result['event_bindings'].append({
                'event': m.group(1),
                'handler': m.group(2) or m.group(3) or '(anonymous)',
                'method': 'jQuery.on',
                'file': filename,
                'line': content[:m.start()].count('\n') + 1,
                'context': content[max(0, m.start() - 50):m.end() + 100].strip(),
            })

        for m in RE_JQUERY_SHORTHAND.finditer(content):
            result['event_bindings'].append({
                'event': m.group(1),
                'handler': m.group(2) or m.group(3) or '(anonymous)',
                'method': 'jQuery.' + m.group(1),
                'file': filename,
                'line': content[:m.start()].count('\n') + 1,
                'context': content[max(0, m.start() - 50):m.end() + 100].strip(),
            })

        # --- AJAX calls ---
        for m in RE_AJAX_JQUERY.finditer(content):
            result['ajax_calls'].append({
                'method': m.group(1),
                'url': m.group(2),
                'type': 'jQuery.' + m.group(1),
                'file': filename,
                'line': content[:m.start()].count('\n') + 1,
            })

        for m in RE_AJAX_JQUERY_OBJ.finditer(content):
            result['ajax_calls'].append({
                'method': 'ajax',
                'url': m.group(1),
                'type': 'jQuery.ajax({})',
                'file': filename,
                'line': content[:m.start()].count('\n') + 1,
            })

        for m in RE_FETCH.finditer(content):
            result['ajax_calls'].append({
                'method': 'fetch',
                'url': m.group(1),
                'type': 'fetch',
                'file': filename,
                'line': content[:m.start()].count('\n') + 1,
            })

        for m in RE_XHR_OPEN.finditer(content):
            result['ajax_calls'].append({
                'method': m.group(1),
                'url': m.group(2),
                'type': 'XMLHttpRequest',
                'file': filename,
                'line': content[:m.start()].count('\n') + 1,
            })

        return result


# =====================================================================
# PHP Analyzer
# =====================================================================

def _resolve_php_var(content, var_name, before_pos):
    """Try to find a simple assignment like  $var = "value";  before `before_pos`.

    Returns the resolved string value (with quotes stripped), or None.
    Handles patterns like:
        $send = "a@b.com";
        $send = 'a@b.com,c@d.com';
        $send = "a@b.com" . ",c@d.com";
    """
    escaped = re.escape(var_name)
    # Look for the latest assignment before before_pos
    pattern = re.compile(
        escaped + r'\s*=\s*["\']([^"\']*(?:\.[^"\']*)*)["\']',
        re.MULTILINE)
    best = None
    for m in pattern.finditer(content[:before_pos]):
        best = m
    if best:
        return best.group(1).strip()

    # Try concatenation with . operator: $var = "a" . "," . "b";
    pattern2 = re.compile(
        escaped + r'\s*=\s*(.+?);\s*$',
        re.MULTILINE)
    for m2 in pattern2.finditer(content[:before_pos]):
        best = m2
    if best:
        parts = re.findall(r'["\']([^"\']*)["\']', best.group(1))
        if parts:
            return ''.join(parts)

    return None


class PHPAnalyzer:
    """Parse PHP source to extract data handling logic."""

    @staticmethod
    def analyze(content, filename=''):
        """Analyze PHP content and return structured data."""
        result = {
            'receives_post': [],
            'receives_get': [],
            'actions': [],
            'includes': [],
            'exfil': [],
        }

        # POST/GET/REQUEST field access
        for m in RE_PHP_POST.finditer(content):
            result['receives_post'].append(m.group(1))
        for m in RE_PHP_GET.finditer(content):
            result['receives_get'].append(m.group(1))
        for m in RE_PHP_REQUEST.finditer(content):
            result['receives_post'].append(m.group(1))

        result['receives_post'] = sorted(set(result['receives_post']))
        result['receives_get'] = sorted(set(result['receives_get']))

        # mail() -- detect all mail() calls, both literal and variable-based
        #  Case 1: mail("addr@example.com", ...)  -> literal string recipient
        #  Case 2: mail($variable, ...)           -> variable recipient
        _mail_found = set()
        for m in RE_PHP_MAIL_TO.finditer(content):
            addr = m.group(1).strip()
            if '@' in addr or '$' in addr:
                key = ('mail', addr, content[:m.start()].count('\n') + 1)
                if key not in _mail_found:
                    _mail_found.add(key)
                    result['actions'].append({
                        'type': 'mail',
                        'target': addr,
                        'line': key[2],
                    })
                    result['exfil'].append('email:' + addr)

        # Also match mail($var, ...) where recipient is a PHP variable
        for m in RE_PHP_MAIL.finditer(content):
            first_arg = m.group(1).split(',')[0].strip()
            line_no = content[:m.start()].count('\n') + 1
            key = ('mail', first_arg, line_no)
            if key in _mail_found:
                continue
            _mail_found.add(key)
            if first_arg.startswith('$'):
                # Try to resolve the variable value from nearby assignment
                var_name = first_arg
                resolved = _resolve_php_var(content, var_name, m.start())
                target = resolved if resolved else var_name
                result['actions'].append({
                    'type': 'mail',
                    'target': target,
                    'variable': var_name,
                    'line': line_no,
                })
                if '@' in target:
                    result['exfil'].append('email:' + target)
                else:
                    result['exfil'].append('email:' + var_name)
            elif '@' not in first_arg:
                # Already caught by RE_PHP_MAIL_TO above if it had @
                result['actions'].append({
                    'type': 'mail',
                    'target': first_arg,
                    'line': line_no,
                })
                result['exfil'].append('email:' + first_arg)

        # Telegram
        for m in RE_PHP_TELEGRAM.finditer(content):
            result['actions'].append({
                'type': 'telegram',
                'target': 'api.telegram.org/bot' + m.group(1),
                'line': content[:m.start()].count('\n') + 1,
            })
            result['exfil'].append('telegram:' + m.group(1)[:20])

        # header(Location:)
        for m in RE_PHP_HEADER.finditer(content):
            result['actions'].append({
                'type': 'redirect',
                'target': m.group(1).strip(),
                'line': content[:m.start()].count('\n') + 1,
            })

        # curl
        for m in RE_PHP_CURL.finditer(content):
            result['actions'].append({
                'type': 'curl',
                'target': m.group(1),
                'line': content[:m.start()].count('\n') + 1,
            })
            result['exfil'].append('curl:' + m.group(1))

        # file_get_contents (remote)
        for m in RE_PHP_FILE_GET.finditer(content):
            result['actions'].append({
                'type': 'file_get_contents',
                'target': m.group(1),
                'line': content[:m.start()].count('\n') + 1,
            })

        # fwrite (local logging)
        for m in RE_PHP_FWRITE.finditer(content):
            result['actions'].append({
                'type': 'fwrite',
                'target': '(file)',
                'line': content[:m.start()].count('\n') + 1,
            })

        # includes
        for m in RE_PHP_INCLUDE.finditer(content):
            result['includes'].append(m.group(1))

        result['exfil'] = sorted(set(result['exfil']))

        # Return None if nothing interesting
        if not any([result['receives_post'], result['receives_get'],
                     result['actions']]):
            return None

        return result


# =====================================================================
# Code Map Builder -- scan a kit and build the full map
# =====================================================================

class StaticCodeAnalyzer:
    """Scan a phishing kit directory and build a code map.

    The code map contains:
      - All JS function definitions (name, params, file, line, body)
      - All event handler bindings (element + event -> function)
      - All AJAX call targets
      - PHP file behaviors (what each PHP file does with POST data)
      - Form structure (action targets, fields, inline handlers)
      - A normalized function body index for cross-referencing with
        dynamic (anonymous) functions
    """

    def __init__(self, kit_path, web_root=None):
        self.kit_path = os.path.realpath(kit_path)
        self.web_root = web_root or self.kit_path

    def build(self):
        """Scan the kit and return the code map."""
        code_map = {
            'kit_path': self.kit_path,
            'html_files': {},
            'js_files': {},
            'php_files': {},
            'function_index': {},
            'form_actions': {},
            'event_chain': [],
            'data_flow': [],
        }

        for dirpath, dirnames, filenames in os.walk(self.kit_path):
            dirnames[:] = [d for d in dirnames
                           if d not in SKIP_DIRS and not d.startswith('.')]

            for fname in filenames:
                filepath = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(filepath, self.web_root)
                _, ext = os.path.splitext(fname)
                ext = ext.lower()

                if ext not in ALL_EXTENSIONS:
                    continue

                try:
                    with open(filepath, 'r', encoding='utf-8',
                              errors='ignore') as f:
                        content = f.read()
                except Exception:
                    continue

                if len(content) < 5:
                    continue

                if ext in HTML_EXTENSIONS:
                    self._analyze_html(content, rel_path, code_map)
                elif ext in JS_EXTENSIONS:
                    self._analyze_js(content, rel_path, code_map)
                elif ext in PHP_EXTENSIONS:
                    self._analyze_php(content, rel_path, code_map)

        # Build derived structures
        self._build_function_index(code_map)
        self._build_data_flow(code_map)

        return code_map

    def _analyze_html(self, content, rel_path, code_map):
        parser = FormHTMLParser()
        try:
            parser.feed(content)
        except Exception:
            pass

        html_info = {
            'forms': parser.forms,
            'inline_handlers': parser.inline_handlers,
            'embedded_js': [],
        }

        # Analyze embedded <script> blocks
        for i, script in enumerate(parser.scripts):
            script_name = '%s:<script#%d>' % (rel_path, i + 1)
            js_result = JSAnalyzer.analyze(script, script_name)
            html_info['embedded_js'].append(js_result)

            # Also merge embedded JS analysis into the global code map
            # so that _build_data_flow and _build_function_index can
            # discover AJAX calls and functions from embedded scripts.
            entry = code_map.setdefault('js_files', {}).setdefault(
                script_name, {'functions': [], 'event_bindings': [],
                              'ajax_calls': []})
            for func in js_result['functions']:
                entry['functions'].append(func)
            for eb in js_result.get('event_bindings', []):
                entry['event_bindings'].append(eb)
            for ac in js_result.get('ajax_calls', []):
                entry['ajax_calls'].append(ac)

        # Map form actions
        for form in parser.forms:
            action = form.get('action', '')
            if action:
                action_file = action.split('?')[0].strip()
                code_map['form_actions'][action_file] = {
                    'source_file': rel_path,
                    'method': form['method'],
                    'fields': form['fields'],
                }

        code_map['html_files'][rel_path] = html_info

    def _analyze_js(self, content, rel_path, code_map):
        js_result = JSAnalyzer.analyze(content, rel_path)
        code_map['js_files'][rel_path] = js_result

    def _analyze_php(self, content, rel_path, code_map):
        php_result = PHPAnalyzer.analyze(content, rel_path)
        if php_result:
            php_result['file'] = rel_path
            code_map['php_files'][rel_path] = php_result

        # PHP files often contain embedded HTML + JavaScript (e.g. index.php).
        # Also analyze the HTML/JS content so functions, event bindings,
        # and form structures inside PHP files are not missed.
        if '<html' in content.lower() or '<form' in content.lower() or '<script' in content.lower():
            self._analyze_html(content, rel_path, code_map)

    def _build_function_index(self, code_map):
        """Build a normalized body -> function info index.

        Used to resolve dynamic (anonymous) functions back to their
        real names by matching function body text.
        """
        index = {}

        for file_key, js_info in code_map.get('js_files', {}).items():
            for func in js_info.get('functions', []):
                body = func.get('body_preview', '')
                if not body or len(body) < 20:
                    continue
                norm = self._normalize_js(body)
                index[norm] = {
                    'name': func['name'],
                    'file': func['file'],
                    'line': func['line'],
                    'params': func['params'],
                }

        # Also index inline handlers
        for file_key, html_info in code_map.get('html_files', {}).items():
            for handler in html_info.get('inline_handlers', []):
                code = handler.get('handler_code', '')
                if code:
                    index[self._normalize_js(code)] = {
                        'name': '(inline:%s)' % handler['event'],
                        'file': file_key,
                        'line': 0,
                        'params': 'event',
                        'element': '%s#%s' % (
                            handler['tag'],
                            handler.get('element_id', '')),
                    }

        code_map['function_index'] = index

    def _build_data_flow(self, code_map):
        """Build the data flow chain: form -> action -> PHP behavior."""
        flows = []

        for action_file, form_info in code_map.get('form_actions', {}).items():
            # Find the PHP file that handles this action
            php_info = None
            for php_key, php_data in code_map.get('php_files', {}).items():
                # Match by filename (action might be relative)
                if (php_key == action_file or
                        php_key.endswith('/' + action_file) or
                        os.path.basename(php_key) == os.path.basename(
                            action_file)):
                    php_info = php_data
                    break

            flow = {
                'form_source': form_info['source_file'],
                'form_method': form_info['method'],
                'form_fields': [f['name'] for f in form_info['fields']
                                if f['name']],
                'action_target': action_file,
                'server_file': php_info['file'] if php_info else None,
                'server_receives': (
                    php_info['receives_post'] if php_info else []),
                'server_actions': (
                    php_info['actions'] if php_info else []),
                'exfil': php_info['exfil'] if php_info else [],
            }
            flows.append(flow)

        # Also check JS AJAX calls -> PHP files
        for file_key, js_info in code_map.get('js_files', {}).items():
            for ajax in js_info.get('ajax_calls', []):
                url = ajax['url']
                url_file = url.split('?')[0].strip().lstrip('/')
                php_info = None
                for php_key, php_data in code_map.get(
                        'php_files', {}).items():
                    if (php_key == url_file or
                            php_key.endswith('/' + url_file) or
                            os.path.basename(php_key) == os.path.basename(
                                url_file)):
                        php_info = php_data
                        break

                flows.append({
                    'form_source': file_key,
                    'form_method': ajax['method'],
                    'form_fields': [],
                    'action_target': url,
                    'server_file': php_info['file'] if php_info else None,
                    'server_receives': (
                        php_info['receives_post'] if php_info else []),
                    'server_actions': (
                        php_info['actions'] if php_info else []),
                    'exfil': php_info['exfil'] if php_info else [],
                    'ajax_type': ajax['type'],
                    'ajax_source_line': ajax['line'],
                })

        code_map['data_flow'] = flows

    @staticmethod
    def _normalize_js(code):
        """Normalize JS code for fuzzy matching.

        Strips whitespace, lowercases, removes common noise.
        """
        s = re.sub(r'\s+', ' ', code.strip())
        return s[:200]


# =====================================================================
# Resolver -- cross-reference dynamic results with static code map
# =====================================================================

class DynamicResolver:
    """Cross-reference dynamic analysis results with a static code map.

    Enriches triggeredFunctions with resolved names and networkReqs
    with server-side behavior.
    """

    def __init__(self, code_map):
        self.code_map = code_map
        self.func_index = code_map.get('function_index', {})
        self.php_files = code_map.get('php_files', {})
        self.data_flows = code_map.get('data_flow', [])

    def resolve_function(self, triggered_fn):
        """Try to resolve a triggered function to its static definition.

        Args:
            triggered_fn: dict with 'functionName', 'functionSource', etc.

        Returns:
            dict with resolved info, or None if no match.
        """
        fn_source = triggered_fn.get('functionSource', '')
        fn_name = triggered_fn.get('functionName', '')

        # 1. Direct name match (if not anonymous)
        if fn_name and fn_name != '(anonymous)':
            for norm_body, info in self.func_index.items():
                if info['name'] == fn_name:
                    return {
                        'resolved_name': info['name'],
                        'file': info['file'],
                        'line': info['line'],
                        'params': info['params'],
                        'match_type': 'name_match',
                    }

        # 2. Body substring match
        if fn_source and len(fn_source) > 20:
            norm = StaticCodeAnalyzer._normalize_js(fn_source)
            # Try exact prefix match
            for norm_body, info in self.func_index.items():
                if norm_body.startswith(norm[:80]) or norm.startswith(
                        norm_body[:80]):
                    return {
                        'resolved_name': info['name'],
                        'file': info['file'],
                        'line': info['line'],
                        'params': info['params'],
                        'match_type': 'body_match',
                    }

            # Try looser: check if significant tokens overlap
            src_tokens = set(re.findall(r'[a-zA-Z_$]\w+', fn_source[:200]))
            best_match = None
            best_score = 0
            for norm_body, info in self.func_index.items():
                idx_tokens = set(
                    re.findall(r'[a-zA-Z_$]\w+', norm_body))
                if not idx_tokens:
                    continue
                overlap = len(src_tokens & idx_tokens)
                score = overlap / max(len(src_tokens), len(idx_tokens), 1)
                if score > best_score and score > 0.5:
                    best_score = score
                    best_match = info

            if best_match:
                return {
                    'resolved_name': best_match['name'],
                    'file': best_match['file'],
                    'line': best_match['line'],
                    'params': best_match['params'],
                    'match_type': 'token_match (%.0f%%)' % (
                        best_score * 100),
                }

        return None

    def resolve_network_request(self, net_req):
        """Resolve a network request URL to server-side behavior.

        Args:
            net_req: dict with 'url', 'method', etc.

        Returns:
            dict describing what the server does, or None.
        """
        url = net_req.get('url', '')
        if not url:
            return None

        url_file = url.split('?')[0].strip().rstrip('/')
        url_basename = os.path.basename(url_file)

        # Search PHP files
        for php_key, php_data in self.php_files.items():
            if (php_key == url_file or
                    php_key.endswith('/' + url_file.lstrip('/')) or
                    os.path.basename(php_key) == url_basename):
                return {
                    'server_file': php_data['file'],
                    'receives_fields': php_data['receives_post'],
                    'actions': php_data['actions'],
                    'exfil': php_data.get('exfil', []),
                }

        # Check data_flow for AJAX matches
        for flow in self.data_flows:
            target = flow.get('action_target', '')
            if (os.path.basename(target) == url_basename or
                    target == url_file):
                return {
                    'server_file': flow.get('server_file', ''),
                    'receives_fields': flow.get('server_receives', []),
                    'actions': flow.get('server_actions', []),
                    'exfil': flow.get('exfil', []),
                }

        return None

    def enrich_form_result(self, form_result):
        """Enrich a FormAnalyzer form result dict with static resolution.

        Modifies form_result in-place, adding 'resolved' keys to
        triggeredFunctions and networkReqs entries.
        """
        # Enrich field-level logs
        for field in form_result.get('fields', []):
            self._enrich_logs(field.get('typing_log', []),
                              log_type='typing')
            self._enrich_log_dict(field.get('backspace_log', {}))
            self._enrich_log_dict(field.get('other_log', {}))

        # Enrich submit logs
        submit_log = form_result.get('submit_log', {})
        for key in ('enter_key_logs', 'submit_click_logs'):
            logs = submit_log.get(key, {})
            if isinstance(logs, dict):
                self._resolve_log_snapshot(logs)

        # Add form-level static analysis
        form_action = form_result.get('action', '')
        if form_action:
            action_file = form_action.split('?')[0].strip()
            action_basename = os.path.basename(action_file)
            for php_key, php_data in self.php_files.items():
                if os.path.basename(php_key) == action_basename:
                    form_result['static_action_analysis'] = {
                        'server_file': php_data['file'],
                        'receives_fields': php_data['receives_post'],
                        'actions': php_data['actions'],
                        'exfil': php_data.get('exfil', []),
                    }
                    break

    def _enrich_logs(self, typing_log, log_type='typing'):
        for char_entry in typing_log:
            if not isinstance(char_entry, dict):
                continue
            for phase in ('keydown', 'keypress', 'input', 'keyup'):
                logs = char_entry.get(phase, {})
                if isinstance(logs, dict):
                    self._resolve_log_snapshot(logs)

    def _enrich_log_dict(self, log_dict):
        if not isinstance(log_dict, dict):
            return
        for key, logs in log_dict.items():
            if isinstance(logs, dict) and 'triggeredFunctions' in logs:
                self._resolve_log_snapshot(logs)
            elif isinstance(logs, dict):
                for sub_key, sub_logs in logs.items():
                    if isinstance(sub_logs, dict):
                        self._resolve_log_snapshot(sub_logs)

    def _resolve_log_snapshot(self, snapshot):
        """Resolve triggered functions and network requests in a snapshot."""
        for fn in snapshot.get('triggeredFunctions', []):
            resolved = self.resolve_function(fn)
            if resolved:
                fn['resolved'] = resolved

        for req in snapshot.get('networkReqs', []):
            resolved = self.resolve_network_request(req)
            if resolved:
                req['resolved_server'] = resolved


# =====================================================================
# CLI
# =====================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Static Code Analyzer for Phishing Kits')
    parser.add_argument(
        '--kit-path', required=True,
        help='Path to the phishing kit directory to analyze')
    parser.add_argument(
        '--output', default=None,
        help='Output JSON file (default: stdout summary)')
    parser.add_argument(
        '--web-root', default=None,
        help='Web root within kit-path (for URL alignment)')
    args = parser.parse_args()

    analyzer = StaticCodeAnalyzer(args.kit_path, args.web_root)
    code_map = analyzer.build()

    # Summary
    n_html = len(code_map.get('html_files', {}))
    n_js = len(code_map.get('js_files', {}))
    n_php = len(code_map.get('php_files', {}))
    n_funcs = len(code_map.get('function_index', {}))
    n_flows = len(code_map.get('data_flow', []))

    print("=" * 60)
    print("  Static Code Analysis Results")
    print("=" * 60)
    print("  HTML files:    %d" % n_html)
    print("  JS files:      %d" % n_js)
    print("  PHP files:     %d" % n_php)
    print("  Functions:     %d" % n_funcs)
    print("  Data flows:    %d" % n_flows)

    # Print data flows
    if code_map['data_flow']:
        print("\n  Data Flow Chains:")
        for flow in code_map['data_flow']:
            src = flow.get('form_source', '?')
            target = flow.get('action_target', '?')
            server = flow.get('server_file', '?')
            actions = flow.get('server_actions', [])
            exfil = flow.get('exfil', [])
            action_str = ', '.join(
                '%s->%s' % (a['type'], a['target'][:40])
                for a in actions) or 'none'
            print("    %s -> %s -> [%s] %s"
                  % (src, target, action_str,
                     ('EXFIL: ' + ','.join(exfil)) if exfil else ''))

    # Print functions
    funcs = code_map.get('function_index', {})
    if funcs:
        print("\n  JS Functions Found:")
        for norm, info in sorted(funcs.items(),
                                  key=lambda x: x[1]['file']):
            print("    %s:%d  %s(%s)"
                  % (info['file'], info['line'],
                     info['name'], info['params']))

    # Print PHP files
    for php_key, php_data in code_map.get('php_files', {}).items():
        print("\n  PHP: %s" % php_key)
        if php_data['receives_post']:
            print("    Receives POST: %s"
                  % ', '.join(php_data['receives_post']))
        for action in php_data['actions']:
            print("    Action: %s -> %s (line %d)"
                  % (action['type'], action['target'][:60],
                     action['line']))

    print("=" * 60)

    if args.output:
        # Serialize (remove body_preview for cleaner output)
        clean = json.loads(json.dumps(code_map, default=str))
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(clean, f, indent=2, ensure_ascii=False)
        print("[Output] Saved to %s" % args.output)


if __name__ == '__main__':
    main()
