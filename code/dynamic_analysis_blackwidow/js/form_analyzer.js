/*
 * Form Analyzer - Browser-side instrumentation for dynamic form behavior analysis.
 *
 * Hooks into:
 *   (A) MutationObserver - DOM change detection
 *   (B) XHR/Fetch - Network request/response capture (pass-through)
 *   (C) Document-level event capturing - All relevant events
 *   (D) HTML5 Validation - 'invalid' event capture
 *
 * Depends on: lib.js (getXPath, Simulate)
 */

window.__fa = {
    active: false,
    phase: '',
    stepCounter: 0,
    domChanges: [],
    networkReqs: [],
    firedEvents: [],
    html5Validation: [],
    triggeredFunctions: [],
    registeredHandlers: []
};

// ============================================================
// (A) MutationObserver - DOM Change Detection
// ============================================================

var __fa_observer = new MutationObserver(function(mutations) {
    if (!window.__fa.active) return;
    mutations.forEach(function(mutation) {
        var targetXPath = '';
        try {
            if (mutation.target && mutation.target.nodeType === 1) {
                targetXPath = getXPath(mutation.target);
            }
        } catch(e) { targetXPath = 'unknown'; }

        var addedHTML = [];
        for (var i = 0; i < mutation.addedNodes.length && i < 5; i++) {
            var n = mutation.addedNodes[i];
            addedHTML.push(n.outerHTML || n.textContent || '');
        }

        var removedHTML = [];
        for (var j = 0; j < mutation.removedNodes.length && j < 5; j++) {
            var m = mutation.removedNodes[j];
            removedHTML.push(m.outerHTML || m.textContent || '');
        }

        window.__fa.domChanges.push({
            step: window.__fa.stepCounter,
            phase: window.__fa.phase,
            type: mutation.type,
            targetXPath: targetXPath,
            targetTag: mutation.target.tagName || 'unknown',
            addedNodes: addedHTML,
            removedNodes: removedHTML,
            attributeName: mutation.attributeName || null,
            oldValue: mutation.oldValue || null,
            timestamp: Date.now()
        });
    });
});


// ============================================================
// (A-2) Triggered Function Tracking
//       Wraps event handler callbacks to log WHICH page-defined
//       JS function actually runs when an event fires.
// ============================================================

// Helper: wrap a callback so its execution is logged.
function __fa_wrapCallback(origFn, eventType, element) {
    if (!origFn || origFn.__fa_internal || origFn.__fa_wrapped) {
        return origFn;
    }

    var fnName = origFn.name || '(anonymous)';
    var fnSource = '';
    try { fnSource = origFn.toString().substring(0, 500); } catch(e) {}

    // Skip form_analyzer's own code
    if (fnName.indexOf('__fa_') === 0 ||
        fnSource.indexOf('window.__fa') !== -1 ||
        fnSource.indexOf('__fa_') !== -1) {
        return origFn;
    }

    var wrapper = function() {
        if (window.__fa && window.__fa.active) {
            var xpath = '';
            try {
                if (element && element.nodeType === 1) xpath = getXPath(element);
            } catch(e) {}

            window.__fa.triggeredFunctions.push({
                step: window.__fa.stepCounter,
                phase: window.__fa.phase,
                source: 'addEventListener',
                eventType: eventType,
                functionName: fnName,
                functionSource: fnSource,
                elementXPath: xpath,
                elementTag: element ? (element.tagName || '') : '',
                elementName: element ? (element.name || '') : '',
                timestamp: Date.now()
            });
        }
        return origFn.apply(this, arguments);
    };
    wrapper.__fa_wrapped = true;
    wrapper.__fa_internal = true;
    wrapper.__fa_origFn = origFn;
    return wrapper;
}

// Chain on Element.prototype.addEventListener
// (addeventlistener_wrapper.js already wrapped this; we chain on top)
var __fa_prevElemAddListener = Element.prototype.addEventListener;
Element.prototype.addEventListener = function(type, callback, options) {
    if (typeof callback === 'function' &&
        !callback.__fa_internal && !callback.__fa_wrapped) {
        var wrapped = __fa_wrapCallback(callback, type, this);
        if (wrapped !== callback) {
            if (!this.__fa_cbMap) this.__fa_cbMap = [];
            this.__fa_cbMap.push({ type: type, orig: callback, wrapped: wrapped });
            return __fa_prevElemAddListener.call(this, type, wrapped, options);
        }
    }
    return __fa_prevElemAddListener.call(this, type, callback, options);
};

// Keep removeEventListener working with wrapped callbacks
var __fa_prevElemRemoveListener = Element.prototype.removeEventListener;
Element.prototype.removeEventListener = function(type, callback, options) {
    if (this.__fa_cbMap) {
        for (var i = this.__fa_cbMap.length - 1; i >= 0; i--) {
            var m = this.__fa_cbMap[i];
            if (m.type === type && m.orig === callback) {
                var w = m.wrapped;
                this.__fa_cbMap.splice(i, 1);
                return __fa_prevElemRemoveListener.call(this, type, w, options);
            }
        }
    }
    return __fa_prevElemRemoveListener.call(this, type, callback, options);
};


// ============================================================
// (B) XHR/Fetch Interception (pass-through with logging)
// ============================================================

// --- XHR ---
// IMPORTANT: lib.js may have already wrapped XMLHttpRequest.prototype.open
// (for its need_to_wait flag).  We capture whatever .open/.send/.setRequestHeader
// currently points to, so our wrapper chains on top of any prior wrappers.
var __fa_origXHROpen = XMLHttpRequest.prototype.open;
var __fa_origXHRSend = XMLHttpRequest.prototype.send;
var __fa_origXHRSetHeader = XMLHttpRequest.prototype.setRequestHeader;

function __fa_headersToObject(rawHeaders) {
    if (!rawHeaders) return {};
    var out = {};
    String(rawHeaders).split(/\r?\n/).forEach(function(line) {
        if (!line) return;
        var idx = line.indexOf(':');
        if (idx === -1) return;
        var key = line.slice(0, idx).trim();
        var value = line.slice(idx + 1).trim();
        if (key) out[key] = value;
    });
    return out;
}

XMLHttpRequest.prototype.open = function(method, url, async, user, pass) {
    this.__fa_method = method;
    this.__fa_url = url;
    this.__fa_headers = {};
    return __fa_origXHROpen.apply(this, arguments);
};

XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    if (this.__fa_headers) {
        this.__fa_headers[name] = value;
    }
    return __fa_origXHRSetHeader.apply(this, arguments);
};

XMLHttpRequest.prototype.send = function(body) {
    if (!window.__fa.active) {
        return __fa_origXHRSend.apply(this, arguments);
    }

    var xhr = this;
    var stackTrace = '';
    try { throw new Error('__fa_xhr_trace'); }
    catch(e) { stackTrace = (e.stack || '').substring(0, 1500); }

    var reqEntry = {
        step: window.__fa.stepCounter,
        phase: window.__fa.phase,
        type: 'xhr',
        method: xhr.__fa_method || 'unknown',
        url: xhr.__fa_url || 'unknown',
        requestHeaders: xhr.__fa_headers || {},
        requestContentType: (xhr.__fa_headers || {})['Content-Type'] || '',
        requestBody: body ? String(body).substring(0, 2000) : null,
        callStack: stackTrace,
        status: null,
        response: null,
        responseHeaders: null,
        responseContentType: '',
        responseReturned: false,
        redirected: false,
        finalUrl: null,
        responseBodyLength: null,
        timestamp: Date.now(),
        latencyMs: null,
        ttfbMs: null
    };
    var __fa_sendTs = Date.now();

    xhr.addEventListener('load', function() {
        var __fa_loadTs = Date.now();
        reqEntry.status = xhr.status;
        reqEntry.response = xhr.responseText
            ? xhr.responseText.substring(0, 2000)
            : null;
        reqEntry.responseHeaders = __fa_headersToObject(xhr.getAllResponseHeaders());
        reqEntry.responseContentType = xhr.getResponseHeader('Content-Type') || '';
        reqEntry.responseReturned = true;
        reqEntry.finalUrl = xhr.responseURL || reqEntry.url;
        reqEntry.redirected = !!(xhr.responseURL && xhr.responseURL !== reqEntry.url);
        reqEntry.responseBodyLength = xhr.responseText ? xhr.responseText.length : 0;
        reqEntry.latencyMs = __fa_loadTs - __fa_sendTs;
    });

    xhr.addEventListener('error', function() {
        reqEntry.status = 'error';
        reqEntry.response = null;
        reqEntry.responseReturned = false;
    });

    window.__fa.networkReqs.push(reqEntry);
    return __fa_origXHRSend.apply(this, arguments);
};

// --- Fetch ---
if (window.fetch) {
    var __fa_origFetch = window.fetch;

    // Safely serialise headers which can be a Headers object, a plain
    // object, or an array of [key,value] pairs.
    function __fa_serializeHeaders(hdrs) {
        if (!hdrs) return {};
        try {
            if (hdrs instanceof Headers) {
                var obj = {};
                hdrs.forEach(function(value, key) { obj[key] = value; });
                return obj;
            }
            // Plain objects or arrays -- JSON round-trip handles both
            return JSON.parse(JSON.stringify(hdrs));
        } catch(e) {
            return {};
        }
    }

    window.fetch = function(input, init) {
        if (!window.__fa.active) {
            return __fa_origFetch.apply(this, arguments);
        }

        var stackTrace = '';
        try { throw new Error('__fa_fetch_trace'); }
        catch(e) { stackTrace = (e.stack || '').substring(0, 1500); }

        var reqEntry = {
            step: window.__fa.stepCounter,
            phase: window.__fa.phase,
            type: 'fetch',
            url: (typeof input === 'string') ? input : (input.url || 'unknown'),
            method: (init && init.method) ? init.method : 'GET',
            requestHeaders: __fa_serializeHeaders(init && init.headers),
            requestContentType: '',
            requestBody: (init && init.body)
                ? String(init.body).substring(0, 2000)
                : null,
            callStack: stackTrace,
            status: null,
            response: null,
            responseHeaders: null,
            timestamp: Date.now(),
            latencyMs: null
        };
        var __fa_fetchSendTs = Date.now();

        reqEntry.requestContentType =
            reqEntry.requestHeaders['Content-Type'] ||
            reqEntry.requestHeaders['content-type'] || '';

        window.__fa.networkReqs.push(reqEntry);

        return __fa_origFetch.apply(this, arguments).then(function(response) {
            reqEntry.latencyMs = Date.now() - __fa_fetchSendTs;
            reqEntry.status = response.status;
            reqEntry.responseHeaders = __fa_serializeHeaders(response.headers);
            reqEntry.responseContentType = response.headers.get('content-type') || '';
            reqEntry.responseReturned = true;
            reqEntry.redirected = !!response.redirected;
            reqEntry.finalUrl = response.url || reqEntry.url;
            var cloned = response.clone();
            cloned.text().then(function(text) {
                reqEntry.response = text.substring(0, 2000);
                reqEntry.responseBodyLength = text.length;
            }).catch(function() {});
            return response;
        }).catch(function(err) {
            reqEntry.status = 'error';
            reqEntry.response = err.toString();
            reqEntry.responseReturned = false;
            throw err;
        });
    };
}


// ============================================================
// (C) Document-level Event Capturing
// ============================================================

var __fa_monitored_events = [
    'keydown', 'keypress', 'keyup', 'input', 'change',
    'focus', 'blur', 'click', 'submit',
    'compositionstart', 'compositionend', 'compositionupdate',
    'mousedown', 'mouseup', 'mouseover', 'mouseout',
    'dragstart', 'drag', 'dragend', 'drop'
];

__fa_monitored_events.forEach(function(eventType) {
    document.addEventListener(eventType, function(e) {
        if (!window.__fa.active) return;

        var targetXPath = '';
        try {
            if (e.target && e.target.nodeType === 1) {
                targetXPath = getXPath(e.target);
            }
        } catch(err) { targetXPath = 'unknown'; }

        // Capture a lightweight call-stack so we can see which JS
        // handler was on the stack when the event fired.
        var stackTrace = '';
        try { throw new Error('__fa_event_trace'); }
        catch(err) { stackTrace = (err.stack || '').substring(0, 1000); }

        window.__fa.firedEvents.push({
            step: window.__fa.stepCounter,
            phase: window.__fa.phase,
            eventType: eventType,
            targetXPath: targetXPath,
            targetTag: e.target ? (e.target.tagName || 'unknown') : 'unknown',
            targetName: e.target ? (e.target.name || '') : '',
            targetType: e.target ? (e.target.type || '') : '',
            targetValue: e.target ? (String(e.target.value || '').substring(0, 200)) : '',
            key: e.key || null,
            keyCode: e.keyCode || null,
            defaultPrevented: e.defaultPrevented,
            callStack: stackTrace,
            timestamp: Date.now()
        });
    }, true);  // capture phase
});


// ============================================================
// (D) HTML5 Validation Detection
// ============================================================

document.addEventListener('invalid', function(e) {
    if (!window.__fa.active) return;

    var targetXPath = '';
    try {
        if (e.target && e.target.nodeType === 1) {
            targetXPath = getXPath(e.target);
        }
    } catch(err) { targetXPath = 'unknown'; }

    window.__fa.html5Validation.push({
        step: window.__fa.stepCounter,
        phase: window.__fa.phase,
        targetXPath: targetXPath,
        targetTag: e.target.tagName || 'unknown',
        targetType: e.target.type || '',
        targetName: e.target.name || '',
        validationMessage: e.target.validationMessage || '',
        validity: {
            valueMissing: e.target.validity.valueMissing,
            typeMismatch: e.target.validity.typeMismatch,
            patternMismatch: e.target.validity.patternMismatch,
            tooLong: e.target.validity.tooLong,
            tooShort: e.target.validity.tooShort,
            rangeUnderflow: e.target.validity.rangeUnderflow,
            rangeOverflow: e.target.validity.rangeOverflow,
            stepMismatch: e.target.validity.stepMismatch,
            customError: e.target.validity.customError,
            badInput: e.target.validity.badInput
        },
        timestamp: Date.now()
    });
}, true);


// ============================================================
// (F) on* Property Handler Instrumentation
//     Wraps inline/property event handlers (onkeyup, onclick, etc.)
//     so we can log which function body executes at runtime.
//     Called from Python before dispatching events on a field.
// ============================================================

window.__fa_instrumentOnHandlers = function(xpath) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return 0;

    var props = [
        'onkeydown','onkeypress','onkeyup','oninput','onchange',
        'onfocus','onblur','onclick','onsubmit','onmousedown',
        'onmouseup','ondblclick','oninvalid','ondragstart','ondrag',
        'ondragend','ondrop'
    ];

    if (!el.__fa_origOnHandlers) el.__fa_origOnHandlers = {};
    var count = 0;

    for (var i = 0; i < props.length; i++) {
        var prop = props[i];
        if (typeof el[prop] === 'function' && !el[prop].__fa_internal) {
            var orig = el[prop];

            var fnName = orig.name || prop;
            var fnSource = '';
            try { fnSource = orig.toString().substring(0, 500); } catch(e) {}

            // Skip our own code
            if (fnName.indexOf('__fa_') === 0 ||
                fnSource.indexOf('window.__fa') !== -1) {
                continue;
            }

            el.__fa_origOnHandlers[prop] = orig;

            // IIFE to capture loop variables correctly
            (function(propName, origFn, funcName, funcSource, elRef, xp) {
                elRef[propName] = function() {
                    if (window.__fa && window.__fa.active) {
                        window.__fa.triggeredFunctions.push({
                            step: window.__fa.stepCounter,
                            phase: window.__fa.phase,
                            source: 'on-property',
                            eventType: propName.replace(/^on/, ''),
                            functionName: funcName,
                            functionSource: funcSource,
                            elementXPath: xp,
                            elementTag: elRef.tagName || '',
                            elementName: elRef.name || '',
                            timestamp: Date.now()
                        });
                    }
                    return origFn.apply(this, arguments);
                };
                elRef[propName].__fa_internal = true;
            })(prop, orig, fnName, fnSource, el, xpath);

            count++;
        }
    }
    return count;
};

window.__fa_restoreOnHandlers = function(xpath) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el || !el.__fa_origOnHandlers) return;

    for (var prop in el.__fa_origOnHandlers) {
        if (el.__fa_origOnHandlers.hasOwnProperty(prop)) {
            el[prop] = el.__fa_origOnHandlers[prop];
        }
    }
    el.__fa_origOnHandlers = {};
};


// ============================================================
// Helper Functions (called from Python via execute_script)
// ============================================================

window.__fa_start = function() {
    window.__fa.active = true;
    window.__fa.stepCounter = 0;
    window.__fa.domChanges = [];
    window.__fa.networkReqs = [];
    window.__fa.firedEvents = [];
    window.__fa.html5Validation = [];
    window.__fa.triggeredFunctions = [];
    window.__fa.registeredHandlers = [];

    __fa_observer.observe(document.body || document.documentElement, {
        childList: true,
        attributes: true,
        characterData: true,
        subtree: true,
        attributeOldValue: true,
        characterDataOldValue: true
    });
};

window.__fa_stop = function() {
    window.__fa.active = false;
    __fa_observer.disconnect();
};

window.__fa_setPhase = function(phase) {
    window.__fa.phase = phase;
};

window.__fa_incrementStep = function() {
    window.__fa.stepCounter++;
};

window.__fa_getLogs = function() {
    return JSON.stringify(window.__fa);
};

window.__fa_getAndClearLogs = function() {
    var snapshot = {
        step: window.__fa.stepCounter,
        phase: window.__fa.phase,
        domChanges: window.__fa.domChanges.slice(),
        networkReqs: window.__fa.networkReqs.slice(),
        firedEvents: window.__fa.firedEvents.slice(),
        html5Validation: window.__fa.html5Validation.slice(),
        triggeredFunctions: window.__fa.triggeredFunctions.slice()
    };
    window.__fa.domChanges = [];
    window.__fa.networkReqs = [];
    window.__fa.firedEvents = [];
    window.__fa.html5Validation = [];
    window.__fa.triggeredFunctions = [];
    return JSON.stringify(snapshot);
};

window.__fa_getRegisteredHandlers = function() {
    var handlers = [];
    var allElements = document.querySelectorAll('input, textarea, select, button, form');
    var eventProps = [
        'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
        'onmouseover', 'onmouseout', 'onkeydown', 'onkeypress',
        'onkeyup', 'oninput', 'onchange', 'onfocus', 'onblur',
        'onsubmit', 'oninvalid', 'ondragstart', 'ondrag',
        'ondragend', 'ondrop'
    ];

    for (var i = 0; i < allElements.length; i++) {
        var el = allElements[i];
        var elXPath = '';
        try { elXPath = getXPath(el); } catch(e) { elXPath = 'unknown'; }

        var elHandlers = [];
        for (var j = 0; j < eventProps.length; j++) {
            var prop = eventProps[j];
            if (el[prop] != null) {
                elHandlers.push({
                    event: prop,
                    functionBody: el[prop].toString().substring(0, 500)
                });
            }
        }

        if (elHandlers.length > 0) {
            handlers.push({
                xpath: elXPath,
                tag: el.tagName,
                name: el.name || '',
                type: el.type || '',
                id: el.id || '',
                handlers: elHandlers
            });
        }
    }

    // Also include addEventListener-tracked handlers if available
    if (typeof added_events !== 'undefined' && added_events.length > 0) {
        for (var k = 0; k < added_events.length; k++) {
            var ae = added_events[k];
            handlers.push({
                xpath: ae.addr || 'unknown',
                tag: ae.tag || 'unknown',
                name: '',
                type: '',
                id: ae.id || '',
                handlers: [{
                    event: ae.event,
                    functionBody: '(addEventListener) function_id=' + (ae.function_id || 'unknown')
                }],
                source: 'addEventListener'
            });
        }
    }

    return JSON.stringify(handlers);
};

// Map a single character to the correct KeyboardEvent.code value.
// Letters -> 'KeyA'..'KeyZ', digits -> 'Digit0'..'Digit9',
// everything else -> best-effort lookup or the key itself.
function __fa_keyToCode(key) {
    if (/^[a-zA-Z]$/.test(key)) {
        return 'Key' + key.toUpperCase();
    }
    if (/^[0-9]$/.test(key)) {
        return 'Digit' + key;
    }
    var special = {
        ' ': 'Space', '.': 'Period', ',': 'Comma',
        '/': 'Slash', '\\': 'Backslash', '-': 'Minus',
        '=': 'Equal', '[': 'BracketLeft', ']': 'BracketRight',
        ';': 'Semicolon', "'": 'Quote', '`': 'Backquote',
        '@': 'Digit2', '#': 'Digit3', '$': 'Digit4',
        '!': 'Digit1',
    };
    return special[key] || key;
}

// Dispatch a synthetic keyboard event on an element found by XPath
window.__fa_dispatchKeyEvent = function(xpath, eventType, key, keyCode, charCode) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return false;

    var evt = new KeyboardEvent(eventType, {
        key: key,
        code: __fa_keyToCode(key),
        keyCode: keyCode,
        charCode: charCode || 0,
        which: keyCode,
        bubbles: true,
        cancelable: true
    });
    el.dispatchEvent(evt);
    return true;
};

// Dispatch a synthetic backspace key event
window.__fa_dispatchBackspace = function(xpath, eventType) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return false;

    var evt = new KeyboardEvent(eventType, {
        key: 'Backspace',
        code: 'Backspace',
        keyCode: 8,
        charCode: 0,
        which: 8,
        bubbles: true,
        cancelable: true
    });
    el.dispatchEvent(evt);
    return true;
};

// Update element value and dispatch input event
window.__fa_updateValueAndInput = function(xpath, newValue) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return false;

    // Use native setter to trigger any framework bindings
    var nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
    );
    var nativeTextareaValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLTextAreaElement.prototype, 'value'
    );

    if (el.tagName === 'TEXTAREA' && nativeTextareaValueSetter) {
        nativeTextareaValueSetter.set.call(el, newValue);
    } else if (nativeInputValueSetter) {
        nativeInputValueSetter.set.call(el, newValue);
    } else {
        el.value = newValue;
    }

    var inputEvt = new Event('input', { bubbles: true, cancelable: true });
    el.dispatchEvent(inputEvt);
    return true;
};

// Dispatch Enter key and check if it was prevented
window.__fa_dispatchEnterKey = function(xpath) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return { dispatched: false, defaultPrevented: false };

    var evt = new KeyboardEvent('keydown', {
        key: 'Enter',
        code: 'Enter',
        keyCode: 13,
        charCode: 13,
        which: 13,
        bubbles: true,
        cancelable: true
    });
    el.dispatchEvent(evt);
    return { dispatched: true, defaultPrevented: evt.defaultPrevented };
};

// Dispatch focus event
window.__fa_dispatchFocus = function(xpath) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return false;
    el.focus();
    return true;
};

// Dispatch blur event
window.__fa_dispatchBlur = function(xpath) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return false;
    el.blur();
    return true;
};

// Dispatch change event
window.__fa_dispatchChange = function(xpath) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return false;
    var evt = new Event('change', { bubbles: true, cancelable: true });
    el.dispatchEvent(evt);
    return true;
};

// Get current value of element
window.__fa_getValue = function(xpath) {
    var el = document.evaluate(xpath, document, null,
        XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;
    if (!el) return null;
    return el.value;
};