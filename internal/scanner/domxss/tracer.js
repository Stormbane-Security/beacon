// DOM XSS source-to-sink tracer — injected by beacon before page navigation.
// Instruments known XSS sinks to detect when tainted data from URL sources
// (location.hash, location.search, document.referrer) flows into them.
//
// When a sink receives data containing the canary string, we push a trace
// record to window.__beacon_xss_traces for the Go scanner to collect.
(function() {
  'use strict';
  window.__beacon_xss_traces = [];
  var CANARY = window.__beacon_canary || 'BEACON_XSS_CANARY';

  function record(sink, data) {
    if (typeof data !== 'string') return;
    if (data.indexOf(CANARY) === -1) return;
    window.__beacon_xss_traces.push({
      sink: sink,
      data: data.substring(0, 512),
      url: location.href,
      timestamp: Date.now()
    });
  }

  // --- innerHTML / outerHTML ---
  var elemProto = Element.prototype;
  var origInnerHTML = Object.getOwnPropertyDescriptor(elemProto, 'innerHTML');
  if (origInnerHTML && origInnerHTML.set) {
    Object.defineProperty(elemProto, 'innerHTML', {
      set: function(v) { record('innerHTML', v); return origInnerHTML.set.call(this, v); },
      get: origInnerHTML.get,
      configurable: true
    });
  }
  var origOuterHTML = Object.getOwnPropertyDescriptor(elemProto, 'outerHTML');
  if (origOuterHTML && origOuterHTML.set) {
    Object.defineProperty(elemProto, 'outerHTML', {
      set: function(v) { record('outerHTML', v); return origOuterHTML.set.call(this, v); },
      get: origOuterHTML.get,
      configurable: true
    });
  }

  // --- document.write / writeln ---
  var origWrite = document.write;
  document.write = function() {
    for (var i = 0; i < arguments.length; i++) record('document.write', arguments[i]);
    return origWrite.apply(document, arguments);
  };
  var origWriteln = document.writeln;
  document.writeln = function() {
    for (var i = 0; i < arguments.length; i++) record('document.writeln', arguments[i]);
    return origWriteln.apply(document, arguments);
  };

  // --- eval ---
  var origEval = window.eval;
  window.eval = function(code) {
    record('eval', code);
    return origEval.call(window, code);
  };

  // --- setTimeout / setInterval with string arg ---
  var origSetTimeout = window.setTimeout;
  window.setTimeout = function(fn, delay) {
    if (typeof fn === 'string') record('setTimeout', fn);
    return origSetTimeout.apply(window, arguments);
  };
  var origSetInterval = window.setInterval;
  window.setInterval = function(fn, delay) {
    if (typeof fn === 'string') record('setInterval', fn);
    return origSetInterval.apply(window, arguments);
  };

  // --- location assignment ---
  // Cannot fully override location, but we can watch location.href set via
  // a MutationObserver on <a> elements and script-driven navigation.

  // --- insertAdjacentHTML ---
  var origInsertAdj = elemProto.insertAdjacentHTML;
  if (origInsertAdj) {
    elemProto.insertAdjacentHTML = function(pos, html) {
      record('insertAdjacentHTML', html);
      return origInsertAdj.call(this, pos, html);
    };
  }

  // --- DOMParser (secondary sink) ---
  var origParseFromString = DOMParser.prototype.parseFromString;
  DOMParser.prototype.parseFromString = function(str, type) {
    if (type && type.indexOf('html') !== -1) record('DOMParser.parseFromString', str);
    return origParseFromString.call(this, str, type);
  };
})();
