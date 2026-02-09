// Highlighter v2 - Universal focus/visibility spoofing
// Keeps pages appearing focused and active even when minimized or switching windows.
// Targets: Canvas quiz lockdown, GoGuardian content scripts, any page-level focus detection.

(function() {
  'use strict';

  if (window.__hlActive) return;
  window.__hlActive = true;

  // =========================================================
  // 1. Override visibility/focus properties
  // =========================================================

  Object.defineProperty(document, 'hidden', {
    get: () => false, configurable: true
  });
  Object.defineProperty(document, 'visibilityState', {
    get: () => 'visible', configurable: true
  });
  Object.defineProperty(document, 'webkitHidden', {
    get: () => false, configurable: true
  });
  Object.defineProperty(document, 'webkitVisibilityState', {
    get: () => 'visible', configurable: true
  });

  // Also override on prototype so libraries reading from there are caught
  try {
    Object.defineProperty(Document.prototype, 'hidden', {
      get: () => false, configurable: true
    });
    Object.defineProperty(Document.prototype, 'visibilityState', {
      get: () => 'visible', configurable: true
    });
  } catch(e) {}

  document.hasFocus = () => true;
  if (window.parent && window.parent !== window) {
    try { window.parent.document.hasFocus = () => true; } catch(e) {}
  }

  // Lock onblur/onfocus/onvisibilitychange property setters
  Object.defineProperty(window, 'onblur', {
    get: () => null, set: () => {}, configurable: true
  });
  Object.defineProperty(window, 'onfocus', {
    get: () => null, set: () => {}, configurable: true
  });
  Object.defineProperty(document, 'onvisibilitychange', {
    get: () => null, set: () => {}, configurable: true
  });
  Object.defineProperty(document, 'onfocusin', {
    get: () => null, set: () => {}, configurable: true
  });
  Object.defineProperty(document, 'onfocusout', {
    get: () => null, set: () => {}, configurable: true
  });

  // =========================================================
  // 2. Block all focus/visibility events (capture phase)
  // =========================================================

  const blocked = [
    'visibilitychange', 'webkitvisibilitychange',
    'blur', 'focus', 'focusin', 'focusout',
    'pagehide', 'pageshow',
    'freeze', 'resume'
  ];

  const stopEvent = (e) => {
    e.stopImmediatePropagation();
    e.stopPropagation();
    e.preventDefault();
    return false;
  };

  blocked.forEach(evt => {
    window.addEventListener(evt, stopEvent, true);
    document.addEventListener(evt, stopEvent, true);
  });

  // =========================================================
  // 3. Intercept addEventListener to block future listeners
  // =========================================================

  const origAdd = EventTarget.prototype.addEventListener;
  EventTarget.prototype.addEventListener = function(type, listener, options) {
    if (blocked.includes(type)) return;
    return origAdd.call(this, type, listener, options);
  };

  // =========================================================
  // 4. requestAnimationFrame normalization
  // =========================================================
  // When backgrounded, rAF pauses. Normalize so frame-based
  // detection doesn't trigger stale-tab heuristics.

  const origRAF = window.requestAnimationFrame;
  let lastTime = performance.now();
  window.requestAnimationFrame = function(cb) {
    return origRAF.call(window, (ts) => {
      lastTime = performance.now();
      cb(ts);
    });
  };

  // =========================================================
  // 5. Activity simulation
  // =========================================================
  // GoGuardian's content scripts + page code may check for
  // recent user activity. Simulate subtle input.

  // Mouse movement every 4s
  setInterval(() => {
    document.dispatchEvent(new MouseEvent('mousemove', {
      bubbles: true, cancelable: true,
      clientX: Math.floor(Math.random() * (window.innerWidth || 800)),
      clientY: Math.floor(Math.random() * (window.innerHeight || 600)),
      view: window
    }));
  }, 4000);

  // Shift key every 8s (invisible, non-typing key)
  setInterval(() => {
    document.dispatchEvent(new KeyboardEvent('keydown', {
      bubbles: true, cancelable: true,
      key: 'Shift', code: 'ShiftLeft', keyCode: 16, which: 16, view: window
    }));
    setTimeout(() => {
      document.dispatchEvent(new KeyboardEvent('keyup', {
        bubbles: true, cancelable: true,
        key: 'Shift', code: 'ShiftLeft', keyCode: 16, which: 16, view: window
      }));
    }, 50);
  }, 8000);

  // Scroll event every 12s (some trackers check scroll activity)
  setInterval(() => {
    window.dispatchEvent(new Event('scroll', { bubbles: true }));
  }, 12000);

  // Periodic focus event so "last focus time" checks see recent activity
  setInterval(() => {
    try {
      window.dispatchEvent(new FocusEvent('focus', { bubbles: false }));
    } catch(e) {}
  }, 15000);

  // =========================================================
  // 6. Cleanup existing handlers set before us
  // =========================================================

  setTimeout(() => {
    document.onblur = null;
    window.onblur = null;
    document.onvisibilitychange = null;
    document.onfocusin = null;
    document.onfocusout = null;
  }, 500);

  // Late cleanup for scripts that set handlers after DOMContentLoaded
  setTimeout(() => {
    document.onblur = null;
    window.onblur = null;
    document.onvisibilitychange = null;
  }, 3000);

  // =========================================================
  // 7. Worker heartbeat
  // =========================================================
  // Background thread prevents page throttling when backgrounded.
  try {
    const blob = new Blob([
      'setInterval(()=>self.postMessage(1),1000)'
    ], { type: 'application/javascript' });
    const w = new Worker(URL.createObjectURL(blob));
    w.onmessage = () => {};
  } catch(e) {}

})();
