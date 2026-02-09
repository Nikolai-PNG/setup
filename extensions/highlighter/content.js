// Content loader

(async function() {
  'use strict';

  const result = await chrome.storage.local.get(['tabFreezeEnabled']);
  if (result.tabFreezeEnabled === false) return;

  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('inject.js');
  script.onload = function() { this.remove(); };
  (document.head || document.documentElement).appendChild(script);
})();
