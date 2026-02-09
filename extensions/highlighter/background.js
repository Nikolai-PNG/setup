// Background service worker - manages enabled state

// Initialize default state
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ tabFreezeEnabled: true });
  updateGlobalBadge(true);
});

// Update badge to show global state
function updateGlobalBadge(enabled) {
  if (enabled) {
    chrome.action.setBadgeText({ text: 'ON' });
    chrome.action.setBadgeBackgroundColor({ color: '#22c55e' });
  } else {
    chrome.action.setBadgeText({ text: 'OFF' });
    chrome.action.setBadgeBackgroundColor({ color: '#ef4444' });
  }
}

// Handle messages from popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.action === 'getStatus') {
    chrome.storage.local.get(['tabFreezeEnabled'], (result) => {
      const enabled = result.tabFreezeEnabled !== false;
      sendResponse({ enabled: enabled });
    });
    return true;
  }

  if (msg.action === 'toggle') {
    chrome.storage.local.get(['tabFreezeEnabled'], (result) => {
      const currentState = result.tabFreezeEnabled !== false;
      const newState = !currentState;

      chrome.storage.local.set({ tabFreezeEnabled: newState }, () => {
        updateGlobalBadge(newState);
        sendResponse({ enabled: newState, needsReload: true });
      });
    });
    return true;
  }

  if (msg.action === 'reloadTab') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        chrome.tabs.reload(tabs[0].id);
      }
      sendResponse({ ok: true });
    });
    return true;
  }
});

// Set initial badge on startup
chrome.storage.local.get(['tabFreezeEnabled'], (result) => {
  const enabled = result.tabFreezeEnabled !== false;
  updateGlobalBadge(enabled);
});
