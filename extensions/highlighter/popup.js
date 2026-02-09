// Popup UI

const statusEl = document.getElementById('status');
const toggleBtn = document.getElementById('toggleBtn');
const reloadBtn = document.getElementById('reloadBtn');

function updateUI(enabled) {
  if (enabled) {
    statusEl.textContent = 'Active';
    statusEl.className = 'status on';
    toggleBtn.textContent = 'Disable';
    toggleBtn.className = 'btn-disable';
  } else {
    statusEl.textContent = 'Inactive';
    statusEl.className = 'status off';
    toggleBtn.textContent = 'Enable';
    toggleBtn.className = 'btn-enable';
  }
}

chrome.runtime.sendMessage({ action: 'getStatus' }, (response) => {
  if (response) updateUI(response.enabled);
});

toggleBtn.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'toggle' }, (response) => {
    if (response) {
      updateUI(response.enabled);
      if (response.needsReload) reloadBtn.style.display = 'block';
    }
  });
});

reloadBtn.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: 'reloadTab' }, () => window.close());
});
