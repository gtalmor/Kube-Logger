// Service worker — handles badge updates and viewer tab management

let viewerTabId = null;

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === 'open-viewer') {
    if (viewerTabId !== null) {
      // Focus existing viewer tab
      chrome.tabs.get(viewerTabId, tab => {
        if (chrome.runtime.lastError || !tab) {
          openNewViewer();
        } else {
          chrome.tabs.update(viewerTabId, { active: true });
          chrome.windows.update(tab.windowId, { focused: true });
        }
      });
    } else {
      openNewViewer();
    }
    reply({ ok: true });
    return true;
  }

  if (msg.type === 'badge') {
    const { text, color } = msg;
    chrome.action.setBadgeText({ text: text || '' });
    chrome.action.setBadgeBackgroundColor({ color: color || '#f85149' });
  }
});

function openNewViewer() {
  chrome.tabs.create({ url: chrome.runtime.getURL('viewer.html') }, tab => {
    viewerTabId = tab.id;
  });
}

// Clean up when viewer tab closes
chrome.tabs.onRemoved.addListener(tabId => {
  if (tabId === viewerTabId) viewerTabId = null;
});
