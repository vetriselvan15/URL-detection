// Background Service Worker for PhishGuard AI Extension

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "phishguard-scan-link",
    title: "Scan link with PhishGuard AI",
    contexts: ["link"]
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "phishguard-scan-link" && info.linkUrl) {
    try {
      const response = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: info.linkUrl })
      });

      const data = await response.json();
      
      let message = `[PhishGuard AI]\nURL: ${data.url}\nVerdict: ${data.verdict} (${data.confidence}% confidence)`;
      if (data.heuristic_flags && data.heuristic_flags.length > 0) {
        message += `\nFlags: ${data.heuristic_flags.join('; ')}`;
      }

      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: (alertMsg) => { alert(alertMsg); },
        args: [message]
      });

    } catch (err) {
      chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => { alert("PhishGuard AI Server connection error. Ensure Flask app.py is running on http://localhost:5000"); }
      });
    }
  }
});
