document.addEventListener('DOMContentLoaded', async () => {
  const urlDisplay = document.getElementById('active-url');
  const btnScan = document.getElementById('btn-scan');
  const loader = document.getElementById('loader');
  const verdictBox = document.getElementById('verdict-box');
  const verdictBadge = document.getElementById('verdict-badge');
  const verdictIcon = document.getElementById('verdict-icon');
  const verdictText = document.getElementById('verdict-text');
  const confidenceScore = document.getElementById('confidence-score');
  const flagsContainer = document.getElementById('flags-container');
  const flagsUl = document.getElementById('flags-ul');

  let activeTabUrl = '';

  // 1. Query active tab URL
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab && tab.url) {
      activeTabUrl = tab.url;
      urlDisplay.innerText = activeTabUrl;
    } else {
      urlDisplay.innerText = 'Unable to detect tab URL.';
    }
  } catch (err) {
    urlDisplay.innerText = 'Error getting tab URL.';
  }

  // Auto-trigger scan on popup open if valid URL
  if (activeTabUrl && (activeTabUrl.startsWith('http://') || activeTabUrl.startsWith('https://'))) {
    scanUrl(activeTabUrl);
  }

  // 2. Button click handler
  btnScan.addEventListener('click', () => {
    if (activeTabUrl) {
      scanUrl(activeTabUrl);
    }
  });

  async function scanUrl(url) {
    loader.style.display = 'block';
    verdictBox.style.display = 'none';

    try {
      const response = await fetch('http://localhost:5000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
      });

      const data = await response.json();
      loader.style.display = 'none';

      if (response.ok) {
        renderVerdict(data);
      } else {
        alert(data.error || 'Scan failed.');
      }
    } catch (err) {
      loader.style.display = 'none';
      alert('Cannot connect to PhishGuard AI server. Make sure app.py is running on http://localhost:5000.');
    }
  }

  function renderVerdict(data) {
    verdictText.innerText = data.verdict;
    confidenceScore.innerText = data.confidence + '%';

    if (data.verdict_status === 'phishing') {
      verdictBadge.className = 'badge-verdict danger';
      verdictIcon.className = 'fa-solid fa-triangle-exclamation';
      confidenceScore.style.color = 'var(--accent-rose)';
    } else {
      verdictBadge.className = 'badge-verdict safe';
      verdictIcon.className = 'fa-solid fa-shield-check';
      confidenceScore.style.color = 'var(--accent-emerald)';
    }

    if (data.heuristic_flags && data.heuristic_flags.length > 0) {
      flagsContainer.style.display = 'block';
      flagsUl.innerHTML = '';
      data.heuristic_flags.forEach(flag => {
        const li = document.createElement('li');
        li.innerText = flag;
        flagsUl.appendChild(li);
      });
    } else {
      flagsContainer.style.display = 'none';
    }

    verdictBox.style.display = 'block';
  }
});
