document.addEventListener('DOMContentLoaded', () => {
    initTabNavigation();
    loadSamplePresets();
    loadModelStats();
    loadThreatIntel();
    initSingleScanner();
    initBatchScanner();
    initPhishLab();
    initHistoryDrawer();
});

// Navigation Tabs
function initTabNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');

            navButtons.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.add('hidden'));

            btn.classList.add('active');
            const targetPane = document.getElementById(`tab-${targetTab}`);
            if (targetPane) {
                targetPane.classList.remove('hidden');
                targetPane.classList.add('active');
            }
        });
    });
}

// Preset URL loader
async function loadSamplePresets() {
    const container = document.getElementById('sample-presets-container');
    if (!container) return;

    try {
        const resp = await fetch('/api/sample-urls');
        const samples = await resp.json();

        container.innerHTML = '';
        samples.forEach(sample => {
            const btn = document.createElement('button');
            btn.className = 'preset-btn';
            btn.innerHTML = `<i class="fa-solid fa-link"></i> ${sample.label}`;
            btn.addEventListener('click', () => {
                const input = document.getElementById('target-url-input');
                input.value = sample.url;
                document.getElementById('clear-input-btn').style.display = 'block';
                runSingleScan(sample.url);
            });
            container.appendChild(btn);
        });
    } catch (e) {
        console.error('Failed to load sample presets', e);
    }
}

// Single URL Scanner
function initSingleScanner() {
    const scanBtn = document.getElementById('run-scan-btn');
    const input = document.getElementById('target-url-input');
    const clearBtn = document.getElementById('clear-input-btn');

    input.addEventListener('input', () => {
        clearBtn.style.display = input.value.trim() ? 'block' : 'none';
    });

    clearBtn.addEventListener('click', () => {
        input.value = '';
        clearBtn.style.display = 'none';
        document.getElementById('scan-results-wrapper').classList.add('hidden');
    });

    scanBtn.addEventListener('click', () => {
        const url = input.value.trim();
        if (url) {
            runSingleScan(url);
        } else {
            alert('Please enter a target URL to analyze.');
        }
    });

    input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            scanBtn.click();
        }
    });
}

async function runSingleScan(url) {
    const loading = document.getElementById('scan-loading');
    const results = document.getElementById('scan-results-wrapper');
    const doLiveCheck = document.getElementById('live-check-toggle').checked;

    loading.classList.remove('hidden');
    results.classList.add('hidden');

    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, live_check: doLiveCheck })
        });

        const data = await resp.json();
        loading.classList.add('hidden');

        if (resp.ok) {
            renderScanResults(data);
            results.classList.remove('hidden');
            updateHistoryBadge();
        } else {
            alert(`Scan Error: ${data.error || 'Failed to scan URL'}`);
        }
    } catch (err) {
        loading.classList.add('hidden');
        alert(`Network Error: ${err.message}`);
    }
}

function renderScanResults(data) {
    // 1. Risk Score Radial Gauge
    const scoreNum = document.getElementById('risk-score-num');
    const gaugeFill = document.getElementById('gauge-fill');
    const score = data.risk_score;

    scoreNum.textContent = `${score}%`;
    const offset = 440 - (440 * score / 100);
    gaugeFill.style.strokeDashoffset = offset;

    let strokeColor = 'var(--emerald)';
    if (score >= 80) strokeColor = 'var(--danger)';
    else if (score >= 50) strokeColor = 'var(--amber)';
    else if (score >= 25) strokeColor = '#facc15';
    gaugeFill.style.stroke = strokeColor;

    // 2. Verdict & Badges
    const verdictBadge = document.getElementById('verdict-badge');
    const threatLevelTag = document.getElementById('threat-level-tag');
    const targetUrlDisplay = document.getElementById('target-url-display');
    const metricConfidence = document.getElementById('metric-confidence');
    const metricScanTime = document.getElementById('metric-scan-time');

    verdictBadge.textContent = data.verdict;
    verdictBadge.className = `verdict-badge badge-${data.verdict_color.replace('warning-high', 'malicious')}`;
    threatLevelTag.textContent = data.threat_level;
    targetUrlDisplay.textContent = data.url;
    metricConfidence.textContent = `${data.confidence}%`;
    metricScanTime.textContent = `${data.scan_time_ms}ms`;

    // 3. Heuristic Alert Banners
    const alertBox = document.getElementById('heuristic-alerts-container');
    alertBox.innerHTML = '';
    if (data.heuristic_alerts && data.heuristic_alerts.length > 0) {
        alertBox.classList.remove('hidden');
        data.heuristic_alerts.forEach(alertText => {
            const div = document.createElement('div');
            div.className = 'alert-item';
            div.innerHTML = `<i class="fa-solid fa-triangle-exclamation"></i> <span>${alertText}</span>`;
            alertBox.appendChild(div);
        });
    } else {
        alertBox.classList.add('hidden');
    }

    // 4. URL Structure Decomposition
    const structBox = document.getElementById('url-structure-box');
    const meta = data.metadata;
    structBox.innerHTML = `
        <span class="url-part part-scheme">${meta.scheme}://</span>
        ${meta.subdomains ? `<span class="url-part part-subdomain">${meta.subdomains}.</span>` : ''}
        <span class="url-part part-domain">${meta.domain.split('.')[0]}</span>
        <span class="url-part part-tld">.${meta.tld}</span>
        ${meta.path ? `<span class="url-part part-path">${meta.path}</span>` : ''}
        ${meta.query ? `<span class="url-part part-query">?${meta.query}</span>` : ''}
    `;

    // 5. Live Diagnostics
    const liveBox = document.getElementById('live-checks-container');
    const live = data.live_checks;
    if (live) {
        liveBox.innerHTML = `
            <div class="probe-item">
                <span class="probe-name"><i class="fa-solid fa-server"></i> DNS Resolution</span>
                <span class="probe-val ${live.dns_resolvable ? 'text-success' : 'text-danger'}">
                    ${live.dns_resolvable ? `Resolves (${live.resolved_ips.join(', ')})` : 'Unresolvable / Offline'}
                </span>
            </div>
            <div class="probe-item">
                <span class="probe-name"><i class="fa-solid fa-lock"></i> SSL Handshake</span>
                <span class="probe-val ${live.ssl_valid ? 'text-success' : 'text-warning'}">
                    ${live.ssl_valid ? `Valid (${live.ssl_issuer || 'Verified SSL'})` : 'Invalid / No SSL'}
                </span>
            </div>
            <div class="probe-item">
                <span class="probe-name"><i class="fa-solid fa-globe"></i> HTTP Response Code</span>
                <span class="probe-val ${live.http_status === 200 ? 'text-success' : 'text-warning'}">
                    ${live.http_status ? `HTTP ${live.http_status}` : 'No Response / Connection Timeout'}
                </span>
            </div>
            <div class="probe-item">
                <span class="probe-name"><i class="fa-solid fa-shield-halved"></i> HSTS Security Header</span>
                <span class="probe-val ${live.has_hsts ? 'text-success' : 'text-danger'}">
                    ${live.has_hsts ? 'Enabled (HSTS Active)' : 'Disabled / Missing'}
                </span>
            </div>
        `;
    } else {
        liveBox.innerHTML = `<div class="probe-item"><span class="probe-name">Live checks disabled by user.</span></div>`;
    }

    // 6. ML Explainability Impact Bar List
    const explainBox = document.getElementById('explainability-container');
    explainBox.innerHTML = '';
    data.explainability.forEach(item => {
        const div = document.createElement('div');
        div.className = 'impact-item';
        div.innerHTML = `
            <div class="impact-header">
                <span class="impact-name">${item.feature}</span>
                <span class="impact-val">Weight: ${item.importance_weight}% | Val: ${item.value}</span>
            </div>
            <div class="impact-bar-bg">
                <div class="impact-bar-fill ${item.concerning ? 'concerning' : ''}" style="width: ${Math.min(item.importance_weight * 5, 100)}%;"></div>
            </div>
        `;
        explainBox.appendChild(div);
    });

    // 7. Full Lexical Matrix Table
    const tbody = document.getElementById('lexical-features-tbody');
    tbody.innerHTML = '';
    const feats = data.features;
    
    const rows = [
        { name: 'URL Character Length', val: feats.url_length, thresh: '> 65 chars (High risk)', status: feats.url_length > 65 ? 'Elevated' : 'Normal' },
        { name: 'Domain Character Length', val: feats.domain_length, thresh: '> 25 chars (Suspicious)', status: feats.domain_length > 25 ? 'Elevated' : 'Normal' },
        { name: 'Subdomain Depth Count', val: feats.subdomain_count, thresh: '>= 3 subdomains (Stacking)', status: feats.subdomain_count >= 3 ? 'High Risk' : 'Normal' },
        { name: 'Host IPv4/IPv6 Presence', val: feats.has_ip ? 'Yes (Raw IP)' : 'No (Domain)', thresh: 'Raw IP Host (Phishing Indicator)', status: feats.has_ip ? 'Malicious' : 'Safe' },
        { name: 'Shannon Entropy Score', val: feats.entropy, thresh: '> 4.2 (High randomness/Hex)', status: feats.entropy > 4.2 ? 'Elevated' : 'Normal' },
        { name: 'Suspicious TLD Extension', val: feats.suspicious_tld ? 'Yes' : 'No', thresh: 'Unrestricted TLD (.xyz, .top, etc)', status: feats.suspicious_tld ? 'High Risk' : 'Safe' },
        { name: 'URL Shortener Service', val: feats.url_shortener ? 'Yes' : 'No', thresh: 'Shortener domain obfuscation', status: feats.url_shortener ? 'Suspicious' : 'Safe' },
        { name: 'Sensitive Keyword Count', val: feats.sensitive_keywords_count, thresh: '>= 1 keywords (credential harvesting)', status: feats.sensitive_keywords_count >= 1 ? 'High Risk' : 'Safe' },
        { name: 'Brand Impersonation Flag', val: feats.brand_impersonation ? 'IMPERSONATION DETECTED' : 'None', thresh: 'Brand match on non-official domain', status: feats.brand_impersonation ? 'CRITICAL' : 'Safe' },
        { name: 'Homoglyph / Punycode', val: feats.homoglyph ? 'Detected' : 'Clean', thresh: 'IDN homograph spoofing', status: feats.homoglyph ? 'CRITICAL' : 'Safe' },
    ];

    rows.forEach(r => {
        const tr = document.createElement('tr');
        const isBad = r.status !== 'Normal' && r.status !== 'Safe';
        tr.innerHTML = `
            <td><strong>${r.name}</strong></td>
            <td><code>${r.val}</code></td>
            <td style="color: var(--text-muted); font-size:12px;">${r.thresh}</td>
            <td><span class="${isBad ? 'text-danger' : 'text-success'}">${r.status}</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Batch Scanner
function initBatchScanner() {
    const btn = document.getElementById('run-batch-btn');
    const input = document.getElementById('batch-urls-input');
    const sampleBtn = document.getElementById('load-batch-samples-btn');
    const resultsContainer = document.getElementById('batch-results-container');
    const exportBtn = document.getElementById('export-batch-csv-btn');

    sampleBtn.addEventListener('click', () => {
        input.value = [
            'https://www.google.com',
            'http://paypaI-security-update.account-verify.xyz/login.html',
            'http://192.168.1.105/paypal/login.php?user=verify',
            'http://bit.ly/3xX9PzL_paypal_verify',
            'https://drive.google.com/file/d/1A2B3C4D5E6F7G8H9I0/view',
            'http://login.account-update.bank.gq/login?id=84920492'
        ].join('\n');
    });

    btn.addEventListener('click', async () => {
        const lines = input.value.split('\n').map(l => l.trim()).filter(l => l.length > 0);
        if (lines.length === 0) {
            alert('Please enter at least one URL for batch analysis.');
            return;
        }

        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processing Batch...';

        try {
            const resp = await fetch('/api/batch-scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ urls: lines })
            });

            const data = await resp.json();
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-play"></i> Run Batch Analysis';

            if (resp.ok) {
                renderBatchResults(data);
                resultsContainer.classList.remove('hidden');
            } else {
                alert(`Batch Scan Error: ${data.error}`);
            }
        } catch (e) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-play"></i> Run Batch Analysis';
            alert(`Error: ${e.message}`);
        }
    });

    exportBtn.addEventListener('click', () => {
        exportBatchCSV();
    });
}

function renderBatchResults(data) {
    const summary = data.summary;
    document.getElementById('batch-total-num').textContent = summary.total;
    document.getElementById('batch-safe-num').textContent = summary.safe;
    document.getElementById('batch-suspicious-num').textContent = summary.suspicious;
    document.getElementById('batch-malicious-num').textContent = summary.malicious + summary.high_risk;

    const tbody = document.getElementById('batch-table-body');
    tbody.innerHTML = '';

    window.lastBatchResults = data.results;

    data.results.forEach((item, index) => {
        const tr = document.createElement('tr');
        let badgeClass = 'badge-safe';
        if (item.verdict === 'MALICIOUS' || item.verdict === 'HIGH-RISK') badgeClass = 'badge-malicious';
        else if (item.verdict === 'SUSPICIOUS') badgeClass = 'badge-suspicious';

        tr.innerHTML = `
            <td>${index + 1}</td>
            <td style="font-family: var(--font-mono); font-size:13px;">${item.url}</td>
            <td>${item.domain}</td>
            <td><strong>${item.risk_score}%</strong></td>
            <td><span class="verdict-badge ${badgeClass}">${item.verdict}</span></td>
            <td>
                <button class="btn btn-outline btn-sm" onclick="inspectSingleBatchUrl('${item.url}')">Inspect</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

window.inspectSingleBatchUrl = (url) => {
    document.querySelector('[data-tab="single-scan"]').click();
    document.getElementById('target-url-input').value = url;
    runSingleScan(url);
};

function exportBatchCSV() {
    if (!window.lastBatchResults) return;
    let csv = 'URL,Domain,RiskScore,Verdict\n';
    window.lastBatchResults.forEach(r => {
        csv += `"${r.url}","${r.domain}",${r.risk_score},"${r.verdict}"\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `phishshield_batch_report_${Date.now()}.csv`;
    a.click();
}

// Model Engine Stats
async function loadModelStats() {
    try {
        const resp = await fetch('/api/model-stats');
        const data = await resp.json();

        const m = data.metrics;
        document.getElementById('stat-accuracy').textContent = `${(m.accuracy * 100).toFixed(2)}%`;
        document.getElementById('stat-precision').textContent = `${(m.precision * 100).toFixed(2)}%`;
        document.getElementById('stat-recall').textContent = `${(m.recall * 100).toFixed(2)}%`;
        document.getElementById('stat-roc').textContent = m.roc_auc.toFixed(4);

        if (m.confusion_matrix) {
            const cm = m.confusion_matrix;
            document.getElementById('cm-tn').textContent = cm[0][0];
            document.getElementById('cm-fp').textContent = cm[0][1];
            document.getElementById('cm-fn').textContent = cm[1][0];
            document.getElementById('cm-tp').textContent = cm[1][1];
        }

        renderFeatureImportanceChart(data.feature_importances);
    } catch (e) {
        console.error('Failed to load model stats', e);
    }
}

function renderFeatureImportanceChart(importances) {
    const ctx = document.getElementById('feature-importance-chart').getContext('2d');
    const labels = Object.keys(importances).slice(0, 10);
    const values = Object.values(importances).slice(0, 10).map(v => (v * 100).toFixed(2));

    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Global Feature Weight (%)',
                data: values,
                backgroundColor: 'rgba(0, 242, 254, 0.6)',
                borderColor: '#00f2fe',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: { color: '#94a3b8' }
                },
                y: {
                    grid: { display: false },
                    ticks: { color: '#f8fafc', font: { family: 'JetBrains Mono' } }
                }
            }
        }
    });
}

// Threat Intel Tab
async function loadThreatIntel() {
    try {
        const resp = await fetch('/api/threat-intel');
        const data = await resp.json();

        // Top Targeted Brands
        const brandList = document.getElementById('targeted-brands-list');
        brandList.innerHTML = '';
        data.top_targeted_brands.forEach(b => {
            const li = document.createElement('li');
            li.style.cssText = 'display:flex; justify-content:space-between; padding:10px 0; border-bottom:1px solid rgba(255,255,255,0.06);';
            li.innerHTML = `<span><strong>${b.brand}</strong></span> <span class="text-cyan">${b.phish_share}</span>`;
            brandList.appendChild(li);
        });

        // Abused TLDs
        const tldContainer = document.getElementById('abused-tlds-container');
        tldContainer.innerHTML = '';
        data.most_abused_tlds.forEach(tld => {
            const badge = document.createElement('span');
            badge.className = 'verdict-badge badge-suspicious';
            badge.style.margin = '4px';
            badge.textContent = tld;
            tldContainer.appendChild(badge);
        });

        // Attack Vectors
        const vectorGrid = document.getElementById('attack-vectors-grid');
        vectorGrid.innerHTML = '';
        data.common_attack_vectors.forEach(v => {
            const card = document.createElement('div');
            card.className = 'metric-card';
            card.innerHTML = `
                <strong style="color:var(--cyan); margin-bottom:6px;">${v.vector}</strong>
                <p style="font-size:13px; color:var(--text-secondary);">${v.risk_desc}</p>
            `;
            vectorGrid.appendChild(card);
        });
    } catch (e) {
        console.error('Failed to load threat intel', e);
    }
}

// Phish Lab & Sandbox
function initPhishLab() {
    const homoglyphBtn = document.getElementById('gen-homoglyph-btn');
    const homoglyphInput = document.getElementById('homoglyph-input');
    const homoglyphOut = document.getElementById('homoglyph-output');

    homoglyphBtn.addEventListener('click', () => {
        const val = homoglyphInput.value.trim();
        if (!val) return;

        const variations = [
            val.replace('l', 'I'),
            val.replace('o', '0'),
            val.replace('e', '3'),
            `xn--${val.replace('.com', '')}-9da.com (Punycode IDN)`
        ];

        homoglyphOut.innerHTML = variations.map(v => `• http://${v}`).join('<br>');
    });

    const obfuscateBtn = document.getElementById('gen-obfuscated-btn');
    const obfuscateInput = document.getElementById('obfuscator-input');
    const obfuscateOut = document.getElementById('obfuscator-output');

    obfuscateBtn.addEventListener('click', () => {
        const val = obfuscateInput.value.trim();
        if (!val) return;

        obfuscateOut.innerHTML = `
            • Hex Encoded Path: ${val.replace('/', '%2F').replace(':', '%3A')}<br>
            • IP Representation: http://0xC0.0xA8.0x01.0x69/login<br>
            • Decimal IP Form: http://3232235881/auth
        `;
    });
}

// History Drawer
function initHistoryDrawer() {
    const modal = document.getElementById('history-modal');
    const toggleBtn = document.getElementById('history-toggle-btn');
    const closeBtn = document.getElementById('close-modal-btn');
    const clearBtn = document.getElementById('clear-history-btn');

    toggleBtn.addEventListener('click', () => {
        modal.classList.remove('hidden');
        fetchHistory();
    });

    closeBtn.addEventListener('click', () => {
        modal.classList.add('hidden');
    });

    clearBtn.addEventListener('click', async () => {
        await fetch('/api/history', { method: 'DELETE' });
        fetchHistory();
        updateHistoryBadge();
    });
}

async function fetchHistory() {
    const list = document.getElementById('history-list');
    try {
        const resp = await fetch('/api/history');
        const data = await resp.json();

        list.innerHTML = '';
        if (data.history.length === 0) {
            list.innerHTML = '<p style="color:var(--text-muted); text-align:center;">No recent scan history.</p>';
            return;
        }

        data.history.forEach(item => {
            const div = document.createElement('div');
            div.style.cssText = 'padding:10px; border-bottom:1px solid rgba(255,255,255,0.06); display:flex; justify-content:space-between; align-items:center;';
            div.innerHTML = `
                <div>
                    <div style="font-family:var(--font-mono); font-size:13px; font-weight:600;">${item.url}</div>
                    <div style="font-size:11px; color:var(--text-muted);">${item.timestamp}</div>
                </div>
                <div>
                    <span class="verdict-badge badge-${item.verdict === 'SAFE' ? 'safe' : 'malicious'}">${item.verdict} (${item.risk_score}%)</span>
                </div>
            `;
            list.appendChild(div);
        });
    } catch (e) {
        console.error('Failed to fetch scan history', e);
    }
}

async function updateHistoryBadge() {
    try {
        const resp = await fetch('/api/history');
        const data = await resp.json();
        document.getElementById('history-count').textContent = data.history.length;
    } catch (e) {}
}
