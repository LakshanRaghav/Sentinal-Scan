// Initialize Icons safely
try {
    if (typeof lucide !== 'undefined') {
        lucide.createIcons();
    }
} catch (e) {
    console.warn('Icons failed to load:', e);
}

// Elements
const btnScan = document.getElementById('btn-scan');
const urlInput = document.getElementById('target-url');
const terminalLogs = document.getElementById('terminal-logs');
const viewEntry = document.getElementById('scan-entry');
const viewDashboard = document.getElementById('dashboard');
const viewArchive = document.getElementById('archive');
const progressBar = document.getElementById('scan-progress');

// Nav Elements
const navLive = document.getElementById('nav-live');
const navDashboard = document.getElementById('nav-dashboard');
const navArchive = document.getElementById('nav-archive');

// Dashboard Elements
const execSummaryText = document.getElementById('exec-summary-text');
const verdictText = document.getElementById('verdict-text');
const priorityAction = document.getElementById('priority-action');
const riskScore = document.getElementById('risk-score');
const riskLabel = document.getElementById('risk-label');
const riskSvg = document.getElementById('risk-svg');
const findingsContainer = document.getElementById('findings-container');
const btnExportPdf = document.getElementById('btn-export-pdf');

// Stat Elements
const statCrit = document.getElementById('stat-critical');
const statHigh = document.getElementById('stat-high');
const statMed = document.getElementById('stat-medium');
const statLow = document.getElementById('stat-low');

// Archive Elements
const archiveContainer = document.getElementById('archive-container');

// Modal Elements
const modal = document.getElementById('fix-modal');
const modalClose = document.getElementById('close-modal');
const modalTitle = document.getElementById('modal-title');
const modalSteps = document.getElementById('fix-steps-list');
const modalTime = document.getElementById('modal-time');

modalClose.addEventListener('click', () => modal.classList.add('hidden'));

// --- VIEW ROUTER ---
function switchView(view) {
    viewEntry.classList.add('hidden');
    viewDashboard.classList.add('hidden');
    viewArchive.classList.add('hidden');
    navLive.classList.remove('active');
    navDashboard.classList.remove('active');
    navArchive.classList.remove('active');

    if (view === 'live') {
        viewEntry.classList.remove('hidden');
        navLive.classList.add('active');
    } else if (view === 'dashboard') {
        viewDashboard.classList.remove('hidden');
        navDashboard.classList.add('active');
    } else if (view === 'archive') {
        viewArchive.classList.remove('hidden');
        navArchive.classList.add('active');
        renderArchive();
    }
}

navLive.addEventListener('click', () => switchView('live'));
navDashboard.addEventListener('click', () => switchView('dashboard'));
navArchive.addEventListener('click', () => switchView('archive'));

// --- TERMINAL LOGGER ---
function logTerminal(message, type = '') {
    const time = new Date().toISOString().split('T')[1].substring(0, 8);
    const id = type ? `[${type.toUpperCase()}]` : '[SYSTEM]';
    const wrapper = document.createElement('div');
    wrapper.className = `log-line ${type}`;
    wrapper.innerText = `${time} ${id} ${message}`;
    terminalLogs.appendChild(wrapper);
    terminalLogs.scrollTop = terminalLogs.scrollHeight;
}

// --- SCAN ORCHESTRATOR ---
async function performScan(url) {
    btnScan.disabled = true;
    btnScan.innerHTML = '<i data-lucide="loader" class="spin"></i> SCANNING...';
    lucide.createIcons();
    terminalLogs.innerHTML = '';
    progressBar.style.width = '0%';
    
    const dinoContainer = document.getElementById('dino-container');
    if (dinoContainer) dinoContainer.classList.remove('hidden');
    
    let aggregatedFindings = [];
    let progress = 0;

    const updateProgress = (val) => {
        progress += val;
        progressBar.style.width = `${progress}%`;
    };

    try {
        logTerminal(`Initializing Orbital Scan on ${url}...`, 'info');

        // 1. SSL Audit
        logTerminal(`Verifying TLS/SSL Certificate Chain...`);
        try {
            const sslRes = await fetch('/api/recon/ssl', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({targetUrl: url}) });
            const sslData = await sslRes.json();
            if(sslData.findings) aggregatedFindings.push(...sslData.findings);
            logTerminal(`[SSL] Checked issuer: ${sslData.sslInfo?.issuer || 'Unknown'}`, 'success');
        } catch(e) { logTerminal(`[SSL] Module Error`, 'warning'); }
        updateProgress(15);

        // 2. DNS Analysis
        logTerminal(`Querying DNS, SPF, DMARC records...`);
        try {
            const dnsRes = await fetch('/api/recon/dns', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({targetUrl: url}) });
            const dnsData = await dnsRes.json();
            if(dnsData.findings) aggregatedFindings.push(...dnsData.findings);
            logTerminal(`[DNS] Resolved MX and TXT records`, 'success');
        } catch(e) { logTerminal(`[DNS] Module Error`, 'warning'); }
        updateProgress(15);

        // 3. Security Headers
        logTerminal(`Inspecting HTTP Security Headers and CORS...`);
        try {
            const headerRes = await fetch('/api/recon/headers', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({targetUrl: url}) });
            const headerData = await headerRes.json();
            if(headerData.findings) aggregatedFindings.push(...headerData.findings);
            logTerminal(`[HEADERS] Response headers analyzed`, 'success');
        } catch(e) { logTerminal(`[HEADERS] Module Error`, 'warning'); }
        updateProgress(15);

        // 4. Tech Stack Fingerprinting
        logTerminal(`Fingerprinting Web Application Framework...`);
        try {
            const techRes = await fetch('/api/recon/techstack', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({targetUrl: url}) });
            const techData = await techRes.json();
            if(techData.findings) aggregatedFindings.push(...techData.findings);
            logTerminal(`[STACK] Detected: ${techData.techStack?.join(', ') || 'Unknown'}`, 'success');
        } catch(e) { logTerminal(`[STACK] Module Error`, 'warning'); }
        updateProgress(15);

        // 5. Subdomain Enumeration
        logTerminal(`Searching crt.sh for exposed subdomains...`);
        try {
            const subRes = await fetch('/api/recon/subdomains', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({targetUrl: url}) });
            const subData = await subRes.json();
            if(subData.findings) aggregatedFindings.push(...subData.findings);
            logTerminal(`[SUBDOMAINS] Found ${subData.subdomains?.length || 0} external nodes`, 'success');
        } catch(e) { logTerminal(`[SUBDOMAINS] Module Error`, 'warning'); }
        updateProgress(15);

        // 6. DAST
        logTerminal(`Running lightweight DAST payloads (XSS, SQLi, LFI)...`);
        try {
            const dastRes = await fetch('/api/recon/dast', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({targetUrl: url}) });
            const dastData = await dastRes.json();
            if(dastData.findings) aggregatedFindings.push(...dastData.findings);
            logTerminal(`[DAST] Payload injection sequence complete`, 'success');
        } catch(e) { logTerminal(`[DAST] Module Error`, 'warning'); }
        updateProgress(10);

        // 7. AI Analysis
        logTerminal(`Transmitting aggregated intelligence to Neural Core...`, 'info');
        const aiRes = await fetch('/api/analyze', { 
            method: 'POST', 
            headers: {'Content-Type':'application/json'}, 
            body: JSON.stringify({targetUrl: url, aggregatedData: aggregatedFindings}) 
        });
        
        if(!aiRes.ok) throw new Error('AI Analysis failed');
        const aiData = await aiRes.json();
        
        updateProgress(15);
        logTerminal(`Neural Analysis Complete. Rendering Dashboard...`, 'success');

        const finalReport = aiData.report;
        finalReport.targetUrl = url;
        finalReport.timestamp = new Date().toISOString();

        // Save to Archive
        saveToArchive(finalReport);

        setTimeout(() => {
            renderDashboard(finalReport);
            switchView('dashboard');
        }, 1000);

    } catch (error) {
        logTerminal(`SCAN FAILED: ${error.message}`, 'error');
    }

    if (dinoContainer) dinoContainer.classList.add('hidden');

    btnScan.disabled = false;
    btnScan.innerHTML = '<i data-lucide="zap"></i> INITIATE SCAN';
    lucide.createIcons();
}

// --- ARCHIVE SYSTEM ---
function saveToArchive(report) {
    try {
        let archive = JSON.parse(localStorage.getItem('sentinelArchive') || '[]');
        archive.unshift(report); // Add to beginning
        if(archive.length > 20) archive.pop(); // Keep last 20
        localStorage.setItem('sentinelArchive', JSON.stringify(archive));
    } catch(e) {
        console.error("Local storage error", e);
    }
}

function renderArchive() {
    archiveContainer.innerHTML = '';
    let archive = [];
    try {
        archive = JSON.parse(localStorage.getItem('sentinelArchive') || '[]');
    } catch(e) {}

    if (archive.length === 0) {
        archiveContainer.innerHTML = '<p style="color: var(--text-muted)">No past scans found.</p>';
        return;
    }

    archive.forEach((report, index) => {
        const date = new Date(report.timestamp).toLocaleString();
        const card = document.createElement('div');
        card.className = `finding-card ${report.overall_severity.toLowerCase() === 'red' ? 'critical' : report.overall_severity.toLowerCase() === 'yellow' ? 'high' : 'low'}`;
        card.style.cursor = 'pointer';
        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <h4 style="margin: 0; color: #fff;">${report.targetUrl}</h4>
                    <span style="font-size: 0.8rem; color: var(--text-muted);">${date}</span>
                </div>
                <span class="finding-badge ${report.overall_severity.toLowerCase() === 'red' ? 'critical' : report.overall_severity.toLowerCase() === 'yellow' ? 'high' : 'low'}">${report.overall_severity} Risk</span>
            </div>
        `;
        card.addEventListener('click', () => {
            renderDashboard(report);
            switchView('dashboard');
        });
        archiveContainer.appendChild(card);
    });
}

// --- DASHBOARD RENDERER ---
function setProgress(percent, colorVar) {
    const radius = riskSvg.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (percent / 100) * circumference;
    riskSvg.style.strokeDasharray = `${circumference} ${circumference}`;
    riskSvg.style.strokeDashoffset = offset;
    riskSvg.style.stroke = `var(${colorVar})`;
}

function renderDashboard(report) {
    window.currentReportData = report; // Store for PDF export
    execSummaryText.innerText = report.executive_summary;
    verdictText.innerText = report.risk_verdict;
    priorityAction.innerText = report.priority_action;
    
    if (document.getElementById('comp-pci')) document.getElementById('comp-pci').innerText = report.compliance_impact?.pci_dss || 'N/A';
    if (document.getElementById('comp-gdpr')) document.getElementById('comp-gdpr').innerText = report.compliance_impact?.gdpr || 'N/A';
    if (document.getElementById('comp-iso')) document.getElementById('comp-iso').innerText = report.compliance_impact?.iso_27001 || 'N/A';

    riskScore.innerText = report.risk_score;
    riskLabel.innerText = report.overall_severity;

    let colorVar = '--neon-blue';
    if(report.overall_severity === 'RED') { colorVar = '--neon-red'; }
    else if(report.overall_severity === 'YELLOW') { colorVar = '--neon-orange'; }

    setTimeout(() => { setProgress(report.risk_score, colorVar); }, 100);
    verdictText.style.color = `var(${colorVar})`;

    findingsContainer.innerHTML = '';
    let cCount=0, hCount=0, mCount=0, lCount=0;

    if (!report.findings || report.findings.length === 0) {
        findingsContainer.innerHTML = '<p style="color:var(--neon-blue)">No vulnerabilities detected on this scan vector.</p>';
    }

    let categories = {};

    report.findings.forEach(vuln => {
        if (!vuln.title || vuln.title.toLowerCase() === 'none') return;
        
        const cat = vuln.owasp_category || vuln.module || 'Uncategorized';
        categories[cat] = (categories[cat] || 0) + 1;

        const card = document.createElement('div');
        let sevClass = 'low';
        // Note: the Vercel backend uses critical, high, medium, low instead of RED/YELLOW/BLUE, but handle both
        const sevUpper = vuln.severity ? vuln.severity.toUpperCase() : 'LOW';
        if(sevUpper === 'RED' || sevUpper === 'CRITICAL') { sevClass = 'critical'; cCount++; }
        else if(sevUpper === 'YELLOW' || sevUpper === 'HIGH') { sevClass = 'high'; hCount++; }
        else if(sevUpper === 'BLUE' || sevUpper === 'MEDIUM') { sevClass = 'info'; mCount++; }
        else { sevClass = 'low'; lCount++; }
        
        card.className = `finding-card ${sevClass}`;

        card.innerHTML = `
            <div class="finding-header">
                <div>
                    <h4 class="finding-title">${vuln.title}</h4>
                    <span class="finding-badge ${sevClass}">${vuln.severity} ${vuln.cvss_score ? `(CVSS: ${vuln.cvss_score})` : ''}</span>
                    ${vuln.cwe_id ? `<span class="finding-badge info">${vuln.cwe_id}</span>` : ''}
                </div>
                <i data-lucide="${sevClass === 'critical' ? 'alert-octagon' : sevClass === 'high' ? 'alert-triangle' : 'info'}"></i>
            </div>
            <p class="finding-desc">${vuln.impact || 'No description provided.'}</p>
            ${vuln.evidence ? `<div class="finding-preview" style="font-family: monospace;">Evidence: ${JSON.stringify(vuln.evidence)}</div>` : ''}
            ${vuln.affected_component ? `<div class="finding-location" style="margin-top: 5px; font-size: 0.9rem; color: var(--text-muted);"><strong>Location:</strong> ${vuln.affected_component}</div>` : ''}
            ${(vuln.remediation && vuln.remediation.length > 0) ? `<button class="btn-fix" style="margin-top: 15px;"><i data-lucide="wrench"></i> REMEDIATION</button>` : ''}
        `;

        const fixBtn = card.querySelector('.btn-fix');
        if (fixBtn) {
            fixBtn.addEventListener('click', () => {
                modalTitle.innerText = vuln.title;
                modalTime.innerText = vuln.owasp_category || 'N/A';
                modalTitle.style.color = `var(--neon-${sevClass === 'critical' ? 'red' : sevClass === 'high' ? 'orange' : 'cyan'})`;
                modalSteps.innerHTML = vuln.remediation.map(step => `<li>${step}</li>`).join('');
                modal.classList.remove('hidden');
            });
        }
        findingsContainer.appendChild(card);
    });

    // Populate Threat Distribution Chart
    const threatChart = document.getElementById('threat-chart');
    if (threatChart) {
        threatChart.innerHTML = '';
        if (Object.keys(categories).length === 0) {
            threatChart.innerHTML = '<p style="color:var(--text-muted)">No threats to display.</p>';
        } else {
            const maxCat = Math.max(...Object.values(categories));
            for (const [cat, count] of Object.entries(categories).sort((a,b) => b[1] - a[1])) {
                const pct = Math.max(5, Math.floor((count / maxCat) * 100));
                const barHTML = `
                    <div style="display: flex; align-items: center; justify-content: space-between; font-size: 0.85rem; color: #fff; margin-bottom: 4px;">
                        <span style="flex: 1; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; padding-right: 10px;">${cat}</span>
                        <span style="width: 30px; text-align: right;">${count}</span>
                    </div>
                    <div style="width: 100%; background: var(--surface-elevated); height: 12px; border-radius: 4px; overflow: hidden;">
                        <div style="width: ${pct}%; height: 100%; background: var(--neon-cyan); border-radius: 4px;"></div>
                    </div>
                `;
                const wrapper = document.createElement('div');
                wrapper.innerHTML = barHTML;
                threatChart.appendChild(wrapper);
            }
        }
    }

    statCrit.innerText = cCount;
    statHigh.innerText = hCount;
    statMed.innerText = mCount;
    statLow.innerText = lCount;

    lucide.createIcons();
}

// --- PDF EXPORT ---
btnExportPdf.addEventListener('click', () => {
    if (!window.currentReportData) return;
    const report = window.currentReportData;

    const printContainer = document.createElement('div');
    printContainer.style.width = '800px';
    printContainer.style.padding = '40px';
    printContainer.style.background = '#ffffff';
    printContainer.style.color = '#000000';
    printContainer.style.fontFamily = 'Arial, sans-serif';
    printContainer.style.position = 'absolute';
    printContainer.style.left = '-9999px';
    printContainer.style.top = '0';
    
    let findingsHTML = '';
    report.findings.forEach(vuln => {
        if (!vuln.title || vuln.title.toLowerCase() === 'none') return;
        const color = vuln.severity?.toUpperCase() === 'CRITICAL' ? '#d32f2f' : vuln.severity?.toUpperCase() === 'HIGH' ? '#f57c00' : '#1976d2';
        findingsHTML += `
            <div style="margin-bottom: 20px; page-break-inside: avoid; border: 1px solid #ddd; padding: 15px; border-radius: 8px;">
                <h4 style="margin: 0 0 10px 0; color: ${color};">${vuln.title} [${vuln.severity}]</h4>
                <p style="margin: 0 0 10px 0; font-size: 14px; line-height: 1.4;"><strong>Impact:</strong> ${vuln.impact}</p>
                ${vuln.affected_component ? `<p style="margin: 0 0 10px 0; font-size: 14px;"><strong>Location:</strong> ${vuln.affected_component}</p>` : ''}
                ${vuln.remediation && vuln.remediation.length > 0 ? `<p style="margin: 0; font-size: 14px; line-height: 1.4;"><strong>Remediation:</strong> ${vuln.remediation.join(', ')}</p>` : ''}
            </div>
        `;
    });

    printContainer.innerHTML = `
        <div style="text-align: center; margin-bottom: 40px; border-bottom: 2px solid #000; padding-bottom: 20px;">
            <h1 style="margin: 0; color: #000;">SentinelScan Security Audit</h1>
            <p style="color: #666; margin-top: 5px;">Target: ${report.targetUrl || 'Unknown'} | Date: ${new Date(report.timestamp || Date.now()).toLocaleString()}</p>
        </div>
        
        <div style="margin-bottom: 40px;">
            <h2 style="border-bottom: 1px solid #ccc; padding-bottom: 5px; color: #000;">Executive Summary</h2>
            <p style="line-height: 1.5;">${report.executive_summary}</p>
            <div style="background: #f5f5f5; padding: 15px; border-radius: 6px; margin-top: 15px;">
                <p style="margin: 0 0 5px 0;"><strong>Verdict:</strong> ${report.risk_verdict}</p>
                <p style="margin: 0;"><strong>Risk Score:</strong> ${report.risk_score}/100 (${report.overall_severity})</p>
            </div>
        </div>
        
        <div style="margin-bottom: 40px;">
            <h2 style="border-bottom: 1px solid #ccc; padding-bottom: 5px; color: #000;">Vulnerability Findings</h2>
            ${findingsHTML || '<p>No vulnerabilities detected on this scan vector.</p>'}
        </div>
    `;
    
    document.body.appendChild(printContainer);
    
    const opt = {
      margin:       0.5,
      filename:     'SentinelScan_Report.pdf',
      image:        { type: 'jpeg', quality: 0.98 },
      html2canvas:  { scale: 2, useCORS: true },
      jsPDF:        { unit: 'in', format: 'letter', orientation: 'portrait' },
      pagebreak:    { mode: ['avoid-all', 'css', 'legacy'] }
    };
    
    const originalText = btnExportPdf.innerHTML;
    btnExportPdf.innerHTML = 'Exporting...';
    
    html2pdf().set(opt).from(printContainer).save().then(() => {
        document.body.removeChild(printContainer);
        btnExportPdf.innerHTML = originalText;
    });
});

// --- INIT ---
btnScan.addEventListener('click', () => {
    let url = urlInput.value.trim();
    if(url) {
        if(!url.startsWith('http')) url = 'https://' + url;
        performScan(url);
    } else {
        logTerminal("Error: Target URL required.", "error");
    }
});

urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        btnScan.click();
    }
});