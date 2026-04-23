// Config loaded via <script> tag

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

// Dashboard Elements
const execSummaryText = document.getElementById('exec-summary-text');
const verdictText = document.getElementById('verdict-text');
const priorityAction = document.getElementById('priority-action');
const riskScore = document.getElementById('risk-score');
const riskLabel = document.getElementById('risk-label');
const riskSvg = document.getElementById('risk-svg');
const findingsContainer = document.getElementById('findings-container');

// Stat Elements
const statCrit = document.getElementById('stat-critical');
const statHigh = document.getElementById('stat-high');
const statMed = document.getElementById('stat-medium');
const statLow = document.getElementById('stat-low');

// Modal Elements
const modal = document.getElementById('fix-modal');
const modalClose = document.getElementById('close-modal');
const modalTitle = document.getElementById('modal-title');
const modalSteps = document.getElementById('fix-steps-list');
const modalTime = document.getElementById('modal-time');

modalClose.addEventListener('click', () => modal.classList.add('hidden'));

function logTerminal(message, type = '') {
    const time = new Date().toISOString().split('T')[1].substring(0, 8);
    const id = type ? `[${type.toUpperCase()}]` : '[SYSTEM]';
    const wrapper = document.createElement('div');
    wrapper.className = `log-line ${type}`;
    wrapper.innerText = `${time} ${id} ${message}`;
    terminalLogs.appendChild(wrapper);
    terminalLogs.scrollTop = terminalLogs.scrollHeight;
}

// Call local API (which fetches real data and hits NVIDIA)
async function performScan(url) {
    btnScan.disabled = true;
    btnScan.innerText = "SCANNING...";
    terminalLogs.innerHTML = '';

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ targetUrl: url })
        });

        if (!response.ok) {
            throw new Error(`API returned ${response.status}`);
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder("utf-8");
        let buffer = "";

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            let lines = buffer.split('\n');
            buffer = lines.pop(); // keep remainder

            for (const line of lines) {
                if (!line.trim()) continue;
                try {
                    const data = JSON.parse(line);
                    if (data.type === "log") {
                        logTerminal(data.message, data.level);
                    } else if (data.type === "report") {
                        logTerminal(`Neural Analysis Complete. Rendering Dashboard...`, 'success');
                        setTimeout(() => renderDashboard(data.data), 1000);
                    }
                } catch(e) {
                    console.error("Parse error on chunk:", line);
                }
            }
        }

    } catch (error) {
        logTerminal(`SCAN FAILED: ${error.message}`, 'error');
    }

    btnScan.disabled = false;
    btnScan.innerText = "INITIATE SCAN";
}

// Update SVG Circle progress
function setProgress(percent, colorVar) {
    const radius = riskSvg.r.baseVal.value;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (percent / 100) * circumference;
    riskSvg.style.strokeDasharray = `${circumference} ${circumference}`;
    riskSvg.style.strokeDashoffset = offset;
    riskSvg.style.stroke = `var(${colorVar})`;
}

// Render the results into the DOM
function renderDashboard(report) {
    viewEntry.classList.add('hidden');
    viewDashboard.classList.remove('hidden');

    execSummaryText.innerText = report.executive_summary;
    verdictText.innerText = report.risk_verdict;
    priorityAction.innerText = report.priority_action;

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
        // Fallback for secure sites
        findingsContainer.innerHTML = '<p style="color:var(--neon-blue)">No vulnerabilities detected on this scan vector.</p>';
    }

    report.findings.forEach(vuln => {
        if (!vuln.title || vuln.title.toLowerCase() === 'none' || vuln.what_it_is.toLowerCase() === 'none' || vuln.title.toLowerCase().includes('secure')) {
            return;
        }

        const card = document.createElement('div');
        let sevClass = 'low';
        if(vuln.severity === 'RED') { sevClass = 'critical'; cCount++; }
        else if(vuln.severity === 'YELLOW') { sevClass = 'high'; hCount++; }
        else { sevClass = 'low'; lCount++; }
        card.className = `finding-card ${sevClass}`;

        card.innerHTML = `
            <div class="finding-header">
                <div>
                    <h4 class="finding-title">${vuln.title}</h4>
                    <span class="finding-badge ${sevClass}">${vuln.severity}</span>
                </div>
                <i data-lucide="${sevClass === 'critical' ? 'alert-octagon' : 'alert-triangle'}"></i>
            </div>
            <p class="finding-desc">${vuln.what_it_is}</p>
            <p class="finding-why">"${vuln.why_dangerous}"</p>
            ${vuln.exposed_value_preview ? `<div class="finding-preview">Evidence: ${vuln.exposed_value_preview}</div>` : ''}
            ${vuln.location ? `<div class="finding-location" style="margin-top: 5px; font-size: 0.9rem; color: var(--text-muted);"><i data-lucide="map-pin" style="width: 14px; height: 14px; vertical-align: middle; margin-right: 4px;"></i><strong>Location:</strong> <a href="${vuln.location}" target="_blank" style="color: inherit;">${vuln.location}</a></div>` : ''}
            ${(vuln.status_code || vuln.response_time || vuln.file_size || vuln.confidence_score) ? `
            <div class="finding-meta" style="display: flex; gap: 15px; margin-top: 10px; font-size: 0.85rem; color: var(--text-muted); flex-wrap: wrap;">
                ${vuln.status_code ? `<span style="display: flex; align-items: center; gap: 4px;"><i data-lucide="activity" style="width: 14px; height: 14px;"></i> ${vuln.status_code} OK</span>` : ''}
                ${vuln.response_time ? `<span style="display: flex; align-items: center; gap: 4px;"><i data-lucide="clock" style="width: 14px; height: 14px;"></i> ${vuln.response_time}</span>` : ''}
                ${vuln.file_size ? `<span style="display: flex; align-items: center; gap: 4px;"><i data-lucide="file" style="width: 14px; height: 14px;"></i> ${vuln.file_size}</span>` : ''}
                ${vuln.confidence_score ? `<span style="display: flex; align-items: center; gap: 4px;"><i data-lucide="percent" style="width: 14px; height: 14px;"></i> ${vuln.confidence_score}% Confidence</span>` : ''}
            </div>` : ''}
            ${(vuln.fix_steps && vuln.fix_steps.length > 0) ? `<button class="btn-fix" style="margin-top: 15px;">HOW TO FIX</button>` : ''}
        `;

        const fixBtn = card.querySelector('.btn-fix');
        if (fixBtn) {
            fixBtn.addEventListener('click', () => {
                modalTitle.innerText = vuln.title;
                modalTime.innerText = vuln.fix_time || 'Unknown';
                modalTitle.style.color = `var(--neon-${sevClass === 'critical' ? 'red' : sevClass === 'high' ? 'orange' : 'cyan'})`;

                modalSteps.innerHTML = vuln.fix_steps.map(step => `<li>${step}</li>`).join('');
                modal.classList.remove('hidden');
            });
        }

        findingsContainer.appendChild(card);
    });

    statCrit.innerText = cCount;
    statHigh.innerText = hCount;
    statMed.innerText = mCount;
    statLow.innerText = lCount;

    lucide.createIcons();
}

btnScan.addEventListener('click', () => {
    let url = urlInput.value.trim();
    if(url) {
        if(!url.startsWith('http')) url = 'https://' + url;
        performScan(url);
    } else {
        logTerminal("Error: Target URL required.", "error");
    }
});