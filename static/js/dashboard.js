let audioInitialized = false;

function toggleAudioInit() {
    if (!audioInitialized) {
        window.cyberAudio.playBootSound();
        audioInitialized = true;
        const btn = document.getElementById("audioToggleBtn");
        btn.innerText = "[AUDIO ARMED]";
        btn.style.borderColor = "var(--neon-green)";
        btn.style.color = "var(--neon-green)";
    } else {
        window.cyberAudio.playBlip();
    }
}

// Fetch telemetry metrics and populate tables
async function fetchLiveTelemetry() {
    try {
        const response = await fetch("/api/v1/metrics");
        const data = await response.json();

        // 1. Update blocked counter
        document.getElementById("totalBlockedVal").innerText = data.total_blocked;

        // 2. Populate live intercept table
        const tbody = document.getElementById("telemetryTableBody");
        if (data.recent_events && data.recent_events.length > 0) {
            tbody.innerHTML = "";
            data.recent_events.forEach(evt => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td style="color: #64748b;">${evt.timestamp}</td>
                    <td style="color: var(--neon-cyan);">${evt.client_ip}</td>
                    <td style="color: var(--neon-red); font-weight: 700;">${evt.threat_type}</td>
                    <td style="color: #94a3b8;">${evt.endpoint}</td>
                    <td style="color: #cbd5e1; font-family: monospace;"><code>${escapeHtml(evt.payload_sample || "N/A")}</code></td>
                    <td><span class="badge-blocked">DROP // 403</span></td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (err) {
        console.error("Telemetry sync failure:", err);
    }
}

// Interactive Vulnerability Audit Execution
async function executeAuditScan() {
    const input = document.getElementById("targetUrlInput");
    const targetUrl = input.value.trim();
    if (!targetUrl) return;

    if (audioInitialized) window.cyberAudio.playBlip();

    const scanBtn = document.getElementById("runScanBtn");
    scanBtn.innerText = "TRIAGING TARGET...";
    scanBtn.disabled = true;

    try {
        const res = await fetch("/api/v1/audit", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target_url: targetUrl })
        });
        const result = await res.json();

        renderAuditResults(result);
        if (audioInitialized) {
            if (result.security_score < 70) {
                window.cyberAudio.playAlertTone();
            } else {
                window.cyberAudio.playBlip();
            }
        }
    } catch (err) {
        alert("Failed to reach scanner service: " + err);
    } finally {
        scanBtn.innerText = "RUN SECURITY AUDIT";
        scanBtn.disabled = false;
    }
}

function renderAuditResults(result) {
    const container = document.getElementById("auditResultsContainer");
    const targetLabel = document.getElementById("auditTargetLabel");
    const scoreBadge = document.getElementById("auditScoreBadge");
    const list = document.getElementById("findingsList");

    container.style.display = "block";
    targetLabel.innerText = "TARGET: " + result.target_url;

    // Score coloring
    const score = result.security_score;
    scoreBadge.innerText = `SCORE: ${score}/100`;
    if (score >= 80) {
        scoreBadge.style.color = "var(--neon-green)";
    } else if (score >= 50) {
        scoreBadge.style.color = "var(--neon-yellow)";
    } else {
        scoreBadge.style.color = "var(--neon-red)";
    }

    document.getElementById("auditHealthVal").innerText = `${score}%`;

    // Render findings
    list.innerHTML = "";
    if (result.findings && result.findings.length > 0) {
        result.findings.forEach(f => {
            const item = document.createElement("div");
            item.style.background = "rgba(0,0,0,0.3)";
            item.style.padding = "8px 12px";
            item.style.borderRadius = "3px";
            item.style.borderLeft = f.severity === "Info" ? "3px solid var(--neon-green)" : "3px solid var(--neon-red)";
            item.innerHTML = `
                <div style="display:flex; justify-content:space-between; font-size:0.8rem;">
                    <span style="font-weight:700; color:#fff;">[${f.category}] ${f.item}</span>
                    <span style="color:${f.severity === 'Info' ? 'var(--neon-green)' : 'var(--neon-red)'}; font-size:0.75rem;">${f.severity}</span>
                </div>
                <div style="font-size:0.75rem; color:#94a3b8; margin-top:2px;">${f.impact} // ${f.recommendation}</div>
            `;
            list.appendChild(item);
        });
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.innerText = text;
    return div.innerHTML;
}

// Initial Telemetry Poll on load
document.addEventListener("DOMContentLoaded", () => {
    fetchLiveTelemetry();
    setInterval(fetchLiveTelemetry, 5000); // 5s polling for real-time WAF telemetry
});