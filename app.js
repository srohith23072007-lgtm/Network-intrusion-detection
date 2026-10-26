/**
 * CYBERSHIELD NIDS - Frontend Application Logic
 */

let allAlerts = [];
let autoRefreshTimer = null;

// Preset attacks for quick simulation
const PRESET_ATTACKS = {
    sqli: {
        signature: "ET WEB_SPECIFIC_APPS SQL Injection Attempt in URI (UNION SELECT)",
        category: "Web Application Attack",
        severity: "Critical",
        proto: "TCP",
        src_ip: "198.51.100.77",
        src_port: 50130,
        dst_ip: "10.0.0.8",
        dst_port: 80,
        desc: "Automated injection test vector targeting vulnerable backend parameters: ?id=1 UNION SELECT null, username, password FROM users --"
    },
    ssh_brute: {
        signature: "ET SCAN Potential SSH Brute Force Rate Exceeded",
        category: "Attempted Administrator Privilege Gain",
        severity: "High",
        proto: "TCP",
        src_ip: "203.0.113.195",
        src_port: 48991,
        dst_ip: "10.0.0.5",
        dst_port: 22,
        desc: "Over 60 authentication attempts per minute from single IP targeting port 22."
    },
    c2_beacon: {
        signature: "ET MALWARE Cobalt Strike Malleable C2 Beaconing Observed",
        category: "Command and Control",
        severity: "Critical",
        proto: "TCP",
        src_ip: "192.168.1.72",
        src_port: 54101,
        dst_ip: "185.190.140.12",
        dst_port: 443,
        desc: "Regular jittered HTTPS heartbeat pattern matching known Cobalt Strike teamserver profile."
    },
    eternalblue: {
        signature: "ET EXPLOIT SMBv1 Exploit Attempt (MS17-010 EternalBlue)",
        category: "Attempted Administrator Privilege Gain",
        severity: "Critical",
        proto: "TCP",
        src_ip: "192.168.1.205",
        src_port: 44102,
        dst_ip: "10.0.0.15",
        dst_port: 445,
        desc: "Malformed SMB_COM_TRANSACTION2 request targeting OS ring-0 kernel memory."
    },
    syn_flood: {
        signature: "ET DOS High Volume TCP SYN Flood Detected",
        category: "Denial of Service",
        severity: "High",
        proto: "TCP",
        src_ip: "198.51.100.99",
        src_port: 39912,
        dst_ip: "10.0.0.1",
        dst_port: 443,
        desc: "High packet rate with SYN flag set and missing ACK handshakes."
    }
};

// Initialize Application
document.addEventListener("DOMContentLoaded", () => {
    setupEventListeners();
    fetchStats();
    fetchAlerts();
    startAutoRefresh();
});

// Event Listeners setup
function setupEventListeners() {
    // Refresh button
    document.getElementById("btn-refresh").addEventListener("click", () => {
        fetchStats();
        fetchAlerts();
        showToast("Telemetry refreshed from Suricata backend.", "info");
    });

    // Auto-refresh switch
    const autoSwitch = document.getElementById("auto-refresh-checkbox");
    autoSwitch.addEventListener("change", (e) => {
        if (e.target.checked) {
            startAutoRefresh();
            showToast("Live stream auto-refresh active (5s interval).", "success");
        } else {
            stopAutoRefresh();
            showToast("Live stream paused.", "info");
        }
    });

    // Filters
    document.getElementById("filter-search").addEventListener("input", renderAlertsTable);
    document.getElementById("filter-severity").addEventListener("change", renderAlertsTable);
    document.getElementById("filter-status").addEventListener("change", renderAlertsTable);

    // Detail Modal Close
    document.getElementById("btn-close-detail").addEventListener("click", () => {
        document.getElementById("detail-modal").style.display = "none";
    });

    // Simulate Modal
    const simModal = document.getElementById("simulate-modal");
    document.getElementById("btn-simulate").addEventListener("click", () => {
        simModal.style.display = "flex";
    });
    document.getElementById("btn-close-simulate").addEventListener("click", () => {
        simModal.style.display = "none";
    });
    document.getElementById("btn-cancel-simulate").addEventListener("click", () => {
        simModal.style.display = "none";
    });

    // Preset Buttons
    document.querySelectorAll(".preset-btn").forEach(btn => {
        btn.addEventListener("click", (e) => {
            const key = e.currentTarget.getAttribute("data-type");
            const preset = PRESET_ATTACKS[key];
            if (preset) {
                document.getElementById("sim-signature").value = preset.signature;
                document.getElementById("sim-category").value = preset.category;
                document.getElementById("sim-severity").value = preset.severity;
                document.getElementById("sim-protocol").value = preset.proto;
                document.getElementById("sim-src-ip").value = preset.src_ip;
                document.getElementById("sim-src-port").value = preset.src_port;
                document.getElementById("sim-dst-ip").value = preset.dst_ip;
                document.getElementById("sim-dst-port").value = preset.dst_port;
                document.getElementById("sim-desc").value = preset.desc;
            }
        });
    });

    // Simulate Form Submit
    document.getElementById("simulate-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const payload = {
            signature: document.getElementById("sim-signature").value,
            category: document.getElementById("sim-category").value,
            severity: document.getElementById("sim-severity").value,
            protocol: document.getElementById("sim-protocol").value,
            source_ip: document.getElementById("sim-src-ip").value,
            source_port: parseInt(document.getElementById("sim-src-port").value) || null,
            dest_ip: document.getElementById("sim-dst-ip").value,
            dest_port: parseInt(document.getElementById("sim-dst-port").value) || null,
            description: document.getElementById("sim-desc").value,
        };

        try {
            const res = await fetch("/api/simulate/alert", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });

            if (!res.ok) throw new Error("Simulation endpoint error");
            const created = await res.json();
            showToast(`Threat simulated: ${created.signature.substring(0, 30)}...`, "danger");
            simModal.style.display = "none";
            fetchStats();
            fetchAlerts();
        } catch (err) {
            showToast(`Failed to inject attack: ${err.message}`, "danger");
        }
    });

    // PCAP Modal
    const pcapModal = document.getElementById("pcap-modal");
    document.getElementById("btn-open-pcap-modal").addEventListener("click", () => {
        pcapModal.style.display = "flex";
    });
    document.getElementById("btn-close-pcap").addEventListener("click", () => {
        pcapModal.style.display = "none";
    });
    document.getElementById("btn-cancel-pcap").addEventListener("click", () => {
        pcapModal.style.display = "none";
    });

    // Run PCAP Preset Button
    document.getElementById("btn-use-sample-pcap").addEventListener("click", () => {
        document.getElementById("pcap-path-input").value = "./samples/sample_attack.pcap";
    });

    // PCAP Form Submit
    document.getElementById("pcap-form").addEventListener("submit", async (e) => {
        e.preventDefault();
        const pcapPath = document.getElementById("pcap-path-input").value.trim();
        const resultBox = document.getElementById("pcap-result-box");
        resultBox.style.display = "block";
        resultBox.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Running Suricata engine analysis on PCAP...';

        try {
            const res = await fetch("/api/pcap/analyze", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ pcap_path: pcapPath })
            });

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.detail || "PCAP analysis failed");
            }

            const data = await res.json();
            resultBox.innerHTML = `<strong>Success!</strong> Ingested <strong>${data.added_alerts}</strong> alerts from PCAP dump into database.`;
            fetchStats();
            fetchAlerts();
        } catch (err) {
            resultBox.style.backgroundColor = "rgba(239, 68, 68, 0.15)";
            resultBox.style.color = "#fca5a5";
            resultBox.innerHTML = `<strong>Analysis Note:</strong> ${err.message}. If the PCAP file does not exist, use the "Simulate Attack" tool to generate live intrusion alerts.`;
        }
    });

    // Close modals when clicking backdrop
    window.addEventListener("click", (e) => {
        if (e.target.classList.contains("cyber-modal-overlay")) {
            e.target.style.display = "none";
        }
    });
}

// Fetch stats from /api/stats
async function fetchStats() {
    try {
        const res = await fetch("/api/stats");
        if (!res.ok) throw new Error("Stats fetch failed");
        const stats = await res.json();
        updateStatsUI(stats);
    } catch (err) {
        console.error("Error fetching stats:", err);
    }
}

// Update stats in the UI
function updateStatsUI(stats) {
    const total = stats.total || 0;
    document.getElementById("kpi-total-val").textContent = total;
    document.getElementById("kpi-24h-val").textContent = stats.last_24h || 0;

    const sevCounts = stats.by_severity || {};
    const crit = (sevCounts["Critical"] || 0) + (sevCounts["High"] || 0);
    document.getElementById("kpi-critical-val").textContent = crit;
    
    const pct = total > 0 ? Math.round((crit / total) * 100) : 0;
    document.getElementById("kpi-critical-pct").textContent = `${pct}% of total alerts`;

    // Threat level Defcon calculation
    const threatPill = document.getElementById("threat-level-pill");
    const threatText = document.getElementById("threat-level-text");
    if (crit > 5) {
        threatPill.className = "threat-level-pill";
        threatText.textContent = "DEFCON 1 // SEVERE THREAT";
    } else if (crit > 0) {
        threatPill.className = "threat-level-pill";
        threatText.textContent = "DEFCON 2 // ELEVATED";
    } else {
        threatPill.className = "threat-level-pill";
        threatPill.style.borderColor = "rgba(16, 185, 129, 0.4)";
        threatPill.style.color = "#34d399";
        threatText.textContent = "DEFCON 4 // NORMAL";
    }

    // Severity Bars
    const cCount = sevCounts["Critical"] || 0;
    const hCount = sevCounts["High"] || 0;
    const mCount = sevCounts["Medium"] || 0;
    const lCount = (sevCounts["Low"] || 0) + (sevCounts["Info"] || 0);

    document.getElementById("sev-critical-count").textContent = cCount;
    document.getElementById("sev-high-count").textContent = hCount;
    document.getElementById("sev-medium-count").textContent = mCount;
    document.getElementById("sev-low-count").textContent = lCount;

    const maxCount = Math.max(cCount, hCount, mCount, lCount, 1);
    document.getElementById("bar-critical").style.width = `${(cCount / maxCount) * 100}%`;
    document.getElementById("bar-high").style.width = `${(hCount / maxCount) * 100}%`;
    document.getElementById("bar-medium").style.width = `${(mCount / maxCount) * 100}%`;
    document.getElementById("bar-low").style.width = `${(lCount / maxCount) * 100}%`;

    // Protocols
    const protoCounts = stats.by_protocol || {};
    document.getElementById("proto-tcp-count").textContent = protoCounts["TCP"] || 0;
    document.getElementById("proto-udp-count").textContent = protoCounts["UDP"] || 0;
    document.getElementById("proto-icmp-count").textContent = protoCounts["ICMP"] || 0;

    const activeProtos = Object.keys(protoCounts).length;
    document.getElementById("kpi-proto-breakdown").textContent = `${activeProtos} protocols observed`;
}

// Fetch all alerts
async function fetchAlerts() {
    try {
        const res = await fetch("/api/alerts");
        if (!res.ok) throw new Error("Alerts fetch failed");
        allAlerts = await res.json();
        renderAlertsTable();
    } catch (err) {
        console.error("Error fetching alerts:", err);
        const tbody = document.getElementById("alerts-tbody");
        tbody.innerHTML = `<tr><td colspan="9" class="loading-cell" style="color: #f87171;"><i class="fa-solid fa-triangle-exclamation"></i> Error loading alerts: ${err.message}</td></tr>`;
    }
}

// Render the alerts table based on filters
function renderAlertsTable() {
    const search = document.getElementById("filter-search").value.toLowerCase().trim();
    const sevFilter = document.getElementById("filter-severity").value;
    const statusFilter = document.getElementById("filter-status").value;

    const filtered = allAlerts.filter(a => {
        if (sevFilter && a.severity !== sevFilter) return false;
        if (statusFilter && a.status !== statusFilter) return false;
        if (search) {
            const haystack = `${a.signature} ${a.category} ${a.source_ip} ${a.dest_ip} ${a.protocol} ${a.description}`.toLowerCase();
            if (!haystack.includes(search)) return false;
        }
        return true;
    });

    document.getElementById("displayed-alert-count").textContent = `${filtered.length} of ${allAlerts.length} alerts`;
    const tbody = document.getElementById("alerts-tbody");

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="loading-cell">No intrusion alerts match the active filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = filtered.map(a => {
        const timeFormatted = formatDate(a.timestamp);
        const src = `${a.source_ip || "N/A"}${a.source_port ? `:${a.source_port}` : ""}`;
        const dst = `${a.dest_ip || "N/A"}${a.dest_port ? `:${a.dest_port}` : ""}`;

        return `
            <tr data-id="${a.id}">
                <td><span class="ip-port">#${a.id}</span></td>
                <td><span class="ip-port" style="color: #94a3b8;">${timeFormatted}</span></td>
                <td><span class="sev-badge ${a.severity}">${a.severity}</span></td>
                <td>
                    <div class="threat-sig">${escapeHtml(a.signature || "Unknown Threat")}</div>
                    <div class="threat-cat">${escapeHtml(a.category || "General Intrusion")}</div>
                </td>
                <td><span class="ip-port">${escapeHtml(src)}</span></td>
                <td><span class="ip-port">${escapeHtml(dst)}</span></td>
                <td><span class="proto-tag">${a.protocol || "TCP"}</span></td>
                <td>
                    <select class="status-select" onchange="changeAlertStatus(${a.id}, this.value)">
                        <option value="open" ${a.status === 'open' ? 'selected' : ''}>Open</option>
                        <option value="investigating" ${a.status === 'investigating' ? 'selected' : ''}>Investigating</option>
                        <option value="resolved" ${a.status === 'resolved' ? 'selected' : ''}>Resolved</option>
                        <option value="dismissed" ${a.status === 'dismissed' ? 'selected' : ''}>Dismissed</option>
                    </select>
                </td>
                <td>
                    <button class="btn-inspect" onclick="openAlertDetail(${a.id})" title="Inspect full forensic packet">
                        <i class="fa-solid fa-magnifying-glass"></i>
                    </button>
                </td>
            </tr>
        `;
    }).join("");
}

// Change alert status via PATCH /api/alerts/{id}
async function changeAlertStatus(id, newStatus) {
    try {
        const res = await fetch(`/api/alerts/${id}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ status: newStatus })
        });

        if (!res.ok) throw new Error("Status update failed");
        const updated = await res.json();
        
        // Update local state
        const target = allAlerts.find(a => a.id === id);
        if (target) target.status = updated.status;

        showToast(`Alert #${id} status updated to ${newStatus}.`, "success");
    } catch (err) {
        showToast(`Failed to update status: ${err.message}`, "danger");
    }
}

// Open alert forensic detail modal
function openAlertDetail(id) {
    const alert = allAlerts.find(a => a.id === id);
    if (!alert) return;

    const modalBody = document.getElementById("detail-modal-body");
    const formattedDate = new Date(alert.timestamp).toLocaleString();

    modalBody.innerHTML = `
        <div class="forensic-grid">
            <div class="forensic-item">
                <label>THREAT SIGNATURE</label>
                <span style="color: #38bdf8;">${escapeHtml(alert.signature)}</span>
            </div>
            <div class="forensic-item">
                <label>SEVERITY LEVEL</label>
                <span class="sev-badge ${alert.severity}">${alert.severity}</span>
            </div>
            <div class="forensic-item">
                <label>ATTACK CATEGORY</label>
                <span>${escapeHtml(alert.category || "N/A")}</span>
            </div>
            <div class="forensic-item">
                <label>TIMESTAMP</label>
                <span>${formattedDate}</span>
            </div>
            <div class="forensic-item">
                <label>SOURCE ENDPOINT</label>
                <span>${alert.source_ip || "N/A"} : ${alert.source_port || "N/A"}</span>
            </div>
            <div class="forensic-item">
                <label>TARGET ENDPOINT</label>
                <span>${alert.dest_ip || "N/A"} : ${alert.dest_port || "N/A"}</span>
            </div>
            <div class="forensic-item">
                <label>IP PROTOCOL</label>
                <span>${alert.protocol || "TCP"}</span>
            </div>
            <div class="forensic-item">
                <label>CURRENT TRIAGE STATUS</label>
                <span style="text-transform: capitalize;">${alert.status}</span>
            </div>
        </div>

        <div class="form-group" style="margin-bottom: 20px;">
            <label style="color: var(--text-muted); font-size: 0.75rem; font-weight: 700;">DESCRIPTION & BEHAVIORAL NOTES</label>
            <p style="font-size: 0.85rem; color: #cbd5e1; background: rgba(255,255,255,0.03); padding: 10px; border-radius: 6px; border: 1px solid var(--border-subtle);">
                ${escapeHtml(alert.description || "No specific forensic description logged.")}
            </p>
        </div>

        <div class="form-group">
            <label style="color: var(--text-muted); font-size: 0.75rem; font-weight: 700;">RAW SURICATA EVE EVENT RECORD</label>
            <div class="raw-payload-box">${escapeHtml(alert.raw_data || JSON.stringify(alert, null, 2))}</div>
        </div>

        <div class="modal-actions" style="margin-top: 24px;">
            <button class="btn btn-secondary" onclick="document.getElementById('detail-modal').style.display='none'">Close</button>
            <button class="btn btn-outline-cyan" onclick="navigator.clipboard.writeText(JSON.stringify(allAlerts.find(a=>a.id===${alert.id}), null, 2)); showToast('Forensic telemetry copied to clipboard!', 'info');">
                <i class="fa-solid fa-copy"></i> Copy JSON Record
            </button>
        </div>
    `;

    document.getElementById("detail-modal").style.display = "flex";
}

// Helpers
function formatDate(isoStr) {
    if (!isoStr) return "--";
    try {
        const d = new Date(isoStr);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
        return isoStr;
    }
}

function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/[&<>'"]/g, tag => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
    }[tag] || tag));
}

function showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    const icon = type === "danger" ? "fa-circle-exclamation" : (type === "success" ? "fa-circle-check" : "fa-circle-info");
    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = "0";
        toast.style.transition = "opacity 0.4s ease";
        setTimeout(() => toast.remove(), 400);
    }, 3500);
}

function startAutoRefresh() {
    stopAutoRefresh();
    autoRefreshTimer = setInterval(() => {
        fetchStats();
        fetchAlerts();
    }, 5000);
}

function stopAutoRefresh() {
    if (autoRefreshTimer) {
        clearInterval(autoRefreshTimer);
        autoRefreshTimer = null;
    }
}
