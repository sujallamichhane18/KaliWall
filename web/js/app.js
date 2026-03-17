// KaliWall — Frontend Application
// Handles navigation, API calls, table rendering, and rule management.

(function () {
    "use strict";

    const API = "/api/v1";
    var bandwidthChart = null; // Hoisted for theme access

    // ---------- Theme Management ----------
    const themeToggle = document.getElementById("themeToggle");
    const html = document.documentElement;
    
    function initTheme() {
        const savedTheme = localStorage.getItem("theme");
        const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
        const theme = savedTheme ? savedTheme : (prefersDark ? "dark" : "light");
        setTheme(theme);
    }

    function setTheme(theme) {
        html.setAttribute("data-theme", theme);
        localStorage.setItem("theme", theme);
        
        // Update icon
        if (themeToggle) {
            themeToggle.innerHTML = theme === "dark" 
                ? '<i class="fa-solid fa-sun"></i>' 
                : '<i class="fa-solid fa-moon"></i>';
        }

        // Update Chart.js defaults
        const textColor = theme === "dark" ? "#9ca3af" : "#4b5563";
        const gridColor = theme === "dark" ? "#334155" : "#e5e7eb";
        
        if (window.Chart) {
            Chart.defaults.color = textColor;
            Chart.defaults.borderColor = gridColor;
        }
        
        // Update active chart if exists
        if (bandwidthChart) {
            bandwidthChart.options.scales.x.grid.color = gridColor;
            bandwidthChart.options.scales.y.grid.color = gridColor;
            bandwidthChart.options.scales.x.ticks.color = textColor;
            bandwidthChart.options.scales.y.ticks.color = textColor;
            bandwidthChart.update('none');
        }

        // Update gauges
        document.querySelectorAll(".gauge-bg").forEach(bg => {
            bg.style.stroke = theme === "dark" ? "#334155" : "#f3f4f6";
        });
    }

    if (themeToggle) {
        themeToggle.addEventListener("click", () => {
            const current = html.getAttribute("data-theme");
            setTheme(current === "dark" ? "light" : "dark");
        });
    }

    // Initialize theme immediately
    initTheme();

    // ---------- Navigation ----------

    const navItems = document.querySelectorAll(".nav-item");
    const pages = document.querySelectorAll(".page");
    const pageTitle = document.getElementById("pageTitle");
    const sidebar = document.getElementById("sidebar");
    const menuToggle = document.getElementById("menuToggle");

    const pageTitles = {
        dashboard: "Dashboard",
        rules: "Firewall Rules",
        connections: "Active Connections",
        blocked: "Blocked IPs",
        threats: "Threat Intelligence",
        websites: "Website Blocking",
        logs: "Traffic Logs",
        settings: "Settings",
    };

    navItems.forEach((item) => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            const target = item.dataset.page;
            navItems.forEach((n) => n.classList.remove("active"));
            item.classList.add("active");
            pages.forEach((p) => p.classList.remove("active"));
            document.getElementById("page-" + target).classList.add("active");
            pageTitle.textContent = pageTitles[target] || "KaliWall";
            sidebar.classList.remove("open");
            // Stop log stream when leaving the logs page
            if (target !== "logs") stopLogStream();
            loadPageData(target);
        });
    });

    menuToggle.addEventListener("click", () => sidebar.classList.toggle("open"));

    // ---------- Data Loading ----------

    function loadPageData(page) {
        switch (page) {
            case "dashboard":
                loadStats();
                loadSysInfo();
                loadTrafficVisibility();
                loadFirewallLogs();
                loadDashboardLogs();
                loadDashboardConnections();
                loadAnalytics();
                startBandwidthStream();
                break;
            case "rules":
                loadRules();
                break;
            case "connections":
                loadConnections();
                break;
            case "logs":
                loadLogs();
                break;
            case "settings":
                loadSettings();
                loadFirewallEngineSettings();
                break;
            case "blocked":
                loadBlocked();
                break;
            case "threats":
                loadThreats();
                break;
            case "websites":
                loadWebsites();
                break;
        }
        if (page !== "dashboard") stopBandwidthStream();
    }

    async function apiFetch(endpoint) {
        const res = await fetch(API + endpoint);
        return res.json();
    }

    // ---------- Dashboard ----------

    async function loadStats() {
        const res = await apiFetch("/stats");
        if (!res.success) return;
        const d = res.data;

        // Firewall stat cards
        document.getElementById("statTotalRules").textContent = d.total_rules;
        document.getElementById("statActiveRules").textContent = d.active_rules;
        document.getElementById("statBlocked").textContent = d.blocked_today;
        document.getElementById("statAllowed").textContent = d.allowed_today;
        document.getElementById("statConnections").textContent = d.active_connections;
        document.querySelector("#ruleCount span").textContent = d.active_rules;

        // System info banner
        document.getElementById("sysHostname").textContent = d.hostname || "--";
        document.getElementById("sysKernel").textContent = d.kernel || "--";
        document.getElementById("sysUptime").textContent = d.uptime || "--";
        document.getElementById("sysLoad").textContent = d.load_average || "--";
        document.getElementById("sysEngine").textContent = d.firewall_engine || "memory";

        // CPU gauge
        var cpuPct = d.cpu_usage_percent || 0;
        setGauge("gaugeCPU", "gaugeCPUText", cpuPct);
        document.getElementById("gaugeCPUCores").textContent = (d.cpu_cores || 0) + " cores";

        // Memory gauge
        var memPct = d.mem_usage_percent || 0;
        setGauge("gaugeMem", "gaugeMemText", memPct);
        var memUsedMB = ((d.mem_used_bytes || 0) / 1048576).toFixed(0);
        var memTotalMB = ((d.mem_total_bytes || 0) / 1048576).toFixed(0);
        document.getElementById("gaugeMemDetail").textContent = memUsedMB + " / " + memTotalMB + " MB";

        // Network totals
        document.getElementById("netRxValue").textContent = formatBytes(d.net_rx_bytes || 0);
        document.getElementById("netTxValue").textContent = formatBytes(d.net_tx_bytes || 0);
    }

    async function loadTrafficVisibility() {
        const res = await apiFetch("/traffic/visibility?limit=1200");
        if (!res.success) return;
        const v = res.data || {};
        document.getElementById("visConnections").textContent = v.active_connections || 0;
        document.getElementById("visRemoteIPs").textContent = v.unique_remote_ips || 0;
        document.getElementById("visBlocked").textContent = v.recent_blocked || 0;
        document.getElementById("visAllowed").textContent = v.recent_allowed || 0;

        const tbody = document.querySelector("#visTopProtocols tbody");
        if (!tbody) return;
        tbody.innerHTML = "";
        const protocols = v.top_protocols || [];
        if (protocols.length === 0) {
            tbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:#9ca3af">No traffic sample yet</td></tr>';
            return;
        }
        protocols.forEach(function (p) {
            const tr = document.createElement("tr");
            tr.innerHTML = "<td>" + escapeHtml(p.name) + "</td><td>" + (p.count || 0) + "</td>";
            tbody.appendChild(tr);
        });
    }

    async function loadFirewallLogs() {
        const res = await apiFetch("/firewall/logs?limit=120");
        if (!res.success) return;
        const logBox = document.getElementById("firewallLogs");
        if (!logBox) return;
        const lines = res.data || [];
        logBox.textContent = lines.join("\n");
    }

    // Set a circular SVG gauge by percentage (0-100).
    function setGauge(circleId, textId, percent) {
        var circumference = 2 * Math.PI * 52; // r=52
        var offset = circumference - (percent / 100) * circumference;
        var circle = document.getElementById(circleId);
        if (circle) circle.style.strokeDashoffset = offset;
        var text = document.getElementById(textId);
        if (text) text.textContent = percent.toFixed(1) + "%";
    }

    // Format bytes into human-readable string.
    function formatBytes(bytes) {
        if (bytes === 0) return "0 B";
        var units = ["B", "KB", "MB", "GB", "TB"];
        var i = Math.floor(Math.log(bytes) / Math.log(1024));
        if (i >= units.length) i = units.length - 1;
        return (bytes / Math.pow(1024, i)).toFixed(1) + " " + units[i];
    }

    // Load detailed system info including network interfaces.
    async function loadSysInfo() {
        const res = await apiFetch("/sysinfo");
        if (!res.success) return;
        const si = res.data;

        // Populate interfaces table
        var tbody = document.querySelector("#ifacesTable tbody");
        if (!tbody) return;
        tbody.innerHTML = "";
        if (si.interfaces && si.interfaces.length > 0) {
            si.interfaces.forEach(function (iface) {
                var tr = document.createElement("tr");
                var addrs = (iface.addresses || []).map(escapeHtml).join(", ") || "none";
                tr.innerHTML =
                    "<td><strong>" + escapeHtml(iface.name) + "</strong></td>" +
                    "<td>" + addrs + "</td>" +
                    "<td>" + formatBytes(iface.rx_bytes || 0) + "</td>" +
                    "<td>" + formatBytes(iface.tx_bytes || 0) + "</td>";
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#9ca3af">No network interfaces detected</td></tr>';
        }
    }

    async function loadDashboardLogs() {
        const res = await apiFetch("/logs?limit=8");
        if (!res.success) return;
        const tbody = document.querySelector("#dashRecentLogs tbody");
        tbody.innerHTML = "";
        res.data.forEach((entry) => {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + formatTime(entry.timestamp) + "</td>" +
                "<td>" + actionBadge(entry.action) + "</td>" +
                "<td>" + escapeHtml(entry.src_ip) + "</td>" +
                "<td>" + escapeHtml(entry.dst_ip) + "</td>" +
                "<td>" + escapeHtml(entry.protocol) + "</td>" +
                "<td>" + escapeHtml(entry.detail) + "</td>";
            tbody.appendChild(tr);
        });
    }

    async function loadDashboardConnections() {
        const res = await apiFetch("/connections");
        if (!res.success) return;
        const tbody = document.querySelector("#dashConnections tbody");
        tbody.innerHTML = "";
        res.data.slice(0, 6).forEach((c) => {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + escapeHtml(c.protocol) + "</td>" +
                "<td>" + escapeHtml(c.local_ip) + ":" + escapeHtml(c.local_port) + "</td>" +
                "<td>" + escapeHtml(c.remote_ip) + ":" + escapeHtml(c.remote_port) + "</td>" +
                "<td>" + stateBadge(c.state) + "</td>";
            tbody.appendChild(tr);
        });
    }

    // ---------- Rules ----------

    async function loadRules() {
        const res = await apiFetch("/rules");
        if (!res.success) return;
        const tbody = document.querySelector("#rulesTable tbody");
        tbody.innerHTML = "";
        res.data.forEach((rule) => {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + enabledBadge(rule.enabled) + "</td>" +
                "<td>" + chainBadge(rule.chain) + "</td>" +
                "<td>" + escapeHtml(rule.protocol) + "</td>" +
                "<td>" + escapeHtml(rule.src_ip) + (rule.src_port !== "any" ? ":" + escapeHtml(rule.src_port) : "") + "</td>" +
                "<td>" + escapeHtml(rule.dst_ip) + "</td>" +
                "<td>" + escapeHtml(rule.dst_port) + "</td>" +
                "<td>" + actionBadge(rule.action) + "</td>" +
                "<td>" + escapeHtml(rule.comment) + "</td>" +
                '<td class="action-cell">' +
                    '<button class="btn-icon" title="Edit" onclick="KaliWall.editRule(\'' + rule.id + '\')"><i class="fa-solid fa-pen"></i></button>' +
                    '<button class="btn-icon" title="Toggle" onclick="KaliWall.toggleRule(\'' + rule.id + '\')"><i class="fa-solid fa-toggle-' + (rule.enabled ? "on" : "off") + '"></i></button>' +
                    '<button class="btn-icon danger" title="Delete" onclick="KaliWall.deleteRule(\'' + rule.id + '\')"><i class="fa-solid fa-trash"></i></button>' +
                "</td>";
            tbody.appendChild(tr);
        });
    }

    // ---------- Connections ----------

    async function loadConnections() {
        const res = await apiFetch("/connections");
        if (!res.success) return;
        const tbody = document.querySelector("#connectionsTable tbody");
        tbody.innerHTML = "";
        res.data.forEach((c) => {
            const tr = document.createElement("tr");
            var remoteIP = c.remote_ip || "";
            tr.innerHTML =
                "<td>" + escapeHtml(c.protocol) + "</td>" +
                "<td>" + escapeHtml(c.local_ip) + "</td>" +
                "<td>" + escapeHtml(c.local_port) + "</td>" +
                "<td>" + escapeHtml(remoteIP) + "</td>" +
                "<td>" + escapeHtml(c.remote_port) + "</td>" +
                "<td>" + stateBadge(c.state) + "</td>" +
                '<td class="threat-cell" data-ip="' + escapeHtml(remoteIP) + '"><span class="badge badge-disabled">-</span></td>';
            tbody.appendChild(tr);
        });
        // Auto-check threat for non-private remote IPs
        checkThreatForConnections();
    }

    // ---------- Logs (Real-time SSE) ----------

    var logEventSource = null;
    var logLive = true;     // live vs paused
    var maxLogRows = 500;   // cap DOM rows

    function startLogStream() {
        stopLogStream();
        logLive = true;
        updateLiveUI();

        logEventSource = new EventSource(API + "/logs/stream");

        logEventSource.addEventListener("log", function (e) {
            if (!logLive) return;
            try {
                var entry = JSON.parse(e.data);
                prependLogRow(entry, true);
            } catch (_) {}
        });

        logEventSource.onerror = function () {
            // Browser will auto-reconnect; just update indicator briefly
            var ind = document.getElementById("liveIndicator");
            if (ind) ind.classList.add("paused");
            setTimeout(function () {
                if (logLive && ind) ind.classList.remove("paused");
            }, 2000);
        };
    }

    function stopLogStream() {
        if (logEventSource) {
            logEventSource.close();
            logEventSource = null;
        }
    }

    function prependLogRow(entry, animate) {
        var tbody = document.querySelector("#logsTable tbody");
        if (!tbody) return;
        var tr = document.createElement("tr");
        if (animate) tr.className = "log-new";
        tr.innerHTML =
            "<td>" + formatTime(entry.timestamp) + "</td>" +
            "<td>" + actionBadge(entry.action) + "</td>" +
            "<td>" + escapeHtml(entry.src_ip) + "</td>" +
            "<td>" + escapeHtml(entry.dst_ip) + "</td>" +
            "<td>" + escapeHtml(entry.protocol) + "</td>" +
            "<td>" + escapeHtml(entry.detail) + "</td>";
        tbody.insertBefore(tr, tbody.firstChild);
        // Trim excess rows
        while (tbody.children.length > maxLogRows) {
            tbody.removeChild(tbody.lastChild);
        }
    }

    function updateLiveUI() {
        var ind = document.getElementById("liveIndicator");
        var icon = document.getElementById("liveToggleIcon");
        var text = document.getElementById("liveToggleText");
        if (logLive) {
            if (ind) ind.classList.remove("paused");
            if (icon) icon.className = "fa-solid fa-pause";
            if (text) text.textContent = "Pause";
        } else {
            if (ind) ind.classList.add("paused");
            if (icon) icon.className = "fa-solid fa-play";
            if (text) text.textContent = "Resume";
        }
    }

    async function loadLogs() {
        // Load historical logs first, then start SSE stream
        const res = await apiFetch("/logs?limit=200");
        if (res.success) {
            const tbody = document.querySelector("#logsTable tbody");
            tbody.innerHTML = "";
            res.data.forEach(function (entry) {
                prependLogRow(entry, false);
            });
        }
        startLogStream();
    }

    // ---------- Rule CRUD ----------

    const ruleModal = document.getElementById("ruleModal");
    const ruleForm = document.getElementById("ruleForm");

    document.getElementById("btnAddRule").addEventListener("click", () => {
        ruleForm.reset();
        document.getElementById("ruleEditId").value = "";
        document.getElementById("ruleModalTitle").textContent = "Add Firewall Rule";
        document.getElementById("ruleSubmitBtn").innerHTML = '<i class="fa-solid fa-check"></i> Create Rule';
        document.getElementById("ruleSrcIP").value = "any";
        document.getElementById("ruleSrcPort").value = "any";
        ruleModal.classList.add("open");
    });

    document.getElementById("modalClose").addEventListener("click", () => ruleModal.classList.remove("open"));
    document.getElementById("btnCancelRule").addEventListener("click", () => ruleModal.classList.remove("open"));
    ruleModal.addEventListener("click", (e) => {
        if (e.target === ruleModal) ruleModal.classList.remove("open");
    });

    ruleForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const editId = document.getElementById("ruleEditId").value;
        const body = {
            chain: document.getElementById("ruleChain").value,
            protocol: document.getElementById("ruleProtocol").value,
            src_ip: document.getElementById("ruleSrcIP").value || "any",
            dst_ip: document.getElementById("ruleDstIP").value || "any",
            src_port: document.getElementById("ruleSrcPort").value || "any",
            dst_port: document.getElementById("ruleDstPort").value || "any",
            action: document.getElementById("ruleAction").value,
            comment: document.getElementById("ruleComment").value,
            enabled: document.getElementById("ruleEnabled").value === "true",
        };

        let res;
        if (editId) {
            res = await fetch(API + "/rules/" + encodeURIComponent(editId), {
                method: "PUT",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
        } else {
            res = await fetch(API + "/rules", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body),
            });
        }
        const data = await res.json();
        if (data.success) {
            toast(editId ? "Rule updated" : "Rule created", "success");
            ruleModal.classList.remove("open");
            loadRules();
            loadStats();
        } else {
            toast(data.message || "Failed to save rule", "error");
        }
    });

    async function toggleRule(id) {
        const res = await fetch(API + "/rules/" + encodeURIComponent(id), { method: "PATCH" });
        const data = await res.json();
        if (data.success) {
            toast("Rule toggled", "success");
            loadRules();
            loadStats();
        } else {
            toast(data.message, "error");
        }
    }

    async function deleteRule(id) {
        if (!confirm("Delete this firewall rule?")) return;
        const res = await fetch(API + "/rules/" + encodeURIComponent(id), { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            toast("Rule deleted", "success");
            loadRules();
            loadStats();
        } else {
            toast(data.message, "error");
        }
    }

    // ---------- Edit Rule ----------

    async function editRule(id) {
        const res = await apiFetch("/rules/" + encodeURIComponent(id));
        if (!res.success) { toast("Failed to load rule", "error"); return; }
        const rule = res.data;
        document.getElementById("ruleEditId").value = rule.id;
        document.getElementById("ruleChain").value = rule.chain;
        document.getElementById("ruleProtocol").value = rule.protocol;
        document.getElementById("ruleSrcIP").value = rule.src_ip || "any";
        document.getElementById("ruleDstIP").value = rule.dst_ip || "any";
        document.getElementById("ruleSrcPort").value = rule.src_port || "any";
        document.getElementById("ruleDstPort").value = rule.dst_port || "any";
        document.getElementById("ruleAction").value = rule.action;
        document.getElementById("ruleEnabled").value = rule.enabled ? "true" : "false";
        document.getElementById("ruleComment").value = rule.comment || "";
        document.getElementById("ruleModalTitle").textContent = "Edit Firewall Rule";
        document.getElementById("ruleSubmitBtn").innerHTML = '<i class="fa-solid fa-check"></i> Update Rule';
        ruleModal.classList.add("open");
    }

    // ---------- Blocked IPs ----------

    async function loadBlocked() {
        const res = await apiFetch("/blocked");
        if (!res.success) return;
        const tbody = document.querySelector("#blockedTable tbody");
        tbody.innerHTML = "";
        if (!res.data || res.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#9ca3af;padding:20px">No blocked IPs</td></tr>';
            return;
        }
        res.data.forEach(function (entry) {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td><strong>" + escapeHtml(entry.ip) + "</strong></td>" +
                "<td>" + escapeHtml(entry.reason || "-") + "</td>" +
                "<td>" + formatTime(entry.created_at) + "</td>" +
                '<td class="action-cell">' +
                    '<button class="btn btn-sm btn-danger" onclick="KaliWall.unblockIP(\'' + escapeHtml(entry.ip) + '\')"><i class="fa-solid fa-unlock"></i> Unblock</button>' +
                "</td>";
            tbody.appendChild(tr);
        });
    }

    async function unblockIP(ip) {
        if (!confirm("Unblock IP " + ip + "?")) return;
        const res = await fetch(API + "/blocked/" + encodeURIComponent(ip), { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            toast("IP unblocked", "success");
            loadBlocked();
        } else {
            toast(data.message || "Failed to unblock IP", "error");
        }
    }

    // ---------- Threat Intelligence ----------

    async function loadThreats() {
        const res = await apiFetch("/threat/cache");
        if (!res.success) return;
        const data = res.data || [];
        var safe = 0, suspicious = 0, malicious = 0;
        data.forEach(function (e) {
            if (e.threat_level === "safe") safe++;
            else if (e.threat_level === "suspicious") suspicious++;
            else if (e.threat_level === "malicious") malicious++;
        });
        document.getElementById("threatSafe").textContent = safe;
        document.getElementById("threatSuspicious").textContent = suspicious;
        document.getElementById("threatMalicious").textContent = malicious;
        document.getElementById("threatTotal").textContent = data.length;

        const tbody = document.querySelector("#threatCacheTable tbody");
        tbody.innerHTML = "";
        if (data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="12" style="text-align:center;color:#9ca3af;padding:20px">No cached threat data. Configure a VirusTotal API key in Settings and scan IPs from Connections.</td></tr>';
            return;
        }
        data.forEach(function (entry) {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td><strong>" + escapeHtml(entry.ip) + "</strong></td>" +
                "<td>" + threatBadge(entry) + "</td>" +
                "<td>" + (entry.malicious || 0) + "</td>" +
                "<td>" + (entry.suspicious || 0) + "</td>" +
                "<td>" + (entry.harmless || 0) + "</td>" +
                "<td>" + (entry.reputation || 0) + "</td>" +
                "<td>" + escapeHtml(entry.country || "-") + "</td>" +
                "<td>" + escapeHtml(entry.owner || "-") + "</td>" +
                "<td>" + (entry.has_connection ? '<span class="badge badge-enabled"><i class="fa-solid fa-link"></i> Yes</span>' : '<span class="badge badge-disabled">No</span>') + "</td>" +
                "<td>" + (entry.is_blocked ? '<span class="badge badge-drop"><i class="fa-solid fa-ban"></i> Blocked</span>' : '<span class="badge badge-enabled">Open</span>') + "</td>" +
                "<td>" + formatTime(entry.checked_at) + "</td>" +
                '<td class="action-cell">' +
                    (entry.is_blocked ? "" : '<button class="btn-icon danger" title="Block this IP" onclick="KaliWall.blockIPFromThreat(\'' + escapeHtml(entry.ip) + '\')"><i class="fa-solid fa-ban"></i></button>') +
                "</td>";
            tbody.appendChild(tr);
        });
    }

    async function blockIPFromThreat(ip) {
        if (!confirm("Block IP " + ip + "?")) return;
        const res = await fetch(API + "/blocked", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip, reason: "Blocked from Threat Intelligence" }),
        });
        const data = await res.json();
        if (data.success) {
            toast("IP blocked", "success");
            loadThreats();
        } else {
            toast(data.message || "Failed to block IP", "error");
        }
    }

    // ---------- Website Blocking ----------

    async function loadWebsites() {
        const res = await apiFetch("/websites");
        if (!res.success) return;
        const tbody = document.querySelector("#websitesTable tbody");
        tbody.innerHTML = "";
        if (!res.data || res.data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#9ca3af;padding:20px">No blocked websites</td></tr>';
            return;
        }
        res.data.forEach(function (entry) {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td><strong>" + escapeHtml(entry.domain) + "</strong></td>" +
                "<td>" + escapeHtml(entry.reason || "-") + "</td>" +
                "<td>" + formatTime(entry.created_at) + "</td>" +
                '<td class="action-cell">' +
                    '<button class="btn btn-sm btn-secondary" onclick="KaliWall.unblockWebsite(\'' + escapeHtml(entry.domain) + '\')"><i class="fa-solid fa-unlock"></i> Unblock</button>' +
                "</td>";
            tbody.appendChild(tr);
        });
    }

    async function unblockWebsite(domain) {
        if (!confirm("Unblock website " + domain + "?")) return;
        const res = await fetch(API + "/websites/" + encodeURIComponent(domain), { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            toast("Website unblocked", "success");
            loadWebsites();
        } else {
            toast(data.message || "Failed to unblock website", "error");
        }
    }

    // Expose to inline onclick handlers safely
    window.KaliWall = { toggleRule, deleteRule, editRule, unblockIP, unblockWebsite, blockIPFromThreat };

    // ---------- Refresh Buttons ----------

    document.getElementById("btnRefresh").addEventListener("click", () => {
        const activePage = document.querySelector(".nav-item.active").dataset.page;
        loadPageData(activePage);
        toast("Data refreshed", "success");
    });

    document.getElementById("btnRefreshConn").addEventListener("click", () => loadConnections());
    document.getElementById("btnRefreshLogs").addEventListener("click", () => loadLogs());

    document.getElementById("btnToggleLive").addEventListener("click", function () {
        logLive = !logLive;
        updateLiveUI();
        if (logLive && !logEventSource) startLogStream();
    });

    document.getElementById("btnClearLogs").addEventListener("click", function () {
        var tbody = document.querySelector("#logsTable tbody");
        if (tbody) tbody.innerHTML = "";
    });

    // ---------- Block IP Modal ----------

    document.getElementById("btnBlockIP").addEventListener("click", function () {
        document.getElementById("blockIPForm").reset();
        document.getElementById("blockIPModal").classList.add("open");
    });

    document.getElementById("blockIPForm").addEventListener("submit", async function (e) {
        e.preventDefault();
        var ip = document.getElementById("blockIP").value.trim();
        var reason = document.getElementById("blockReason").value.trim();
        if (!ip) { toast("Enter an IP address", "error"); return; }
        var res = await fetch(API + "/blocked", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip, reason: reason }),
        });
        var data = await res.json();
        if (data.success) {
            toast("IP blocked", "success");
            document.getElementById("blockIPModal").classList.remove("open");
            loadBlocked();
        } else {
            toast(data.message || "Failed to block IP", "error");
        }
    });

    // ---------- Block Website Modal ----------

    document.getElementById("btnBlockWebsite").addEventListener("click", function () {
        document.getElementById("blockWebsiteForm").reset();
        document.getElementById("blockWebsiteModal").classList.add("open");
    });

    document.getElementById("blockWebsiteForm").addEventListener("submit", async function (e) {
        e.preventDefault();
        var domain = document.getElementById("blockDomain").value.trim();
        var reason = document.getElementById("blockWebsiteReason").value.trim();
        if (!domain) { toast("Enter a domain", "error"); return; }
        var res = await fetch(API + "/websites", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: domain, reason: reason }),
        });
        var data = await res.json();
        if (data.success) {
            toast("Website blocked", "success");
            document.getElementById("blockWebsiteModal").classList.remove("open");
            loadWebsites();
        } else {
            toast(data.message || "Failed to block website", "error");
        }
    });

    // ---------- Threat Intel Refresh ----------

    document.getElementById("btnRefreshThreats").addEventListener("click", function () {
        loadThreats();
    });

    // ---------- Settings & Threat Intelligence ----------

    async function loadSettings() {
        var res = await apiFetch("/threat/apikey");
        if (!res.success) return;
        var badge = document.getElementById("apiKeyBadge");
        var removeBtn = document.getElementById("btnRemoveApiKey");
        if (res.data.configured) {
            badge.className = "badge badge-enabled";
            badge.innerHTML = '<i class="fa-solid fa-check"></i> API key configured (' + res.data.cache_entries + ' cached IPs)';
            removeBtn.style.display = "";
        } else {
            badge.className = "badge badge-disabled";
            badge.textContent = "Not configured";
            removeBtn.style.display = "none";
        }

        loadFirewallEngineSettings();
    }

    async function loadFirewallEngineSettings() {
        var res = await apiFetch("/firewall/engine");
        if (!res.success) return;

        var select = document.getElementById("firewallEngineSelect");
        var status = document.getElementById("firewallEngineStatus");
        if (!select || !status) return;

        select.innerHTML = "";
        var current = res.data.current_engine || "memory";
        var engines = res.data.available_engines || [];
        if (engines.indexOf("memory") === -1) engines.push("memory");
        engines.forEach(function (name) {
            var opt = document.createElement("option");
            opt.value = name;
            opt.textContent = name;
            if (name === current) opt.selected = true;
            select.appendChild(opt);
        });

        if (res.data.live_mode) {
            status.className = "badge badge-enabled";
            status.textContent = "Live mode: " + current;
        } else {
            status.className = "badge badge-disabled";
            status.textContent = "Memory mode";
        }

        if (res.data.last_error) {
            status.className = "badge badge-reject";
            status.textContent = "Engine warning: " + res.data.last_error;
        }
    }

    document.getElementById("btnSaveFirewallEngine").addEventListener("click", async function () {
        var select = document.getElementById("firewallEngineSelect");
        if (!select) return;
        var engine = select.value;
        var res = await fetch(API + "/firewall/engine", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ engine: engine }),
        });
        var data = await res.json();
        if (data.success) {
            toast("Firewall engine switched to " + engine, "success");
            loadFirewallEngineSettings();
            loadStats();
            loadFirewallLogs();
        } else {
            toast(data.message || "Failed to switch engine", "error");
        }
    });

    document.getElementById("btnSaveApiKey").addEventListener("click", async function () {
        var key = document.getElementById("vtApiKey").value.trim();
        if (!key) { toast("Enter an API key", "error"); return; }
        var res = await fetch(API + "/threat/apikey", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ api_key: key }),
        });
        var data = await res.json();
        if (data.success) {
            toast("API key saved", "success");
            document.getElementById("vtApiKey").value = "";
            loadSettings();
        } else {
            toast(data.message || "Failed to save key", "error");
        }
    });

    document.getElementById("btnRemoveApiKey").addEventListener("click", async function () {
        if (!confirm("Remove the VirusTotal API key?")) return;
        await fetch(API + "/threat/apikey", { method: "DELETE" });
        toast("API key removed", "success");
        loadSettings();
    });

    document.getElementById("btnClearCache").addEventListener("click", async function () {
        threatCache = {};
        toast("Local threat cache cleared", "success");
    });

    // Automatically check threat for each unique remote IP in the connections table
    var threatCache = {};

    async function checkThreatForConnections() {
        var cells = document.querySelectorAll("#connectionsTable .threat-cell");
        var checked = {};
        for (var i = 0; i < cells.length; i++) {
            var ip = cells[i].getAttribute("data-ip");
            if (!ip || ip === "0.0.0.0" || ip === "127.0.0.1" || ip === "::1" || ip === "*" || ip === "") continue;
            if (checked[ip]) {
                // Apply cached result
                if (threatCache[ip]) cells[i].innerHTML = threatBadge(threatCache[ip]);
                continue;
            }
            checked[ip] = true;
            if (threatCache[ip]) {
                cells[i].innerHTML = threatBadge(threatCache[ip]);
                continue;
            }
            // Async lookup — fire and forget to avoid blocking
            (function(cell, ipAddr) {
                fetch(API + "/threat/check/" + encodeURIComponent(ipAddr))
                    .then(function(r) { return r.json(); })
                    .then(function(res) {
                        if (res.data) {
                            threatCache[ipAddr] = res.data;
                            // Update all cells with this IP
                            document.querySelectorAll('#connectionsTable .threat-cell[data-ip="' + ipAddr + '"]').forEach(function(c) {
                                c.innerHTML = threatBadge(res.data);
                            });
                        }
                    })
                    .catch(function() {});
            })(cells[i], ip);
        }
    }

    function threatBadge(verdict) {
        if (!verdict || !verdict.threat_level) return '<span class="badge badge-disabled">-</span>';
        var level = verdict.threat_level;
        var cls = "badge-threat-" + level;
        var icon = level === "malicious" ? "fa-skull-crossbones"
                 : level === "suspicious" ? "fa-triangle-exclamation"
                 : level === "safe" ? "fa-shield-check"
                 : level === "internal" ? "fa-house-signal"
                 : "fa-question";
        var label = level.charAt(0).toUpperCase() + level.slice(1);
        var title = "";
        if (verdict.owner) title += verdict.owner;
        if (verdict.country) title += (title ? " | " : "") + verdict.country;
        if (verdict.malicious > 0) title += (title ? " | " : "") + verdict.malicious + " malicious detections";
        return '<span class="badge ' + cls + '" title="' + escapeHtml(title) + '"><i class="fa-solid ' + icon + '"></i> ' + escapeHtml(label) + '</span>';
    }

    // ---------- Live Charts (Chart.js) ----------

    // var bandwidthChart = null; // Hoisted
    var protocolChart = null;
    var blockedAllowedChart = null;
    var topTalkersChart = null;
    var bandwidthEventSource = null;
    var analyticsRefreshInterval = null;

    var chartColors = {
        blue:    "rgba(26, 115, 232, 1)",
        blueFill:"rgba(26, 115, 232, 0.12)",
        teal:    "rgba(0, 137, 123, 1)",
        tealFill:"rgba(0, 137, 123, 0.12)",
        red:     "rgba(217, 48, 37, 1)",
        green:   "rgba(30, 142, 62, 1)",
        orange:  "rgba(232, 113, 10, 1)",
        purple:  "rgba(132, 48, 206, 1)",
        yellow:  "rgba(249, 171, 0, 1)",
        gray:    "rgba(156, 163, 175, 1)",
    };

    var pieColors = [
        chartColors.blue, chartColors.teal, chartColors.orange,
        chartColors.purple, chartColors.yellow, chartColors.gray,
        chartColors.red, chartColors.green,
    ];

    function initBandwidthChart() {
        if (bandwidthChart) return;
        var ctx = document.getElementById("chartBandwidth");
        if (!ctx) return;
        bandwidthChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: [],
                datasets: [
                    {
                        label: "RX (bytes/s)",
                        data: [],
                        borderColor: chartColors.blue,
                        backgroundColor: chartColors.blueFill,
                        fill: true,
                        tension: 0.3,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                    {
                        label: "TX (bytes/s)",
                        data: [],
                        borderColor: chartColors.teal,
                        backgroundColor: chartColors.tealFill,
                        fill: true,
                        tension: 0.3,
                        pointRadius: 0,
                        borderWidth: 2,
                    },
                ],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: { position: "top", labels: { usePointStyle: true, padding: 16, font: { family: "Inter", size: 12 } } },
                    tooltip: {
                        callbacks: {
                            label: function (ctx) { return ctx.dataset.label + ": " + formatBytes(ctx.parsed.y) + "/s"; },
                        },
                    },
                },
                scales: {
                    x: { display: true, grid: { display: false }, ticks: { maxTicksLimit: 10, font: { size: 10 } } },
                    y: {
                        display: true,
                        beginAtZero: true,
                        grid: { color: "rgba(0,0,0,0.05)" },
                        ticks: {
                            font: { size: 10 },
                            callback: function (v) { return formatBytes(v) + "/s"; },
                        },
                    },
                },
                animation: { duration: 300 },
            },
        });
    }

    function initProtocolChart() {
        if (protocolChart) return;
        var ctx = document.getElementById("chartProtocol");
        if (!ctx) return;
        protocolChart = new Chart(ctx, {
            type: "doughnut",
            data: { labels: [], datasets: [{ data: [], backgroundColor: pieColors, borderWidth: 2, borderColor: "#fff" }] },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom", labels: { usePointStyle: true, padding: 12, font: { family: "Inter", size: 11 } } },
                },
                cutout: "60%",
                animation: { duration: 400 },
            },
        });
    }

    function initBlockedAllowedChart() {
        if (blockedAllowedChart) return;
        var ctx = document.getElementById("chartBlockedAllowed");
        if (!ctx) return;
        blockedAllowedChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: ["Blocked", "Allowed"],
                datasets: [{ data: [0, 0], backgroundColor: [chartColors.red, chartColors.green], borderWidth: 2, borderColor: "#fff" }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom", labels: { usePointStyle: true, padding: 12, font: { family: "Inter", size: 11 } } },
                },
                cutout: "60%",
                animation: { duration: 400 },
            },
        });
    }

    function initTopTalkersChart() {
        if (topTalkersChart) return;
        var ctx = document.getElementById("chartTopTalkers");
        if (!ctx) return;
        topTalkersChart = new Chart(ctx, {
            type: "bar",
            data: {
                labels: [],
                datasets: [{
                    label: "Events",
                    data: [],
                    backgroundColor: chartColors.blue,
                    borderRadius: 4,
                    maxBarThickness: 28,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",
                plugins: {
                    legend: { display: false },
                },
                scales: {
                    x: { beginAtZero: true, grid: { color: "rgba(0,0,0,0.05)" }, ticks: { font: { size: 10 } } },
                    y: { grid: { display: false }, ticks: { font: { family: "Inter", size: 10 } } },
                },
                animation: { duration: 400 },
            },
        });
    }

    async function loadAnalytics() {
        initBandwidthChart();
        initProtocolChart();
        initBlockedAllowedChart();
        initTopTalkersChart();

        var res = await apiFetch("/analytics");
        if (!res.success) return;
        var snap = res.data;

        // Fill bandwidth history
        if (bandwidthChart && snap.bandwidth) {
            bandwidthChart.data.labels = snap.bandwidth.map(function (s) {
                var d = new Date(s.time);
                return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
            });
            bandwidthChart.data.datasets[0].data = snap.bandwidth.map(function (s) { return s.rx_bps; });
            bandwidthChart.data.datasets[1].data = snap.bandwidth.map(function (s) { return s.tx_bps; });
            bandwidthChart.update("none");
        }

        // Protocol breakdown
        if (protocolChart && snap.protocols) {
            protocolChart.data.labels = snap.protocols.map(function (p) { return p.protocol; });
            protocolChart.data.datasets[0].data = snap.protocols.map(function (p) { return p.count; });
            protocolChart.update();
        }

        // Blocked vs Allowed
        if (blockedAllowedChart) {
            blockedAllowedChart.data.datasets[0].data = [snap.blocked_count || 0, snap.allowed_count || 0];
            blockedAllowedChart.update();
        }

        // Top Talkers
        if (topTalkersChart && snap.top_talkers) {
            topTalkersChart.data.labels = snap.top_talkers.map(function (t) { return t.ip; });
            topTalkersChart.data.datasets[0].data = snap.top_talkers.map(function (t) { return t.count; });
            topTalkersChart.update();
        }

        // Set up periodic refresh for non-bandwidth charts (every 10s)
        if (!analyticsRefreshInterval) {
            analyticsRefreshInterval = setInterval(function () {
                if (!document.getElementById("page-dashboard").classList.contains("active")) return;
                loadAnalytics();
            }, 10000);
        }
    }

    function startBandwidthStream() {
        stopBandwidthStream();
        initBandwidthChart();
        bandwidthEventSource = new EventSource(API + "/analytics/stream");
        bandwidthEventSource.addEventListener("bandwidth", function (e) {
            if (!bandwidthChart) return;
            try {
                var sample = JSON.parse(e.data);
                var d = new Date(sample.time);
                var label = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
                bandwidthChart.data.labels.push(label);
                bandwidthChart.data.datasets[0].data.push(sample.rx_bps);
                bandwidthChart.data.datasets[1].data.push(sample.tx_bps);
                // Keep max 120 points
                if (bandwidthChart.data.labels.length > 120) {
                    bandwidthChart.data.labels.shift();
                    bandwidthChart.data.datasets[0].data.shift();
                    bandwidthChart.data.datasets[1].data.shift();
                }
                bandwidthChart.update("none");
            } catch (_) {}
        });
    }

    function stopBandwidthStream() {
        if (bandwidthEventSource) {
            bandwidthEventSource.close();
            bandwidthEventSource = null;
        }
    }

    // ---------- Helpers ----------

    function escapeHtml(str) {
        if (!str) return "";
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

    function formatTime(ts) {
        if (!ts) return "-";
        const d = new Date(ts);
        return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    }

    function actionBadge(action) {
        const a = (action || "").toUpperCase();
        const cls =
            a === "ACCEPT" || a === "ALLOW"
                ? "badge-accept"
                : a === "DROP" || a === "BLOCK"
                ? "badge-drop"
                : a === "REJECT"
                ? "badge-reject"
                : "";
        return '<span class="badge ' + cls + '">' + escapeHtml(a) + "</span>";
    }

    function chainBadge(chain) {
        const c = (chain || "").toUpperCase();
        const cls =
            c === "INPUT"
                ? "badge-input"
                : c === "OUTPUT"
                ? "badge-output"
                : c === "FORWARD"
                ? "badge-forward"
                : "";
        return '<span class="badge ' + cls + '">' + escapeHtml(c) + "</span>";
    }

    function enabledBadge(enabled) {
        return enabled
            ? '<span class="badge badge-enabled"><i class="fa-solid fa-circle" style="font-size:6px"></i> ON</span>'
            : '<span class="badge badge-disabled"><i class="fa-solid fa-circle" style="font-size:6px"></i> OFF</span>';
    }

    function stateBadge(state) {
        const s = (state || "").toUpperCase();
        const cls = "badge-" + s.toLowerCase().replace(/ /g, "_");
        return '<span class="badge ' + cls + '">' + escapeHtml(s) + "</span>";
    }

    function toast(message, type) {
        const el = document.getElementById("toast");
        el.textContent = message;
        el.className = "toast show " + (type || "");
        setTimeout(() => (el.className = "toast"), 3000);
    }

    // ---------- Global Table Sorting ----------
    document.addEventListener("click", function(e) {
        if (!e.target.matches("th") && !e.target.parentNode.matches("th")) return;
        const th = e.target.matches("th") ? e.target : e.target.parentNode;
        const table = th.closest("table");
        if (!table) return;
        
        const tbody = table.querySelector("tbody");
        if (!tbody || tbody.rows.length < 2) return;
        
        const index = Array.from(th.parentNode.children).indexOf(th);
        const asc = th.getAttribute("data-asc") === "true";
        
        // Reset icons
        table.querySelectorAll("th i.sort-icon").forEach(i => i.remove());
        
        // Add icon
        const icon = document.createElement("i");
        icon.className = "sort-icon fa-solid fa-sort-" + (asc ? "down" : "up"); // flipped logic for UX
        icon.style.opacity = "0.7";
        icon.style.marginLeft = "6px";
        icon.style.fontSize = "0.75em";
        th.appendChild(icon);
        
        th.setAttribute("data-asc", !asc);

        const rows = Array.from(tbody.querySelectorAll("tr"));
        rows.sort((a, b) => {
            const aVal = a.children[index].textContent.trim();
            const bVal = b.children[index].textContent.trim();
            
            // Time sort specific
            if (aVal.match(/\d+:\d+:\d+/)) {
                return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
            }
            
            // Numeric sort
            const aNum = parseFloat(aVal.replace(/[^0-9.-]+/g,""));
            const bNum = parseFloat(bVal.replace(/[^0-9.-]+/g,""));
            
            if (!isNaN(aNum) && !isNaN(bNum) && !aVal.includes(".")) {
                 return asc ? aNum - bNum : bNum - aNum;
            }
            return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
        });
        
        // Minimize DOM reflow
        const fragment = document.createDocumentFragment();
        rows.forEach(row => fragment.appendChild(row));
        tbody.appendChild(fragment);
    });

    // ---------- Initial Load ----------
    loadPageData("dashboard");
})();
