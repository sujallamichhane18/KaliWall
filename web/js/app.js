// KaliWall — Frontend Application
// Handles navigation, API calls, table rendering, and rule management.

(function () {
    "use strict";

    const API = "/api/v1";
    var bandwidthChart = null; // Hoisted for theme access
    var socFirewallFlowChart = null;
    var socDPIProtocolChart = null;
    var socMitreChart = null;
    var firewallEventSource = null;
    var geoAttackEventSource = null;
    var geoMap = null;
    var geoLayer = null;
    var geoMarkers = [];
    var geoCountryAgg = {};
    var maxEventRows = 120;
    var maxGeoMarkers = 450;
    var peerHostMap = {};
    var dpiRunning = false;
    const SIDEBAR_WIDTH_KEY = "kaliwall_sidebar_width";
    const LOG_TABLE_SETTINGS_KEY = "kaliwall_log_table_settings";
    const DASHBOARD_PREFS_KEY = "kaliwall_dashboard_prefs";
    var logTableSettings = {
        density: "normal",
        height: 600,
        wrap: false,
        dpiOnly: false,
        columns: {
            timestamp: true,
            action: true,
            src: true,
            dst: true,
            protocol: true,
            detail: true,
        },
    };
    var dashboardPrefs = {
        density: "normal",
        autoRefreshSec: 10,
    };
    var dashboardAutoRefreshTimer = null;
    var socFlowHistory = [];

    // ---------- Theme Management ----------
    const themeToggle = document.getElementById("themeToggle");
    const html = document.documentElement;
    
    function initTheme() {
        const savedTheme = localStorage.getItem("theme");
        const theme = savedTheme || "light";
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
    initSidebarWidthControls();
    initLogTableControls();
    initDashboardControls();

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

    function goToPage(target) {
        if (!target || !document.getElementById("page-" + target)) return;
        navItems.forEach((n) => n.classList.toggle("active", n.dataset.page === target));
        pages.forEach((p) => p.classList.remove("active"));
        document.getElementById("page-" + target).classList.add("active");
        pageTitle.textContent = pageTitles[target] || "KaliWall";
        sidebar.classList.remove("open");
        if (target !== "logs") stopLogStream();
        loadPageData(target);
    }

    navItems.forEach((item) => {
        item.addEventListener("click", (e) => {
            e.preventDefault();
            goToPage(item.dataset.page);
        });
    });

    // Dashboard quick navigation cards
    document.querySelectorAll("[data-page-target]").forEach((el) => {
        el.style.cursor = "pointer";
        el.addEventListener("click", function () {
            goToPage(el.getAttribute("data-page-target"));
        });
    });

    menuToggle.addEventListener("click", () => sidebar.classList.toggle("open"));

    // ---------- Data Loading ----------

    function loadPageData(page) {
        stopDashboardAutoRefresh();
        switch (page) {
            case "dashboard":
                loadStats();
                loadSysInfo();
                loadDPIStatus();
                loadTrafficVisibility();
                loadDashboardLogs();
                loadDashboardConnections();
                loadFirewallEvents();
                loadDNSStats();
                startFirewallEventStream();
                loadAnalytics();
                startBandwidthStream();
                loadSOCGeoAttacks();
                startGeoAttackStream();
                startDashboardAutoRefresh();
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
        if (page !== "dashboard") stopFirewallEventStream();
        if (page !== "dashboard") stopGeoAttackStream();
    }

    async function apiFetch(endpoint) {
        const res = await fetch(API + endpoint, {
            headers: { "Accept": "application/json" },
        });
        const raw = await res.text();
        let data = {};
        if (raw) {
            try {
                data = JSON.parse(raw);
            } catch (_err) {
                data = {
                    success: false,
                    message: "Invalid JSON response from server",
                    data: null,
                };
            }
        }
        if (typeof data !== "object" || data === null) {
            data = { success: false, message: "Invalid response payload", data: null };
        }
        if (typeof data.success !== "boolean") {
            data.success = res.ok;
        }
        if (!res.ok && !data.message) {
            data.message = "HTTP " + res.status;
        }
        return data;
    }

    function initDashboardControls() {
        loadDashboardPrefs();
        applyDashboardPrefs();

        const density = document.getElementById("dashboardDensity");
        const autoRefresh = document.getElementById("dashboardAutoRefreshSec");

        if (density) {
            density.value = dashboardPrefs.density;
            density.addEventListener("change", function () {
                dashboardPrefs.density = density.value;
                persistDashboardPrefs();
                applyDashboardPrefs();
            });
        }

        if (autoRefresh) {
            autoRefresh.value = String(dashboardPrefs.autoRefreshSec);
            autoRefresh.addEventListener("change", function () {
                dashboardPrefs.autoRefreshSec = parseInt(autoRefresh.value, 10) || 0;
                persistDashboardPrefs();
                startDashboardAutoRefresh();
            });
        }

        document.querySelectorAll("#dashboardNav [data-scroll-target]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                const target = btn.getAttribute("data-scroll-target");
                if (!target) return;
                const section = document.querySelector('[data-dashboard-section="' + target + '"]');
                if (section) {
                    section.scrollIntoView({ behavior: "smooth", block: "start" });
                }
            });
        });
    }

    function loadDashboardPrefs() {
        try {
            const raw = localStorage.getItem(DASHBOARD_PREFS_KEY);
            if (!raw) return;
            const parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== "object") return;
            if (parsed.density) dashboardPrefs.density = parsed.density;
            if (parsed.autoRefreshSec !== undefined) {
                const sec = parseInt(parsed.autoRefreshSec, 10);
                dashboardPrefs.autoRefreshSec = isNaN(sec) ? 10 : Math.max(0, Math.min(60, sec));
            }
        } catch (_err) {}
    }

    function persistDashboardPrefs() {
        localStorage.setItem(DASHBOARD_PREFS_KEY, JSON.stringify(dashboardPrefs));
    }

    function applyDashboardPrefs() {
        const page = document.getElementById("page-dashboard");
        if (!page) return;
        page.classList.remove("dashboard-compact", "dashboard-comfortable");
        if (dashboardPrefs.density === "compact") page.classList.add("dashboard-compact");
        if (dashboardPrefs.density === "comfortable") page.classList.add("dashboard-comfortable");
    }

    function startDashboardAutoRefresh() {
        stopDashboardAutoRefresh();
        const active = document.querySelector(".nav-item.active");
        if (!active || active.dataset.page !== "dashboard") return;
        const sec = parseInt(dashboardPrefs.autoRefreshSec, 10) || 0;
        if (sec <= 0) return;
        dashboardAutoRefreshTimer = setInterval(function () {
            loadStats();
            loadSysInfo();
            loadDPIStatus();
            loadTrafficVisibility();
            loadDashboardLogs();
            loadDashboardConnections();
            loadFirewallEvents();
            loadDNSStats();
        }, sec * 1000);
    }

    function stopDashboardAutoRefresh() {
        if (dashboardAutoRefreshTimer) {
            clearInterval(dashboardAutoRefreshTimer);
            dashboardAutoRefreshTimer = null;
        }
    }

    // ---------- Dashboard ----------

    async function loadStats() {
        const res = await apiFetch("/stats");
        if (!res.success) return;
        const d = res.data;

        updateSOCFlowChart(d.allowed_today || 0, d.blocked_today || 0);

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

    async function loadSOCDashboard() {
        await Promise.all([
            loadSOCOverview(),
            loadSOCConnections(),
            loadSOCPortProtocolStats(),
            loadSOCAlerts(),
            loadSOCDPIRulesAndSignatures(),
            loadSOCGeoAttacks(),
            loadSOCThreatIntel(),
        ]);
        startGeoAttackStream();
    }

    async function loadSOCOverview() {
        const [statsRes, dpiRes, threatRes] = await Promise.all([
            apiFetch("/stats"),
            apiFetch("/dpi/status"),
            apiFetch("/threat/apikey"),
        ]);

        if (statsRes.success) {
            const s = statsRes.data || {};
            setText("socFwState", (s.engine_live_mode ? "LIVE" : "MEMORY") + " / " + (s.firewall_engine || "memory").toUpperCase());
            const packetsRate = Math.max(0, Math.floor(((s.net_rx_bytes || 0) + (s.net_tx_bytes || 0)) / 1024));
            setText("socPacketsRate", packetsRate);
        }

        if (dpiRes.success) {
            const d = dpiRes.data || {};
            setText("socDpiState", d.running ? "RUNNING" : "OFF");
            setText("socEventsRate", d.packets_seen ? Math.floor((d.packets_seen || 0) / Math.max((d.uptime_sec || 1), 1)) : 0);
        } else {
            setText("socDpiState", "UNAVAILABLE");
            setText("socEventsRate", 0);
        }

        if (threatRes.success) {
            const t = threatRes.data || {};
            setText("socTiFreshness", t.configured ? "configured" : "not configured");
        }
    }

    async function loadSOCConnections() {
        const res = await apiFetch("/connections");
        if (!res.success) return;
        const tbody = document.querySelector("#socConnectionsTable tbody");
        if (!tbody) return;
        tbody.innerHTML = "";
        (res.data || []).slice(0, 12).forEach(function (c) {
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + escapeHtml(c.protocol) + "</td>" +
                "<td>" + escapeHtml(c.local_ip) + ":" + escapeHtml(c.local_port) + "</td>" +
                "<td>" + escapeHtml(c.remote_ip) + ":" + escapeHtml(c.remote_port) + "</td>" +
                "<td>" + stateBadge(c.state) + "</td>";
            tbody.appendChild(tr);
        });
    }

    async function loadSOCPortProtocolStats() {
        const res = await apiFetch("/traffic/visibility?limit=1200");
        if (!res.success) return;
        const data = res.data || {};
        const tbody = document.querySelector("#socProtocolPortTable tbody");
        if (!tbody) return;
        tbody.innerHTML = "";

        (data.top_protocols || []).slice(0, 6).forEach(function (p) {
            const tr = document.createElement("tr");
            tr.innerHTML = "<td>Protocol</td><td>" + escapeHtml(p.name) + "</td><td>" + (p.count || 0) + "</td>";
            tbody.appendChild(tr);
        });
        (data.top_destination_ports || []).slice(0, 6).forEach(function (p) {
            const tr = document.createElement("tr");
            tr.innerHTML = "<td>Port</td><td>" + escapeHtml(p.name) + "</td><td>" + (p.count || 0) + "</td>";
            tbody.appendChild(tr);
        });

        renderSOCProtocolChart(data.top_protocols || []);
    }

    async function loadSOCAlerts() {
        const res = await apiFetch("/events?limit=80");
        if (!res.success) return;
        const rows = res.data || [];
        const tbody = document.querySelector("#socAlertsTable tbody");
        if (!tbody) return;
        tbody.innerHTML = "";

        var sev = { critical: 0, high: 0, medium: 0, low: 0 };
        rows.slice(0, 20).forEach(function (ev) {
            const s = mapSeverity(ev);
            sev[s] = (sev[s] || 0) + 1;
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td>" + formatTime(ev.timestamp) + "</td>" +
                "<td>" + severityBadge(s) + "</td>" +
                "<td>" + eventTypeBadge(ev.event_type || "event") + "</td>" +
                "<td>" + actionBadge(ev.action || "-") + "</td>" +
                "<td>" + escapeHtml(ev.src_ip || "-") + "</td>" +
                "<td>" + escapeHtml((ev.detail || "-").slice(0, 80)) + "</td>";
            tbody.appendChild(tr);
        });

        setText("socSeverityMix", (sev.critical || 0) + " / " + (sev.high || 0) + " / " + (sev.medium || 0) + " / " + (sev.low || 0));
        renderSOCMitre(rows);
    }

    async function loadSOCDPIRulesAndSignatures() {
        const res = await apiFetch("/logs?limit=400");
        if (!res.success) return;
        const logs = (res.data || []).filter(isDPILogEntry);

        const ruleHits = {};
        const sigRows = [];
        const severityHits = { critical: 0, high: 0, medium: 0, low: 0 };

        logs.forEach(function (entry) {
            const detail = String(entry.detail || "");
            const rule = extractTag(detail, "rule") || "unknown";
            const action = (entry.action || "ALLOW").toUpperCase();
            if (!ruleHits[rule]) ruleHits[rule] = { hits: 0, action: action, severity: mapSeverityFromAction(action) };
            ruleHits[rule].hits++;
            severityHits[ruleHits[rule].severity]++;

            if (sigRows.length < 20) {
                sigRows.push({
                    sig: sanitizeSignature(detail),
                    proto: entry.protocol || "-",
                    pair: (entry.src_ip || "-") + " -> " + (entry.dst_ip || "-"),
                    conf: action === "BLOCK" ? "0.95" : action === "LOG" ? "0.72" : "0.60",
                });
            }
        });

        const topRules = Object.keys(ruleHits)
            .map(function (k) { return { name: k, hits: ruleHits[k].hits, action: ruleHits[k].action, severity: ruleHits[k].severity }; })
            .sort(function (a, b) { return b.hits - a.hits; })
            .slice(0, 12);

        const rulesBody = document.querySelector("#socDPIRulesTable tbody");
        if (rulesBody) {
            rulesBody.innerHTML = "";
            topRules.forEach(function (r) {
                const tr = document.createElement("tr");
                tr.innerHTML =
                    "<td>" + escapeHtml(r.name) + "</td>" +
                    "<td>" + r.hits + "</td>" +
                    "<td>" + actionBadge(r.action) + "</td>" +
                    "<td>" + severityBadge(r.severity) + "</td>";
                rulesBody.appendChild(tr);
            });
        }

        const sigBody = document.querySelector("#socDPISignaturesTable tbody");
        if (sigBody) {
            sigBody.innerHTML = "";
            sigRows.forEach(function (r) {
                const tr = document.createElement("tr");
                tr.innerHTML =
                    "<td>" + escapeHtml(r.sig) + "</td>" +
                    "<td>" + escapeHtml(r.proto) + "</td>" +
                    "<td>" + escapeHtml(r.pair) + "</td>" +
                    "<td>" + escapeHtml(r.conf) + "</td>";
                sigBody.appendChild(tr);
            });
        }

        const sevBody = document.querySelector("#socDPISeverityTable tbody");
        if (sevBody) {
            sevBody.innerHTML = "";
            ["critical", "high", "medium", "low"].forEach(function (k) {
                const tr = document.createElement("tr");
                tr.innerHTML = "<td>" + severityBadge(k) + "</td><td>" + (severityHits[k] || 0) + "</td>";
                sevBody.appendChild(tr);
            });
        }
    }

    async function loadSOCThreatIntel() {
        const res = await apiFetch("/threat/cache");
        if (!res.success) return;
        const items = res.data || [];

        const iocBody = document.querySelector("#socIOCTable tbody");
        if (iocBody) {
            iocBody.innerHTML = "";
            items.slice(0, 15).forEach(function (i) {
                const tr = document.createElement("tr");
                tr.innerHTML =
                    "<td>" + escapeHtml(i.ip || "-") + "</td>" +
                    "<td>" + threatBadge({ threat_level: i.threat_level || "unknown" }) + "</td>" +
                    "<td>" + escapeHtml(i.country || "-") + "</td>" +
                    "<td>" + (i.is_blocked ? enabledBadge(true) : enabledBadge(false)) + "</td>";
                iocBody.appendChild(tr);
            });
        }

        renderSOCRecommendations(items);
    }

    async function loadSOCGeoAttacks() {
        initGeoMap();
        geoCountryAgg = {};
        const res = await apiFetch("/geo/attacks?limit=300");
        clearGeoMarkers();
        if (!res.success) {
            renderSOCGeoTable();
            return;
        }
        (res.data || []).forEach(function (point) {
            ingestGeoPoint(point, false);
        });
        renderSOCGeoTable();
    }

    function startGeoAttackStream() {
        stopGeoAttackStream();
        geoAttackEventSource = new EventSource(API + "/geo/stream");
        geoAttackEventSource.addEventListener("geo-attack", function (e) {
            try {
                var point = JSON.parse(e.data);
                ingestGeoPoint(point, true);
                renderSOCGeoTable();
            } catch (_) {}
        });
    }

    function stopGeoAttackStream() {
        if (geoAttackEventSource) {
            geoAttackEventSource.close();
            geoAttackEventSource = null;
        }
    }

    function initGeoMap() {
        if (geoMap || !window.L) return;
        var canvas = document.getElementById("geoWidgetMap") || document.getElementById("socGeoMap");
        if (!canvas) return;
        geoMap = L.map(canvas.id, { zoomControl: true, worldCopyJump: true }).setView([20, 0], 2);
        L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
            maxZoom: 18,
            attribution: "&copy; OpenStreetMap contributors",
        }).addTo(geoMap);
        geoLayer = L.layerGroup().addTo(geoMap);
    }

    function clearGeoMarkers() {
        geoMarkers = [];
        if (geoLayer) geoLayer.clearLayers();
    }

    function ingestGeoPoint(point, keepView) {
        if (!point || !point.source) return;
        initGeoMap();
        var src = point.source || {};
        var lat = Number(src.latitude || 0);
        var lon = Number(src.longitude || 0);
        if (!isFinite(lat) || !isFinite(lon) || (lat === 0 && lon === 0)) return;

        var sev = mapSeverity(point);
        var country = src.country || "Unknown";
        if (!geoCountryAgg[country]) geoCountryAgg[country] = { hits: 0, threat: {} };
        geoCountryAgg[country].hits++;
        geoCountryAgg[country].threat[sev] = (geoCountryAgg[country].threat[sev] || 0) + 1;

        if (!geoLayer || !window.L) return;
        var marker = L.circleMarker([lat, lon], {
            radius: sev === "critical" ? 8 : sev === "high" ? 7 : 6,
            color: geoSeverityColor(sev),
            fillColor: geoSeverityColor(sev),
            fillOpacity: 0.55,
            weight: 1,
        });
        var target = point.target || {};
        marker.bindPopup(
            "<strong>" + escapeHtml(country) + "</strong><br>" +
            "IP: " + escapeHtml(src.ip || "-") + "<br>" +
            "Action: " + escapeHtml((point.action || "-").toUpperCase()) + "<br>" +
            "Severity: " + escapeHtml(sev) + "<br>" +
            "Target: " + escapeHtml(target.ip || "-")
        );
        marker.addTo(geoLayer);
        geoMarkers.push(marker);

        while (geoMarkers.length > maxGeoMarkers) {
            var old = geoMarkers.shift();
            geoLayer.removeLayer(old);
        }

        if (!keepView && geoMarkers.length === 1) {
            geoMap.setView([lat, lon], 3);
        }
    }

    function renderSOCGeoTable() {
        const geoBody = document.querySelector("#geoWidgetTable tbody") || document.querySelector("#socGeoTable tbody");
        if (!geoBody) return;
        geoBody.innerHTML = "";
        var countries = Object.keys(geoCountryAgg);
        setText("geoPublicCount", countries.length + " public sources");
        if (countries.length === 0) {
            geoBody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#9ca3af">No geo attack data yet</td></tr>';
            return;
        }
        countries
            .sort(function (a, b) { return geoCountryAgg[b].hits - geoCountryAgg[a].hits; })
            .slice(0, 10)
            .forEach(function (c) {
                var levels = geoCountryAgg[c].threat || {};
                var topThreat = Object.keys(levels).sort(function (a, b) { return (levels[b] || 0) - (levels[a] || 0); })[0] || "low";
                const tr = document.createElement("tr");
                tr.innerHTML = "<td>" + escapeHtml(c) + "</td><td>" + (geoCountryAgg[c].hits || 0) + "</td><td>" + severityBadge(topThreat) + "</td>";
                geoBody.appendChild(tr);
            });
    }

    function geoSeverityColor(sev) {
        if (sev === "critical") return "#ef4444";
        if (sev === "high") return "#f97316";
        if (sev === "medium") return "#f59e0b";
        return "#22c55e";
    }

    function renderSOCRecommendations(items) {
        const list = document.getElementById("socRecommendations");
        if (!list) return;
        list.innerHTML = "";

        const blocked = items.filter(function (i) { return !!i.is_blocked; }).length;
        const malicious = items.filter(function (i) { return (i.threat_level || "").toLowerCase() === "malicious"; }).length;
        const recs = [];

        if (malicious > 0) recs.push({ level: "critical", text: "Block all malicious IOC sources and isolate hosts with repeated contact." });
        if (blocked < malicious) recs.push({ level: "high", text: "Enable auto-block for high-confidence threat intel matches." });
        recs.push({ level: "medium", text: "Tighten outbound policy for script-like clients and unknown TLS fingerprints." });
        recs.push({ level: "low", text: "Review top 10 DPI rules weekly and tune noisy LOG-only signatures." });

        recs.forEach(function (r) {
            const li = document.createElement("li");
            li.className = "warning-item";
            li.innerHTML = severityBadge(r.level) + " " + escapeHtml(r.text);
            list.appendChild(li);
        });
    }

    function updateSOCFlowChart(allowed, blocked) {
        if (!document.getElementById("chartFirewallFlow") || !window.Chart) return;
        socFlowHistory.push({ t: new Date().toLocaleTimeString([], { hour12: false }), a: allowed, b: blocked });
        if (socFlowHistory.length > 24) socFlowHistory.shift();

        if (!socFirewallFlowChart) {
            const ctx = document.getElementById("chartFirewallFlow");
            socFirewallFlowChart = new Chart(ctx, {
                type: "line",
                data: {
                    labels: socFlowHistory.map(function (x) { return x.t; }),
                    datasets: [
                        { label: "Allowed", data: socFlowHistory.map(function (x) { return x.a; }), borderColor: "#22c55e", backgroundColor: "rgba(34,197,94,0.18)", fill: true, tension: 0.25 },
                        { label: "Blocked", data: socFlowHistory.map(function (x) { return x.b; }), borderColor: "#ef4444", backgroundColor: "rgba(239,68,68,0.18)", fill: true, tension: 0.25 },
                    ],
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#cbd5e1" } } }, scales: { x: { ticks: { color: "#93a4c5" }, grid: { color: "#1f2a44" } }, y: { ticks: { color: "#93a4c5" }, grid: { color: "#1f2a44" } } } },
            });
            return;
        }

        socFirewallFlowChart.data.labels = socFlowHistory.map(function (x) { return x.t; });
        socFirewallFlowChart.data.datasets[0].data = socFlowHistory.map(function (x) { return x.a; });
        socFirewallFlowChart.data.datasets[1].data = socFlowHistory.map(function (x) { return x.b; });
        socFirewallFlowChart.update("none");
    }

    function renderSOCProtocolChart(protocols) {
        if (!document.getElementById("chartDPIProtocolMix") || !window.Chart) return;
        const labels = (protocols || []).slice(0, 6).map(function (p) { return p.name || "-"; });
        const values = (protocols || []).slice(0, 6).map(function (p) { return p.count || 0; });
        if (!socDPIProtocolChart) {
            const ctx = document.getElementById("chartDPIProtocolMix");
            socDPIProtocolChart = new Chart(ctx, {
                type: "doughnut",
                data: { labels: labels, datasets: [{ data: values, backgroundColor: ["#3b82f6", "#22c55e", "#eab308", "#f97316", "#ef4444", "#a78bfa"] }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color: "#cbd5e1" } } } },
            });
            return;
        }
        socDPIProtocolChart.data.labels = labels;
        socDPIProtocolChart.data.datasets[0].data = values;
        socDPIProtocolChart.update("none");
    }

    function renderSOCMitre(events) {
        if (!document.getElementById("chartMitreBreakdown") || !window.Chart) return;
        const buckets = { "Initial Access": 0, Execution: 0, Discovery: 0, "Command and Control": 0, Exfiltration: 0, "Lateral Movement": 0 };
        (events || []).forEach(function (e) {
            const text = ((e.event_type || "") + " " + (e.detail || "")).toLowerCase();
            if (text.indexOf("login") >= 0 || text.indexOf("sqli") >= 0) buckets["Initial Access"]++;
            if (text.indexOf("exec") >= 0 || text.indexOf("powershell") >= 0) buckets.Execution++;
            if (text.indexOf("scan") >= 0 || text.indexOf("dns") >= 0) buckets.Discovery++;
            if (text.indexOf("dpi") >= 0 || text.indexOf("c2") >= 0) buckets["Command and Control"]++;
            if (text.indexOf("exfil") >= 0 || text.indexOf("upload") >= 0) buckets.Exfiltration++;
            if (text.indexOf("smb") >= 0 || text.indexOf("rdp") >= 0 || text.indexOf("winrm") >= 0) buckets["Lateral Movement"]++;
        });
        const labels = Object.keys(buckets);
        const vals = labels.map(function (k) { return buckets[k]; });

        if (!socMitreChart) {
            const ctx = document.getElementById("chartMitreBreakdown");
            socMitreChart = new Chart(ctx, {
                type: "bar",
                data: { labels: labels, datasets: [{ label: "Count", data: vals, backgroundColor: "#f59e0b" }] },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: "#cbd5e1" }, grid: { color: "#1f2a44" } }, y: { ticks: { color: "#cbd5e1" }, grid: { color: "#1f2a44" } } } },
            });
            return;
        }
        socMitreChart.data.labels = labels;
        socMitreChart.data.datasets[0].data = vals;
        socMitreChart.update("none");
    }

    function extractTag(detail, key) {
        const m = String(detail || "").match(new RegExp(key + "=([^\\s]+)"));
        return m ? m[1] : "";
    }

    function sanitizeSignature(detail) {
        const d = String(detail || "");
        if (!d) return "-";
        const reduced = d.replace(/\b([0-9]{1,3}\.){3}[0-9]{1,3}\b/g, "x.x.x.x").replace(/[A-Za-z0-9]{24,}/g, "sig_token");
        return reduced.slice(0, 72);
    }

    function mapSeverity(ev) {
        const s = String((ev && ev.severity) || "").toLowerCase();
        if (s === "critical") return "critical";
        if (s === "warning" || s === "high") return "high";
        if (s === "medium") return "medium";
        return "low";
    }

    function mapSeverityFromAction(action) {
        const a = String(action || "").toUpperCase();
        if (a === "BLOCK" || a === "DROP") return "critical";
        if (a === "LOG") return "medium";
        return "low";
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

        const peersTbody = document.querySelector("#visPeersTable tbody");
        if (!peersTbody) return;
        peersTbody.innerHTML = "";
        const peers = v.resolved_peers || [];
        peerHostMap = {};
        if (peers.length === 0) {
            peersTbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#9ca3af">No active remote host data</td></tr>';
            return;
        }
        peers.forEach(function (peer) {
            peerHostMap[peer.ip] = {
                host: peer.host || "unresolved",
                verified: !!peer.verified,
            };
            const tr = document.createElement("tr");
            tr.innerHTML =
                "<td><strong>" + escapeHtml(peer.ip) + "</strong></td>" +
                "<td>" + renderHostBadge(peer.host || "unresolved", !!peer.verified) + "</td>" +
                "<td>" + (peer.count || 0) + "</td>";
            peersTbody.appendChild(tr);
        });
    }

    async function loadDPIStatus() {
        let res;
        try {
            res = await apiFetch("/dpi/status");
        } catch (_err) {
            res = { success: false, data: { enabled: false, running: false } };
        }
        const s = (res && res.data) || { enabled: false, running: false };
        const on = !!s.enabled && !!s.running;
        dpiRunning = on;
        setText("dpiStatusText", on ? "ON" : "OFF");
        setText("dpiPacketsSeen", s.packets_seen || 0);
        setText("dpiBlockedCount", s.blocked || 0);
        setText("dpiLoggedCount", s.logged || 0);
        setText("dpiDecodeErrors", s.decode_errors || 0);

        setText("dpiIfaceBadge", "iface: " + (s.interface || "-"));
        setText("dpiWorkersBadge", "workers: " + (s.workers || 0));
        setText("dpiUptimeBadge", "uptime: " + formatDurationSeconds(s.uptime_sec || 0));

        const statusEl = document.getElementById("dpiStatusText");
        if (statusEl) statusEl.style.color = on ? "var(--color-success)" : "var(--color-danger)";

        const btn = document.getElementById("btnToggleDPI");
        if (btn) {
            btn.innerHTML = on
                ? '<i class="fa-solid fa-power-off"></i> Turn OFF DPI'
                : '<i class="fa-solid fa-power-off"></i> Turn ON DPI';
            btn.classList.toggle("btn-danger", on);
            btn.classList.toggle("btn-primary", !on);
            btn.disabled = false;
        }

        if (!res.success && res.message) {
            toast(res.message, "error");
        }
    }

    async function toggleDPI() {
        const btn = document.getElementById("btnToggleDPI");
        const nextEnabled = !dpiRunning;
        if (btn) btn.disabled = true;
        try {
            const resp = await fetch(API + "/dpi/control", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ enabled: nextEnabled }),
            });
            const raw = await resp.text();
            let data;
            try {
                data = raw ? JSON.parse(raw) : {};
            } catch (_err) {
                throw new Error("DPI control endpoint returned non-JSON response. Restart server with latest build.");
            }
            if (!data.success) {
                throw new Error(data.message || "Failed to toggle DPI");
            }
            toast(data.message || (nextEnabled ? "DPI enabled" : "DPI disabled"), "success");
        } catch (err) {
            toast(err.message || "Failed to toggle DPI", "error");
        }
        await loadDPIStatus();
    }

    function initSidebarWidthControls() {
        const slider = document.getElementById("sidebarWidthSlider");
        const value = document.getElementById("sidebarWidthValue");
        const reset = document.getElementById("btnResetSidebarWidth");
        if (!slider || !value || !reset) return;

        const saved = parseInt(localStorage.getItem(SIDEBAR_WIDTH_KEY) || "260", 10);
        const width = isNaN(saved) ? 260 : Math.max(220, Math.min(380, saved));
        slider.value = String(width);
        applySidebarWidth(width);

        slider.addEventListener("input", function () {
            const w = parseInt(slider.value, 10) || 260;
            applySidebarWidth(w);
            localStorage.setItem(SIDEBAR_WIDTH_KEY, String(w));
        });

        reset.addEventListener("click", function () {
            slider.value = "260";
            applySidebarWidth(260);
            localStorage.setItem(SIDEBAR_WIDTH_KEY, "260");
            toast("Sidebar width reset", "success");
        });
    }

    function applySidebarWidth(width) {
        document.documentElement.style.setProperty("--sidebar-width", width + "px");
        setText("sidebarWidthValue", width + "px");
    }

    function formatDurationSeconds(total) {
        const sec = Math.max(0, Math.floor(total));
        const h = Math.floor(sec / 3600);
        const m = Math.floor((sec % 3600) / 60);
        const s = sec % 60;
        if (h > 0) return h + "h " + m + "m";
        if (m > 0) return m + "m " + s + "s";
        return s + "s";
    }

    async function refreshPeerHostMap() {
        const res = await apiFetch("/traffic/visibility?limit=1200");
        if (!res.success) return;
        const peers = (res.data && res.data.resolved_peers) || [];
        const next = {};
        peers.forEach(function (peer) {
            next[peer.ip] = {
                host: peer.host || "unresolved",
                verified: !!peer.verified,
            };
        });
        peerHostMap = next;
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
        await refreshPeerHostMap();
        const res = await apiFetch("/connections");
        if (!res.success) return;
        const tbody = document.querySelector("#connectionsTable tbody");
        tbody.innerHTML = "";
        res.data.forEach((c) => {
            const tr = document.createElement("tr");
            var remoteIP = c.remote_ip || "";
            var host = peerHostMap[remoteIP] || { host: "unresolved", verified: false };
            tr.innerHTML =
                "<td>" + escapeHtml(c.protocol) + "</td>" +
                "<td>" + escapeHtml(c.local_ip) + "</td>" +
                "<td>" + escapeHtml(c.local_port) + "</td>" +
                "<td>" + escapeHtml(remoteIP) + "</td>" +
                "<td>" + renderHostBadge(host.host, host.verified) + "</td>" +
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

    function startLogStream(force) {
        if (logEventSource && !force) {
            return;
        }
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
        if (logTableSettings.dpiOnly && !isDPILogEntry(entry)) {
            return;
        }
        var tbody = document.querySelector("#logsTable tbody");
        if (!tbody) return;
        var tr = document.createElement("tr");
        if (animate) tr.className = "log-new";
        tr.innerHTML =
            '<td class="col-timestamp">' + formatTime(entry.timestamp) + "</td>" +
            '<td class="col-action">' + actionBadge(entry.action) + "</td>" +
            '<td class="col-src">' + escapeHtml(entry.src_ip) + "</td>" +
            '<td class="col-dst">' + escapeHtml(entry.dst_ip) + "</td>" +
            '<td class="col-protocol">' + escapeHtml(entry.protocol) + "</td>" +
            '<td class="col-detail">' + escapeHtml(entry.detail) + "</td>";
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

    async function refreshLogsFromBackend() {
        const res = await apiFetch("/logs?limit=200");
        if (res.success) {
            const tbody = document.querySelector("#logsTable tbody");
            tbody.innerHTML = "";
            res.data.forEach(function (entry) {
                prependLogRow(entry, false);
            });
        }
    }

    async function loadLogs() {
        // Refresh logs data from backend and keep live stream attached.
        await refreshLogsFromBackend();
        startLogStream(false);
    }

    function isDPILogEntry(entry) {
        if (!entry) return false;
        var detail = String(entry.detail || "").toLowerCase();
        return detail.indexOf("dpi:") === 0;
    }

    function initLogTableControls() {
        loadLogTableSettings();
        applyLogTableSettings();

        var density = document.getElementById("logsDensitySelect");
        var heightRange = document.getElementById("logsHeightRange");
        var wrap = document.getElementById("logsWrapToggle");
        var dpiOnly = document.getElementById("logsDPIOnlyToggle");
        var columnsBtn = document.getElementById("btnToggleLogColumns");
        var panel = document.getElementById("logsColumnsPanel");

        if (density) {
            density.value = logTableSettings.density;
            density.addEventListener("change", function () {
                logTableSettings.density = density.value;
                persistAndApplyLogTableSettings();
            });
        }
        if (heightRange) {
            heightRange.value = String(logTableSettings.height);
            heightRange.addEventListener("input", function () {
                var v = parseInt(heightRange.value, 10) || 600;
                logTableSettings.height = Math.max(260, Math.min(900, v));
                persistAndApplyLogTableSettings();
            });
        }
        if (wrap) {
            wrap.checked = !!logTableSettings.wrap;
            wrap.addEventListener("change", function () {
                logTableSettings.wrap = !!wrap.checked;
                persistAndApplyLogTableSettings();
            });
        }
        if (dpiOnly) {
            dpiOnly.checked = !!logTableSettings.dpiOnly;
            dpiOnly.addEventListener("change", function () {
                logTableSettings.dpiOnly = !!dpiOnly.checked;
                persistAndApplyLogTableSettings();
                loadLogs();
            });
        }
        if (columnsBtn && panel) {
            columnsBtn.addEventListener("click", function () {
                panel.style.display = panel.style.display === "none" ? "flex" : "none";
            });
            panel.querySelectorAll("input[type=checkbox][data-col]").forEach(function (cb) {
                var col = cb.getAttribute("data-col");
                cb.checked = !!(logTableSettings.columns && logTableSettings.columns[col]);
                cb.addEventListener("change", function () {
                    logTableSettings.columns[col] = !!cb.checked;
                    persistAndApplyLogTableSettings();
                });
            });
        }
    }

    function loadLogTableSettings() {
        try {
            var raw = localStorage.getItem(LOG_TABLE_SETTINGS_KEY);
            if (!raw) return;
            var parsed = JSON.parse(raw);
            if (!parsed || typeof parsed !== "object") return;
            if (parsed.density) logTableSettings.density = parsed.density;
            if (parsed.height) logTableSettings.height = parsed.height;
            logTableSettings.wrap = !!parsed.wrap;
            logTableSettings.dpiOnly = !!parsed.dpiOnly;
            if (parsed.columns && typeof parsed.columns === "object") {
                Object.keys(logTableSettings.columns).forEach(function (k) {
                    if (Object.prototype.hasOwnProperty.call(parsed.columns, k)) {
                        logTableSettings.columns[k] = !!parsed.columns[k];
                    }
                });
            }
        } catch (_err) {}
    }

    function persistAndApplyLogTableSettings() {
        localStorage.setItem(LOG_TABLE_SETTINGS_KEY, JSON.stringify(logTableSettings));
        applyLogTableSettings();
    }

    function applyLogTableSettings() {
        var table = document.getElementById("logsTable");
        var container = document.getElementById("logContainer");
        var heightLabel = document.getElementById("logsHeightLabel");
        if (!table || !container) return;

        table.classList.remove("table-compact", "table-comfortable", "table-wrap-detail");
        if (logTableSettings.density === "compact") table.classList.add("table-compact");
        if (logTableSettings.density === "comfortable") table.classList.add("table-comfortable");
        if (logTableSettings.wrap) table.classList.add("table-wrap-detail");

        container.style.maxHeight = logTableSettings.height + "px";
        if (heightLabel) heightLabel.textContent = logTableSettings.height + "px";

        Object.keys(logTableSettings.columns).forEach(function (col) {
            table.classList.toggle("hide-col-" + col, !logTableSettings.columns[col]);
        });
    }

    // ---------- Firewall Events (SSE + Dashboard Cards) ----------

    async function loadFirewallEvents() {
        const res = await apiFetch("/events?limit=40");
        if (!res.success) return;
        const events = res.data || [];
        const tbody = document.querySelector("#eventsTable tbody");
        if (!tbody) return;
        tbody.innerHTML = "";
        events.forEach(function (ev) {
            appendEventRow(ev, false);
        });
        recomputeEventStats();
    }

    function startFirewallEventStream() {
        stopFirewallEventStream();
        const tbody = document.querySelector("#eventsTable tbody");
        if (!tbody) return;
        firewallEventSource = new EventSource(API + "/events/stream");
        firewallEventSource.addEventListener("firewall-event", function (e) {
            try {
                var ev = JSON.parse(e.data);
                appendEventRow(ev, true);
                recomputeEventStats();
            } catch (_) {}
        });
    }

    function stopFirewallEventStream() {
        if (firewallEventSource) {
            firewallEventSource.close();
            firewallEventSource = null;
        }
    }

    function appendEventRow(ev, prepend) {
        const tbody = document.querySelector("#eventsTable tbody");
        if (!tbody) return;
        const tr = document.createElement("tr");
        tr.innerHTML =
            "<td>" + formatTime(ev.timestamp) + "</td>" +
            "<td>" + eventTypeBadge(ev.event_type) + "</td>" +
            "<td>" + actionBadge(ev.action) + "</td>" +
            "<td>" + escapeHtml(ev.src_ip || "-") + "</td>" +
            "<td>" + escapeHtml(ev.dst_ip || "-") + "</td>" +
            "<td>" + severityBadge(ev.severity) + "</td>";
        if (prepend) {
            tbody.insertBefore(tr, tbody.firstChild);
        } else {
            tbody.appendChild(tr);
        }
        while (tbody.children.length > maxEventRows) {
            tbody.removeChild(tbody.lastChild);
        }
    }

    function recomputeEventStats() {
        const rows = document.querySelectorAll("#eventsTable tbody tr");
        var warn = 0;
        var critical = 0;
        rows.forEach(function (row) {
            var sev = (row.querySelector(".badge-severity") || {}).getAttribute ? row.querySelector(".badge-severity").getAttribute("data-severity") : "";
            if (sev === "warning") warn++;
            if (sev === "critical") critical++;
        });
        var totalEl = document.getElementById("eventTotalCount");
        var warnEl = document.getElementById("eventWarningCount");
        var critEl = document.getElementById("eventCriticalCount");
        if (totalEl) totalEl.textContent = String(rows.length);
        if (warnEl) warnEl.textContent = String(warn);
        if (critEl) critEl.textContent = String(critical);
    }

    async function loadDNSStats() {
        const res = await apiFetch("/dns/stats");
        if (!res.success) return;
        const s = res.data || {};
        const hits = s.cache_hits || 0;
        const misses = s.cache_misses || 0;
        const total = hits + misses;
        const rate = total > 0 ? ((hits / total) * 100).toFixed(1) + "%" : "0%";

        setText("dnsLookupsTotal", s.lookups_total || 0);
        setText("dnsCacheHitRate", rate);
        setText("dnsVerifiedPTR", s.verified_ptr || 0);
        setText("dnsUnresolved", s.unresolved || 0);
    }

    // ---------- Rule CRUD ----------

    const ruleModal = document.getElementById("ruleModal");
    const ruleForm = document.getElementById("ruleForm");

    document.getElementById("btnAddRule").addEventListener("click", () => {
        ruleForm.reset();
        renderRuleWarnings([]);
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

        const validationRes = await fetch(API + "/rules/validate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        const validationData = await validationRes.json();
        if (!validationRes.ok || !validationData.success) {
            toast(validationData.message || "Rule validation failed", "error");
            return;
        }
        const warnings = validationData.data || [];
        renderRuleWarnings(warnings);
        if (warnings.length > 0 && !confirm("Rule analyzer found warnings. Continue anyway?")) {
            return;
        }

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
        renderRuleWarnings([]);
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

    function renderRuleWarnings(warnings) {
        const card = document.getElementById("ruleWarningsCard");
        const list = document.getElementById("ruleWarningsList");
        const modalWrap = document.getElementById("ruleFormWarnings");
        const modalList = document.getElementById("ruleFormWarningsList");
        if (!card || !list || !modalWrap || !modalList) return;
        list.innerHTML = "";
        modalList.innerHTML = "";
        if (!warnings || warnings.length === 0) {
            card.style.display = "none";
            modalWrap.style.display = "none";
            return;
        }
        warnings.forEach(function (w) {
            const li = document.createElement("li");
            li.className = "warning-item";
            li.innerHTML = '<span class="badge ' + (w.level === "error" ? "badge-drop" : "badge-reject") + '">' + escapeHtml(w.level || "warning") + '</span> ' +
                '<strong>' + escapeHtml(w.code || "rule_warning") + '</strong> - ' + escapeHtml(w.message || "Rule warning");
            list.appendChild(li);

            const modalLi = li.cloneNode(true);
            modalList.appendChild(modalLi);
        });
        card.style.display = "block";
        modalWrap.style.display = "block";
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
        if (activePage === "logs") {
            refreshLogsFromBackend();
            toast("Logs refreshed", "success");
            return;
        }
        loadPageData(activePage);
        toast("Data refreshed", "success");
    });

    document.getElementById("btnRefreshConn").addEventListener("click", () => loadConnections());
    document.getElementById("btnRefreshLogs").addEventListener("click", () => {
        refreshLogsFromBackend();
        toast("Logs refreshed", "success");
    });
    document.getElementById("btnRefreshDNSStats").addEventListener("click", () => loadDNSStats());
    document.getElementById("btnRefreshDPIStatus").addEventListener("click", () => loadDPIStatus());
    document.getElementById("btnToggleDPI").addEventListener("click", () => toggleDPI());
    document.getElementById("btnFirewallStop").addEventListener("click", () => stopFirewallFromTopbar());
    document.getElementById("btnFirewallRestart").addEventListener("click", () => restartFirewallFromTopbar());

    document.getElementById("btnClearDNSCache").addEventListener("click", async function () {
        const res = await fetch(API + "/dns/cache", { method: "DELETE" });
        const data = await res.json();
        if (data.success) {
            toast("DNS cache cleared", "success");
            loadDNSStats();
            loadTrafficVisibility();
        } else {
            toast(data.message || "Failed to clear DNS cache", "error");
        }
    });

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

    async function stopFirewallFromTopbar() {
        if (!confirm("Switch firewall to memory mode (stop live backend)?")) return;
        var res = await fetch(API + "/firewall/engine", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ engine: "memory" }),
        });
        var data = await res.json();
        if (!data.success) {
            toast(data.message || "Failed to stop firewall", "error");
            return;
        }
        toast("Firewall switched to memory mode", "success");
        loadFirewallEngineSettings();
        loadStats();
    }

    async function restartFirewallFromTopbar() {
        var info = await apiFetch("/firewall/engine");
        if (!info.success) {
            toast("Failed to read firewall status", "error");
            return;
        }
        var engines = (info.data && info.data.available_engines) || [];
        var target = "memory";
        for (var i = 0; i < engines.length; i++) {
            var name = String(engines[i] || "").toLowerCase();
            if (name && name !== "memory") {
                target = name;
                break;
            }
        }
        if (target === "memory") {
            toast("No live backend available to restart", "error");
            return;
        }
        var res = await fetch(API + "/firewall/engine", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ engine: target }),
        });
        var data = await res.json();
        if (!data.success) {
            toast(data.message || "Failed to restart firewall", "error");
            return;
        }
        toast("Firewall restarted on " + target, "success");
        loadFirewallEngineSettings();
        loadStats();
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
            loadTrafficVisibility();
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

    function eventTypeBadge(eventType) {
        var text = (eventType || "event").replace(/_/g, " ");
        return '<span class="badge badge-input">' + escapeHtml(text) + '</span>';
    }

    function severityBadge(severity) {
        var sev = (severity || "info").toLowerCase();
        var cls = sev === "critical" ? "badge-drop" : sev === "warning" ? "badge-reject" : "badge-enabled";
        return '<span class="badge badge-severity ' + cls + '" data-severity="' + escapeHtml(sev) + '">' + escapeHtml(sev) + '</span>';
    }

    function renderHostBadge(host, verified) {
        var label = host || "unresolved";
        var cls = verified ? "host-pill host-pill-verified" : "host-pill host-pill-unverified";
        var icon = verified ? "fa-circle-check" : "fa-circle-question";
        return '<span class="' + cls + '"><i class="fa-solid ' + icon + '"></i> ' + escapeHtml(label) + '</span>';
    }

    function setText(id, value) {
        var el = document.getElementById(id);
        if (el) el.textContent = String(value);
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
    goToPage("dashboard");
})();
