// API Base URL
const API_BASE = 'http://127.0.0.1:5000';

// Check auth token
const token = localStorage.getItem('soc_token');
if (!token) {
    window.location.href = 'login.html';
}

const authHeaders = {
    'Authorization': `Bearer ${token}`
};

// Initialize Socket.IO
const socket = io(API_BASE);

// Initialize Lucide icons
lucide.createIcons();

// Global State
let loginChartInstance = null;
let mapInstance = null;
let heatLayer = null;
let currentSearch = '';
let currentEventType = 'all';
let markers = []; 
let geoPoints = []; // For heatmap

// DOM Elements
const elements = {
    totalLogs: document.getElementById('totalLogsCount'),
    totalAlerts: document.getElementById('totalAlertsCount'),
    criticalAlerts: document.getElementById('criticalAlertsCount'),
    logsTableBody: document.getElementById('logsTableBody'),
    irTableBody: document.getElementById('irTableBody'),
    topIpsBody: document.getElementById('topIpsBody'),
    topCountriesBody: document.getElementById('topCountriesBody'),
    searchInput: document.getElementById('searchInput'),
    eventTypeFilter: document.getElementById('eventTypeFilter'),
    timeRangeFilter: document.getElementById('timeRangeFilter')
};

// --- Initialization ---
async function init() {
    const username = localStorage.getItem('soc_username');
    const role = localStorage.getItem('soc_role') || 'viewer';
    
    if (username) {
        document.querySelector('.user-name').textContent = username;
        document.querySelector('.avatar').textContent = username.charAt(0).toUpperCase();
        document.querySelector('.user-role').textContent = role.charAt(0).toUpperCase() + role.slice(1);
    }

    applyRBAC(role);
    initMap();
    initChart();
    
    // Initial fetch
    fetchStats();
    fetchAlerts();
    fetchLogs();
    fetchLogsForChart();
}

function applyRBAC(role) {
    if (role !== 'admin') {
        document.querySelectorAll('.rbac-admin').forEach(el => el.style.display = 'none');
    }
    if (role === 'viewer') {
        document.querySelectorAll('.rbac-analyst').forEach(el => el.style.display = 'none');
    }
}

// --- Tab & Modal Management ---
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    
    document.getElementById(`${tabId}-tab`).classList.add('active');
    document.querySelector(`a[href="#${tabId}"]`).classList.add('active');
    
    if(tabId === 'analytics') fetchAnalytics();
    if(tabId === 'incident-response') fetchAlerts();
}

function openModal(modalId) { document.getElementById(modalId).classList.add('active'); }
function closeModal(modalId) { document.getElementById(modalId).classList.remove('active'); }

// --- Map Initialization ---
function initMap() {
    mapInstance = L.map('worldMap').setView([20, 0], 2);
    
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors',
        className: 'map-tiles'
    }).addTo(mapInstance);
}

function updateHeatmap() {
    if (heatLayer) mapInstance.removeLayer(heatLayer);
    heatLayer = L.heatLayer(geoPoints, {radius: 20, blur: 15, maxZoom: 10}).addTo(mapInstance);
}

// --- API Calls ---

async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/stats`, { headers: authHeaders });
        if (response.status === 401) return handleUnauthorized();
        const data = await response.json();
        
        elements.totalLogs.textContent = data.total_logs;
        elements.totalAlerts.textContent = data.total_alerts;
        elements.criticalAlerts.textContent = data.critical_alerts;
        
        if (data.critical_alerts > 0) {
            elements.criticalAlerts.parentElement.parentElement.classList.add('pulse');
            setTimeout(() => elements.criticalAlerts.parentElement.parentElement.classList.remove('pulse'), 1000);
        }
    } catch (error) { console.error('Error fetching stats:', error); }
}

async function fetchAlerts() {
    try {
        const response = await fetch(`${API_BASE}/alerts`, { headers: authHeaders });
        if (response.status === 401) return handleUnauthorized();
        const alerts = await response.json();
        
        elements.irTableBody.innerHTML = '';
        if (alerts.length === 0) {
            elements.irTableBody.innerHTML = '<tr><td colspan="7" style="text-align:center;">No alerts detected.</td></tr>';
            return;
        }

        alerts.forEach(alert => {
            const tr = document.createElement('tr');
            let mitreHtml = alert.mitre_technique_id ? `<span class="mitre-tag">${alert.mitre_technique_id}</span>` : '';
            let severityClass = `badge badge-${alert.severity === 'critical' ? 'danger' : alert.severity === 'high' ? 'warning' : 'info'}`;
            
            tr.innerHTML = `
                <td><span style="color: var(--text-muted); font-size: 0.85rem;">${formatTime(alert.timestamp)}</span></td>
                <td><span class="${severityClass}">${alert.severity}</span></td>
                <td>${mitreHtml} ${alert.rule_triggered}</td>
                <td>${alert.description}</td>
                <td><span class="badge ${alert.status === 'resolved' ? 'badge-success' : 'badge-danger'}">${alert.status}</span></td>
                <td>${alert.assignee_name || 'Unassigned'}</td>
                <td class="action-buttons">
                    ${alert.status !== 'resolved' ? `<button class="glass-btn btn-sm btn-success rbac-analyst" onclick="openResolveModal(${alert.id})"><i data-lucide="check-circle" style="width:14px;"></i></button>` : ''}
                </td>
            `;
            elements.irTableBody.appendChild(tr);
        });
        
        applyRBAC(localStorage.getItem('soc_role') || 'viewer');
        lucide.createIcons();
    } catch (error) { console.error('Error fetching alerts:', error); }
}

async function fetchLogs() {
    try {
        let url = `${API_BASE}/logs?`;
        if (currentEventType !== 'all') url += `event_type=${currentEventType}&`;
        if (currentSearch) url += `search=${currentSearch}`;

        const response = await fetch(url, { headers: authHeaders });
        if (response.status === 401) return handleUnauthorized();
        const logs = await response.json();
        
        elements.logsTableBody.innerHTML = '';
        geoPoints = [];

        if (logs.length === 0) {
            elements.logsTableBody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No logs found.</td></tr>';
            return;
        }

        logs.forEach(log => {
            if (log.latitude && log.longitude) {
                let intensity = log.risk_score > 50 ? 1.0 : 0.5;
                geoPoints.push([log.latitude, log.longitude, intensity]);
            }

            const tr = document.createElement('tr');
            let riskClass = 'risk-low';
            if (log.risk_score > 75) riskClass = 'risk-high';
            else if (log.risk_score > 40) riskClass = 'risk-med';
            
            let tagsHtml = log.threat_tags ? `<span class="threat-tag">${log.threat_tags}</span>` : '';

            tr.innerHTML = `
                <td><span style="color: var(--text-muted); font-size: 0.85rem;">${formatDate(log.timestamp)}</span></td>
                <td><span class="ip-mono">${log.ip_address}</span></td>
                <td><span class="badge ${getEventBadgeClass(log.event_type)}">${formatEventName(log.event_type)}</span></td>
                <td class="${riskClass}">${log.risk_score || 0} / 100</td>
                <td>${tagsHtml}</td>
                <td>${log.description} <br><small style="color:var(--text-muted)">${log.city || 'Unknown'}, ${log.country || 'Unknown'}</small></td>
            `;
            elements.logsTableBody.appendChild(tr);
        });
        
        updateHeatmap();
    } catch (error) { console.error('Error fetching logs:', error); }
}

async function fetchAnalytics() {
    try {
        const response = await fetch(`${API_BASE}/analytics`, { headers: authHeaders });
        if (response.status === 401) return handleUnauthorized();
        const data = await response.json();
        
        elements.topIpsBody.innerHTML = '';
        data.top_ips.forEach(ip => {
            elements.topIpsBody.innerHTML += `<tr><td><span class="ip-mono">${ip.ip}</span></td><td>${ip.count}</td></tr>`;
        });
        
        elements.topCountriesBody.innerHTML = '';
        data.countries.forEach(c => {
            elements.topCountriesBody.innerHTML += `<tr><td>${c.country}</td><td>${c.count}</td></tr>`;
        });
    } catch (e) { console.error(e); }
}

async function fetchLogsForChart() {
    try {
        const response = await fetch(`${API_BASE}/logs`, { headers: authHeaders });
        if (response.status === 401) return handleUnauthorized();
        const logs = await response.json();
        
        const loginLogs = logs.filter(l => l.event_type === 'successful_login' || l.event_type === 'failed_login').reverse();
        
        const timeData = {};
        loginLogs.forEach(log => {
            const timeKey = formatTime(log.timestamp).substring(0, 5);
            if (!timeData[timeKey]) timeData[timeKey] = { success: 0, failed: 0 };
            if (log.event_type === 'successful_login') timeData[timeKey].success++;
            if (log.event_type === 'failed_login') timeData[timeKey].failed++;
        });

        const labels = Object.keys(timeData).slice(-15);
        const successData = labels.map(l => timeData[l].success);
        const failedData = labels.map(l => timeData[l].failed);

        updateChart(labels, successData, failedData);
    } catch (error) { console.error('Error fetching logs for chart:', error); }
}

// --- Action Functions ---

async function uploadLogs() {
    const fileInput = document.getElementById('logFileInput');
    if (!fileInput.files.length) return alert('Select a file first');
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    try {
        const res = await fetch(`${API_BASE}/logs/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` }, // Note: no Content-Type for FormData
            body: formData
        });
        if(res.ok) {
            alert('Logs uploaded successfully!');
            closeModal('uploadModal');
            fetchLogs();
            fetchStats();
        } else {
            alert('Upload failed');
        }
    } catch (e) { console.error(e); }
}

async function triggerSimulation() {
    const attackType = document.getElementById('attackTypeSelect').value;
    try {
        const res = await fetch(`${API_BASE}/simulate`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ attack_type: attackType })
        });
        if(res.ok) {
            alert('Simulation started!');
            closeModal('simulateModal');
        }
    } catch (e) { console.error(e); }
}

function openResolveModal(id) {
    document.getElementById('resolveAlertId').value = id;
    document.getElementById('resolveNotes').value = '';
    openModal('resolveModal');
}

async function submitResolve() {
    const id = document.getElementById('resolveAlertId').value;
    const notes = document.getElementById('resolveNotes').value;
    try {
        const res = await fetch(`${API_BASE}/alerts/${id}`, {
            method: 'PUT',
            headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'resolved', notes: notes })
        });
        if(res.ok) {
            closeModal('resolveModal');
            fetchAlerts();
            fetchStats();
        }
    } catch (e) { console.error(e); }
}

// --- WebSockets ---
socket.on('new_log', (log) => {
    fetchStats();
    
    if ((currentEventType === 'all' || log.event_type === currentEventType) &&
        (!currentSearch || log.ip_address.includes(currentSearch) || log.description.includes(currentSearch))) {
        
        let riskClass = log.risk_score > 75 ? 'risk-high' : log.risk_score > 40 ? 'risk-med' : 'risk-low';
        let tagsHtml = log.threat_tags ? `<span class="threat-tag">${log.threat_tags}</span>` : '';
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span style="color: var(--text-muted); font-size: 0.85rem;">${formatDate(log.timestamp)}</span></td>
            <td><span class="ip-mono">${log.ip_address}</span></td>
            <td><span class="badge ${getEventBadgeClass(log.event_type)}">${formatEventName(log.event_type)}</span></td>
            <td class="${riskClass}">${log.risk_score || 0} / 100</td>
            <td>${tagsHtml}</td>
            <td>${log.description} <br><small style="color:var(--text-muted)">${log.city || 'Unknown'}, ${log.country || 'Unknown'}</small></td>
        `;
        
        if (elements.logsTableBody.firstChild && elements.logsTableBody.firstChild.textContent.includes('No logs found')) {
            elements.logsTableBody.innerHTML = '';
        }
        elements.logsTableBody.prepend(tr);
        if (elements.logsTableBody.children.length > 100) elements.logsTableBody.removeChild(elements.logsTableBody.lastChild);
    }
    
    if (log.latitude && log.longitude) {
        geoPoints.push([log.latitude, log.longitude, log.risk_score > 50 ? 1.0 : 0.5]);
        if(geoPoints.length > 500) geoPoints.shift();
        updateHeatmap();
    }
    
    fetchLogsForChart();
});

socket.on('new_alert', (alert) => {
    fetchStats();
    if(document.getElementById('incident-response-tab').classList.contains('active')) {
        fetchAlerts();
    } else {
        // Just show a small notification if you want, or let it passively update
    }
});

// --- Utilities ---
elements.searchInput.addEventListener('input', (e) => { currentSearch = e.target.value; fetchLogs(); });
elements.eventTypeFilter.addEventListener('change', (e) => { currentEventType = e.target.value; fetchLogs(); });

function formatTime(isoString) { return new Date(isoString).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
function formatDate(isoString) { return new Date(isoString).toLocaleString(); }
function getEventBadgeClass(eventType) {
    switch(eventType) {
        case 'successful_login': return 'badge-success';
        case 'failed_login': return 'badge-danger';
        case 'system_start': return 'badge-info';
        case 'config_change': return 'badge-warning';
        default: return 'badge-info';
    }
}
function formatEventName(eventType) { return eventType.split('_').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' '); }

function initChart() {
    const ctx = document.getElementById('loginChart').getContext('2d');
    Chart.defaults.color = '#94A3B8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    loginChartInstance = new Chart(ctx, {
        type: 'line',
        data: { labels: [], datasets: [
            { label: 'Failed Logins', data: [], borderColor: '#EF4444', backgroundColor: 'rgba(239, 68, 68, 0.1)', borderWidth: 2, tension: 0.4, fill: true },
            { label: 'Successful Logins', data: [], borderColor: '#10B981', backgroundColor: 'rgba(16, 185, 129, 0.05)', borderWidth: 2, tension: 0.4, fill: true }
        ]},
        options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true, ticks: { stepSize: 1 } } } }
    });
}
function updateChart(labels, successData, failedData) {
    if (!loginChartInstance) initChart();
    loginChartInstance.data.labels = labels;
    loginChartInstance.data.datasets[0].data = failedData;
    loginChartInstance.data.datasets[1].data = successData;
    loginChartInstance.update('none');
}

function handleUnauthorized() {
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_username');
    localStorage.removeItem('soc_role');
    window.location.href = 'login.html';
}

if (document.getElementById('logoutBtn')) {
    document.getElementById('logoutBtn').addEventListener('click', () => handleUnauthorized());
}

// Start app
init();
