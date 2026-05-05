// API Base URL
const API_BASE = window.location.origin;

// Check auth token
const token = localStorage.getItem('soc_token');
if (!token) {
    window.location.href = 'login.html';
}

const authHeaders = {
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json'
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
let currentIncidentId = null;
let geoPoints = [];

// DOM Elements
const elements = {
    totalLogs: document.getElementById('totalLogsCount'),
    totalAlerts: document.getElementById('totalAlertsCount'),
    criticalAlerts: document.getElementById('criticalAlertsCount'),
    logsTableBody: document.getElementById('logsTableBody'),
    incidentsTableBody: document.getElementById('incidentsTableBody'),
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
        document.querySelectorAll('.user-name').forEach(el => el.textContent = username);
        document.querySelectorAll('.avatar').forEach(el => el.textContent = username.charAt(0).toUpperCase());
        document.querySelectorAll('.user-role').forEach(el => el.textContent = role.charAt(0).toUpperCase() + role.slice(1));
    }

    applyRBAC(role);
    initMap();
    initChart();
    
    // Initial fetch
    fetchStats();
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
    document.querySelectorAll('.tab-content').forEach(tab => tab.style.display = 'none');
    document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
    
    document.getElementById(`${tabId}-tab`).style.display = 'block';
    document.querySelector(`a[href="#${tabId}"]`).classList.add('active');
    
    if(tabId === 'analytics') fetchAnalytics();
    if(tabId === 'incident-response') fetchIncidents();
}

function openModal(modalId) { document.getElementById(modalId).classList.add('active'); }
function closeModal(modalId) { document.getElementById(modalId).classList.remove('active'); }

// --- Map Initialization ---
function initMap() {
    mapInstance = L.map('worldMap').setView([20, 0], 2);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '© OpenStreetMap contributors'
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
    } catch (e) { console.error(e); }
}

async function fetchIncidents() {
    try {
        const status = document.getElementById('incidentStatusFilter').value;
        const response = await fetch(`${API_BASE}/incidents?status=${status}`, { headers: authHeaders });
        const incidents = await response.json();
        
        elements.incidentsTableBody.innerHTML = '';
        incidents.forEach(inc => {
            const tr = document.createElement('tr');
            let severityClass = `badge badge-${inc.severity === 'critical' ? 'danger' : inc.severity === 'high' ? 'warning' : 'info'}`;
            let statusClass = inc.status === 'resolved' ? 'badge-success' : inc.status === 'in_progress' ? 'badge-warning' : 'badge-danger';
            
            tr.innerHTML = `
                <td>#${inc.id}</td>
                <td><small>${formatTime(inc.created_at)}</small></td>
                <td><strong>${inc.alert_type}</strong></td>
                <td><code class="ip-mono">${inc.source_ip}</code></td>
                <td><span class="${severityClass}">${inc.severity}</span></td>
                <td><span class="badge ${statusClass}">${inc.status.replace('_', ' ')}</span></td>
                <td>${inc.assignee_name}</td>
                <td class="action-buttons">
                    <button class="glass-btn btn-sm" onclick="viewIncidentDetail(${inc.id})"><i data-lucide="eye" style="width:14px;"></i> Details</button>
                    ${inc.status === 'open' ? `<button class="glass-btn btn-sm btn-success" onclick="assignIncident(${inc.id})">Assign</button>` : ''}
                </td>
            `;
            elements.incidentsTableBody.appendChild(tr);
        });
        lucide.createIcons();
    } catch (e) { console.error(e); }
}

async function viewIncidentDetail(id) {
    currentIncidentId = id;
    const res = await fetch(`${API_BASE}/incidents`, { headers: authHeaders });
    const incidents = await res.json();
    const inc = incidents.find(i => i.id === id);
    
    const content = document.getElementById('incidentDetailContent');
    content.innerHTML = `
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
            <div><strong>Status:</strong> ${inc.status}</div>
            <div><strong>Severity:</strong> ${inc.severity}</div>
            <div><strong>Created:</strong> ${formatDate(inc.created_at)}</div>
            <div><strong>Updated:</strong> ${formatDate(inc.updated_at)}</div>
        </div>
        <div class="timeline">
            <div class="timeline-item">
                <div class="timeline-marker"></div>
                <div class="timeline-content">
                    <h4>Incident Opened</h4>
                    <p>${formatTime(inc.created_at)}</p>
                </div>
            </div>
            ${inc.status !== 'open' ? `<div class="timeline-item">
                <div class="timeline-marker" style="background:var(--accent-blue)"></div>
                <div class="timeline-content"><h4>Assigned to ${inc.assignee_name}</h4></div>
            </div>` : ''}
            ${inc.status === 'resolved' ? `<div class="timeline-item">
                <div class="timeline-marker" style="background:var(--color-success)"></div>
                <div class="timeline-content"><h4>Resolved</h4><p>${formatTime(inc.resolved_at)}</p></div>
            </div>` : ''}
        </div>
    `;

    const notesList = document.getElementById('incidentNotesList');
    notesList.innerHTML = inc.notes.map(n => `
        <div style="background:rgba(255,255,255,0.03); padding:10px; border-radius:8px; margin-bottom:8px; border-left: 3px solid var(--accent-blue);">
            <div style="font-size:0.8rem; color:var(--text-muted); margin-bottom:4px;">${n.author_name} - ${formatTime(n.timestamp)}</div>
            <div>${n.content}</div>
        </div>
    `).join('') || '<p style="color:var(--text-muted)">No investigation notes yet.</p>';

    document.getElementById('resolveBtnModal').style.display = inc.status === 'resolved' ? 'none' : 'block';
    openModal('incidentDetailModal');
}

async function assignIncident(id) {
    await fetch(`${API_BASE}/incidents/${id}/assign`, { method: 'POST', headers: authHeaders });
    fetchIncidents();
}

async function resolveIncidentAction() {
    await fetch(`${API_BASE}/incidents/${currentIncidentId}/resolve`, { method: 'POST', headers: authHeaders });
    closeModal('incidentDetailModal');
    fetchIncidents();
}

async function submitIncidentNote() {
    const content = document.getElementById('newIncidentNote').value;
    if(!content) return;
    await fetch(`${API_BASE}/incidents/${currentIncidentId}/notes`, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ content })
    });
    document.getElementById('newIncidentNote').value = '';
    viewIncidentDetail(currentIncidentId);
}

async function fetchLogs() {
    try {
        let url = `${API_BASE}/logs?`;
        if (currentEventType !== 'all') url += `event_type=${currentEventType}&`;
        if (currentSearch) url += `search=${currentSearch}`;

        const response = await fetch(url, { headers: authHeaders });
        const logs = await response.json();
        elements.logsTableBody.innerHTML = '';
        logs.forEach(log => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><small>${formatDate(log.timestamp)}</small></td>
                <td><code class="ip-mono">${log.ip_address}</code></td>
                <td><span class="badge ${getEventBadgeClass(log.event_type)}">${log.event_type}</span></td>
                <td>${log.risk_score}</td>
                <td>${log.threat_tags || ''}</td>
                <td>${log.description}</td>
            `;
            elements.logsTableBody.appendChild(tr);
        });
    } catch (e) { console.error(e); }
}

async function fetchAnalytics() {
    const res = await fetch(`${API_BASE}/analytics`, { headers: authHeaders });
    const data = await res.json();
    elements.topIpsBody.innerHTML = data.top_ips.map(ip => `<tr><td>${ip.ip}</td><td>${ip.count}</td></tr>`).join('');
    elements.topCountriesBody.innerHTML = data.countries.map(c => `<tr><td>${c.country}</td><td>${c.count}</td></tr>`).join('');
}

async function triggerSimulation() {
    const attackType = document.getElementById('attackTypeSelect').value;
    try {
        const res = await fetch(`${API_BASE}/simulate`, {
            method: 'POST',
            headers: authHeaders,
            body: JSON.stringify({ attack_type: attackType })
        });
        if(res.ok) {
            alert('Simulation started successfully!');
            closeModal('simulateModal');
        } else {
            alert('Simulation failed to start. Check backend logs.');
        }
    } catch (e) { 
        console.error(e); 
        alert('Network error when triggering simulation.');
    }
}

async function uploadLogs() {
    const fileInput = document.getElementById('logFileInput');
    if (!fileInput.files.length) return alert('Select a file first');
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    try {
        const res = await fetch(`${API_BASE}/logs/upload`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${token}` },
            body: formData
        });
        if(res.ok) {
            alert('Logs uploaded successfully!');
            closeModal('uploadModal');
            fetchLogs();
        }
    } catch (e) { console.error(e); }
}

function handleUnauthorized() {
    localStorage.clear();
    window.location.href = 'login.html';
}

function formatTime(iso) { return new Date(iso).toLocaleTimeString(); }
function formatDate(iso) { return new Date(iso).toLocaleString(); }
function getEventBadgeClass(type) { return type.includes('fail') ? 'badge-danger' : 'badge-info'; }

document.getElementById('logoutBtn').addEventListener('click', handleUnauthorized);

// Socket.IO Events
socket.on('new_log', (log) => {
    fetchStats();
    fetchLogs();
});

socket.on('new_alert', (alert) => {
    fetchStats();
    fetchIncidents();
});

init();
