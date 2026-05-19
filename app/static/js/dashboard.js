/* ─────────────────────────────────────────────────────────────
   SentinelBM Dashboard — dashboard.js
   Real-time IDS frontend powered by Socket.IO + REST polling
───────────────────────────────────────────────────────────── */

'use strict';

// ── STATE ───────────────────────────────────────────────────────
const state = {
    alerts: [],          // full alert history (newest-first)
    filtered: [],        // view-filtered subset
    activeFilter: 'all',
    signatures: {},      // { name: pattern }
    metrics: {},
    rowCounter: 0,
    socket: null,
};

// ── ATTACK-TYPE → CSS CLASS MAPPING ────────────────────────────
const TYPE_CLASS = {
    'SQL Injection':               'type-sqli',
    'Cross-Site Scripting (XSS)': 'type-xss',
    'Path Traversal':             'type-path',
    'Command Injection':          'type-cmd',
};
const TYPE_COLOR = {
    'SQL Injection':               '#f87171',
    'Cross-Site Scripting (XSS)': '#fbbf24',
    'Path Traversal':             '#c084fc',
    'Command Injection':          '#4ade80',
};

// ── DOM REFS ────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const DOM = {
    connDot:       $('conn-dot'),
    connLabel:     $('conn-label'),
    navThreats:    $('nav-threats'),
    navLogs:       $('nav-logs'),
    kpiThreats:    $('kpi-threats'),
    kpiLogs:       $('kpi-logs'),
    kpiRate:       $('kpi-rate'),
    kpiSigs:       $('kpi-sigs'),
    badgeTotal:    $('badge-total'),
    breakdownList: $('breakdown-list'),
    sigList:       $('sig-list'),
    sigForm:       $('sig-form'),
    sigName:       $('sig-name'),
    sigPattern:    $('sig-pattern'),
    statComp:      $('stat-comparisons'),
    statSkip:      $('stat-skipped'),
    statExec:      $('stat-exec'),
    statEff:       $('stat-efficiency'),
    alertTbody:    $('alert-tbody'),
    emptyRow:      $('empty-row'),
    toastCont:     $('toast-container'),
    btnAddSig:     $('btn-add-sig'),
    btnCancelSig:  $('btn-cancel-sig'),
    btnSaveSig:    $('btn-save-sig'),
    btnClear:      $('btn-clear'),
};

// ── SOCKET.IO ───────────────────────────────────────────────────
function initSocket() {
    const socket = io({ transports: ['websocket', 'polling'] });
    state.socket = socket;

    socket.on('connect', () => {
        setConnectionState(true);
        toast('Connected to SentinelBM engine', 'info');
    });

    socket.on('disconnect', () => {
        setConnectionState(false);
        toast('Connection lost — retrying…', 'danger');
    });

    socket.on('new_alert', alert => {
        state.alerts.unshift(alert);
        applyFilter();
        updateBreakdown();
        updateKPIs();
        prependRow(alert, true);
        toast(`🚨 ${alert.attack_type} from ${alert.source_ip}`, 'danger');
    });
}

function setConnectionState(online) {
    DOM.connDot.className   = 'status-dot ' + (online ? 'online' : 'offline');
    DOM.connLabel.textContent = online ? 'Engine Online' : 'Disconnected';
}

// ── REST POLLING ─────────────────────────────────────────────── 
async function fetchAlerts() {
    try {
        const res  = await fetch('/api/v1/alerts?per_page=100');
        const data = await res.json();
        state.alerts = data.alerts;
        applyFilter();
        updateBreakdown();
        updateKPIs();
        rebuildTable();
    } catch (e) {
        console.warn('Alert fetch failed', e);
    }
}

async function fetchMetrics() {
    try {
        const res  = await fetch('/api/v1/metrics');
        const data = await res.json();
        state.metrics = data.metrics;
        updateEngineStats(data);
    } catch (e) {
        console.warn('Metrics fetch failed', e);
    }
}

// Initial signatures come from meta tags won't work here —
// so we seed from the DOM after the first metrics call.
// Signatures are tracked locally after user edits.
const INITIAL_SIGS = {
    'SQL Injection':               'UNION SELECT',
    'Cross-Site Scripting (XSS)': "<script>alert",
    'Path Traversal':             '../../../../etc/passwd',
    'Command Injection':          '; rm -rf /',
};

function seedSignatures() {
    state.signatures = { ...INITIAL_SIGS };
    renderSigList();
}

// ── UPDATE FUNCTIONS ────────────────────────────────────────────
function updateKPIs() {
    const threats = state.metrics.total_threats_detected ?? state.alerts.length;
    const logs    = state.metrics.total_logs_processed   ?? 0;
    const rate    = logs ? ((threats / logs) * 100).toFixed(1) + '%' : '0%';
    const sigs    = Object.keys(state.signatures).length;

    DOM.kpiThreats.textContent  = fmt(threats);
    DOM.kpiLogs.textContent     = fmt(logs);
    DOM.kpiRate.textContent     = rate;
    DOM.kpiSigs.textContent     = sigs;
    DOM.navThreats.textContent  = fmt(threats);
    DOM.navLogs.textContent     = fmt(logs);
}

function updateEngineStats(data) {
    const m = data.metrics;
    DOM.statComp.textContent = fmt(m.total_comparisons ?? 0);
    DOM.statSkip.textContent = fmt(m.total_characters_skipped ?? 0);
    DOM.statExec.textContent = (m.total_execution_time_ms ?? 0).toFixed(2) + ' ms';

    const comp = m.total_comparisons ?? 0;
    const skip = m.total_characters_skipped ?? 0;
    const eff  = comp ? ((skip / (comp + skip)) * 100).toFixed(1) + '%' : '—';
    DOM.statEff.textContent  = eff;

    DOM.kpiSigs.textContent = data.active_signatures_count ?? Object.keys(state.signatures).length;
}

function updateBreakdown() {
    const counts = {};
    for (const a of state.alerts) {
        counts[a.attack_type] = (counts[a.attack_type] ?? 0) + 1;
    }
    const total = state.alerts.length;
    DOM.badgeTotal.textContent = `${total} detected`;

    if (total === 0) {
        DOM.breakdownList.innerHTML = '<li class="breakdown-empty">No threats detected yet</li>';
        return;
    }

    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    DOM.breakdownList.innerHTML = sorted.map(([type, count]) => {
        const pct   = total ? ((count / total) * 100).toFixed(0) : 0;
        const cls   = TYPE_CLASS[type] ?? 'type-unknown';
        const color = TYPE_COLOR[type] ?? '#94a3b8';
        return `
        <li class="breakdown-item">
            <span class="breakdown-label">
                <span class="breakdown-dot" style="background:${color}"></span>
                ${esc(type)}
            </span>
            <span class="breakdown-count">${count}</span>
        </li>
        <div class="breakdown-bar">
            <div class="breakdown-bar-fill" style="width:${pct}%;background:${color}"></div>
        </div>`;
    }).join('');
}

// ── SIGNATURE RENDERING ─────────────────────────────────────────
function renderSigList() {
    const entries = Object.entries(state.signatures);
    if (entries.length === 0) {
        DOM.sigList.innerHTML = '<li class="breakdown-empty">No signatures loaded</li>';
        return;
    }
    DOM.sigList.innerHTML = entries.map(([name, pattern]) => `
        <li class="sig-item">
            <span class="sig-name">${esc(name)}</span>
            <span class="sig-pattern" title="${esc(pattern)}">${esc(pattern)}</span>
        </li>`).join('');
    updateKPIs();
}

// ── TABLE ───────────────────────────────────────────────────────
function applyFilter() {
    if (state.activeFilter === 'all') {
        state.filtered = state.alerts;
    } else {
        state.filtered = state.alerts.filter(a => a.attack_type === state.activeFilter);
    }
}

function rebuildTable() {
    DOM.alertTbody.innerHTML = '';
    if (state.filtered.length === 0) {
        DOM.alertTbody.appendChild(DOM.emptyRow);
        return;
    }
    state.rowCounter = state.filtered.length;
    state.filtered.forEach((alert, idx) => prependRow(alert, false, state.filtered.length - idx));
}

function prependRow(alert, animate = false, num = null) {
    // Remove empty state row
    if (DOM.emptyRow.parentNode === DOM.alertTbody) {
        DOM.alertTbody.removeChild(DOM.emptyRow);
    }

    if (num === null) {
        state.rowCounter++;
        num = state.rowCounter;
    }

    const cls  = TYPE_CLASS[alert.attack_type] ?? 'type-unknown';
    const time = new Date(alert.timestamp).toLocaleTimeString('en-IN', { hour12: false });
    const date = new Date(alert.timestamp).toLocaleDateString('en-IN', { day:'2-digit', month:'short' });

    const tr = document.createElement('tr');
    if (animate) tr.style.animation = 'rowSlide .35s ease both';

    tr.innerHTML = `
        <td>${num}</td>
        <td class="td-time">${date}<br><span style="color:var(--text-muted)">${time}</span></td>
        <td><span class="attack-badge ${cls}">${esc(alert.attack_type)}</span></td>
        <td class="td-ip">${esc(alert.source_ip)}</td>
        <td class="td-log" title="${esc(alert.raw_log)}">${esc(alert.raw_log)}</td>
    `;

    if (animate) {
        DOM.alertTbody.insertBefore(tr, DOM.alertTbody.firstChild);
    } else {
        DOM.alertTbody.appendChild(tr);
    }
}

// ── FILTER CHIPS ────────────────────────────────────────────────
document.querySelectorAll('.filter-chip').forEach(chip => {
    chip.addEventListener('click', () => {
        document.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
        state.activeFilter = chip.dataset.filter;
        applyFilter();
        rebuildTable();
    });
});

// ── SIG FORM ────────────────────────────────────────────────────
DOM.btnAddSig.addEventListener('click', () => {
    DOM.sigForm.classList.toggle('hidden');
    if (!DOM.sigForm.classList.contains('hidden')) DOM.sigName.focus();
});

DOM.btnCancelSig.addEventListener('click', () => {
    DOM.sigForm.classList.add('hidden');
    DOM.sigName.value = '';
    DOM.sigPattern.value = '';
});

DOM.btnSaveSig.addEventListener('click', async () => {
    const name    = DOM.sigName.value.trim();
    const pattern = DOM.sigPattern.value.trim();

    if (!name || !pattern) {
        toast('Please fill in both name and pattern', 'danger');
        return;
    }

    const newSigs = { ...state.signatures, [name]: pattern };

    try {
        const res = await fetch('/api/v1/signatures', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(newSigs),
        });

        if (res.ok) {
            state.signatures = newSigs;
            renderSigList();
            DOM.sigForm.classList.add('hidden');
            DOM.sigName.value = '';
            DOM.sigPattern.value = '';
            toast(`Signature "${name}" deployed ✓`, 'success');
        } else {
            toast('Server rejected signature update', 'danger');
        }
    } catch (e) {
        toast('Network error — could not deploy signature', 'danger');
    }
});

// ── CLEAR FEED ──────────────────────────────────────────────────
DOM.btnClear.addEventListener('click', () => {
    state.alerts  = [];
    state.filtered = [];
    state.rowCounter = 0;
    DOM.alertTbody.innerHTML = '';
    DOM.alertTbody.appendChild(DOM.emptyRow);
    updateBreakdown();
});

// ── TOAST ────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
    const icons = { danger: '🚨', success: '✅', info: 'ℹ️' };
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.innerHTML = `
        <span class="toast-icon">${icons[type] ?? 'ℹ️'}</span>
        <span class="toast-msg">${esc(msg)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
    `;
    DOM.toastCont.appendChild(el);
    setTimeout(() => {
        el.style.animation = 'toastOut .3s ease forwards';
        setTimeout(() => el.remove(), 300);
    }, 4000);
}

// ── UTILITY ──────────────────────────────────────────────────────
function esc(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function fmt(n) {
    return Number(n).toLocaleString('en-IN');
}

// ── BOOT ─────────────────────────────────────────────────────────
(async function init() {
    seedSignatures();
    await fetchAlerts();
    await fetchMetrics();
    initSocket();

    // Poll metrics every 3 seconds
    setInterval(fetchMetrics, 3000);
})();
