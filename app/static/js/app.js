/**
 * NIGHTWATCH — Application Frontend State and Controller
 * Title: NIGHTWATCH — Lightweight Security Intelligence Platform
 */

const NW = {
  activeTab: 'dashboard',
  currentSearchResults: null,
  currentViewMode: 'table', // 'table' or 'raw'
  apiBase: '',

  init() {
    this.setupNavigation();
    this.setupSearchEvents();
    this.setupModalEvents();
    this.loadDashboard();
    this.pollStatus();
  },

  // Navigation Controller
  setupNavigation() {
    document.querySelectorAll('.nw-nav-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const tab = btn.dataset.tab;
        this.switchTab(tab);
      });
    });
  },

  switchTab(tab) {
    this.activeTab = tab;
    document.querySelectorAll('.nw-nav-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
    document.querySelectorAll('.nw-view').forEach(v => v.classList.toggle('active', v.id === `view-${tab}`));

    if (tab === 'dashboard') this.loadDashboard();
    else if (tab === 'search') this.focusSearch();
    else if (tab === 'alerts') this.loadAlerts();
    else if (tab === 'inputs') this.loadInputs();
    else if (tab === 'saved_searches') this.loadSavedSearches();
    else if (tab === 'health') this.loadHealth();
  },

  showToast(message, type = 'info') {
    const container = document.getElementById('nw-toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'nw-toast';
    const icon = type === 'error' ? '❌' : (type === 'success' ? '✅' : 'ℹ️');
    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  },

  // 1. Dashboard View
  async loadDashboard() {
    try {
      const res = await fetch('/api/system/health');
      if (!res.ok) return;
      const data = await res.json();

      // Update KPI metrics
      document.getElementById('kpi-total-events').innerText = (data.database.total_events || 0).toLocaleString();
      document.getElementById('kpi-active-alerts').innerText = (data.alerts.total_alerts || 0).toLocaleString();
      document.getElementById('kpi-db-size').innerText = `${data.database.db_size_mb} MB`;
      document.getElementById('kpi-process-ram').innerText = `${data.application.process_rss_mb} MB`;

      // Render Charts
      NightwatchCharts.renderDonutChart('chart-severities', data.database.severity_counts);
      NightwatchCharts.renderDonutChart('chart-sourcetypes', data.database.sourcetype_counts);

      // Load Top Hosts & Top IPs
      this.loadDashboardTopEntities();

      // Load Recent Alerts
      this.loadDashboardRecentAlerts();
    } catch (e) {
      console.error('Error loading dashboard:', e);
    }
  },

  async loadDashboardTopEntities() {
    try {
      const resHosts = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'index=* | top 5 host' })
      });
      if (resHosts.ok) {
        const d = await resHosts.json();
        NightwatchCharts.renderHorizontalBars('chart-top-hosts', d.records, 'host', 'count');
      }

      const resIps = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'index=* | stats count by src_ip | sort - count | head 5' })
      });
      if (resIps.ok) {
        const d = await resIps.json();
        NightwatchCharts.renderHorizontalBars('chart-top-ips', d.records, 'src_ip', 'count');
      }
    } catch (e) {
      console.error(e);
    }
  },

  async loadDashboardRecentAlerts() {
    try {
      const res = await fetch('/api/alerts?limit=5');
      if (!res.ok) return;
      const alerts = await res.json();
      const tbody = document.getElementById('dashboard-alerts-body');
      if (!tbody) return;

      if (alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-dim);padding:20px;">No alerts triggered. System operating normally.</td></tr>';
        return;
      }

      tbody.innerHTML = alerts.map(a => `
        <tr onclick="NW.openAlertModal('${a.id}')">
          <td><span class="badge-sev badge-sev-${a.severity}">${a.severity}</span></td>
          <td style="font-weight:600;color:var(--text-main);">${a.rule_name}</td>
          <td style="color:var(--text-muted);">${a.description}</td>
          <td><span class="badge-status status-${a.status}">${a.status}</span></td>
          <td style="color:var(--text-dim);">${a.triggered_at.substring(11, 19)}</td>
        </tr>
      `).join('');
    } catch (e) {
      console.error(e);
    }
  },

  // 2. Search & Analytics View
  setupSearchEvents() {
    const input = document.getElementById('nw-search-input');
    const btn = document.getElementById('nw-search-submit');
    if (!input || !btn) return;

    btn.addEventListener('click', () => this.runSearch());
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') this.runSearch();
    });

    // View toggle buttons
    document.querySelectorAll('.nw-toggle-btn').forEach(b => {
      b.addEventListener('click', () => {
        document.querySelectorAll('.nw-toggle-btn').forEach(btn => btn.classList.remove('active'));
        b.classList.add('active');
        this.currentViewMode = b.dataset.mode;
        this.renderSearchResults();
      });
    });
  },

  focusSearch() {
    const input = document.getElementById('nw-search-input');
    if (input) input.focus();
    if (!this.currentSearchResults) {
      this.runSearch('*');
    }
    this.loadSidebarFields();
  },

  setQuery(query) {
    const input = document.getElementById('nw-search-input');
    if (input) {
      input.value = query;
      this.switchTab('search');
      this.runSearch();
    }
  },

  async runSearch(customQuery = null) {
    const input = document.getElementById('nw-search-input');
    const query = customQuery !== null ? customQuery : (input ? input.value : '*');
    if (input && customQuery !== null) input.value = customQuery;

    const timeRange = document.getElementById('nw-search-timerange').value;
    let earliestEpoch = null;
    const now = Date.now() / 1000;

    if (timeRange === '15m') earliestEpoch = now - (15 * 60);
    else if (timeRange === '1h') earliestEpoch = now - 3600;
    else if (timeRange === '24h') earliestEpoch = now - 86400;
    else if (timeRange === '7d') earliestEpoch = now - (7 * 86400);

    const statsEl = document.getElementById('nw-search-stats');
    if (statsEl) statsEl.innerText = 'Executing query...';

    try {
      const res = await fetch('/api/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: query || '*',
          earliest_epoch: earliestEpoch,
          limit: 1000
        })
      });

      const data = await res.json();
      if (data.status === 'error') {
        if (statsEl) statsEl.innerHTML = `<span style="color:var(--accent-rose);">Error: ${data.error}</span>`;
        return;
      }

      this.currentSearchResults = data;
      if (statsEl) {
        statsEl.innerText = `${data.result_count.toLocaleString()} events matching in ${data.duration_ms} ms (Scanned ${data.total_scanned.toLocaleString()})`;
      }

      // Render Timeline Histogram
      NightwatchCharts.renderHistogram('nw-search-histogram', data.timeline_buckets);

      // Render Records
      this.renderSearchResults();
      this.loadSidebarFields();
    } catch (e) {
      console.error(e);
      if (statsEl) statsEl.innerText = 'Search failed: ' + e;
    }
  },

  renderSearchResults() {
    const container = document.getElementById('nw-search-results-content');
    if (!container || !this.currentSearchResults) return;

    const data = this.currentSearchResults;
    if (!data.records || data.records.length === 0) {
      container.innerHTML = '<div style="padding:40px;text-align:center;color:var(--text-dim);">No events matched your query criteria.</div>';
      return;
    }

    if (this.currentViewMode === 'table') {
      const cols = data.columns || Object.keys(data.records[0]);
      let ths = cols.map(c => `<th>${c}</th>`).join('');
      let trs = data.records.map(r => {
        let tds = cols.map(c => {
          let val = r[c];
          if (val === undefined || val === null) val = '-';
          if (typeof val === 'object') val = JSON.stringify(val);
          return `<td>${this.escapeHtml(String(val))}</td>`;
        }).join('');
        return `<tr onclick="NW.openEventModal(${r.id || 0})">${tds}</tr>`;
      }).join('');

      container.innerHTML = `
        <table class="nw-table">
          <thead><tr>${ths}</tr></thead>
          <tbody>${trs}</tbody>
        </table>
      `;
    } else {
      // Raw Log View
      let html = '<div class="nw-raw-list">';
      data.records.forEach(r => {
        const raw = r._raw || r.raw || JSON.stringify(r);
        const time = r._time || r.timestamp || '';
        html += `
          <div class="nw-raw-row" onclick="NW.openEventModal(${r.id || 0})">
            <span class="nw-raw-time">${time.substring(0, 19)}</span>
            <span class="nw-raw-text">${this.escapeHtml(raw)}</span>
          </div>
        `;
      });
      html += '</div>';
      container.innerHTML = html;
    }
  },

  async loadSidebarFields() {
    const container = document.getElementById('nw-sidebar-fields');
    if (!container) return;

    try {
      const res = await fetch('/api/events/summary/fields');
      if (!res.ok) return;
      const data = await res.json();

      let html = '<div class="nw-sidebar-title">Discovered Fields</div>';
      data.fields.forEach(f => {
        html += `
          <div class="nw-field-item" onclick="NW.insertFieldToSearch('${f.name}')">
            <span class="nw-field-name">${f.name}</span>
            <span class="nw-field-count">${f.distinct_count}</span>
          </div>
        `;
      });
      container.innerHTML = html;
    } catch (e) {
      console.error(e);
    }
  },

  insertFieldToSearch(fieldName) {
    const input = document.getElementById('nw-search-input');
    if (input) {
      input.value = `${input.value.trim()} | stats count by ${fieldName}`;
      this.runSearch();
    }
  },

  exportSearch(format) {
    const input = document.getElementById('nw-search-input');
    const query = input ? input.value : '*';
    const url = `/api/search/export?query=${encodeURIComponent(query)}&format=${format}`;
    window.open(url, '_blank');
  },

  // 3. Alerts View
  async loadAlerts() {
    try {
      const res = await fetch('/api/alerts');
      if (!res.ok) return;
      const alerts = await res.json();
      const tbody = document.getElementById('alerts-table-body');
      if (!tbody) return;

      if (alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;color:var(--text-dim);">No alerts found.</td></tr>';
        return;
      }

      tbody.innerHTML = alerts.map(a => `
        <tr onclick="NW.openAlertModal('${a.id}')">
          <td><span class="badge-sev badge-sev-${a.severity}">${a.severity}</span></td>
          <td style="font-weight:600;color:var(--text-main);">${a.rule_name}</td>
          <td>${a.description}</td>
          <td><span class="badge-status status-${a.status}">${a.status}</span></td>
          <td style="font-family:monospace;color:var(--accent-cyan);font-weight:600;">${a.event_count}</td>
          <td style="color:var(--text-dim);">${a.triggered_at.substring(0, 19)}</td>
        </tr>
      `).join('');

      this.loadDetectionRulesList();
    } catch (e) {
      console.error(e);
    }
  },

  async loadDetectionRulesList() {
    try {
      const res = await fetch('/api/alerts/rules/list');
      if (!res.ok) return;
      const rules = await res.json();
      const tbody = document.getElementById('rules-table-body');
      if (!tbody) return;

      tbody.innerHTML = rules.map(r => `
        <tr>
          <td><input type="checkbox" ${r.enabled ? 'checked' : ''} onchange="NW.toggleRule('${r.id}', this.checked)"></td>
          <td style="font-weight:600;color:var(--text-main);">${r.name}</td>
          <td><span class="badge-sev badge-sev-${r.severity}">${r.severity}</span></td>
          <td style="font-family:monospace;">${r.rule_type}</td>
          <td style="font-family:monospace;">${r.threshold || '-'}</td>
          <td style="color:var(--text-dim);font-size:12px;">${r.description}</td>
        </tr>
      `).join('');
    } catch (e) {
      console.error(e);
    }
  },

  async toggleRule(ruleId, enabled) {
    try {
      await fetch(`/api/alerts/rules/${ruleId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled })
      });
      this.showToast(`Detection rule updated: ${enabled ? 'Enabled' : 'Disabled'}`, 'success');
    } catch (e) {
      this.showToast('Failed to update rule', 'error');
    }
  },

  async triggerDetectionCycle() {
    try {
      const res = await fetch('/api/alerts/evaluate', { method: 'POST' });
      const d = await res.json();
      this.showToast(`Detection cycle finished: ${d.new_alerts_count} new alerts generated.`, 'success');
      this.loadAlerts();
    } catch (e) {
      this.showToast('Detection evaluation failed', 'error');
    }
  },

  // 4. Inputs View
  async loadInputs() {
    try {
      const res = await fetch('/api/inputs');
      if (!res.ok) return;
      const inputs = await res.json();
      const tbody = document.getElementById('inputs-table-body');
      if (!tbody) return;

      if (inputs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:30px;color:var(--text-dim);">No inputs configured.</td></tr>';
        return;
      }

      tbody.innerHTML = inputs.map(inp => `
        <tr>
          <td style="font-weight:600;color:var(--text-main);">${inp.id}</td>
          <td style="font-family:monospace;color:var(--accent-cyan);">${inp.path}</td>
          <td><span class="badge-status status-investigating">${inp.sourcetype}</span></td>
          <td>${inp.index}</td>
          <td style="font-family:monospace;">${inp.last_read_offset.toLocaleString()} B</td>
          <td style="font-family:monospace;font-weight:600;">${inp.total_events_read.toLocaleString()}</td>
          <td>
            <button class="nw-btn nw-btn-secondary nw-btn-sm" onclick="NW.deleteInput('${inp.id}')">Delete</button>
          </td>
        </tr>
      `).join('');
    } catch (e) {
      console.error(e);
    }
  },

  async triggerCollect() {
    try {
      const res = await fetch('/api/inputs/collect', { method: 'POST' });
      const d = await res.json();
      this.showToast(`Collection completed: ${d.ingested_count} new events ingested.`, 'success');
      this.loadInputs();
    } catch (e) {
      this.showToast('Collection failed', 'error');
    }
  },

  async addLogInputSubmit() {
    const id = document.getElementById('input-add-id').value.trim();
    const path = document.getElementById('input-add-path').value.trim();
    const sourcetype = document.getElementById('input-add-sourcetype').value;
    const index = document.getElementById('input-add-index').value.trim() || 'main';

    if (!id || !path) {
      alert('Please fill out input ID and File Path');
      return;
    }

    try {
      const res = await fetch('/api/inputs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, path, sourcetype, index })
      });
      if (res.ok) {
        this.closeModal('modal-add-input');
        this.showToast('Log input added successfully.', 'success');
        this.loadInputs();
      } else {
        const err = await res.json();
        alert('Error: ' + err.detail);
      }
    } catch (e) {
      alert('Failed to add input: ' + e);
    }
  },

  async deleteInput(inputId) {
    if (!confirm(`Are you sure you want to remove log source '${inputId}'?`)) return;
    try {
      await fetch(`/api/inputs/${inputId}`, { method: 'DELETE' });
      this.showToast('Input removed', 'info');
      this.loadInputs();
    } catch (e) {
      this.showToast('Failed to delete input', 'error');
    }
  },

  // 5. Saved Searches & History
  async loadSavedSearches() {
    try {
      const resSaved = await fetch('/api/saved_searches');
      if (resSaved.ok) {
        const list = await resSaved.json();
        const tbody = document.getElementById('saved-searches-body');
        if (tbody) {
          tbody.innerHTML = list.map(s => `
            <tr>
              <td style="font-weight:600;color:var(--text-main);">${s.name}</td>
              <td style="font-family:monospace;color:var(--accent-cyan);cursor:pointer;" onclick="NW.setQuery('${this.escapeHtml(s.query)}')">${this.escapeHtml(s.query)}</td>
              <td style="color:var(--text-muted);">${s.description || '-'}</td>
              <td>${s.run_count}</td>
              <td>
                <button class="nw-btn nw-btn-primary nw-btn-sm" onclick="NW.setQuery('${this.escapeHtml(s.query)}')">Run</button>
              </td>
            </tr>
          `).join('');
        }
      }

      const resHist = await fetch('/api/saved_searches/history/list?limit=25');
      if (resHist.ok) {
        const hist = await resHist.json();
        const tbodyHist = document.getElementById('search-history-body');
        if (tbodyHist) {
          tbodyHist.innerHTML = hist.map(h => `
            <tr>
              <td style="font-family:monospace;cursor:pointer;" onclick="NW.setQuery('${this.escapeHtml(h.query)}')">${this.escapeHtml(h.query)}</td>
              <td>${h.duration_ms} ms</td>
              <td>${h.result_count}</td>
              <td><span class="badge-status ${h.status === 'success' ? 'status-resolved' : 'status-new'}">${h.status}</span></td>
              <td style="color:var(--text-dim);">${new Date(h.executed_at * 1000).toLocaleTimeString()}</td>
            </tr>
          `).join('');
        }
      }
    } catch (e) {
      console.error(e);
    }
  },

  async saveCurrentSearch() {
    const input = document.getElementById('nw-search-input');
    const query = input ? input.value : '';
    const name = prompt('Enter a name for this saved search:', 'Search - ' + new Date().toLocaleTimeString());
    if (!name) return;

    try {
      await fetch('/api/saved_searches', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, query })
      });
      this.showToast('Search saved successfully.', 'success');
    } catch (e) {
      this.showToast('Failed to save search', 'error');
    }
  },

  // 6. System Health & Retention
  async loadHealth() {
    try {
      const res = await fetch('/api/system/health');
      if (!res.ok) return;
      const data = await res.json();

      document.getElementById('health-proc-rss').innerText = `${data.application.process_rss_mb} MB`;
      document.getElementById('health-proc-cpu').innerText = `${data.application.process_cpu_percent} %`;
      document.getElementById('health-uptime').innerText = `${Math.floor(data.application.uptime_seconds / 60)} minutes`;

      document.getElementById('health-host-ram').innerText = `${data.host.used_ram_mb} MB / ${data.host.total_ram_mb} MB (${data.host.ram_percent}%)`;
      document.getElementById('health-host-cpu').innerText = `${data.host.cpu_percent} %`;

      document.getElementById('health-db-size').innerText = `${data.database.db_size_mb} MB / ${data.database.max_storage_mb} MB`;
      document.getElementById('health-disk-free').innerText = `${data.host.disk.free_gb} GB free (${data.host.disk.total_gb} GB total)`;
    } catch (e) {
      console.error(e);
    }
  },

  async triggerRetentionCleanup() {
    if (!confirm('Execute retention cleanup cycle now? Old records beyond configured retention days will be deleted.')) return;
    try {
      const res = await fetch('/api/system/retention/run', { method: 'POST' });
      const d = await res.json();
      this.showToast(`Retention finished. Pruned ${d.deleted_by_age + d.deleted_by_size} records.`, 'success');
      this.loadHealth();
    } catch (e) {
      this.showToast('Retention cleanup failed', 'error');
    }
  },

  // Modals Controller
  setupModalEvents() {
    window.addEventListener('click', (e) => {
      if (e.target.classList.contains('nw-modal-overlay')) {
        e.target.classList.remove('active');
      }
    });
  },

  openModal(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.classList.add('active');
  },

  closeModal(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.classList.remove('active');
  },

  async openEventModal(eventId) {
    if (!eventId) return;
    try {
      const res = await fetch(`/api/events/${eventId}`);
      if (!res.ok) return;
      const ev = await res.json();

      document.getElementById('modal-event-time').innerText = ev.timestamp || '';
      document.getElementById('modal-event-host').innerText = ev.host || '';
      document.getElementById('modal-event-sourcetype').innerText = ev.sourcetype || '';
      document.getElementById('modal-event-raw').innerText = ev._raw || ev.raw || '';

      const fieldsTbody = document.getElementById('modal-event-fields-body');
      if (fieldsTbody) {
        fieldsTbody.innerHTML = Object.entries(ev).map(([k, v]) => {
          if (k === '_raw' || k === 'raw') return '';
          return `
            <tr>
              <td style="font-family:monospace;font-weight:600;color:var(--accent-cyan);">${k}</td>
              <td style="font-family:monospace;">${this.escapeHtml(String(v))}</td>
            </tr>
          `;
        }).join('');
      }

      this.openModal('modal-event-details');
    } catch (e) {
      console.error(e);
    }
  },

  async openAlertModal(alertId) {
    try {
      const res = await fetch(`/api/alerts/${alertId}`);
      if (!res.ok) return;
      const data = await res.json();
      const a = data.alert;

      document.getElementById('modal-alert-title').innerText = a.rule_name;
      document.getElementById('modal-alert-desc').innerText = a.description;
      document.getElementById('modal-alert-sev').className = `badge-sev badge-sev-${a.severity}`;
      document.getElementById('modal-alert-sev').innerText = a.severity;
      document.getElementById('modal-alert-status').value = a.status;
      document.getElementById('modal-alert-id-hidden').value = a.id;
      document.getElementById('modal-alert-notes').value = a.resolution_notes || '';

      const evTbody = document.getElementById('modal-alert-evidence-body');
      if (evTbody) {
        if (data.evidence_events && data.evidence_events.length > 0) {
          evTbody.innerHTML = data.evidence_events.map(ev => `
            <tr>
              <td style="font-family:monospace;color:var(--text-dim);">${(ev.timestamp || '').substring(11, 19)}</td>
              <td>${ev.host || '-'}</td>
              <td>${ev.user || ev.src_ip || '-'}</td>
              <td style="font-family:monospace;font-size:11px;color:var(--text-muted);">${this.escapeHtml((ev._raw || ev.raw || '').substring(0, 100))}...</td>
            </tr>
          `).join('');
        } else {
          evTbody.innerHTML = '<tr><td colspan="4" style="color:var(--text-dim);">No event snapshots stored.</td></tr>';
        }
      }

      this.openModal('modal-alert-details');
    } catch (e) {
      console.error(e);
    }
  },

  async saveAlertStatus() {
    const alertId = document.getElementById('modal-alert-id-hidden').value;
    const status = document.getElementById('modal-alert-status').value;
    const notes = document.getElementById('modal-alert-notes').value;

    try {
      await fetch(`/api/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, notes })
      });
      this.closeModal('modal-alert-details');
      this.showToast('Alert lifecycle updated.', 'success');
      this.loadAlerts();
      this.loadDashboard();
    } catch (e) {
      this.showToast('Failed to update alert', 'error');
    }
  },

  realtimeEnabled: true,

  toggleRealtimeStream() {
    this.realtimeEnabled = !this.realtimeEnabled;
    const btn = document.getElementById('btn-toggle-realtime');
    const badge = document.getElementById('nw-realtime-badge');
    const dot = badge ? badge.querySelector('.status-dot') : null;

    if (this.realtimeEnabled) {
      if (btn) btn.innerText = 'Pause Stream';
      if (badge) {
        badge.style.borderColor = '#BFDBFE';
        badge.style.backgroundColor = '#EFF6FF';
        badge.style.color = '#1D4ED8';
      }
      if (dot) {
        dot.style.backgroundColor = '#10B981';
        dot.style.boxShadow = '0 0 8px #10B981';
      }
      this.showToast('Real-time streaming resumed.', 'info');
      this.refreshActiveTab();
    } else {
      if (btn) btn.innerText = 'Resume Stream';
      if (badge) {
        badge.style.borderColor = '#E2E8F0';
        badge.style.backgroundColor = '#F8FAFC';
        badge.style.color = '#64748B';
      }
      if (dot) {
        dot.style.backgroundColor = '#94A3B8';
        dot.style.boxShadow = 'none';
      }
      this.showToast('Real-time streaming paused.', 'info');
    }
  },

  refreshActiveTab() {
    if (this.activeTab === 'dashboard') {
      this.loadDashboard();
    } else if (this.activeTab === 'alerts') {
      this.loadAlerts();
    } else if (this.activeTab === 'health') {
      this.loadHealth();
    } else if (this.activeTab === 'inputs') {
      this.loadInputs();
    }
  },

  pollStatus() {
    setInterval(async () => {
      if (!this.realtimeEnabled) return;
      try {
        const res = await fetch('/api/system/health');
        if (res.ok) {
          const d = await res.json();
          const pill = document.getElementById('nw-status-pill-text');
          if (pill) {
            pill.innerText = `● LIVE: ${d.database.total_events.toLocaleString()} Events | ${d.application.process_rss_mb} MB RAM`;
          }
          // Dynamically refresh active tab view in real time
          this.refreshActiveTab();
        }
      } catch (e) {}
    }, 3000);
  },

  escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }
};

window.addEventListener('DOMContentLoaded', () => NW.init());
