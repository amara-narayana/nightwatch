/**
 * NIGHTWATCH — Native SVG Charting Library
 * Zero-dependency, offline-first visualization engine for histograms, donuts, and bars.
 */

window.NightwatchCharts = {
  renderHistogram(containerId, buckets) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!buckets || buckets.length === 0) {
      container.innerHTML = '<div style="display:flex;height:100%;align-items:center;justify-content:center;color:var(--text-dim);font-size:12px;">No timeline data</div>';
      return;
    }

    const rect = container.getBoundingClientRect();
    const width = rect.width || 600;
    const height = rect.height || 100;
    const padding = { top: 10, bottom: 20, left: 10, right: 10 };

    const maxCount = Math.max(...buckets.map(b => b.count), 1);
    const plotWidth = width - padding.left - padding.right;
    const plotHeight = height - padding.top - padding.bottom;
    const barWidth = Math.max(2, (plotWidth / buckets.length) - 2);

    let barsSvg = '';
    buckets.forEach((b, i) => {
      const x = padding.left + (i * (plotWidth / buckets.length));
      const barH = (b.count / maxCount) * plotHeight;
      const y = padding.top + (plotHeight - barH);

      barsSvg += `
        <rect x="${x}" y="${y}" width="${barWidth}" height="${barH}" rx="2" fill="#06B6D4" opacity="0.85">
          <title>${b.time}: ${b.count} events</title>
        </rect>
      `;
    });

    const startTime = buckets[0].time.substring(11, 19);
    const endTime = buckets[buckets.length - 1].time.substring(11, 19);

    container.innerHTML = `
      <svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
        <line x1="${padding.left}" y1="${height - padding.bottom}" x2="${width - padding.right}" y2="${height - padding.bottom}" stroke="#26334D" stroke-width="1" />
        ${barsSvg}
        <text x="${padding.left}" y="${height - 4}" fill="#64748B" font-size="10" font-family="monospace">${startTime}</text>
        <text x="${width - padding.right}" y="${height - 4}" fill="#64748B" font-size="10" font-family="monospace" text-anchor="end">${endTime}</text>
      </svg>
    `;
  },

  renderDonutChart(containerId, dataMap, colors) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const entries = Object.entries(dataMap || {}).filter(([_, v]) => v > 0);
    const total = entries.reduce((sum, [_, v]) => sum + v, 0);

    if (total === 0) {
      container.innerHTML = '<div style="display:flex;height:100%;align-items:center;justify-content:center;color:var(--text-dim);font-size:12px;">No events recorded</div>';
      return;
    }

    const defaultColors = {
      critical: '#EF4444',
      high: '#F59E0B',
      medium: '#3B82F6',
      low: '#10B981',
      info: '#64748B',
      linux_auth: '#6366F1',
      suricata_eve: '#EC4899',
      winevt: '#06B6D4',
      syslog: '#10B981',
      json: '#F59E0B'
    };

    const size = 130;
    const strokeWidth = 18;
    const radius = (size - strokeWidth) / 2;
    const circumference = 2 * Math.PI * radius;
    let accumulatedAngle = 0;

    let circlesSvg = '';
    entries.forEach(([key, val]) => {
      const sliceAngle = (val / total) * circumference;
      const color = (colors && colors[key]) || defaultColors[key] || '#94A3B8';
      const offset = circumference - accumulatedAngle;

      circlesSvg += `
        <circle cx="${size / 2}" cy="${size / 2}" r="${radius}"
                fill="transparent" stroke="${color}" stroke-width="${strokeWidth}"
                stroke-dasharray="${sliceAngle} ${circumference - sliceAngle}"
                stroke-dashoffset="${offset}" transform="rotate(-90 ${size / 2} ${size / 2})">
          <title>${key}: ${val} (${Math.round((val / total) * 100)}%)</title>
        </circle>
      `;
      accumulatedAngle += sliceAngle;
    });

    let legendHtml = '<div style="display:flex;flex-direction:column;gap:6px;font-size:12px;">';
    entries.slice(0, 5).forEach(([key, val]) => {
      const color = (colors && colors[key]) || defaultColors[key] || '#94A3B8';
      const pct = Math.round((val / total) * 100);
      legendHtml += `
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
          <div style="display:flex;align-items:center;gap:6px;">
            <span style="width:8px;height:8px;border-radius:2px;background-color:${color};"></span>
            <span style="color:var(--text-muted);text-transform:capitalize;">${key}</span>
          </div>
          <span style="font-family:monospace;font-weight:600;color:#FFFFFF;">${val} (${pct}%)</span>
        </div>
      `;
    });
    legendHtml += '</div>';

    container.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-around;gap:16px;height:100%;">
        <div style="position:relative;width:${size}px;height:${size}px;flex-shrink:0;">
          <svg width="${size}" height="${size}">
            ${circlesSvg}
          </svg>
          <div style="position:absolute;top:0;left:0;width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;">
            <span style="font-size:18px;font-weight:700;font-family:monospace;color:#FFFFFF;">${total}</span>
            <span style="font-size:10px;text-transform:uppercase;color:var(--text-dim);letter-spacing:0.5px;">Events</span>
          </div>
        </div>
        <div style="flex:1;">${legendHtml}</div>
      </div>
    `;
  },

  renderHorizontalBars(containerId, items, labelKey, valueKey) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!items || items.length === 0) {
      container.innerHTML = '<div style="display:flex;height:100%;align-items:center;justify-content:center;color:var(--text-dim);font-size:12px;">No records available</div>';
      return;
    }

    const maxVal = Math.max(...items.map(it => it[valueKey] || 0), 1);
    let html = '<div style="display:flex;flex-direction:column;gap:8px;">';

    items.slice(0, 5).forEach(it => {
      const label = it[labelKey] || 'unknown';
      const val = it[valueKey] || 0;
      const pct = Math.round((val / maxVal) * 100);

      html += `
        <div style="display:flex;flex-direction:column;gap:2px;">
          <div style="display:flex;justify-content:space-between;font-size:12px;font-family:monospace;">
            <span style="color:var(--text-main);">${label}</span>
            <span style="color:var(--accent-cyan);font-weight:600;">${val}</span>
          </div>
          <div style="height:6px;background-color:var(--bg-input);border-radius:3px;overflow:hidden;">
            <div style="width:${pct}%;height:100%;background:linear-gradient(90deg, var(--accent-indigo), var(--accent-cyan));border-radius:3px;"></div>
          </div>
        </div>
      `;
    });
    html += '</div>';

    container.innerHTML = html;
  }
};
