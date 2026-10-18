/**
 * IdentityOS — Enterprise Identity & Access Governance
 * Interactive Frontend Engine (Classic Enterprise Edition)
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initNavigation();
  initCharts();
  initTabs();
});

/* ── 0. THEME SWITCHER (ENTERPRISE LIGHT / SLATE DARK) ────── */
function initTheme() {
  const toggleBtn = document.getElementById('theme-toggle-btn');
  const themeIcon = document.getElementById('theme-icon');
  const savedTheme = localStorage.getItem('identityos-theme') || 'light';

  applyTheme(savedTheme);

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme') || 'light';
      const next = current === 'light' ? 'dark' : 'light';
      applyTheme(next);
      localStorage.setItem('identityos-theme', next);
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    if (themeIcon) {
      if (theme === 'dark') {
        // Sun icon for dark mode
        themeIcon.innerHTML = `
          <circle cx="12" cy="12" r="5"></circle>
          <line x1="12" y1="1" x2="12" y2="3"></line>
          <line x1="12" y1="21" x2="12" y2="23"></line>
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line>
          <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line>
          <line x1="1" y1="12" x2="3" y2="12"></line>
          <line x1="21" y1="12" x2="23" y2="12"></line>
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line>
          <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line>
        `;
      } else {
        // Moon icon for light mode
        themeIcon.innerHTML = `<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path>`;
      }
    }
    // Update chart colors if charts exist
    updateChartsTheme(theme);
  }
}

/* ── 1. NAVIGATION & ROUTING ───────────────────────────────── */
function initNavigation() {
  const navButtons = document.querySelectorAll('.nav-item');
  const pages = document.querySelectorAll('.page');
  const pageTitle = document.getElementById('page-title');
  const breadcrumb = document.getElementById('breadcrumb');

  const pageMeta = {
    'dashboard': { title: 'Dashboard', crumb: 'IdentityOS / Dashboard' },
    'ai-chat': { title: 'AI Assistant', crumb: 'IdentityOS / Automation / AI Assistant' },
    'users': { title: 'Identities Directory', crumb: 'IdentityOS / Lifecycle / Directory' },
    'approvals': { title: 'Approvals Queue', crumb: 'IdentityOS / Governance / Approvals' },
    'risk': { title: 'Risk Analytics', crumb: 'IdentityOS / Security / Risk Scoring' },
    'audit': { title: 'Audit Trail', crumb: 'IdentityOS / Security / Event Logs' },
    'governance': { title: 'Governance & Compliance', crumb: 'IdentityOS / Compliance / Frameworks' },
    'platform-users': { title: 'Platform Users', crumb: 'IdentityOS / Administration / Platform Users' },
    'no-access': { title: 'No Access', crumb: 'IdentityOS' }
  };

  window.navigateTo = function(pageId) {
    navButtons.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.page === pageId);
    });

    pages.forEach(pg => {
      pg.classList.toggle('active', pg.id === `page-${pageId}`);
    });

    if (pageMeta[pageId]) {
      pageTitle.textContent = pageMeta[pageId].title;
      breadcrumb.textContent = pageMeta[pageId].crumb;
    }

    window.scrollTo({ top: 0, behavior: 'smooth' });
    document.dispatchEvent(new CustomEvent('page:show', { detail: pageId }));
  };

  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const pageId = btn.dataset.page;
      navigateTo(pageId);
    });
  });
}

/* ── 3. CHARTS INITIALIZATION ──────────────────────────────── */
let lifecycleChart, requestsChart, riskTrendChart, riskFactorsChart;

function getChartColors(theme) {
  const isDark = theme === 'dark';
  return {
    text: isDark ? '#9ca3af' : '#64748b',
    grid: isDark ? 'rgba(255, 255, 255, 0.07)' : 'rgba(0, 0, 0, 0.05)',
    tooltipBg: isDark ? '#1f2937' : '#0f172a',
    tooltipBorder: isDark ? '#374151' : '#334155'
  };
}

function updateChartsTheme(theme) {
  const c = getChartColors(theme);
  Chart.defaults.color = c.text;

  [lifecycleChart, requestsChart, riskTrendChart, riskFactorsChart].forEach(chart => {
    if (chart) {
      if (chart.options.scales) {
        if (chart.options.scales.x) chart.options.scales.x.grid.color = c.grid;
        if (chart.options.scales.y) chart.options.scales.y.grid.color = c.grid;
      }
      chart.update();
    }
  });
}

function initCharts() {
  const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
  const c = getChartColors(currentTheme);

  Chart.defaults.color = c.text;
  Chart.defaults.font.family = "'Inter', sans-serif";
  Chart.defaults.font.size = 11;

  // 1. Lifecycle Activity Trends (Cobalt Blue, Emerald Green, Crimson)
  const ctxLifecycle = document.getElementById('lifecycleChart');
  if (ctxLifecycle) {
    lifecycleChart = new Chart(ctxLifecycle, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Joiners',
            data: [],
            borderColor: '#1d4ed8',
            backgroundColor: 'rgba(29, 78, 216, 0.08)',
            fill: true,
            tension: 0.3,
            borderWidth: 2,
            pointRadius: 3,
            pointHoverRadius: 5
          },
          {
            label: 'Movers',
            data: [],
            borderColor: '#059669',
            backgroundColor: 'rgba(5, 150, 105, 0.04)',
            fill: true,
            tension: 0.3,
            borderWidth: 2,
            pointRadius: 3,
            pointHoverRadius: 5
          },
          {
            label: 'Leavers',
            data: [],
            borderColor: '#dc2626',
            backgroundColor: 'transparent',
            tension: 0.3,
            borderWidth: 2,
            borderDash: [4, 4],
            pointRadius: 3,
            pointHoverRadius: 5
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#334155',
            borderWidth: 1,
            padding: 8,
            titleFont: { size: 12, weight: 'bold' }
          }
        },
        scales: {
          x: { grid: { color: c.grid } },
          y: { grid: { color: c.grid }, beginAtZero: true }
        }
      }
    });
  }

  // 2. Request Distribution Donut
  const ctxDonut = document.getElementById('requestsDonut');
  if (ctxDonut) {
    requestsChart = new Chart(ctxDonut, {
      type: 'doughnut',
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: ['#1d4ed8', '#059669', '#dc2626', '#d97706'],
          borderWidth: 2,
          borderColor: currentTheme === 'dark' ? '#111827' : '#ffffff',
          hoverOffset: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: { boxWidth: 8, padding: 10, font: { size: 11 } }
          }
        }
      }
    });
  }

  // 3. 30-Day Risk Trajectory Line Chart
  const ctxRiskTrend = document.getElementById('riskTrendChart');
  if (ctxRiskTrend) {
    riskTrendChart = new Chart(ctxRiskTrend, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: 'Avg Identity Risk Index',
          data: [],
          borderColor: '#dc2626',
          backgroundColor: 'rgba(220, 38, 38, 0.06)',
          fill: true,
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { grid: { color: c.grid } },
          y: { grid: { color: c.grid }, min: 0, max: 100 }
        }
      }
    });
  }

  // 4. Primary Risk Triggers Bar Chart
  const ctxRiskFactors = document.getElementById('riskFactorsChart');
  if (ctxRiskFactors) {
    riskFactorsChart = new Chart(ctxRiskFactors, {
      type: 'bar',
      data: {
        labels: [],
        datasets: [{
          label: 'Incidents',
          data: [],
          backgroundColor: ['#dc2626', '#d97706', '#1d4ed8', '#0284c7', '#475569'],
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false } },
          y: { grid: { color: c.grid } }
        }
      }
    });
  }
}

/* ── 4. TAB CONTROLS (USER MANAGEMENT) ─────────────────────── */
function initTabs() {
  const tabs = document.querySelectorAll('.tab');
  const tabContents = document.querySelectorAll('.tab-content');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tabContents.forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      const targetId = `tab-${tab.dataset.tab}`;
      const targetEl = document.getElementById(targetId);
      if (targetEl) targetEl.classList.add('active');
    });
  });
}

/* ── 8. MODAL HELPERS ──────────────────────────── */
window.openModal = function(id) {
  const modal = document.getElementById(id);
  if (modal) modal.showModal();
};

window.closeModal = function(id) {
  const modal = document.getElementById(id);
  if (modal) modal.close();
};

/* ── 10. ENTERPRISE TOAST SYSTEM ───────────────────────────── */
window.showToast = function(message, type = 'info', duration = 3200) {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast--${type}`;

  const icon = type === 'success' ? '✓' : type === 'danger' ? '✕' : type === 'warn' ? '⚠️' : 'ℹ';
  toast.innerHTML = `<span style="font-weight:700">${icon}</span><span>${message}</span>`;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    setTimeout(() => toast.remove(), 250);
  }, duration);
};
