/**
 * IdentityOS — Enterprise Identity & Access Governance
 * Interactive Frontend Engine (Classic Enterprise Edition)
 */

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  initNavigation();
  initCounters();
  initCharts();
  initTabs();
  initSearch();
  initAIChat();
  initAuditFilters();
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
    'governance': { title: 'Governance & Compliance', crumb: 'IdentityOS / Compliance / Frameworks' }
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
  };

  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const pageId = btn.dataset.page;
      navigateTo(pageId);
    });
  });
}

/* ── 2. ANIMATED KPI COUNTERS ──────────────────────────────── */
function initCounters() {
  const counters = document.querySelectorAll('.kpi-value');
  counters.forEach(counter => {
    const target = parseInt(counter.dataset.target, 10);
    const hasUnit = counter.querySelector('.unit') !== null;
    const duration = 900;
    const startTime = performance.now();

    function updateCounter(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      const current = Math.floor(ease * target);

      if (hasUnit) {
        counter.innerHTML = `${current.toLocaleString()}<span class="unit">%</span>`;
      } else {
        counter.textContent = current.toLocaleString();
      }

      if (progress < 1) {
        requestAnimationFrame(updateCounter);
      } else {
        if (hasUnit) {
          counter.innerHTML = `${target.toLocaleString()}<span class="unit">%</span>`;
        } else {
          counter.textContent = target.toLocaleString();
        }
      }
    }
    requestAnimationFrame(updateCounter);
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
        labels: ['May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct'],
        datasets: [
          {
            label: 'Joiners',
            data: [42, 68, 54, 85, 76, 94],
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
            data: [18, 24, 30, 28, 35, 42],
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
            data: [12, 16, 9, 14, 11, 15],
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
        labels: ['Joiners', 'Movers', 'Leavers', 'Elevated Privileges'],
        datasets: [{
          data: [48, 26, 14, 12],
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
        labels: ['Day 1', 'Day 5', 'Day 10', 'Day 15', 'Day 20', 'Day 25', 'Today'],
        datasets: [{
          label: 'Avg Identity Risk Index',
          data: [38, 35, 41, 32, 28, 25, 22],
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
        labels: ['Failed MFA', 'Dormant ID', 'Excess Rights', 'Off-Hours', 'SoD Conflict'],
        datasets: [{
          label: 'Incidents',
          data: [28, 19, 34, 14, 8],
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

/* ── 5. REAL-TIME SEARCH FILTERING ─────────────────────────── */
function initSearch() {
  const userSearch = document.getElementById('user-search');
  if (userSearch) {
    userSearch.addEventListener('input', (e) => {
      const term = e.target.value.toLowerCase();
      const activeTabContent = document.querySelector('.tab-content.active');
      if (!activeTabContent) return;
      const rows = activeTabContent.querySelectorAll('tbody tr');
      rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(term) ? '' : 'none';
      });
    });
  }

  const globalSearch = document.getElementById('global-search');
  if (globalSearch) {
    globalSearch.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        const query = globalSearch.value.trim();
        if (query) {
          showToast(`Querying directory for "${query}"…`, 'info');
        }
      }
    });
  }
}

/* ── 6. AI IDENTITY AUTOMATION ENGINE ──────────────────────── */
function initAIChat() {
  const chatInput = document.getElementById('chat-input');
  const sendBtn = document.getElementById('send-btn');
  const messagesContainer = document.getElementById('chat-messages');

  window.injectPrompt = function(promptText) {
    navigateTo('ai-chat');
    chatInput.value = promptText;
    chatInput.focus();
    chatInput.dispatchEvent(new Event('input'));
  };

  function sendMessage() {
    const text = chatInput.value.trim();
    if (!text) return;

    // Remove welcome screen
    const welcome = messagesContainer.querySelector('.chat-welcome');
    if (welcome) welcome.remove();

    appendBubble(text, 'user');
    chatInput.value = '';
    chatInput.style.height = 'auto';

    const typingIndicator = createTypingIndicator();
    messagesContainer.appendChild(typingIndicator);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;

    setTimeout(() => {
      typingIndicator.remove();
      const response = generateAIResponse(text);
      appendBubble(response.html, 'bot');
      messagesContainer.scrollTop = messagesContainer.scrollHeight;

      if (response.toast) {
        showToast(response.toast.msg, response.toast.type);
      }
    }, 700);
  }

  if (sendBtn) sendBtn.addEventListener('click', sendMessage);
  if (chatInput) {
    chatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
      }
    });

    chatInput.addEventListener('input', () => {
      chatInput.style.height = 'auto';
      chatInput.style.height = Math.min(chatInput.scrollHeight, 100) + 'px';
    });
  }

  function appendBubble(contentHtml, sender) {
    const bubble = document.createElement('div');
    bubble.className = `chat-bubble chat-bubble--${sender}`;
    if (sender === 'bot') {
      bubble.innerHTML = `
        <div class="bot-tag">
          <svg width="12" height="12" viewBox="0 0 20 20" fill="currentColor"><path d="M10 2a8 8 0 100 16 8 8 0 000-16zm1 11H9v-2h2v2zm0-4H9V5h2v4z"/></svg>
          IdentityOS Policy Validation
        </div>
        ${contentHtml}
      `;
    } else {
      bubble.textContent = contentHtml;
    }
    messagesContainer.appendChild(bubble);
  }

  function createTypingIndicator() {
    const div = document.createElement('div');
    div.className = 'chat-bubble chat-bubble--bot';
    div.innerHTML = `<span style="color:var(--text-dim);font-size:0.8rem;">Evaluating SoD policy rules and entitlement matrices…</span>`;
    return div;
  }

  function generateAIResponse(userQuery) {
    const q = userQuery.toLowerCase();

    if (q.includes('onboard') || q.includes('hire') || q.includes('priya') || q.includes('sarah')) {
      return {
        html: `
          <p><strong>Joiner Provisioning Workflow Initialized</strong> (Request ID: <code>REQ-8942</code>)</p>
          <div class="chat-step-box">
            Target Identity: <code>Sarah Johnson (s.johnson@corp.com)</code><br>
            OU Placement: <code>DC=corp,DC=com/OU=Engineering</code><br>
            Entitlements: GitHub Enterprise (Team: Core), Jira Cloud, AWS Sandbox<br>
            Risk Assessment: <strong>Score 12 / 100 (Compliant)</strong> · 0 SoD Conflicts
          </div>
          <p style="margin-top:0.45rem;font-size:0.78rem;color:var(--text-dim);">Workflow submitted to Engineering Lead for 1-click verification.</p>
        `,
        toast: { msg: 'Joiner workflow REQ-8942 submitted for approval', type: 'success' }
      };
    } else if (q.includes('risk') || q.includes('kai') || q.includes('score')) {
      return {
        html: `
          <p><strong>Security Anomaly Detection Report</strong></p>
          <div class="chat-step-box">
            Flagged Identity: <code>kai.chen@corp.com</code> (Risk Score: <strong>87 / 100</strong>)<br>
            Primary Anomaly: 3 failed MFA challenges from unauthorized geo-IP block<br>
            Secondary Trigger: Unscheduled credential rotation request for AWS Production<br>
            Automated Mitigation: Step-up authentication enforced · SIEM Incident #9822 filed
          </div>
          <p style="margin-top:0.45rem;font-size:0.78rem;color:var(--text-dim);">Recommended action: Execute session revocation or confirm with identity owner.</p>
        `,
        toast: { msg: 'SIEM Incident #9822 escalated for Kai Chen', type: 'warn' }
      };
    } else if (q.includes('offboard') || q.includes('revoke') || q.includes('leave') || q.includes('marcus')) {
      return {
        html: `
          <p><strong>Leaver Deprovision Protocol Executed</strong></p>
          <div class="chat-step-box">
            Identity: <code>Marcus Wren (m.wren@corp.com)</code><br>
            Status: 14 Active OAuth & SAML Sessions Revoked<br>
            Federated Directories: Disabled in Active Directory & Azure Entra ID<br>
            Cloud Infrastructure: AWS Access Keys & IAM policies detached<br>
            Audit Trail: Immutable event log generated (SOX 404 / ISO 27001)
          </div>
          <p style="margin-top:0.45rem;font-size:0.78rem;color:var(--text-dim);">All access terminated in 1.4 seconds. Mailbox converted to compliant archive.</p>
        `,
        toast: { msg: 'Access successfully revoked for Marcus Wren', type: 'danger' }
      };
    } else {
      return {
        html: `
          <p><strong>Instruction Validated:</strong> "${userQuery}"</p>
          <div class="chat-step-box">
            Governance Policy: Validated against Segregation of Duties (SoD)<br>
            Scope: 1 identity updated · 0 compliance exceptions detected
          </div>
          <p style="margin-top:0.45rem;font-size:0.78rem;color:var(--text-dim);">Action recorded in the enterprise Audit Logs.</p>
        `,
        toast: { msg: 'Instruction processed successfully', type: 'info' }
      };
    }
  }
}

/* ── 7. APPROVAL HANDLERS ──────────────────────────────────── */
window.handleApproval = function(btnElement, action) {
  const card = btnElement.closest('.approval-card');
  const title = card.querySelector('.approval-title').textContent;

  if (action === 'approve') {
    showToast(`Approved: ${title}`, 'success');
  } else {
    showToast(`Rejected: ${title}`, 'danger');
  }

  card.style.opacity = '0.4';
  card.style.pointerEvents = 'none';

  setTimeout(() => {
    card.remove();
    updatePendingBadge();
  }, 350);
};

function updatePendingBadge() {
  const remaining = document.querySelectorAll('.approval-card').length;
  const badge = document.querySelector('#nav-approvals .nav-badge');
  const countHeader = document.querySelector('.approvals-count-badge');

  if (badge) {
    badge.textContent = remaining;
    if (remaining === 0) badge.style.display = 'none';
  }

  if (countHeader) {
    countHeader.textContent = `${remaining} pending items`;
  }
}

/* ── 8. MODAL & IDENTITY CREATION ──────────────────────────── */
window.openModal = function(id) {
  const modal = document.getElementById(id);
  if (modal) modal.showModal();
};

window.closeModal = function(id) {
  const modal = document.getElementById(id);
  if (modal) modal.close();
};

window.submitAddUser = function(e) {
  e.preventDefault();
  const fname = document.getElementById('user-fname').value.trim();
  const lname = document.getElementById('user-lname').value.trim();
  const email = document.getElementById('user-email').value.trim();
  const dept = document.getElementById('user-dept').value;
  const role = document.getElementById('user-role').value;
  const date = document.getElementById('user-start').value;

  const initials = (fname[0] + lname[0]).toUpperCase();

  const tbody = document.querySelector('#tab-joiners tbody');
  if (tbody) {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>
        <div class="user-cell">
          <div class="user-cell-avatar">${initials}</div>
          <div>
            <div class="user-cell-name">${fname} ${lname}</div>
            <div class="user-cell-email">${email}</div>
          </div>
        </div>
      </td>
      <td>${dept}</td>
      <td>${date || 'Oct 5, 2026'}</td>
      <td>${role}</td>
      <td><span class="status-pill status-pill--pending">Provisioning</span></td>
      <td>
        <div class="action-btns">
          <button class="btn-secondary btn-xs">View</button>
          <button class="btn-approve btn-xs" onclick="showToast('Approved access for ${fname}', 'success')">Approve</button>
        </div>
      </td>
    `;
    tbody.prepend(tr);
  }

  closeModal('add-user-modal');
  e.target.reset();
  showToast(`Onboarding workflow submitted for ${fname} ${lname}`, 'success');
  navigateTo('users');
};

/* ── 9. AUDIT LOG FILTERING ────────────────────────────────── */
function initAuditFilters() {
  const eventFilter = document.getElementById('audit-event-filter');
  const sevFilter = document.getElementById('audit-severity-filter');
  const tbody = document.querySelector('#page-audit tbody');

  function applyFilters() {
    if (!tbody) return;
    const selectedEvent = eventFilter.value.toLowerCase();
    const selectedSev = sevFilter.value.toLowerCase();
    const rows = tbody.querySelectorAll('tr');

    rows.forEach(row => {
      const eventText = row.children[1].textContent.toLowerCase();
      const sevText = row.children[4].textContent.toLowerCase();

      const eventMatch = (selectedEvent === 'all events' || eventText.includes(selectedEvent));
      const sevMatch = (selectedSev === 'all severities' || sevText.includes(selectedSev));

      row.style.display = (eventMatch && sevMatch) ? '' : 'none';
    });
  }

  if (eventFilter) eventFilter.addEventListener('change', applyFilters);
  if (sevFilter) sevFilter.addEventListener('change', applyFilters);
}

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
