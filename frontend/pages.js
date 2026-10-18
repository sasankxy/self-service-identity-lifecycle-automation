/**
 * IdentityOS data layer. Every figure, row, chart point and status on every page is fetched from /api/v1
 * and rendered here. Nothing operational is hardcoded; failed requests show an error state (never fake success).
 */
(() => {
  const $ = (id) => document.getElementById(id);
  const api = (path, opts) => Auth.request(path, opts);
  const esc = (s) => Auth.esc(s);
  const can = (p) => Auth.can(p);

  /* ───────────────────────── formatting helpers ───────────────────────── */
  const fmtDate = (d) => (d ? new Date(/^\d{4}-\d{2}-\d{2}$/.test(d) ? d + 'T00:00:00' : d).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—');
  const pad = (n) => String(n).padStart(2, '0');
  const fmtStamp = (iso) => { const d = new Date(iso); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`; };
  function timeAgo(iso) {
    if (!iso) return '—';
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)}m ago`;
    if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
    if (s < 86400 * 14) return `${Math.floor(s / 86400)}d ago`;
    return fmtDate(iso);
  }
  const pill = (cls, text) => `<span class="status-pill status-pill--${cls}">${esc(text)}</span>`;
  const tag = (cls, text) => `<span class="tag tag--${cls}">${esc(text)}</span>`;
  const LEVEL_CLS = { low: 'success', medium: 'warning', high: 'danger', critical: 'danger' };
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const stateRow = (cols, msg, cls = '') => `<tr><td colspan="${cols}"><div class="pu-state ${cls}">${msg}</div></td></tr>`;
  const errRow = (cols, e, retryId) => stateRow(cols, `${esc(e.message)} <button class="btn-secondary btn-xs" id="${retryId}">Retry</button>`, 'pu-state--error');
  const userCell = (name, email, initials) => `<div class="user-cell"><div class="user-cell-avatar">${esc(initials || name.split(' ').map((w) => w[0]).slice(0, 2).join('').toUpperCase())}</div>
      <div><div class="user-cell-name">${esc(name)}</div><div class="user-cell-email">${esc(email)}</div></div></div>`;
  function debounce(fn, ms = 300) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
  function pager(prefix, st) {
    const from = st.total ? st.offset + 1 : 0, to = Math.min(st.offset + st.limit, st.total);
    $(`${prefix}-range`).textContent = `${from}–${to} of ${st.total}`;
    $(`${prefix}-prev`).disabled = st.offset === 0; $(`${prefix}-next`).disabled = to >= st.total;
  }
  function animateNumber(el, to, { decimals = 0, suffix = '' } = {}) {
    const start = performance.now(), dur = 700;
    const step = (t) => {
      const p = Math.min((t - start) / dur, 1), v = to * (1 - Math.pow(1 - p, 3));
      el.innerHTML = `${v.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals })}${suffix}`;
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }
  function setDelta(el, text, dir) { el.textContent = text; el.className = `kpi-delta${dir ? ` kpi-delta--${dir}` : ''}`; }
  const CONNECTOR = { demo: ['neutral', 'Demo'], not_configured: ['warning', 'Not Configured'], disconnected: ['danger', 'Disconnected'], connected: ['success', 'Connected'] };
  const connPill = (s) => pill(...(CONNECTOR[s] || ['neutral', s]));
  async function download(path, fallback) {
    try {
      const res = await fetch(`/api/v1${path}`, { credentials: 'same-origin' });
      if (!res.ok) { let m = 'Export failed.'; try { m = (await res.json()).error.message; } catch { /* ignore */ } throw new Error(m); }
      const blob = await res.blob(), a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = (res.headers.get('content-disposition') || '').match(/filename="([^"]+)"/)?.[1] || fallback;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(a.href);
    } catch (e) { showToast(e.message, 'danger'); }
  }

  /* ───────────────────────── global badges / status ───────────────────────── */
  async function refreshBadges() {
    if (!can('approvals:read')) return;
    try {
      const d = await api('/approvals?status=pending&limit=1');
      const n = d.counts.pending, b = $('appr-badge');
      b.textContent = n; b.hidden = n === 0; $('notif-dot').hidden = n === 0;
      $('approvals-count').textContent = `${n} pending item${n === 1 ? '' : 's'}`;
    } catch { /* badge is best-effort */ }
  }
  async function refreshSystemStatus() {
    const dot = $('sys-dot'), text = $('sys-text');
    try {
      const h = await (await fetch('/api/v1/health', { credentials: 'same-origin' })).json();
      const down = Object.entries(h).filter(([, v]) => v !== 'ok').map(([k]) => k);
      text.textContent = down.length ? `Degraded: ${down.join(', ')}` : 'All Systems Operational';
      dot.style.background = down.length ? 'var(--danger)' : '';
    } catch { text.textContent = 'API unreachable'; dot.style.background = 'var(--danger)'; }
  }

  /* ───────────────────────── dashboard ───────────────────────── */
  async function loadDashboard() {
    const [sum, trends, act] = await Promise.allSettled([api('/dashboard/summary'), api('/dashboard/trends'), api('/dashboard/activity')]);
    if (sum.status === 'fulfilled') {
      const s = sum.value;
      animateNumber($('kpi-total'), s.total_identities.value);
      const g = s.total_identities.growth_pct_7d;
      setDelta($('kpi-total-delta'), g === null ? '' : `${g >= 0 ? '↑' : '↓'} ${Math.abs(g)}%`, g === null ? '' : g >= 0 ? 'up' : 'down');
      $('kpi-total-sub').textContent = g === null ? 'excludes terminated' : 'vs 7 days ago';

      const p = s.provisioning, badge = $('kpi-prov-badge');
      if (p.success_rate === null) { $('kpi-prov').textContent = '—'; badge.textContent = 'No data'; badge.className = 'kpi-badge kpi-badge--neutral'; setDelta($('kpi-prov-delta'), '', ''); $('kpi-prov-sub').textContent = `no completed requests in ${p.window_days}d`; }
      else {
        animateNumber($('kpi-prov'), p.success_rate, { decimals: 1, suffix: '<span class="unit">%</span>' });
        badge.textContent = p.sla_met === null ? 'Measured' : p.sla_met ? 'SLA Met' : 'Below SLA';
        badge.className = `kpi-badge kpi-badge--${p.sla_met === null ? 'neutral' : p.sla_met ? 'success' : 'danger'}`;
        if (p.sla_target !== null) { const d = p.success_rate - p.sla_target; setDelta($('kpi-prov-delta'), `${d >= 0 ? '↑' : '↓'} ${Math.abs(d).toFixed(1)}%`, d >= 0 ? 'up' : 'down'); $('kpi-prov-sub').textContent = `vs ${p.sla_target}% SLA target`; }
        else { setDelta($('kpi-prov-delta'), '', ''); $('kpi-prov-sub').textContent = `${p.completed} done · ${p.failed} failed (${p.window_days}d)`; }
      }
      const pa = s.pending_approvals;
      animateNumber($('kpi-pending'), pa.value);
      setDelta($('kpi-pending-delta'), `${pa.urgent} urgent`, pa.urgent ? 'down' : '');
      $('kpi-pending-sub').textContent = pa.avg_wait_hours === null ? 'nothing waiting' : `avg wait: ${pa.avg_wait_hours} hrs`;
      animateNumber($('kpi-high'), s.high_risk.value);
      setDelta($('kpi-high-delta'), `${s.high_risk.flagged_last_7d} flagged in 7d`, s.high_risk.flagged_last_7d ? 'down' : '');
      $('kpi-high-sub').textContent = 'risk score ≥ 75';
      $('dash-connectors').innerHTML = s.connectors.length
        ? s.connectors.map((c) => `<div class="connector-item"><span class="connector-name">${esc(c.name)}</span>${connPill(c.status)}</div>`).join('')
        : '<div class="pu-state">No connectors configured.</div>';
    } else {
      ['kpi-total', 'kpi-prov', 'kpi-pending', 'kpi-high'].forEach((id) => { $(id).textContent = '—'; });
      $('dash-connectors').innerHTML = `<div class="pu-state pu-state--error">${esc(sum.reason.message)} <button class="btn-secondary btn-xs" id="dash-retry">Retry</button></div>`;
      const r = $('dash-retry'); if (r) r.onclick = loadDashboard;
    }
    if (trends.status === 'fulfilled') {
      const t = trends.value;
      lifecycleChart.data.labels = t.labels;
      lifecycleChart.data.datasets[0].data = t.series.joiner; lifecycleChart.data.datasets[1].data = t.series.mover; lifecycleChart.data.datasets[2].data = t.series.leaver;
      lifecycleChart.update();
      const NAMES = { joiner: 'Joiners', mover: 'Movers', leaver: 'Leavers', privilege: 'Privileged Access' };
      requestsChart.data.labels = t.distribution.map((d) => NAMES[d.type]);
      requestsChart.data.datasets[0].data = t.distribution.map((d) => d.count);
      requestsChart.update();
    }
    const body = $('dash-activity');
    if (act.status === 'fulfilled') {
      const CAT = { provisioning: 'green', access_change: 'blue', login: 'gray', risk_alert: 'red', approval: 'yellow', system: 'gray' };
      const OUT = { success: 'success', pending: 'pending', flagged: 'warning', blocked: 'danger', failure: 'danger', denied: 'danger' };
      body.innerHTML = act.value.items.length ? act.value.items.map((a) => `<tr><td>${esc(a.identity)}</td><td>${esc(a.department || '—')}</td>
        <td>${tag(CAT[a.category] || 'gray', a.event)}</td><td>${pill(OUT[a.outcome] || 'neutral', a.outcome.toUpperCase())}</td><td class="mono">${timeAgo(a.occurred_at)}</td></tr>`).join('')
        : stateRow(5, 'No activity recorded yet.');
    } else { body.innerHTML = errRow(5, act.reason, 'act-retry'); const r = $('act-retry'); if (r) r.onclick = loadDashboard; }
  }

  /* ───────────────────────── identities ───────────────────────── */
  const TAB_STATE = { joiners: 'joiner', movers: 'mover', leavers: 'leaver', 'all-users': 'all' };
  const TBODY = { joiner: 'tb-joiners', mover: 'tb-movers', leaver: 'tb-leavers', all: 'tb-all' };
  const IDN = { state: 'joiner', q: '', offset: 0, limit: 25, total: 0 };
  const REQ_STATUS = {
    pending_approval: ['pending', 'Pending Approval'], approved: ['pending', 'Approved'], provisioning: ['pending', 'Provisioning'],
    completed: ['success', 'Active'], rejected: ['danger', 'Rejected'], failed: ['danger', 'Failed'], draft: ['neutral', 'Draft'], cancelled: ['neutral', 'Cancelled'],
  };
  const viewBtn = (id) => `<button class="btn-secondary btn-xs" data-view="${id}">View</button>`;
  const delta = (r) => (r ? [...r.added.map((a) => tag('blue', `+${a}`)), ...r.removed.map((a) => tag('red', `−${a}`))].join(' ') || '—' : '—');

  const ROW = {
    joiner: (i) => { const [c, l] = REQ_STATUS[i.request?.status] || ['neutral', '—'];
      return `<tr><td>${userCell(i.name, i.email, i.initials)}</td><td>${esc(i.department || '—')}</td><td>${fmtDate(i.start_date)}</td><td>${esc(i.access_profile || '—')}</td>
        <td>${pill(c, l)}</td><td><div class="action-btns">${viewBtn(i.id)}${i.request?.status === 'pending_approval' && can('approvals:read') ? '<button class="btn-approve btn-xs" data-nav="approvals">Review</button>' : ''}</div></td></tr>`; },
    mover: (i) => { const [c, l] = REQ_STATUS[i.request?.status] || ['neutral', '—'];
      return `<tr><td>${userCell(i.name, i.email, i.initials)}</td><td>${esc(i.request?.from_department || '—')}</td><td>${esc(i.request?.to_department || '—')}</td>
        <td>${fmtDate(i.request?.effective_date)}</td><td>${delta(i.request)}</td><td>${pill(c, l === 'Active' ? 'Completed' : l)}</td></tr>`; },
    leaver: (i) => { const st = i.request?.status;
      const dep = st === 'completed' ? ['success', 'Completed'] : st === 'approved' ? ['warning', 'Scheduled'] : st === 'pending_approval' ? ['pending', 'Pending Approval'] : (REQ_STATUS[st] || ['neutral', '—']);
      const access = !i.access ? '—' : i.access.active === 0 ? tag('gray', 'Revoked') : i.days_remaining >= 0 ? tag('yellow', `Active (${i.days_remaining} day${i.days_remaining === 1 ? '' : 's'} remaining)`) : tag('red', `Active (${-i.days_remaining}d overdue)`);
      return `<tr><td>${userCell(i.name, i.email, i.initials)}</td><td>${esc(i.department || '—')}</td><td>${fmtDate(i.end_date)}</td><td>${pill(...dep)}</td><td>${access}</td>
        <td><div class="action-btns">${viewBtn(i.id)}${can('audit:read') ? `<button class="btn-secondary btn-xs" data-audit-q="${esc(i.email)}">Audit Trail</button>` : ''}</div></td></tr>`; },
    all: (i) => { const LS = { active: ['success', 'Active'], joiner: ['pending', 'Joiner'], mover: ['pending', 'Mover'], leaver: ['warning', 'Leaver'], terminated: ['neutral', 'Terminated'] }[i.lifecycle_state];
      return `<tr><td>${userCell(i.name, i.email, i.initials)}</td><td>${esc(i.department || '—')}</td><td>${esc(i.job_title || '—')}</td>
        <td>${pill(LEVEL_CLS[i.risk_level], `Score: ${i.risk_score}${i.risk_level === 'low' ? '' : ` (${cap(i.risk_level)})`}`)}</td>
        <td class="mono">${i.last_authentication_at ? timeAgo(i.last_authentication_at) : 'Never'}</td><td>${pill(...LS)}</td></tr>`; },
  };
  const EMPTY = { joiner: 'No joiners.', mover: 'No movers.', leaver: 'No leavers.', all: 'No identities found.' };

  async function loadIdentities() {
    const tb = $(TBODY[IDN.state]);
    tb.innerHTML = stateRow(6, 'Loading…');
    const p = new URLSearchParams({ state: IDN.state, limit: IDN.limit, offset: IDN.offset });
    if (IDN.q) p.set('q', IDN.q);
    try {
      const d = await api(`/identities?${p}`);
      IDN.total = d.total;
      tb.innerHTML = d.items.length ? d.items.map(ROW[IDN.state]).join('') : stateRow(6, IDN.q ? 'No identities match your search.' : EMPTY[IDN.state]);
      pager('idn', IDN);
    } catch (e) { tb.innerHTML = errRow(6, e, 'idn-retry'); const r = $('idn-retry'); if (r) r.onclick = loadIdentities; $('idn-range').textContent = ''; }
    loadCounts();
  }
  async function loadCounts() {
    try { const c = await api('/identities/counts'); $('count-joiner').textContent = c.joiner; $('count-mover').textContent = c.mover; $('count-leaver').textContent = c.leaver; $('count-directory').textContent = c.directory.toLocaleString(); } catch { /* keep placeholders */ }
  }

  async function openIdentity(id) {
    $('idm-title').textContent = 'Loading…'; $('idm-sub').textContent = ''; $('idm-body').innerHTML = '<div class="pu-state">Loading…</div>';
    openModal('identity-modal');
    try {
      const d = await api(`/identities/${id}`);
      $('idm-title').textContent = d.name; $('idm-sub').textContent = `${d.email} · ${d.employee_id}${d.is_demo ? ' · DEMO DATA' : ''}`;
      const kv = [['Department', d.department], ['Job title', d.job_title], ['Access profile', d.access_profile], ['Manager', d.manager], ['Type', d.identity_type],
        ['Lifecycle state', d.lifecycle_state], ['Start date', fmtDate(d.start_date)], ['End date', fmtDate(d.end_date)], ['Last sign-in', d.last_authentication_at ? timeAgo(d.last_authentication_at) : 'Never'],
        ['Risk', `${d.risk_score} / 100 (${d.risk_level})`]];
      $('idm-body').innerHTML = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:.4rem 1.5rem;font-size:.85rem">${kv.map(([k, v]) => `<div><span class="meta-label">${esc(k)}:</span> <span class="meta-val">${esc(v ?? '—')}</span></div>`).join('')}</div>
        <h3 style="margin:1.2rem 0 .5rem;font-size:.9rem">Entitlements (${d.entitlements.length})</h3>
        ${d.entitlements.length ? `<table class="data-table"><thead><tr><th>Entitlement</th><th>Application</th><th>Risk</th><th>Status</th></tr></thead><tbody>${d.entitlements.map((e) =>
          `<tr><td>${esc(e.name)}</td><td>${esc(e.application)}</td><td>${pill(LEVEL_CLS[e.risk_level], e.risk_level)}</td><td>${pill({ active: 'success', pending: 'pending', revoked: 'neutral', expired: 'neutral' }[e.status] || 'neutral', e.status)}</td></tr>`).join('')}</tbody></table>` : '<div class="pu-state">No entitlements.</div>'}
        <h3 style="margin:1.2rem 0 .5rem;font-size:.9rem">Recent risk assessments</h3>
        ${d.risk_history.length ? `<ul style="margin:0;padding-left:1.1rem;font-size:.82rem;line-height:1.7">${d.risk_history.slice(0, 5).map((r) => `<li>${fmtDate(r.assessed_at)} · <b>${r.score}</b> (${r.level})${r.triggers.length ? ` — ${esc(r.triggers.join('; '))}` : ''}</li>`).join('')}</ul>` : '<div class="pu-state">No assessments.</div>'}
        <h3 style="margin:1.2rem 0 .5rem;font-size:.9rem">Lifecycle requests</h3>
        ${d.requests.length ? `<ul style="margin:0;padding-left:1.1rem;font-size:.82rem;line-height:1.7">${d.requests.map((r) => `<li>${esc(r.ref)} · ${esc(r.type)} · ${esc(r.status.replace('_', ' '))} · ${timeAgo(r.created_at)}</li>`).join('')}</ul>` : '<div class="pu-state">None.</div>'}`;
    } catch (e) { $('idm-title').textContent = 'Could not load identity'; $('idm-body').innerHTML = `<div class="pu-state pu-state--error">${esc(e.message)}</div>`; }
  }

  /* onboarding modal: dropdowns come from the DB */
  let lookups = null;
  async function ensureLookups() { if (!lookups) lookups = await api('/meta/lookups'); return lookups; }
  window.openOnboard = async function () {
    try {
      const lk = await ensureLookups();
      const dept = $('user-dept'), prof = $('user-role');
      dept.innerHTML = lk.departments.map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
      const fillProfiles = () => {
        const mine = lk.access_profiles.filter((p) => p.department_id === dept.value), list = mine.length ? mine : lk.access_profiles;
        prof.innerHTML = list.map((p) => `<option value="${p.id}">${esc(p.name)}</option>`).join('');
      };
      dept.onchange = fillProfiles; fillProfiles();
      const start = $('user-start'); if (!start.value) start.value = new Date().toISOString().slice(0, 10);
      document.querySelectorAll('#add-user-form .field-error').forEach((e) => { e.textContent = ''; });
      openModal('add-user-modal');
    } catch (e) { showToast(`Could not load form options: ${e.message}`, 'danger'); }
  };
  window.submitAddUser = async function (e) {
    e.preventDefault();
    const btn = $('user-submit'); btn.disabled = true; btn.textContent = 'Submitting…';
    document.querySelectorAll('#add-user-form .field-error').forEach((x) => { x.textContent = ''; });
    try {
      const r = await api('/identities', { method: 'POST', body: {
        first_name: $('user-fname').value, last_name: $('user-lname').value, email: $('user-email').value,
        department_id: $('user-dept').value, access_profile_id: $('user-role').value, start_date: $('user-start').value } });
      closeModal('add-user-modal'); $('add-user-form').reset();
      showToast(`${r.name} submitted for approval (${r.request_ref}).`, 'success');
      refreshBadges(); loadCounts();
      if (document.querySelector('.page.active')?.id === 'page-users') loadIdentities();
    } catch (err) {
      const f = err.fields || {};
      if (f.email || err.code === 'email_exists') { document.querySelector('#add-user-form [data-for="email"]').textContent = f.email || err.message; }
      else if (f.start_date) document.querySelector('#add-user-form [data-for="start_date"]').textContent = f.start_date;
      else showToast(err.message, 'danger');
    } finally { btn.disabled = false; btn.textContent = 'Submit for Approval'; }
  };

  /* ───────────────────────── approvals ───────────────────────── */
  const APR = { status: 'pending', offset: 0, limit: 12, total: 0 };
  const TYPE = { joiner: ['join', 'JOINER ONBOARDING', 'Approve Provisioning', 'btn-primary'], mover: ['move', 'DEPT TRANSFER', 'Approve Transfer', 'btn-primary'],
    privilege: ['access', 'ELEVATED PRIVILEGE', 'Approve Access', 'btn-primary'], leaver: ['leave', 'LEAVER DEPROVISION', 'Revoke Immediately', 'btn-danger'] };
  function approvalCard(a) {
    const [cls, label, okLabel, okBtn] = TYPE[a.type];
    const title = { joiner: `${a.identity.name} · ${a.department || a.to_department || ''}`, mover: `${a.identity.name} · ${a.from_department || '?'} → ${a.to_department || '?'}`,
      privilege: `${a.identity.name} · ${a.added[0] || 'Privileged access'}`, leaver: `${a.identity.name} · ${a.department || ''}` }[a.type];
    const chips = [...a.added.map((x) => `<span class="app-chip">${a.type === 'mover' ? '+' : ''}${esc(x)}</span>`),
      ...a.removed.map((x) => `<span class="app-chip app-chip--revoke">${a.type === 'leaver' ? '' : '-'}${esc(x)}</span>`)];
    if (a.duration_hours) chips.push(`<span class="app-chip">Duration: ${a.duration_hours}h TTL</span>`);
    const risk = a.risk ? pill(LEVEL_CLS[a.risk.level], `Score: ${a.risk.score} (${cap(a.risk.level)})`) : pill('neutral', 'Not assessed');
    const reasonLabel = a.type === 'leaver' ? 'Reason' : 'Justification';
    const decided = a.status !== 'pending';
    const actions = decided
      ? `<div class="approval-actions" style="justify-content:space-between"><span class="kpi-subtext">${esc(cap(a.status))} ${timeAgo(a.decided_at)}${a.decision_comment ? ` · ${esc(a.decision_comment)}` : ''}</span>${pill(a.status === 'approved' ? 'success' : 'danger', a.status.toUpperCase())}</div>`
      : can('approvals:decide') ? `<div class="approval-actions"><button class="btn-secondary btn-sm" data-decide="reject" data-id="${a.id}">Reject</button>
          <button class="${okBtn} btn-sm" data-decide="approve" data-id="${a.id}">${okLabel}</button></div>` : '';
    return `<div class="card approval-card${a.priority === 'urgent' && !decided ? ' approval-card--urgent' : ''}" data-card="${a.id}">
      <div class="approval-top"><div class="approval-header-left"><span class="approval-type-tag approval-type-tag--${cls}">${label}</span><span class="approval-req-id">${esc(a.ref)}</span></div>
        <span class="approval-time mono">${timeAgo(a.requested_at)}</span></div>
      <h3 class="approval-title">${esc(title)}</h3>
      <div class="approval-systems">${chips.join('') || '<span class="kpi-subtext">No entitlement changes</span>'}</div>
      <div class="approval-meta-grid">
        <div><span class="meta-label">Effective Date:</span> <span class="meta-val">${fmtDate(a.effective_date)}</span></div>
        <div><span class="meta-label">Requester:</span> <span class="meta-val">${esc(a.requester || '—')}</span></div>
        ${a.justification ? `<div><span class="meta-label">${reasonLabel}:</span> <span class="meta-val">${esc(a.justification)}</span></div>` : ''}
        <div><span class="meta-label">Risk Assessment:</span> ${risk}</div></div>${actions}</div>`;
  }
  async function loadApprovals() {
    const grid = $('approvals-grid'); grid.innerHTML = '<div class="pu-state">Loading…</div>';
    try {
      const d = await api(`/approvals?status=${APR.status}&limit=${APR.limit}&offset=${APR.offset}`);
      APR.total = d.total;
      grid.innerHTML = d.items.length ? d.items.map(approvalCard).join('') : `<div class="card"><div class="pu-state">${APR.status === 'pending' ? 'No pending approvals. 🎉' : 'No approval history yet.'}</div></div>`;
      pager('appr', APR);
      $('approvals-count').textContent = `${d.counts.pending} pending item${d.counts.pending === 1 ? '' : 's'}`;
      const b = $('appr-badge'); b.textContent = d.counts.pending; b.hidden = d.counts.pending === 0; $('notif-dot').hidden = d.counts.pending === 0;
    } catch (e) { grid.innerHTML = `<div class="card"><div class="pu-state pu-state--error">${esc(e.message)} <button class="btn-secondary btn-xs" id="appr-retry">Retry</button></div></div>`; const r = $('appr-retry'); if (r) r.onclick = loadApprovals; }
  }
  async function decide(btn) {
    const card = btn.closest('.approval-card'); card.querySelectorAll('button').forEach((b) => { b.disabled = true; });
    const kind = btn.dataset.decide;
    try {
      const r = await api(`/approvals/${btn.dataset.id}/${kind}`, { method: 'POST', body: {} });
      showToast(`${r.ref}: ${r.note}`, kind === 'approve' ? 'success' : 'info');
    } catch (e) { showToast(e.message, 'danger'); }       // reflects the real outcome, including 409 "already decided"
    await loadApprovals();
  }

  /* ───────────────────────── risk analytics ───────────────────────── */
  const RISK = { offset: 0, limit: 10, total: 0 };
  const PALETTE = ['#dc2626', '#d97706', '#1d4ed8', '#0284c7', '#475569', '#7c3aed', '#0d9488', '#be185d', '#65a30d'];
  async function loadRisk() {
    const tb = $('risk-flagged'); tb.innerHTML = stateRow(6, 'Loading…');
    const [sum, fl] = await Promise.allSettled([api('/risk/summary'), api(`/risk/flagged?limit=${RISK.limit}&offset=${RISK.offset}`)]);
    if (sum.status === 'fulfilled') {
      const s = sum.value;
      $('risk-high').textContent = s.tiers.high.toLocaleString(); $('risk-med').textContent = s.tiers.medium.toLocaleString(); $('risk-low').textContent = s.tiers.low.toLocaleString();
      $('risk-compliance').textContent = s.compliance.percent === null ? '—' : `${s.compliance.percent}%`;
      $('risk-compliance-sub').textContent = s.compliance.total ? `${s.compliance.passing} of ${s.compliance.total} controls passing` : 'no controls tested';
      riskTrendChart.data.labels = s.trajectory.map((t) => t.label); riskTrendChart.data.datasets[0].data = s.trajectory.map((t) => t.avg_score); riskTrendChart.update();
      riskFactorsChart.data.labels = s.triggers.map((t) => t.label); riskFactorsChart.data.datasets[0].data = s.triggers.map((t) => t.count);
      riskFactorsChart.data.datasets[0].backgroundColor = s.triggers.map((_, i) => PALETTE[i % PALETTE.length]); riskFactorsChart.update();
    } else showToast(`Risk summary failed: ${sum.reason.message}`, 'danger');
    if (fl.status === 'fulfilled') {
      RISK.total = fl.value.total;
      tb.innerHTML = fl.value.items.length ? fl.value.items.map((i) => `<tr><td>${userCell(i.name, i.email)}</td><td>${esc(i.department || '—')}</td>
        <td>${pill('danger', `${i.risk_score} / 100`)}</td><td>${esc(i.triggers.join(' · ') || 'No trigger recorded')}</td><td class="mono">${timeAgo(i.last_review)}</td>
        <td><button class="btn-danger btn-xs" data-view="${i.id}">Investigate</button></td></tr>`).join('') : stateRow(6, 'No identities above the high-risk threshold.');
      pager('risk', RISK);
    } else { tb.innerHTML = errRow(6, fl.reason, 'risk-retry'); const r = $('risk-retry'); if (r) r.onclick = loadRisk; }
  }

  /* ───────────────────────── audit trail ───────────────────────── */
  const AUD = { category: '', severity: '', q: '', offset: 0, limit: 25, total: 0 };
  const SEV = { critical: ['crit', 'CRITICAL'], high: ['high', 'HIGH'], medium: ['med', 'MEDIUM'], low: ['info', 'LOW'], info: ['info', 'INFO'] };
  const OUTCOME = { success: 'success', pending: 'pending', flagged: 'warning', blocked: 'danger', failure: 'danger', denied: 'danger' };
  const audQuery = (extra = {}) => { const p = new URLSearchParams(extra); if (AUD.category) p.set('category', AUD.category); if (AUD.severity) p.set('severity', AUD.severity); if (AUD.q) p.set('q', AUD.q); return p; };
  async function loadAudit() {
    const tb = $('audit-body'); tb.innerHTML = stateRow(6, 'Loading…');
    try {
      const d = await api(`/audit-logs?${audQuery({ limit: AUD.limit, offset: AUD.offset })}`);
      AUD.total = d.total;
      tb.innerHTML = d.items.length ? d.items.map((a) => `<tr><td class="mono">${fmtStamp(a.occurred_at)}</td><td>${esc(a.event)}</td><td>${esc(a.actor)}</td><td>${esc(a.target || '—')}</td>
        <td><span class="sev-badge sev-badge--${SEV[a.severity][0]}">${SEV[a.severity][1]}</span></td><td>${pill(OUTCOME[a.outcome] || 'neutral', a.outcome.toUpperCase())}</td></tr>`).join('') : stateRow(6, 'No events match these filters.');
      pager('audit', AUD);
    } catch (e) { tb.innerHTML = errRow(6, e, 'audit-retry'); const r = $('audit-retry'); if (r) r.onclick = loadAudit; $('audit-range').textContent = ''; }
  }

  /* ───────────────────────── governance ───────────────────────── */
  async function loadGovernance() {
    try {
      const g = await api('/governance/summary');
      const ov = $('gov-overall'); ov.textContent = g.overall.percent === null ? 'No data' : `${g.overall.percent}% Compliant`; ov.className = `status-pill status-pill--${g.overall.percent >= 95 ? 'success' : 'warning'}`;
      $('gov-frameworks').innerHTML = g.frameworks.map((f) => { const cls = f.percent >= 95 ? 'success' : 'warning';
        return `<div class="compliance-item"><div class="compliance-item__top"><span class="compliance-name">${esc(f.name)}</span><span class="mono${cls === 'warning' ? ' text-warning' : ''}" title="${f.passing} of ${f.total} controls">${f.percent ?? '—'}%</span></div>
          <div class="progress-bar"><div class="progress-fill progress-fill--${cls}" style="width:${f.percent || 0}%"></div></div></div>`; }).join('') || '<div class="pu-state">No frameworks.</div>';
      $('gov-campaigns').innerHTML = g.campaigns.map((c) => { const done = c.status === 'completed';
        return `<div class="cert-item"><div><div class="cert-name">${esc(c.name)}</div><div class="cert-meta">${done ? `Completed ${fmtDate(c.completed_at)}` : `Due ${fmtDate(c.due_date)}`} · ${c.total} accounts${c.overdue ? ' · <span class="text-danger">Overdue</span>' : ''}</div></div>
          <div class="cert-progress-wrap"><div class="progress-bar"><div class="progress-fill progress-fill--${done ? 'success' : 'primary'}" style="width:${c.percent}%"></div></div>
          ${done ? '<span class="mono text-success text-sm">✓ Done</span>' : `<span class="mono text-sm">${c.percent}%</span>`}</div></div>`; }).join('') || '<div class="pu-state">No campaigns yet.</div>';
      const n = g.sod_conflicts.length, sc = $('gov-sod-count'); sc.textContent = n ? `${n} Conflict${n === 1 ? '' : 's'}` : 'No conflicts'; sc.className = `status-pill status-pill--${n ? 'danger' : 'success'}`;
      $('gov-sod').innerHTML = n ? g.sod_conflicts.map((c) => `<li class="sod-item"><div class="sod-body"><div class="sod-title">${esc(c.policy)}</div><div class="sod-user mono">${esc(c.identity.email)}</div></div>
        <button class="btn-danger btn-xs" data-view="${c.identity.id}" title="${esc(c.entitlements.join(' + '))}">Review</button></li>`).join('') : '<li class="pu-state">No segregation-of-duties conflicts detected.</li>';
      $('gov-connectors').innerHTML = g.connectors.map((c) => `<li class="system-item"><span class="system-name">${esc(c.name)}</span>${connPill(c.status)}</li>`).join('') || '<li class="pu-state">None.</li>';
    } catch (e) {
      ['gov-frameworks', 'gov-campaigns'].forEach((id) => { $(id).innerHTML = `<div class="pu-state pu-state--error">${esc(e.message)}</div>`; });
      $('gov-sod').innerHTML = `<li class="pu-state pu-state--error">${esc(e.message)}</li>`; $('gov-connectors').innerHTML = '';
    }
  }
  window.openCampaign = async function () {
    try {
      const lk = await ensureLookups();
      $('camp-dept').innerHTML = lk.departments.map((d) => `<option value="${d.id}">${esc(d.name)}</option>`).join('');
      const tomorrow = new Date(Date.now() + 14 * 864e5).toISOString().slice(0, 10); if (!$('camp-due').value) $('camp-due').value = tomorrow;
      document.querySelectorAll('#campaign-form .field-error').forEach((e) => { e.textContent = ''; });
      openModal('campaign-modal');
    } catch (e) { showToast(e.message, 'danger'); }
  };

  /* ───────────────────────── directory assistant ───────────────────────── */
  let welcomeHtml = '';
  window.injectPrompt = (t) => { const i = $('chat-input'); if (i) { i.value = t; i.focus(); } };
  function renderBlocks(blocks) {
    const wrap = document.createElement('div');
    blocks.forEach((b) => {
      let el;
      if (b.type === 'heading') { el = document.createElement('div'); el.style.fontWeight = '600'; el.style.margin = '.2rem 0'; el.textContent = b.text; }
      else if (b.type === 'text') { el = document.createElement('p'); el.style.margin = '.3rem 0'; el.textContent = b.text; }
      else if (b.type === 'list') { el = document.createElement('ul'); el.style.cssText = 'margin:.3rem 0;padding-left:1.1rem;line-height:1.7'; b.items.forEach((t) => { const li = document.createElement('li'); li.textContent = t; el.appendChild(li); }); }
      else if (b.type === 'kv') { el = document.createElement('div'); el.className = 'chat-step-box'; b.items.forEach(([k, v]) => { const r = document.createElement('div'); const s = document.createElement('span'); s.className = 'meta-label'; s.textContent = `${k}: `; r.append(s, document.createTextNode(v)); el.appendChild(r); }); }
      else if (b.type === 'action') { el = document.createElement('button'); el.className = 'btn-secondary btn-sm'; el.style.marginTop = '.4rem'; el.textContent = b.label;
        el.onclick = () => (b.action === 'open-onboard' ? openOnboard() : b.action.startsWith('nav:') && navigateTo(b.action.slice(4))); }
      if (el) wrap.appendChild(el);
    });
    return wrap;
  }
  function initChat() {
    const input = $('chat-input'), box = $('chat-messages'); if (!input || !box) return;
    welcomeHtml = box.innerHTML;
    const bubble = (cls, node) => { const d = document.createElement('div'); d.className = `chat-bubble chat-bubble--${cls}`; d.append(node); box.appendChild(d); box.scrollTop = box.scrollHeight; return d; };
    async function send() {
      const text = input.value.trim(); if (!text) return;
      box.querySelector('.chat-welcome')?.remove();
      bubble('user', document.createTextNode(text)); input.value = ''; input.style.height = 'auto';
      const wait = bubble('bot', document.createTextNode('Looking that up…'));
      try {
        const r = await api('/assistant/query', { method: 'POST', body: { query: text } });
        const out = renderBlocks(r.blocks); const src = document.createElement('div'); src.className = 'kpi-subtext'; src.style.marginTop = '.5rem'; src.textContent = r.source; out.appendChild(src);
        wait.replaceChildren(out);
      } catch (e) { wait.textContent = `Request failed: ${e.message}`; }
      box.scrollTop = box.scrollHeight;
    }
    $('send-btn').addEventListener('click', send);
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
    input.addEventListener('input', () => { input.style.height = 'auto'; input.style.height = Math.min(input.scrollHeight, 100) + 'px'; });
    $('new-chat-btn').addEventListener('click', () => { box.innerHTML = welcomeHtml; });
  }
  async function loadSaved() {
    const ul = $('chat-history');
    try {
      const d = await api('/approvals?status=all&limit=5');
      const L = { joiner: 'Onboard', mover: 'Mover', leaver: 'Offboard', privilege: 'Privilege' };
      ul.innerHTML = d.items.length ? d.items.map((a, i) => `<li class="chat-history-item${i ? '' : ' active'}" data-nav="approvals"><span class="chat-history-bullet"></span><div class="chat-history-body">
        <div class="chat-history-title">${esc(L[a.type])}: ${esc(a.identity.name)}</div><div class="chat-history-time">${esc(a.department || a.to_department || '')} · ${timeAgo(a.requested_at)}</div></div></li>`).join('') : '<li class="pu-state">No requests yet.</li>';
    } catch (e) { ul.innerHTML = `<li class="pu-state pu-state--error">${esc(e.message)}</li>`; }
  }

  /* ───────────────────────── wiring ───────────────────────── */
  const LOADERS = { dashboard: loadDashboard, users: () => { loadIdentities(); }, approvals: loadApprovals, risk: loadRisk, audit: loadAudit, governance: loadGovernance, 'ai-chat': loadSaved };

  document.addEventListener('DOMContentLoaded', () => {
    initChat();
    document.querySelectorAll('.tab[data-tab]').forEach((b) => b.addEventListener('click', () => { IDN.state = TAB_STATE[b.dataset.tab]; IDN.offset = 0; loadIdentities(); }));
    $('user-search').addEventListener('input', debounce((e) => { IDN.q = e.target.value.trim(); IDN.offset = 0; loadIdentities(); }));
    $('idn-prev').onclick = () => { IDN.offset = Math.max(0, IDN.offset - IDN.limit); loadIdentities(); };
    $('idn-next').onclick = () => { IDN.offset += IDN.limit; loadIdentities(); };
    $('appr-tabs').addEventListener('click', (e) => { const b = e.target.closest('.pu-tab'); if (!b) return; document.querySelectorAll('#appr-tabs .pu-tab').forEach((t) => t.classList.toggle('active', t === b)); APR.status = b.dataset.status; APR.offset = 0; loadApprovals(); });
    $('appr-prev').onclick = () => { APR.offset = Math.max(0, APR.offset - APR.limit); loadApprovals(); };
    $('appr-next').onclick = () => { APR.offset += APR.limit; loadApprovals(); };
    $('risk-prev').onclick = () => { RISK.offset = Math.max(0, RISK.offset - RISK.limit); loadRisk(); };
    $('risk-next').onclick = () => { RISK.offset += RISK.limit; loadRisk(); };
    $('risk-export').onclick = () => download('/risk/flagged/export', 'flagged-identities.csv');
    $('audit-event-filter').onchange = (e) => { AUD.category = e.target.value; AUD.offset = 0; loadAudit(); };
    $('audit-severity-filter').onchange = (e) => { AUD.severity = e.target.value; AUD.offset = 0; loadAudit(); };
    $('audit-search').addEventListener('input', debounce((e) => { AUD.q = e.target.value.trim(); AUD.offset = 0; loadAudit(); }));
    $('audit-prev').onclick = () => { AUD.offset = Math.max(0, AUD.offset - AUD.limit); loadAudit(); };
    $('audit-next').onclick = () => { AUD.offset += AUD.limit; loadAudit(); };
    $('audit-export').onclick = () => download(`/audit-logs/export?${audQuery()}`, 'audit-log.csv');
    $('camp-scope').onchange = (e) => { $('camp-dept-wrap').hidden = e.target.value !== 'department'; };
    $('campaign-form').addEventListener('submit', async (e) => {
      e.preventDefault(); const btn = $('camp-submit'); btn.disabled = true;
      document.querySelectorAll('#campaign-form .field-error').forEach((x) => { x.textContent = ''; });
      try {
        const scope = $('camp-scope').value;
        const r = await api('/governance/campaigns', { method: 'POST', body: { name: $('camp-name').value, scope, department_id: scope === 'department' ? $('camp-dept').value : null, due_date: $('camp-due').value } });
        closeModal('campaign-modal'); $('campaign-form').reset(); showToast(`Campaign launched for ${r.accounts} accounts.`, 'success'); loadGovernance();
      } catch (err) {
        const f = err.fields || {}; const keys = Object.keys(f);
        if (keys.length) keys.forEach((k) => { const el = document.querySelector(`#campaign-form [data-for="${k}"]`); if (el) el.textContent = f[k]; });
        else showToast(err.message, 'danger');
      } finally { btn.disabled = false; }
    });
    // delegated actions rendered by the loaders above
    document.addEventListener('click', (e) => {
      const view = e.target.closest('[data-view]'); if (view) return openIdentity(view.dataset.view);
      const dec = e.target.closest('[data-decide]'); if (dec) return decide(dec);
      const nav = e.target.closest('[data-nav]'); if (nav) return navigateTo(nav.dataset.nav);
      const aq = e.target.closest('[data-audit-q]'); if (aq) { AUD.q = aq.dataset.auditQ; $('audit-search').value = AUD.q; AUD.offset = 0; navigateTo('audit'); }
    });
    // global search -> directory search (server-side)
    const gs = $('global-search');
    if (gs) gs.addEventListener('keydown', (e) => { if (e.key !== 'Enter' || !gs.value.trim()) return; IDN.q = gs.value.trim(); IDN.offset = 0; IDN.state = 'all';
      $('user-search').value = IDN.q; document.querySelector('.tab[data-tab="all-users"]')?.click(); navigateTo('users'); });
  });

  document.addEventListener('page:show', (e) => { const fn = LOADERS[e.detail]; if (fn) fn(); });
  document.addEventListener('auth:ready', () => {
    refreshBadges(); refreshSystemStatus(); loadCounts();
    const active = document.querySelector('.page.active')?.id?.replace('page-', '');
    if (LOADERS[active]) LOADERS[active]();
    setInterval(() => { if (document.visibilityState === 'visible') { refreshBadges(); refreshSystemStatus(); } }, 60000);
  });
})();
