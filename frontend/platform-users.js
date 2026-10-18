/** Platform Users (portal login accounts) — approval queue backed by /api/v1/admin/users. */
(() => {
  const $ = (id) => document.getElementById(id);
  const esc = (s) => Auth.esc(s);
  const ALL_ROLES = ['employee', 'approver', 'auditor', 'iam_admin', 'super_admin'];
  const PRIVILEGED = ['iam_admin', 'super_admin'];
  const st = { status: 'pending', q: '', offset: 0, limit: 25, total: 0, loading: false };
  let pendingAction = null;

  const roleOptions = (selected) => ALL_ROLES
    .filter((r) => Auth.can('roles:grant_privileged') || !PRIVILEGED.includes(r) || r === selected)
    .map((r) => `<option value="${r}" ${r === selected ? 'selected' : ''}>${esc(Auth.ROLE_LABEL[r])}</option>`).join('');

  const fmt = (iso) => (iso ? new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—');
  const PILL = { pending: 'pending', active: 'success', suspended: 'warning', disabled: 'danger', rejected: 'danger' };

  function rowActions(u) {
    if (u.id === Auth.me.id) return '<span class="kpi-subtext">You</span>';
    const priv = u.roles.some((r) => PRIVILEGED.includes(r)) && !Auth.can('roles:grant_privileged');
    if (priv) return '<span class="kpi-subtext">Super Administrator required</span>';
    if (!Auth.can('users:approve')) return '';
    if (u.status === 'pending') {
      return `<div class="pu-actions"><select data-role aria-label="Role">${roleOptions('employee')}</select>
        <button class="btn-approve btn-xs" data-act="approve" data-id="${u.id}">Approve</button>
        <button class="btn-danger-outline btn-xs" data-act="reject" data-id="${u.id}">Reject</button></div>`;
    }
    if (u.status === 'active') {
      const roles = Auth.can('users:manage_roles') ? `<select data-role aria-label="Role">${roleOptions(u.roles[0])}</select>
        <button class="btn-secondary btn-xs" data-act="roles" data-id="${u.id}">Set role</button>` : '';
      return `<div class="pu-actions">${roles}<button class="btn-danger-outline btn-xs" data-act="suspend" data-id="${u.id}">Suspend</button></div>`;
    }
    if (u.status === 'suspended') return `<div class="pu-actions"><button class="btn-secondary btn-xs" data-act="reactivate" data-id="${u.id}">Reactivate</button></div>`;
    return '';
  }

  function renderRows(items) {
    return items.map((u) => `<tr data-row="${u.id}">
      <td><div class="user-cell"><div class="user-cell-avatar">${esc(u.full_name.split(' ').map((w) => w[0]).slice(0, 2).join('').toUpperCase())}</div>
        <div><div class="user-cell-name">${esc(u.full_name)}</div><div class="user-cell-email">${esc(u.email)}</div></div></div></td>
      <td>${u.roles.map((r) => esc(Auth.ROLE_LABEL[r] || r)).join(', ') || '—'}</td>
      <td><span class="status-pill status-pill--${PILL[u.status] || 'neutral'}">${esc(u.status)}</span></td>
      <td>${fmt(u.created_at)}</td><td>${fmt(u.last_login_at)}</td><td>${rowActions(u)}</td></tr>`).join('');
  }

  function setBody(html) { $('pu-body').innerHTML = html; }
  const stateRow = (msg, cls = '') => `<tr><td colspan="6"><div class="pu-state ${cls}">${msg}</div></td></tr>`;

  async function load() {
    if (st.loading) return;
    st.loading = true;
    setBody(stateRow('Loading accounts…'));
    const p = new URLSearchParams({ limit: st.limit, offset: st.offset });
    if (st.status !== 'all') p.set('status', st.status);
    if (st.q) p.set('q', st.q);
    try {
      const data = await Auth.request(`/admin/users?${p}`);
      st.total = data.total;
      setBody(data.items.length ? renderRows(data.items) : stateRow(st.q ? 'No accounts match your search.' : `No ${st.status === 'all' ? '' : st.status + ' '}accounts.`));
      const from = data.total ? st.offset + 1 : 0, to = Math.min(st.offset + st.limit, data.total);
      $('pu-range').textContent = `${from}–${to} of ${data.total}`;
      $('pu-prev').disabled = st.offset === 0; $('pu-next').disabled = to >= data.total;
    } catch (e) {
      setBody(stateRow(`${esc(e.message)} <button class="btn-secondary btn-xs" id="pu-retry">Retry</button>`, 'pu-state--error'));
      const r = $('pu-retry'); if (r) r.onclick = load;
    } finally { st.loading = false; }
    updateBadge();
  }

  async function updateBadge() {
    try {
      const d = await Auth.request('/admin/users?status=pending&limit=1');
      const b = $('pu-badge'); b.textContent = d.total; b.hidden = d.total === 0;
    } catch { /* badge is best-effort; the table shows real errors */ }
  }

  async function act(kind, id, extra = {}) {
    const base = `/admin/users/${id}`;
    const call = { approve: ['/approve', 'POST'], reject: ['/reject', 'POST'], suspend: ['/suspend', 'POST'],
      reactivate: ['/reactivate', 'POST'], roles: ['/roles', 'PUT'] }[kind];
    try {
      await Auth.request(base + call[0], { method: call[1], body: extra });
      showToast({ approve: 'Account approved', reject: 'Account rejected', suspend: 'Account suspended — sessions revoked',
        reactivate: 'Account reactivated', roles: 'Role updated' }[kind], 'success');
    } catch (e) {
      showToast(e.message, 'danger');      // never claim success when the backend refused
    }
    await load();
  }

  function askReason(kind, id, title) {
    pendingAction = { kind, id };
    $('pu-reason-title').textContent = title; $('pu-reason-text').value = '';
    openModal('pu-reason-modal');
  }

  document.addEventListener('DOMContentLoaded', () => {
    const page = $('page-platform-users'); if (!page) return;
    $('pu-tabs').addEventListener('click', (e) => {
      const b = e.target.closest('.pu-tab'); if (!b) return;
      document.querySelectorAll('.pu-tab').forEach((t) => t.classList.toggle('active', t === b));
      st.status = b.dataset.status; st.offset = 0; load();
    });
    let timer; $('pu-search').addEventListener('input', (e) => { clearTimeout(timer); timer = setTimeout(() => { st.q = e.target.value.trim(); st.offset = 0; load(); }, 300); });
    $('pu-prev').onclick = () => { st.offset = Math.max(0, st.offset - st.limit); load(); };
    $('pu-next').onclick = () => { st.offset += st.limit; load(); };
    $('pu-body').addEventListener('click', (e) => {
      const btn = e.target.closest('[data-act]'); if (!btn) return;
      const { act: kind, id } = btn.dataset; const sel = btn.closest('tr').querySelector('select[data-role]');
      if (kind === 'approve') act('approve', id, { role: sel.value });
      else if (kind === 'roles') act('roles', id, { roles: [sel.value] });
      else if (kind === 'reactivate') act('reactivate', id);
      else if (kind === 'reject') askReason('reject', id, 'Reject account request');
      else if (kind === 'suspend') askReason('suspend', id, 'Suspend account');
    });
    $('pu-reason-form').addEventListener('submit', (e) => {
      e.preventDefault(); if (!pendingAction) return;
      const { kind, id } = pendingAction; pendingAction = null;
      closeModal('pu-reason-modal'); act(kind, id, { reason: $('pu-reason-text').value.trim() });
    });
    $('nav-platform-users').addEventListener('click', load);
  });

  document.addEventListener('auth:ready', () => { if (Auth.can('users:read')) updateBadge(); });
})();
