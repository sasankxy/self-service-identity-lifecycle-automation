/**
 * IdentityOS auth client (shared by index.html and login.html).
 * Tokens live ONLY in HttpOnly cookies; this file never sees or stores them.
 * The CSRF token (a readable, non-secret-bearing cookie) is echoed in X-CSRF-Token.
 */
class ApiError extends Error {
  constructor(status, code, message, fields) {
    super(message);
    this.status = status; this.code = code; this.fields = fields || null;
  }
}

const Auth = (() => {
  const API = '/api/v1';
  let me = null;
  let refreshing = null;

  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  function csrfToken() {
    const m = document.cookie.split('; ').find((c) => c.startsWith('identityos_csrf='));
    return m ? m.slice('identityos_csrf='.length) : '';
  }
  async function fetchCsrf() { await fetch(`${API}/auth/csrf`, { credentials: 'same-origin' }); }

  function redirectToLogin(reason) {
    if (!location.pathname.endsWith('login.html')) location.replace(`login.html?reason=${encodeURIComponent(reason)}`);
  }

  async function refreshSession() {
    refreshing = refreshing || request('/auth/refresh', { method: 'POST', _noRetry: true })
      .finally(() => { refreshing = null; });
    return refreshing;
  }

  async function request(path, { method = 'GET', body, _noRetry = false, _csrfRetried = false } = {}) {
    const headers = { Accept: 'application/json' };
    if (method !== 'GET') {
      if (!csrfToken()) await fetchCsrf();
      headers['X-CSRF-Token'] = csrfToken();
    }
    if (body !== undefined) headers['Content-Type'] = 'application/json';

    let res;
    try {
      res = await fetch(API + path, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
    } catch {
      throw new ApiError(0, 'network_error', 'Cannot reach the server. Check your connection and try again.');
    }
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    if (res.ok) return data;

    const err = (data && data.error) || { code: `http_${res.status}`, message: `Request failed (${res.status}).` };
    if (res.status === 403 && err.code === 'csrf_failed' && !_csrfRetried) {
      await fetchCsrf();
      return request(path, { method, body, _noRetry, _csrfRetried: true });
    }
    if (res.status === 401 && err.code === 'token_expired' && !_noRetry) {
      try { await refreshSession(); } catch { redirectToLogin('expired'); throw new ApiError(401, 'session_expired', 'Your session has expired.'); }
      return request(path, { method, body, _noRetry: true, _csrfRetried });
    }
    if (res.status === 401 && !path.startsWith('/auth/login') && path !== '/auth/me') {
      redirectToLogin(err.code === 'session_revoked' ? 'revoked' : 'expired');
    }
    throw new ApiError(res.status, err.code, err.message, err.fields);
  }

  // ---- page bootstrap for protected pages ----
  const NAV_PERMISSION = {
    dashboard: 'dashboard:read', 'ai-chat': 'identities:read', users: 'identities:read', approvals: 'approvals:read',
    risk: 'risk:read', audit: 'audit:read', governance: 'governance:read', 'platform-users': 'users:read',
  };
  const ROLE_LABEL = { super_admin: 'Super Administrator', iam_admin: 'IAM Administrator', approver: 'Approver', auditor: 'Auditor', employee: 'Employee' };

  function initials(name) { return name.split(/\s+/).filter(Boolean).slice(0, 2).map((w) => w[0].toUpperCase()).join('') || '?'; }

  function applyUser() {
    const $ = (id) => document.getElementById(id);
    if ($('user-avatar')) $('user-avatar').textContent = initials(me.full_name);
    if ($('user-name')) $('user-name').textContent = me.full_name;
    if ($('user-role')) $('user-role').textContent = me.roles.map((r) => ROLE_LABEL[r] || r).join(', ') || 'No role';

    document.querySelectorAll('[data-perm]').forEach((el) => { el.hidden = !can(el.dataset.perm); });
    let firstAllowed = null;
    document.querySelectorAll('.nav-item').forEach((btn) => {
      const allowed = can(NAV_PERMISSION[btn.dataset.page]);
      btn.hidden = !allowed;
      if (allowed && !firstAllowed) firstAllowed = btn.dataset.page;
    });
    document.querySelectorAll('.nav-section-label').forEach((label) => {
      let el = label.nextElementSibling, any = false;
      while (el && !el.classList.contains('nav-section-label')) { if (el.matches('.nav-item') && !el.hidden) any = true; el = el.nextElementSibling; }
      label.hidden = !any;
    });
    const active = document.querySelector('.nav-item.active');
    if ((!active || active.hidden) && window.navigateTo) window.navigateTo(firstAllowed || 'no-access');
  }

  const can = (perm) => !!me && !!perm && me.permissions.includes(perm);

  async function boot() {
    try {
      me = await request('/auth/me');
    } catch (e) {
      if (e.status === 401) return redirectToLogin(e.code === 'token_expired' ? 'expired' : 'required');
      if (e.status === 403) return redirectToLogin('inactive');
      return showFatal(e.message);
    }
    applyUser();
    document.body.classList.remove('auth-pending');
    document.dispatchEvent(new CustomEvent('auth:ready', { detail: me }));
    const out = document.getElementById('logout-btn');
    if (out) out.addEventListener('click', logout);
  }

  function showFatal(message) {
    document.body.classList.remove('auth-pending');
    document.body.innerHTML = `<div class="auth-fatal"><h2>Service unavailable</h2><p>${esc(message)}</p>
      <button class="btn-primary" onclick="location.reload()">Retry</button></div>`;
  }

  async function logout() {
    try {
      await request('/auth/logout', { method: 'POST' });
    } catch (e) {
      if (window.showToast) showToast(`Sign out failed: ${e.message}`, 'danger');
      return;
    }
    location.replace('login.html?reason=signedout');
  }

  return { request, can, esc, boot, logout, ROLE_LABEL, get me() { return me; } };
})();

if (!location.pathname.endsWith('login.html')) document.addEventListener('DOMContentLoaded', () => Auth.boot());
