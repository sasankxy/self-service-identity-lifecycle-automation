/* IdentityOS — notifications bell.
   Aggregates pending approvals, pending platform-user signups and high-risk
   identities into a dropdown with a count badge. Clicking an item opens its
   page and highlights the matching row/card. Self-contained: injects its own
   CSS; load AFTER pages.js. */
(() => {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => Auth.esc(s);
  const btn = $('notif-btn');
  if (!btn) return;
  const LIMIT = 5;
  let panel, countEl, items = [], totals = { approvals: 0, signups: 0, risk: 0 }, loading = false, failed = false;

  /* ---------- styles ---------- */
  const css = document.createElement('style');
  css.textContent = `
  #notif-dot{display:none!important}
  .notif-count{position:absolute;top:-6px;right:-6px;min-width:18px;height:18px;padding:0 5px;box-sizing:border-box;border-radius:99px;
    background:var(--danger);color:#fff;font:700 .65rem/18px var(--font-sans);text-align:center;border:2px solid var(--bg-surface);pointer-events:none}
  .notif-count[hidden]{display:none}
  .notif-panel{position:fixed;z-index:120;width:380px;max-width:calc(100vw - 1.5rem);max-height:min(560px,calc(100vh - 90px));display:flex;flex-direction:column;
    background:var(--bg-surface);color:var(--text-main);border:1px solid var(--border-subtle);border-radius:12px;box-shadow:var(--shadow-lg,0 20px 40px rgba(0,0,0,.2));
    font-family:var(--font-sans);opacity:0;transform:translateY(-6px);pointer-events:none;transition:opacity .15s,transform .15s}
  .notif-panel.open{opacity:1;transform:none;pointer-events:auto}
  .notif-head{display:flex;align-items:center;justify-content:space-between;padding:.8rem 1rem;border-bottom:1px solid var(--border-subtle)}
  .notif-head h3{margin:0;font-size:.9rem}
  .notif-head span{font-size:.72rem;color:var(--text-muted)}
  .notif-list{overflow-y:auto;padding:.35rem}
  .notif-group{padding:.55rem .65rem .25rem;font-size:.68rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--text-muted)}
  .notif-item{display:flex;gap:.7rem;width:100%;text-align:left;padding:.6rem .65rem;border:0;border-radius:9px;background:none;color:inherit;font:inherit;cursor:pointer}
  .notif-item:hover,.notif-item:focus-visible{background:var(--bg-subtle);outline:0}
  .notif-ico{flex:none;width:32px;height:32px;border-radius:9px;display:grid;place-items:center;font-size:.9rem;font-weight:700}
  .notif-ico--approval{background:var(--info-bg);color:var(--info)}
  .notif-ico--signup{background:var(--warning-bg);color:var(--warning)}
  .notif-ico--risk{background:var(--danger-bg);color:var(--danger)}
  .notif-body{min-width:0;flex:1}
  .notif-title{font-size:.82rem;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .notif-sub{font-size:.74rem;color:var(--text-muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .notif-time{flex:none;font-size:.68rem;color:var(--text-muted);padding-top:2px}
  .notif-more{display:block;width:100%;padding:.5rem;border:0;background:none;color:var(--accent-primary);font:600 .75rem var(--font-sans);cursor:pointer;text-align:center}
  .notif-empty{padding:2rem 1rem;text-align:center;color:var(--text-muted);font-size:.85rem}
  .notif-foot{padding:.4rem;border-top:1px solid var(--border-subtle);text-align:center}
  .notif-highlight{animation:notif-flash 2.6s ease-out 1;position:relative}
  @keyframes notif-flash{0%,35%{box-shadow:0 0 0 3px var(--accent-primary);background-color:var(--accent-primary-light)}100%{box-shadow:0 0 0 0 transparent}}
  tr.notif-highlight>td{animation:notif-flash-td 2.6s ease-out 1}
  @keyframes notif-flash-td{0%,35%{background-color:var(--accent-primary-light)}100%{background-color:transparent}}
  tr.notif-highlight{animation:none;box-shadow:none}
  @media (max-width:520px){.notif-panel{left:.75rem!important;right:.75rem!important;width:auto}}
  @media (prefers-reduced-motion:reduce){.notif-panel{transition:none}.notif-highlight,tr.notif-highlight>td{animation:none;background-color:var(--accent-primary-light)}}`;
  document.head.appendChild(css);

  /* ---------- DOM ---------- */
  countEl = document.createElement('span');
  countEl.className = 'notif-count'; countEl.hidden = true; countEl.setAttribute('aria-hidden', 'true');
  btn.appendChild(countEl);
  btn.setAttribute('aria-haspopup', 'dialog'); btn.setAttribute('aria-expanded', 'false');

  panel = document.createElement('div');
  panel.className = 'notif-panel'; panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-label', 'Notifications');
  document.body.appendChild(panel);

  /* ---------- helpers ---------- */
  function ago(iso) {
    if (!iso) return '';
    const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 60) return 'now'; if (s < 3600) return `${Math.floor(s / 60)}m`;
    if (s < 86400) return `${Math.floor(s / 3600)}h`; return `${Math.floor(s / 86400)}d`;
  }
  const TYPE_LABEL = { joiner: 'Joiner', mover: 'Transfer', privilege: 'Elevated access', leaver: 'Leaver' };

  /* ---------- data ---------- */
  async function refresh() {
    if (loading || typeof Auth === 'undefined' || !Auth.me) return;
    loading = true;
    try {
    const jobs = [
      Auth.can('approvals:read') ? Auth.request(`/approvals?status=pending&limit=${LIMIT}`) : Promise.resolve(null),
      Auth.can('users:read') ? Auth.request(`/admin/users?status=pending&limit=${LIMIT}`) : Promise.resolve(null),
      Auth.request(`/risk/flagged?limit=${LIMIT}`).catch(() => null),   // silently skipped if the role can't read risk
    ];
    const [ap, su, rk] = await Promise.allSettled(jobs);
    failed = [ap, su].every((r) => r.status === 'rejected');
    const val = (r) => (r.status === 'fulfilled' ? r.value : null);
    const A = val(ap), S = val(su), R = val(rk);
    items = [];
    if (A) A.items.forEach((a) => items.push({ kind: 'approval', id: a.id, time: a.requested_at, urgent: a.priority === 'urgent',
      title: `${TYPE_LABEL[a.type] || 'Request'}: ${a.identity?.name || a.ref}`, sub: `${a.ref}${a.requester ? ' · by ' + a.requester : ''}${a.priority === 'urgent' ? ' · Urgent' : ''}` }));
    if (S) S.items.forEach((u) => items.push({ kind: 'signup', id: u.id, time: u.created_at, title: `Access request: ${u.full_name}`, sub: u.email }));
    if (R) R.items.forEach((i) => items.push({ kind: 'risk', id: i.id, time: i.last_review, title: `High risk: ${i.name} (${i.risk_score}/100)`, sub: (i.triggers || []).join(' · ') || i.department || 'Above high-risk threshold' }));
    totals = { approvals: A ? A.total ?? A.counts?.pending ?? A.items.length : 0, signups: S ? S.total : 0, risk: R ? R.total : 0 };
    } catch (err) { console.warn('[notifications] refresh failed:', err); failed = true; }
    finally { loading = false; }
    const n = totals.approvals + totals.signups + totals.risk;
    countEl.textContent = n > 99 ? '99+' : String(n); countEl.hidden = n === 0;
    btn.setAttribute('aria-label', n ? `Notifications, ${n} need attention` : 'Notifications');
    if (panel.classList.contains('open')) render();
  }

  /* ---------- render ---------- */
  const GROUPS = [['approval', 'Pending approvals', 'approvals', '✓', 'approvals'], ['signup', 'Access requests', 'signups', '+', 'platform-users'], ['risk', 'High-risk identities', 'risk', '!', 'risk']];
  function render() {
    const n = totals.approvals + totals.signups + totals.risk;
    let html = `<div class="notif-head"><h3>Notifications</h3><span>${n ? `${n} need attention` : 'All clear'}</span></div><div class="notif-list">`;
    if (!n) html += `<div class="notif-empty">${failed ? 'Couldn’t load notifications.' : 'You’re all caught up 🎉'}</div>`;
    GROUPS.forEach(([kind, label, key, icon, page]) => {
      const list = items.filter((i) => i.kind === kind);
      if (!list.length) return;
      html += `<div class="notif-group">${label}</div>` + list.map((i) => `
        <button class="notif-item" data-kind="${kind}" data-id="${esc(i.id)}">
          <span class="notif-ico notif-ico--${kind}">${icon}</span>
          <span class="notif-body"><div class="notif-title">${esc(i.title)}</div><div class="notif-sub">${esc(i.sub)}</div></span>
          <span class="notif-time">${ago(i.time)}</span></button>`).join('');
      if (totals[key] > list.length) html += `<button class="notif-more" data-more="${page}">View all ${totals[key]} →</button>`;
    });
    panel.innerHTML = html + '</div>';
  }

  /* ---------- open / close ---------- */
  function place() {
    const r = btn.getBoundingClientRect();
    panel.style.top = `${r.bottom + 8}px`;
    panel.style.right = `${Math.max(12, window.innerWidth - r.right)}px`;
    panel.style.left = 'auto';
  }
  function setOpen(open) {
    if (open) { place(); render(); refresh(); }
    panel.classList.toggle('open', open); btn.setAttribute('aria-expanded', String(open));
  }
  btn.addEventListener('click', (e) => { e.stopPropagation(); setOpen(!panel.classList.contains('open')); });
  document.addEventListener('click', (e) => { if (!panel.contains(e.target) && !btn.contains(e.target)) setOpen(false); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && panel.classList.contains('open')) { setOpen(false); btn.focus(); } });
  window.addEventListener('resize', () => { if (panel.classList.contains('open')) place(); });

  /* ---------- go to + highlight ---------- */
  const TARGET = {
    approval: { nav: 'nav-approvals', tabs: '#appr-tabs', find: (id) => document.querySelector(`.approval-card[data-card="${CSS.escape(id)}"]`) },
    signup: { nav: 'nav-platform-users', tabs: '#pu-tabs', find: (id) => document.querySelector(`tr[data-row="${CSS.escape(id)}"]`) },
    risk: { nav: 'nav-risk', tabs: null, find: (id) => document.querySelector(`#risk-flagged [data-view="${CSS.escape(id)}"]`)?.closest('tr') },
  };
  function goTo(kind, id) {
    const t = TARGET[kind]; setOpen(false);
    const nav = $(t.nav); if (!nav) return;
    nav.click();                                              // runs navigateTo + that page's loader
    if (t.tabs) {                                             // make sure we're on the "pending" tab
      const tab = document.querySelector(`${t.tabs} .pu-tab[data-status="pending"]`);
      if (tab && !tab.classList.contains('active')) tab.click();
    }
    if (!id) return;
    const started = Date.now(); let firstHit = 0, scrolled = false;
    const timer = setInterval(() => {
      const el = t.find(id), now = Date.now();
      if (el && !el.classList.contains('notif-highlight')) {
        el.classList.add('notif-highlight');
        if (!scrolled) { el.scrollIntoView({ behavior: 'smooth', block: 'center' }); scrolled = true; }
        firstHit = firstHit || now;
      }
      if ((firstHit && now - firstHit > 3000) || now - started > 7000) clearInterval(timer);
    }, 150);
  }
  panel.addEventListener('click', (e) => {
    const it = e.target.closest('.notif-item'); if (it) return goTo(it.dataset.kind, it.dataset.id);
    const more = e.target.closest('[data-more]');
    if (more) goTo({ approvals: 'approval', 'platform-users': 'signup', risk: 'risk' }[more.dataset.more], null);
  });

  /* ---------- keep the count fresh ---------- */
  document.addEventListener('auth:ready', refresh);
  // Don't depend on event timing: retry until the session is loaded.
  let tries = 0; const boot = setInterval(() => { tries++; if (typeof Auth !== 'undefined' && Auth.me) { clearInterval(boot); refresh(); } else if (tries > 40) clearInterval(boot); }, 500);
  let t; document.addEventListener('page:show', () => { clearTimeout(t); t = setTimeout(refresh, 1200); });
  setInterval(() => { if (document.visibilityState === 'visible') refresh(); }, 60000);
  if (typeof Auth !== 'undefined' && Auth.me) refresh();
})();