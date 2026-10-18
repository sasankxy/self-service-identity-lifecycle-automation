(() => {
  const $ = (s, r = document) => r.querySelector(s);
  document.documentElement.setAttribute('data-theme', localStorage.getItem('identityos-theme') || 'light');

  const banner = $('#auth-banner');
  function showBanner(text, kind = 'info') {
    banner.textContent = text; banner.className = `auth-banner auth-banner--${kind}`; banner.hidden = false;
  }
  const clearBanner = () => { banner.hidden = true; };

  const REASONS = {
    expired: ['Your session expired. Please sign in again.', 'warn'],
    revoked: ['Your session was ended. Please sign in again.', 'warn'],
    inactive: ['Your account is no longer active. Contact an administrator.', 'danger'],
    signedout: ['You have been signed out.', 'success'],
    required: ['Please sign in to continue.', 'info'],
  };
  const reason = new URLSearchParams(location.search).get('reason');
  if (REASONS[reason]) showBanner(...REASONS[reason]);

  // Already signed in? Skip the form.
  Auth.request('/auth/me').then(() => location.replace('/')).catch(() => {});

  // ---- tabs ----
  function setView(view) {
    $('#signin-form').hidden = view !== 'signin';
    $('#signup-form').hidden = view !== 'signup';
    $('#tab-signin').classList.toggle('active', view === 'signin');
    $('#tab-signup').classList.toggle('active', view === 'signup');
    clearBanner();
  }
  $('#tab-signin').onclick = () => setView('signin');
  $('#tab-signup').onclick = () => setView('signup');

  // ---- helpers ----
  function clearErrors(form) { form.querySelectorAll('.field-error').forEach((e) => { e.textContent = ''; }); form.querySelectorAll('input').forEach((i) => i.classList.remove('invalid')); }
  function showFieldErrors(form, fields) {
    let shown = false;
    Object.entries(fields || {}).forEach(([name, msg]) => {
      const el = form.querySelector(`.field-error[data-for="${name}"]`) || form.querySelector('.field-error[data-for="_"]');
      if (el) { el.textContent = msg; shown = true; const input = form.querySelector(`[name="${name}"]`); if (input) input.classList.add('invalid'); }
    });
    return shown;
  }
  function busy(form, on) {
    const btn = form.querySelector('button[type=submit]');
    btn.disabled = on;
    btn.dataset.label = btn.dataset.label || btn.textContent;
    btn.textContent = on ? 'Please wait…' : btn.dataset.label;
  }
  const formData = (form) => Object.fromEntries(new FormData(form).entries());

  // ---- sign in ----
  $('#signin-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target; clearErrors(form); clearBanner();
    const data = formData(form);
    if (!data.email.trim()) return showFieldErrors(form, { email: 'Enter your email' });
    if (!data.password) return showFieldErrors(form, { password: 'Enter your password' });
    busy(form, true);
    try {
      await Auth.request('/auth/login', { method: 'POST', body: { email: data.email, password: data.password } });
      location.replace('/');
    } catch (err) {
      if (err.code === 'validation_error' && showFieldErrors(form, err.fields)) { /* inline */ }
      else if (err.code === 'account_pending') showBanner(err.message, 'info');
      else showBanner(err.message, err.status >= 500 || err.status === 0 || err.status === 429 ? 'warn' : 'danger');
      form.querySelector('[name=password]').value = '';
    } finally { busy(form, false); }
  });

  // ---- sign up ----
  const RULES = {
    len: (p) => p.length >= 12, lower: (p) => /[a-z]/.test(p), upper: (p) => /[A-Z]/.test(p),
    digit: (p) => /\d/.test(p), symbol: (p) => /[^A-Za-z0-9]/.test(p),
  };
  $('#su-password').addEventListener('input', (e) => {
    document.querySelectorAll('#pw-rules li').forEach((li) => li.classList.toggle('ok', RULES[li.dataset.rule](e.target.value)));
  });
  $('#signup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const form = e.target; clearErrors(form); clearBanner();
    const data = formData(form);
    if (data.password !== data.confirm_password) return showFieldErrors(form, { confirm_password: 'Passwords do not match' });
    busy(form, true);
    try {
      const res = await Auth.request('/auth/signup', { method: 'POST', body: data });
      form.reset(); document.querySelectorAll('#pw-rules li').forEach((li) => li.classList.remove('ok'));
      setView('signin'); showBanner(res.message, 'success');
    } catch (err) {
      if (!(err.code === 'validation_error' && showFieldErrors(form, err.fields))) {
        if (err.code === 'email_exists') showFieldErrors(form, { email: err.message });
        else showBanner(err.message, err.status >= 500 || err.status === 429 || err.status === 0 ? 'warn' : 'danger');
      }
    } finally { busy(form, false); }
  });
})();
