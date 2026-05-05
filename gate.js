/**
 * RunFest — gate.js
 * Admin login gate embedded in the public page.
 * Triggered by the visible "Admin" link in the footer.
 * Secured with SHA-256 hashing, rate limiting, session tokens.
 */
(function () {
  'use strict';

  const CREDS_KEY   = 'rf_admin_creds';
  const SESSION_KEY = 'rf_admin_session';
  const LOG_KEY     = 'rf_access_log';
  const LOCK_KEY    = 'rf_login_lock';
  const SESSION_TTL = 2 * 60 * 60 * 1000; // 2 hours
  const MAX_TRIES   = 3;
  const LOCKOUT_MS  = 15 * 60 * 1000;     // 15 minutes
  const DEFAULT_USER = 'admin';
  const DEFAULT_PASS = 'RunFest@2025!';

  /* ── SHA-256 ── */
  async function sha256(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
  }

  /* ── Seed default credentials on first run ── */
  async function seedCreds() {
    if (!localStorage.getItem(CREDS_KEY)) {
      const hash = await sha256(DEFAULT_PASS);
      localStorage.setItem(CREDS_KEY, JSON.stringify({ user: DEFAULT_USER, hash }));
    }
  }

  /* ── Session ── */
  function getSession() {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      const s = JSON.parse(raw);
      if (Date.now() > s.expires) { sessionStorage.removeItem(SESSION_KEY); return null; }
      return s;
    } catch { return null; }
  }

  function createSession(username) {
    const token   = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b=>b.toString(16).padStart(2,'0')).join('');
    const expires = Date.now() + SESSION_TTL;
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({ token, username, expires }));
    return { token, username, expires };
  }

  function destroySession() { sessionStorage.removeItem(SESSION_KEY); }

  /* ── Rate limiting ── */
  function getLock() {
    try { return JSON.parse(localStorage.getItem(LOCK_KEY)) || { attempts:0, lockedUntil:0 }; }
    catch { return { attempts:0, lockedUntil:0 }; }
  }
  function saveLock(s)     { localStorage.setItem(LOCK_KEY, JSON.stringify(s)); }
  function isLocked()      { return getLock().lockedUntil > Date.now(); }
  function minsLeft()      { return Math.ceil((getLock().lockedUntil - Date.now()) / 60000); }

  function recordAttempt(ok) {
    if (ok) { saveLock({ attempts:0, lockedUntil:0 }); return; }
    const s = getLock();
    s.attempts++;
    if (s.attempts >= MAX_TRIES) { s.lockedUntil = Date.now() + LOCKOUT_MS; s.attempts = 0; }
    saveLock(s);
  }

  /* ── Access log ── */
  function logAccess(user, ok, reason) {
    const log = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
    log.unshift({ ts: new Date().toISOString(), username: user, success: ok, reason: reason||'' });
    localStorage.setItem(LOG_KEY, JSON.stringify(log.slice(0,50)));
  }

  /* ── DOM helpers ── */
  const $  = id => document.getElementById(id);
  const esc = s  => String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  /* ── Modal open/close ── */
  window.openAdminModal = function () {
    const m = $('adminLoginModal');
    if (!m) return;
    m.classList.add('open');
    m.setAttribute('aria-hidden','false');
    const session = getSession();
    if (session) { showAuthView(session.username); }
    else         { showLoginView(); setTimeout(() => $('m-user')?.focus(), 100); }
  };

  window.closeAdminModal = function () {
    const m = $('adminLoginModal');
    if (!m) return;
    m.classList.remove('open');
    m.setAttribute('aria-hidden','true');
    clearFeedback();
  };

  function showLoginView() {
    $('adminLoginView').style.display = '';
    $('adminAuthView').style.display  = 'none';
  }

  function showAuthView(username) {
    $('adminLoginView').style.display = 'none';
    $('adminAuthView').style.display  = '';
    const w = $('m-welcomeMsg');
    if (w) w.textContent = `Welcome back, ${esc(username)}. You're signed in.`;
  }

  function clearFeedback() {
    const e = $('m-error'), l = $('m-lockout');
    if (e) e.textContent = '';
    if (l) l.textContent = '';
  }

  /* ── Password toggle ── */
  window.mTogglePass = function () {
    const p = $('m-pass');
    if (!p) return;
    const show = p.type === 'password';
    p.type = show ? 'text' : 'password';
    const open   = $('eyeIconOpen');
    const closed = $('eyeIconClosed');
    if (open)   open.style.display   = show ? 'none' : '';
    if (closed) closed.style.display = show ? '' : 'none';
  };

  /* ── Sign out ── */
  window.mSignOut = function () {
    destroySession();
    showLoginView();
    clearFeedback();
    if ($('m-user')) $('m-user').value = '';
    if ($('m-pass')) $('m-pass').value = '';
    setTimeout(() => $('m-user')?.focus(), 80);
  };

  /* ── Login ── */
  window.mDoLogin = async function () {
    const errEl  = $('m-error');
    const lockEl = $('m-lockout');
    const btn    = $('m-loginBtn');
    const btnTxt = $('m-btnText');
    const arrow  = $('m-btnArrow');
    const spin   = $('m-btnSpinner');
    if (!errEl || !btn) return;

    clearFeedback();

    if (isLocked()) {
      lockEl.textContent = `Account temporarily locked. Try again in ${minsLeft()} minute(s).`;
      return;
    }

    const username = ($('m-user')?.value || '').trim();
    const password =  $('m-pass')?.value || '';

    if (!username) { errEl.textContent = 'Please enter your username.'; $('m-user')?.focus(); return; }
    if (!password) { errEl.textContent = 'Please enter your password.'; $('m-pass')?.focus(); return; }

    /* Loading state */
    btn.disabled = true;
    btnTxt.textContent = 'Verifying…';
    if (arrow) arrow.style.display = 'none';
    if (spin)  spin.style.display  = '';

    /* Delay to prevent timing attacks */
    await new Promise(r => setTimeout(r, 650 + Math.random() * 350));

    try {
      const creds  = JSON.parse(localStorage.getItem(CREDS_KEY));
      const inHash = await sha256(password);

      if (username === creds.user && inHash === creds.hash) {
        recordAttempt(true);
        logAccess(username, true);
        createSession(username);
        showAuthView(username);
      } else {
        recordAttempt(false);
        logAccess(username, false, 'Wrong credentials');
        const lock = getLock();
        errEl.textContent = 'Incorrect username or password.';
        if (lock.lockedUntil > Date.now()) {
          errEl.textContent  = '';
          lockEl.textContent = `Too many attempts. Account locked for ${minsLeft()} minute(s).`;
        } else {
          const left = MAX_TRIES - lock.attempts;
          if (left > 0) lockEl.textContent = `${left} attempt(s) remaining before lockout.`;
        }
        $('m-pass').value = '';
        $('m-pass')?.focus();
      }
    } catch {
      errEl.textContent = 'An error occurred. Please try again.';
    }

    btn.disabled = false;
    btnTxt.textContent = 'Sign In to Dashboard';
    if (arrow) arrow.style.display = '';
    if (spin)  spin.style.display  = 'none';
  };

  /* ── Event bindings ── */
  function bindEvents() {
    /* Close on backdrop click */
    $('adminLoginModal')?.addEventListener('click', e => {
      if (e.target === $('adminLoginModal')) window.closeAdminModal();
    });

    /* Keyboard */
    $('m-pass')?.addEventListener('keydown', e => { if (e.key === 'Enter') window.mDoLogin(); });
    $('m-user')?.addEventListener('keydown', e => { if (e.key === 'Enter') $('m-pass')?.focus(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') window.closeAdminModal();
    });
  }

  /* ── Init ── */
  async function init() {
    await seedCreds();
    bindEvents();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
