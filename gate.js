/**
 * RunFest — gate.js
 * ─────────────────────────────────────────────────────────────────
 * SECRET ADMIN GATE embedded in the public registration page.
 *
 * HOW TO ACCESS:
 *   Triple-click the "·" separator dot in the footer → login modal appears.
 *   On mobile: long-press (800ms) the same dot.
 *
 * The dot looks like decorative punctuation. No tooltip, no label.
 * No link to admin.html exists anywhere in the public HTML.
 *
 * SECURITY:
 *   • SHA-256 hashed passwords (Web Crypto API)
 *   • 3 attempts → 15-minute lockout
 *   • Session stored in sessionStorage (cleared on tab close)
 *   • Every attempt logged with timestamp
 *   • 600–900ms artificial delay to resist brute-force
 * ─────────────────────────────────────────────────────────────────
 */

(function () {
  'use strict';

  /* ── CONFIG ──────────────────────────────────────────────── */
  const CREDS_KEY    = 'rf_admin_creds';
  const SESSION_KEY  = 'rf_admin_session';
  const LOG_KEY      = 'rf_access_log';
  const LOCK_KEY     = 'rf_login_lock';
  const SESSION_TTL  = 2 * 60 * 60 * 1000;  // 2 h
  const MAX_ATTEMPTS = 3;
  const LOCKOUT_MS   = 15 * 60 * 1000;      // 15 min
  const DEFAULT_USER = 'admin';
  const DEFAULT_PASS = 'RunFest@2025!';

  /* ── SHA-256 ─────────────────────────────────────────────── */
  async function sha256(str) {
    const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /* ── SEED DEFAULT CREDS ──────────────────────────────────── */
  async function seedCreds() {
    if (!localStorage.getItem(CREDS_KEY)) {
      const hash = await sha256(DEFAULT_PASS);
      localStorage.setItem(CREDS_KEY, JSON.stringify({ user: DEFAULT_USER, hash }));
    }
  }

  /* ── SESSION ─────────────────────────────────────────────── */
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
    const token   = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join('');
    const expires = Date.now() + SESSION_TTL;
    sessionStorage.setItem(SESSION_KEY, JSON.stringify({ token, username, expires }));
    return { token, username, expires };
  }

  function destroySession() {
    sessionStorage.removeItem(SESSION_KEY);
  }

  /* ── RATE LIMITING ───────────────────────────────────────── */
  function getLock() {
    try { return JSON.parse(localStorage.getItem(LOCK_KEY)) || { attempts: 0, lockedUntil: 0 }; }
    catch { return { attempts: 0, lockedUntil: 0 }; }
  }

  function saveLock(s) { localStorage.setItem(LOCK_KEY, JSON.stringify(s)); }

  function isLocked()        { return getLock().lockedUntil > Date.now(); }
  function lockoutMinsLeft() { return Math.ceil((getLock().lockedUntil - Date.now()) / 60000); }

  function recordAttempt(success) {
    if (success) { saveLock({ attempts: 0, lockedUntil: 0 }); return; }
    const s = getLock();
    s.attempts++;
    if (s.attempts >= MAX_ATTEMPTS) { s.lockedUntil = Date.now() + LOCKOUT_MS; s.attempts = 0; }
    saveLock(s);
  }

  /* ── ACCESS LOG ──────────────────────────────────────────── */
  function logAccess(user, ok, reason) {
    const log = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
    log.unshift({ ts: new Date().toISOString(), username: user, success: ok, reason: reason || '' });
    localStorage.setItem(LOG_KEY, JSON.stringify(log.slice(0, 50)));
  }

  /* ── DOM HELPERS ─────────────────────────────────────────── */
  const $  = id => document.getElementById(id);
  const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  function showModal()   {
    const m = $('adminLoginModal');
    if (!m) return;
    m.classList.add('open');
    m.setAttribute('aria-hidden', 'false');
    // If already authed, go straight to auth view
    const s = getSession();
    if (s) { showAuthView(s.username); }
    else   { showLoginView(); setTimeout(() => $('m-user')?.focus(), 80); }
  }

  function hideModal() {
    const m = $('adminLoginModal');
    if (!m) return;
    m.classList.remove('open');
    m.setAttribute('aria-hidden', 'true');
    clearFields();
  }

  function clearFields() {
    const u = $('m-user'), p = $('m-pass'), e = $('m-error'), l = $('m-lockout');
    if (u) u.value = '';
    if (p) p.value = '';
    if (e) e.textContent = '';
    if (l) l.textContent = '';
  }

  function showLoginView() {
    $('adminLoginView').style.display = '';
    $('adminAuthView').style.display  = 'none';
  }

  function showAuthView(username) {
    $('adminLoginView').style.display  = 'none';
    $('adminAuthView').style.display   = '';
    const w = $('m-welcomeMsg');
    if (w) w.textContent = `Welcome back, ${esc(username)}.`;
    // Pass session token to dashboard via sessionStorage (already stored)
  }

  /* ── PASSWORD TOGGLE ─────────────────────────────────────── */
  window.mTogglePass = function () {
    const p = $('m-pass');
    if (!p) return;
    p.type = p.type === 'password' ? 'text' : 'password';
    const icon = $('eyeIcon');
    if (icon) icon.style.opacity = p.type === 'text' ? '1' : '0.5';
  };

  /* ── SIGN OUT ────────────────────────────────────────────── */
  window.mSignOut = function () {
    destroySession();
    showLoginView();
    clearFields();
  };

  /* ── LOGIN ───────────────────────────────────────────────── */
  window.mDoLogin = async function () {
    const errEl  = $('m-error');
    const lockEl = $('m-lockout');
    const btn    = $('m-loginBtn');
    const btnTxt = $('m-btnText');

    if (!errEl || !btn) return;
    errEl.textContent  = '';
    lockEl.textContent = '';

    /* Lockout check */
    if (isLocked()) {
      lockEl.textContent = `Too many failed attempts. Try again in ${lockoutMinsLeft()} minute(s).`;
      return;
    }

    const username = ($('m-user')?.value || '').trim();
    const password =  $('m-pass')?.value || '';

    if (!username || !password) {
      errEl.textContent = 'Please enter your username and password.';
      return;
    }

    /* Loading state */
    btn.disabled    = true;
    btnTxt.textContent = 'Verifying…';

    /* Artificial delay (600–900ms) */
    await new Promise(r => setTimeout(r, 600 + Math.random() * 300));

    try {
      const creds  = JSON.parse(localStorage.getItem(CREDS_KEY));
      const inHash = await sha256(password);

      if (username === creds.user && inHash === creds.hash) {
        recordAttempt(true);
        logAccess(username, true);
        const session = createSession(username);
        showAuthView(username);
      } else {
        recordAttempt(false);
        logAccess(username, false, 'Wrong credentials');
        const lock      = getLock();
        const remaining = MAX_ATTEMPTS - lock.attempts;
        errEl.textContent = 'Incorrect username or password.';
        if (lock.lockedUntil > Date.now()) {
          lockEl.textContent = `Account locked for ${lockoutMinsLeft()} minute(s).`;
          errEl.textContent  = '';
        } else if (remaining > 0) {
          lockEl.textContent = `${remaining} attempt(s) left before lockout.`;
        }
        $('m-pass').value = '';
        $('m-pass')?.focus();
      }
    } catch {
      errEl.textContent = 'An error occurred. Please try again.';
    }

    btn.disabled    = false;
    btnTxt.textContent = 'Sign In';
  };

  /* ── SECRET TRIGGER LOGIC ────────────────────────────────── */
  function initTrigger() {
    const trigger = $('settingsTrigger');
    if (!trigger) return;

    /* Desktop: triple-click */
    let clickCount = 0;
    let clickTimer = null;

    trigger.addEventListener('click', () => {
      clickCount++;
      clearTimeout(clickTimer);
      clickTimer = setTimeout(() => { clickCount = 0; }, 600);
      if (clickCount >= 3) {
        clickCount = 0;
        clearTimeout(clickTimer);
        showModal();
      }
    });

    /* Mobile: long-press (800ms) */
    let pressTimer = null;
    trigger.addEventListener('touchstart', () => {
      pressTimer = setTimeout(showModal, 800);
    }, { passive: true });
    trigger.addEventListener('touchend',   () => clearTimeout(pressTimer));
    trigger.addEventListener('touchmove',  () => clearTimeout(pressTimer));

    /* Close on overlay click */
    $('adminLoginModal')?.addEventListener('click', e => {
      if (e.target === $('adminLoginModal')) hideModal();
    });

    /* Close button */
    $('adminModalClose')?.addEventListener('click', hideModal);

    /* Enter key inside login modal */
    $('m-pass')?.addEventListener('keydown', e => { if (e.key === 'Enter') window.mDoLogin(); });
    $('m-user')?.addEventListener('keydown', e => { if (e.key === 'Enter') $('m-pass')?.focus(); });

    /* Escape key */
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape') hideModal();
    });
  }

  /* ── INIT ────────────────────────────────────────────────── */
  async function init() {
    await seedCreds();
    initTrigger();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }

})();
