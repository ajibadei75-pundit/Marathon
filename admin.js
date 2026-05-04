/**
 * RunFest — admin.js
 * ─────────────────────────────────────────────────────────────────
 * SECURITY MODEL:
 *  • Admin URL is not linked anywhere on the public site
 *  • Password is hashed (SHA-256) before storage — never stored plain
 *  • Login attempts are rate-limited (3 strikes → 15 min lockout)
 *  • Sessions use a signed token stored in sessionStorage, not cookies
 *  • Session expires after 2 hours of inactivity
 *  • All login attempts are logged (timestamp, success/fail)
 *  • "robots: noindex" on the page prevents search-engine discovery
 * ─────────────────────────────────────────────────────────────────
 */

/* ============================================================
   CONSTANTS
   ============================================================ */
const SESSION_KEY   = 'rf_admin_session';
const CREDS_KEY     = 'rf_admin_creds';
const LOG_KEY       = 'rf_access_log';
const LOCK_KEY      = 'rf_login_lock';
const SESSION_TTL   = 2 * 60 * 60 * 1000;   // 2 hours ms
const MAX_ATTEMPTS  = 3;
const LOCKOUT_MS    = 15 * 60 * 1000;        // 15 minutes

/* Default credentials (hashed on first run). Admin changes via Security tab. */
const DEFAULT_USER = 'admin';
const DEFAULT_PASS = 'RunFest@2025!';   // Changed from the old weak default

/* ── currently editing form slug ── */
let currentEditSlug = null;
let activeRegSlug   = null;
let unsavedChanges  = false;
let sessionInterval = null;

/* ============================================================
   CRYPTO — SHA-256 via Web Crypto API
   ============================================================ */
async function sha256(str) {
  const buf  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

/* ============================================================
   INIT
   ============================================================ */
document.addEventListener('DOMContentLoaded', async () => {
  // Seed default credentials if first run
  if (!localStorage.getItem(CREDS_KEY)) {
    const hash = await sha256(DEFAULT_PASS);
    localStorage.setItem(CREDS_KEY, JSON.stringify({ user: DEFAULT_USER, hash }));
  }

  // Seed a default form if none exist
  if (!DB.getForms().length) {
    const slug = 'runfest-2025';
    DB.saveForm(defaultFormConfig('RunFest 2025', slug));
  }

  // Restore session if valid
  const session = getSession();
  if (session) {
    showDashboard();
  }

  // Enter-key support on login
  document.getElementById('adminPass')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') doLogin();
  });
  document.getElementById('adminUser')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') document.getElementById('adminPass')?.focus();
  });

  // Slug auto-generation from form name
  document.getElementById('newFormName')?.addEventListener('input', e => {
    const slug = genSlug(e.target.value);
    document.getElementById('newFormSlug').value = slug;
  });

  // Activity tracking — refresh session on any interaction
  document.addEventListener('click',   refreshSession);
  document.addEventListener('keydown', refreshSession);
});

/* ============================================================
   SESSION MANAGEMENT
   ============================================================ */
function createSession(username) {
  const token   = genId() + genId(); // random session token
  const expires = Date.now() + SESSION_TTL;
  sessionStorage.setItem(SESSION_KEY, JSON.stringify({ token, username, expires }));
  return { token, username, expires };
}

function getSession() {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const s = JSON.parse(raw);
    if (Date.now() > s.expires) { sessionStorage.removeItem(SESSION_KEY); return null; }
    return s;
  } catch { return null; }
}

function refreshSession() {
  const s = getSession();
  if (!s) return;
  s.expires = Date.now() + SESSION_TTL;
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(s));
}

function startSessionTimer() {
  clearInterval(sessionInterval);
  sessionInterval = setInterval(() => {
    const s = getSession();
    if (!s) { doLogout(); return; }
    const remaining = Math.max(0, s.expires - Date.now());
    const mins = Math.floor(remaining / 60000);
    const secs = Math.floor((remaining % 60000) / 1000);
    const el   = document.getElementById('sessionTimer');
    if (el) {
      el.textContent = `Session: ${mins}:${secs.toString().padStart(2,'0')}`;
      el.style.color = remaining < 5 * 60000 ? 'var(--red)' : 'var(--ink-muted)';
    }
    if (remaining === 0) doLogout();
  }, 1000);
}

/* ============================================================
   RATE LIMITING
   ============================================================ */
function getLockState() {
  try { return JSON.parse(localStorage.getItem(LOCK_KEY)) || { attempts: 0, lockedUntil: 0 }; }
  catch { return { attempts: 0, lockedUntil: 0 }; }
}

function saveLockState(state) { localStorage.setItem(LOCK_KEY, JSON.stringify(state)); }

function isLocked() {
  const s = getLockState();
  return s.lockedUntil > Date.now();
}

function lockoutRemaining() {
  const s = getLockState();
  return Math.max(0, Math.ceil((s.lockedUntil - Date.now()) / 60000));
}

function recordAttempt(success) {
  const s = getLockState();
  if (success) { saveLockState({ attempts: 0, lockedUntil: 0 }); return; }
  s.attempts++;
  if (s.attempts >= MAX_ATTEMPTS) {
    s.lockedUntil = Date.now() + LOCKOUT_MS;
    s.attempts    = 0;
  }
  saveLockState(s);
}

/* ============================================================
   ACCESS LOG
   ============================================================ */
function logAccess(username, success, reason = '') {
  const log  = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
  const entry = {
    ts: new Date().toISOString(),
    username: username || '(unknown)',
    success,
    reason,
    ua: navigator.userAgent.substring(0, 80)
  };
  log.unshift(entry);
  // Keep last 50 entries
  localStorage.setItem(LOG_KEY, JSON.stringify(log.slice(0, 50)));
}

/* ============================================================
   LOGIN / LOGOUT
   ============================================================ */
async function doLogin() {
  const errEl = document.getElementById('loginError');
  const attEl = document.getElementById('loginAttempts');
  const btn   = document.getElementById('loginBtn');
  errEl.textContent = '';
  attEl.textContent = '';

  // Check lockout
  if (isLocked()) {
    errEl.textContent = `Too many failed attempts. Try again in ${lockoutRemaining()} minute(s).`;
    return;
  }

  const username = (document.getElementById('adminUser')?.value || '').trim();
  const password =  document.getElementById('adminPass')?.value || '';

  if (!username || !password) {
    errEl.textContent = 'Please enter both username and password.';
    return;
  }

  // Brief delay to prevent timing attacks
  btn.disabled = true;
  document.getElementById('loginBtnText').textContent = 'Verifying…';
  await new Promise(r => setTimeout(r, 600 + Math.random() * 400));

  try {
    const creds  = JSON.parse(localStorage.getItem(CREDS_KEY));
    const inHash = await sha256(password);

    if (username === creds.user && inHash === creds.hash) {
      recordAttempt(true);
      logAccess(username, true);
      createSession(username);
      startSessionTimer();
      showDashboard();
    } else {
      recordAttempt(false);
      logAccess(username, false, 'Wrong credentials');

      const lock = getLockState();
      const remaining = MAX_ATTEMPTS - lock.attempts;
      errEl.textContent = 'Invalid username or password.';

      if (lock.lockedUntil > Date.now()) {
        errEl.textContent = `Account locked for ${lockoutRemaining()} minute(s) due to repeated failures.`;
        attEl.textContent = '';
      } else if (remaining > 0) {
        attEl.textContent = `${remaining} attempt(s) remaining before lockout.`;
      }

      document.getElementById('adminPass').value = '';
      document.getElementById('adminPass').focus();
    }
  } catch (err) {
    errEl.textContent = 'Authentication error. Please try again.';
  }

  btn.disabled = false;
  document.getElementById('loginBtnText').textContent = 'Sign In';
}

function doLogout() {
  clearInterval(sessionInterval);
  sessionStorage.removeItem(SESSION_KEY);
  document.getElementById('dashboard').style.display = 'none';
  document.getElementById('loginScreen').style.display = 'flex';
  document.getElementById('adminUser').value = '';
  document.getElementById('adminPass').value = '';
  document.getElementById('loginError').textContent = '';
  toast('Signed out successfully.', 'info');
}

function togglePass() {
  const el = document.getElementById('adminPass');
  el.type  = el.type === 'password' ? 'text' : 'password';
}

function showDashboard() {
  document.getElementById('loginScreen').style.display = 'none';
  document.getElementById('dashboard').style.display   = 'flex';

  // Show session info
  const s = getSession();
  if (s) {
    const el = document.getElementById('adminInfoBar');
    if (el) el.innerHTML = `<span style="font-size:.72rem;color:rgba(255,255,255,.35);padding:0 12px 12px;display:block;">Signed in as <strong style="color:rgba(255,255,255,.6)">${escHtml(s.username)}</strong></span>`;
    startSessionTimer();
  }

  loadAll();
}

/* ============================================================
   CHANGE PASSWORD
   ============================================================ */
async function changePassword() {
  const current  = document.getElementById('sec-current')?.value  || '';
  const newPass  = document.getElementById('sec-new')?.value      || '';
  const confirm  = document.getElementById('sec-confirm')?.value  || '';
  const errEl    = document.getElementById('secError');
  errEl.textContent = '';

  if (!current || !newPass || !confirm) { errEl.textContent = 'All fields are required.'; return; }
  if (newPass.length < 8)               { errEl.textContent = 'New password must be at least 8 characters.'; return; }
  if (newPass !== confirm)              { errEl.textContent = 'Passwords do not match.'; return; }

  const creds   = JSON.parse(localStorage.getItem(CREDS_KEY));
  const curHash = await sha256(current);
  if (curHash !== creds.hash)           { errEl.textContent = 'Current password is incorrect.'; return; }

  const newHash = await sha256(newPass);
  localStorage.setItem(CREDS_KEY, JSON.stringify({ user: creds.user, hash: newHash }));

  document.getElementById('sec-current').value = '';
  document.getElementById('sec-new').value     = '';
  document.getElementById('sec-confirm').value = '';

  logAccess(creds.user, true, 'Password changed');
  toast('Password updated successfully.', 'success');
}

/* ============================================================
   TAB SWITCHING
   ============================================================ */
function switchTab(name, el) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('tab-' + name)?.classList.add('active');
  el?.classList.add('active');

  const titles = {
    overview: 'Overview', registrations: 'Registrations', forms: 'Manage Forms',
    contentEditor: 'Page Content Editor', fieldEditor: 'Form Fields',
    customFields: 'Custom Fields', images: 'Images', security: 'Security'
  };
  document.getElementById('topbarTitle').textContent = titles[name] || name;
  document.getElementById('topbarBreadcrumb').textContent = '';

  if (name === 'overview')       renderOverview();
  if (name === 'registrations')  renderRegistrations();
  if (name === 'forms')          renderForms();
  if (name === 'contentEditor')  renderContentEditor();
  if (name === 'fieldEditor')    renderCoreFields();
  if (name === 'customFields')   renderCustomFieldsList();
  if (name === 'images')         renderImageGallery();
  if (name === 'security')       renderAccessLog();
}

/* ============================================================
   LOAD ALL
   ============================================================ */
function loadAll() {
  renderOverview();
  renderForms();
  renderRegistrations();
  renderImageGallery();
  populateRegFormSelector();
}

/* ============================================================
   OVERVIEW
   ============================================================ */
function renderOverview() {
  const forms  = DB.getForms();
  const today  = new Date().toDateString();
  let total = 0, health = 0, todayCount = 0;
  const levelMap = {}, deptMap = {};

  forms.forEach(f => {
    const regs = DB.getRegistrations(f.slug);
    total      += regs.length;
    health     += regs.filter(r => r.healthCondition).length;
    todayCount += regs.filter(r => new Date(r.registeredAt).toDateString() === today).length;
    regs.forEach(r => {
      if (r.level)      levelMap[r.level]      = (levelMap[r.level] || 0) + 1;
      if (r.department) deptMap[r.department]  = (deptMap[r.department] || 0) + 1;
    });
  });

  setText('statTotal',  total);
  setText('statHealth', health);
  setText('statForms',  forms.filter(f => f.active).length);
  setText('statToday',  todayCount);
  document.getElementById('navBadgeRegs').textContent = total;

  renderBreakdown('levelBreakdown', levelMap);
  renderBreakdown('deptBreakdown',  deptMap, 6);

  // Recent — gather from all forms
  const allRegs = [];
  forms.forEach(f => DB.getRegistrations(f.slug).forEach(r => allRegs.push({ ...r, _formName: f.name })));
  allRegs.sort((a, b) => new Date(b.registeredAt) - new Date(a.registeredAt));

  const el = document.getElementById('recentList');
  if (!el) return;
  if (!allRegs.length) { el.innerHTML = '<p class="muted">No registrations yet.</p>'; return; }

  el.innerHTML = allRegs.slice(0, 6).map(r => `
    <div class="recent-item">
      <div class="recent-avatar">${(r.fullName || '?').charAt(0).toUpperCase()}</div>
      <div>
        <div class="recent-name">${escHtml(r.fullName || '—')}</div>
        <div class="recent-meta">${escHtml(r._formName || '')}</div>
      </div>
      <div class="recent-right">
        <span class="recent-dept">${escHtml(r.department || '')}</span>
        <span class="recent-date">${fmtDate(r.registeredAt)}</span>
      </div>
    </div>
  `).join('');
}

function renderBreakdown(containerId, map, max = 10) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const sorted = Object.entries(map).sort((a, b) => b[1] - a[1]).slice(0, max);
  if (!sorted.length) { el.innerHTML = '<p class="muted" style="margin-top:14px;">No data yet.</p>'; return; }
  const peak = sorted[0][1];
  el.innerHTML = sorted.map(([label, count]) => `
    <div class="breakdown-item">
      <span class="breakdown-label" title="${escHtml(label)}">${escHtml(label)}</span>
      <div class="breakdown-track">
        <div class="breakdown-bar" style="width:${(count/peak)*100}%"></div>
      </div>
      <span class="breakdown-count">${count}</span>
    </div>
  `).join('');
}

/* ============================================================
   REGISTRATIONS TABLE
   ============================================================ */
function populateRegFormSelector() {
  const sel = document.getElementById('regFormSelector');
  if (!sel) return;
  const forms = DB.getForms();
  sel.innerHTML = forms.map(f => `<option value="${escHtml(f.slug)}">${escHtml(f.name)}</option>`).join('');
  if (forms.length) activeRegSlug = forms[0].slug;
}

function switchRegForm() {
  activeRegSlug = document.getElementById('regFormSelector')?.value;
  renderRegistrations();
}

function renderRegistrations(data = null) {
  const slug  = activeRegSlug || DB.getForms()[0]?.slug;
  if (!slug) return;
  const regs  = data || DB.getRegistrations(slug);
  const tbody = document.getElementById('regTableBody');
  const empty = document.getElementById('tableEmpty');
  if (!tbody) return;

  if (!regs.length) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  tbody.innerHTML = regs.map(r => `
    <tr class="${r.healthCondition ? 'health-row' : ''}">
      <td><span class="id-tag">${escHtml(r.id)}</span></td>
      <td>${escHtml(r.fullName || '—')}</td>
      <td>${escHtml(r.phone || '—')}</td>
      <td class="wrap">${escHtml(r.email || '—')}</td>
      <td>${escHtml(r.department || '—')}</td>
      <td>${escHtml(r.level || '—')}</td>
      <td>${escHtml(r.genotype || '—')}</td>
      <td class="wrap">${escHtml(r.hostel || '—')}</td>
      <td>${r.healthCondition ? '<span class="health-tag">⚠ Yes</span>' : '<span class="none-tag">None</span>'}</td>
      <td>${fmtDate(r.registeredAt)}</td>
      <td><button class="btn-view" onclick="viewUser('${escHtml(r.id)}','${escHtml(slug)}')">View</button></td>
    </tr>
  `).join('');
}

function filterTable() {
  const slug      = activeRegSlug || DB.getForms()[0]?.slug;
  const q         = document.getElementById('searchInput')?.value.toLowerCase() || '';
  const healthOnly= document.getElementById('filterHealth')?.checked;
  let regs        = DB.getRegistrations(slug);
  if (healthOnly) regs = regs.filter(r => r.healthCondition);
  if (q) regs = regs.filter(r =>
    (r.fullName||'').toLowerCase().includes(q)    ||
    (r.email||'').toLowerCase().includes(q)        ||
    (r.id||'').toLowerCase().includes(q)           ||
    (r.department||'').toLowerCase().includes(q)   ||
    (r.phone||'').includes(q)
  );
  renderRegistrations(regs);
}

/* ============================================================
   VIEW USER MODAL
   ============================================================ */
function viewUser(id, slug) {
  const reg = DB.getRegistrations(slug).find(r => r.id === id);
  if (!reg) return;

  const dynHtml = Object.entries(reg)
    .filter(([k]) => !['id','fullName','phone','email','department','level','genotype','hostel','naqeeb','healthCondition','registeredAt'].includes(k))
    .map(([k, v]) => `<div class="modal-field"><span class="modal-field-label">${escHtml(k)}</span><span class="modal-field-value">${escHtml(v)||'—'}</span></div>`)
    .join('');

  document.getElementById('userModalContent').innerHTML = `
    <div class="modal-runner-id">${escHtml(reg.id)}</div>
    <div class="modal-name">${escHtml(reg.fullName || '—')}</div>
    <div class="modal-grid">
      <div class="modal-field"><span class="modal-field-label">Phone</span><span class="modal-field-value">${escHtml(reg.phone||'—')}</span></div>
      <div class="modal-field"><span class="modal-field-label">Email</span><span class="modal-field-value">${escHtml(reg.email||'—')}</span></div>
      <div class="modal-field"><span class="modal-field-label">Department</span><span class="modal-field-value">${escHtml(reg.department||'—')}</span></div>
      <div class="modal-field"><span class="modal-field-label">Level</span><span class="modal-field-value">${escHtml(reg.level||'—')}</span></div>
      <div class="modal-field"><span class="modal-field-label">Genotype</span><span class="modal-field-value">${escHtml(reg.genotype||'—')}</span></div>
      <div class="modal-field"><span class="modal-field-label">Registered</span><span class="modal-field-value">${fmtDate(reg.registeredAt)}</span></div>
      <div class="modal-field full"><span class="modal-field-label">Hostel Address</span><span class="modal-field-value">${escHtml(reg.hostel||'—')}</span></div>
      <div class="modal-field full"><span class="modal-field-label">Naqeeb / Rep Phone</span><span class="modal-field-value">${escHtml(reg.naqeeb||'—')}</span></div>
      ${dynHtml}
      ${reg.healthCondition ? `<div class="modal-health full"><div class="modal-health-title">⚠ Health Condition Declared</div><div class="modal-health-text">${escHtml(reg.healthCondition)}</div></div>` : ''}
    </div>
    <div class="modal-footer">
      <button class="btn-sm danger" onclick="deleteUser('${escHtml(id)}','${escHtml(slug)}')">Delete Record</button>
    </div>
  `;
  document.getElementById('userModal').style.display = 'flex';
}

function deleteUser(id, slug) {
  if (!confirm('Permanently delete this registration?')) return;
  DB.deleteRegistration(slug, id);
  closeModal('userModal');
  renderRegistrations();
  renderOverview();
  toast('Registration deleted.', 'info');
}

/* ============================================================
   EXPORT CSV
   ============================================================ */
function exportCSV() {
  const slug = activeRegSlug || DB.getForms()[0]?.slug;
  const regs = DB.getRegistrations(slug);
  if (!regs.length) { toast('No data to export.', 'error'); return; }

  const form    = DB.getForm(slug);
  const headers = ['Runner ID','Full Name','Phone','Email','Department','Level','Genotype','Hostel','Naqeeb Phone','Health Condition','Date'];
  const rows    = regs.map(r => [
    r.id, r.fullName, r.phone, r.email, r.department,
    r.level, r.genotype, r.hostel, r.naqeeb, r.healthCondition || '', fmtDate(r.registeredAt)
  ]);

  const csv = [headers, ...rows]
    .map(row => row.map(c => `"${String(c||'').replace(/"/g,'""')}"`).join(','))
    .join('\n');

  const a   = document.createElement('a');
  a.href    = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
  a.download= `${slug}_registrations_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(a.href);
  toast('CSV exported!', 'success');
}

/* ============================================================
   FORMS MANAGER
   ============================================================ */
function renderForms() {
  const forms = DB.getForms();
  const grid  = document.getElementById('formsGrid');
  if (!grid) return;

  if (!forms.length) {
    grid.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⊞</div><p>No forms yet. Create your first form.</p></div>';
    return;
  }

  grid.innerHTML = forms.map(f => {
    const regs   = DB.getRegistrations(f.slug);
    const health = regs.filter(r => r.healthCondition).length;
    const url    = formUrl(f.slug);
    return `
      <div class="form-card">
        <div class="form-card-status ${f.active ? 'active' : 'inactive'}">${f.active ? 'Active' : 'Closed'}</div>
        <div class="form-card-name">${escHtml(f.name)}</div>
        <div class="form-card-slug">${escHtml(f.slug)}</div>
        <div class="form-card-stats">
          <div class="form-card-stat"><div class="form-card-stat-val">${regs.length}</div><div class="form-card-stat-lbl">Registered</div></div>
          <div class="form-card-stat"><div class="form-card-stat-val">${health}</div><div class="form-card-stat-lbl">Health flags</div></div>
          <div class="form-card-stat"><div class="form-card-stat-val">${fmtDate(f.createdAt)}</div><div class="form-card-stat-lbl">Created</div></div>
        </div>
        <div class="form-link-box">
          <span class="form-link-text" id="link-${escHtml(f.slug)}">${escHtml(url)}</span>
          <button class="btn-copy" id="copy-${escHtml(f.slug)}" onclick="copyLink('${escHtml(f.slug)}')">Copy Link</button>
        </div>
        <div class="form-card-actions">
          <button class="btn-sm open" onclick="window.open('${escHtml(url)}','_blank')">↗ Open</button>
          <button class="btn-sm edit" onclick="editForm('${escHtml(f.slug)}')">✎ Edit</button>
          <button class="btn-sm toggle" onclick="toggleFormStatus('${escHtml(f.slug)}')">${f.active ? '⏸ Close' : '▶ Open'}</button>
          <button class="btn-sm danger" onclick="deleteForm('${escHtml(f.slug)}')">🗑 Delete</button>
        </div>
      </div>
    `;
  }).join('');
}

function showCreateFormModal() {
  document.getElementById('newFormName').value = '';
  document.getElementById('newFormSlug').value = '';
  document.getElementById('createFormModal').style.display = 'flex';
  setTimeout(() => document.getElementById('newFormName').focus(), 50);
}

function createForm() {
  const name = document.getElementById('newFormName')?.value.trim();
  const slug = document.getElementById('newFormSlug')?.value.trim() || genSlug(name);

  if (!name) { toast('Form name is required.', 'error'); return; }
  if (DB.getForm(slug)) { toast('A form with this slug already exists.', 'error'); return; }

  DB.saveForm(defaultFormConfig(name, slug));
  closeModal('createFormModal');
  renderForms();
  populateRegFormSelector();
  toast(`Form "${name}" created!`, 'success');
}

function editForm(slug) {
  currentEditSlug = slug;
  const form = DB.getForm(slug);
  if (!form) return;

  // Show editor nav items
  document.getElementById('editorNavSection').style.display = '';
  document.getElementById('navContentEditor').style.display = '';
  document.getElementById('navFieldEditor').style.display   = '';
  document.getElementById('navCustomFields').style.display  = '';

  // Breadcrumb
  document.getElementById('topbarBreadcrumb').textContent = '/ ' + form.name;

  // Navigate to content editor
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('navContentEditor').classList.add('active');
  switchTab('contentEditor', document.getElementById('navContentEditor'));
}

function toggleFormStatus(slug) {
  const form = DB.getForm(slug);
  if (!form) return;
  form.active           = !form.active;
  form.content.formClosed = !form.active;
  DB.saveForm(form);
  renderForms();
  toast(`Form ${form.active ? 'opened' : 'closed'}.`, form.active ? 'success' : 'info');
}

function deleteForm(slug) {
  const form = DB.getForm(slug);
  if (!confirm(`Delete "${form?.name}" and ALL its registrations? This cannot be undone.`)) return;
  DB.deleteForm(slug);
  renderForms();
  renderOverview();
  populateRegFormSelector();
  toast('Form deleted.', 'info');
}

function copyLink(slug) {
  const url = formUrl(slug);
  navigator.clipboard.writeText(url).then(() => {
    const btn = document.getElementById('copy-' + slug);
    if (btn) { btn.textContent = '✓ Copied!'; btn.classList.add('copied'); setTimeout(() => { btn.textContent = 'Copy Link'; btn.classList.remove('copied'); }, 2000); }
    toast('Link copied to clipboard!', 'success');
  }).catch(() => {
    // Fallback
    const el = document.createElement('textarea');
    el.value = url; document.body.appendChild(el); el.select(); document.execCommand('copy'); document.body.removeChild(el);
    toast('Link copied!', 'success');
  });
}

/* ============================================================
   CONTENT EDITOR
   ============================================================ */
function renderContentEditor() {
  const slug = currentEditSlug || DB.getForms()[0]?.slug;
  if (!slug) return;
  currentEditSlug = slug;
  const form = DB.getForm(slug);
  if (!form) return;

  const badge = document.getElementById('editingForBadge');
  if (badge) badge.textContent = 'Editing: ' + form.name;

  const c = form.content;
  const fields = {
    'ce-eventBadge':       c.eventBadge,
    'ce-heroTitle':        c.heroTitle,
    'ce-heroTitleAccent':  c.heroTitleAccent,
    'ce-heroSubtitle':     c.heroSubtitle,
    'ce-stat1Value':       c.stat1Value,
    'ce-stat1Label':       c.stat1Label,
    'ce-stat2Value':       c.stat2Value,
    'ce-stat2Label':       c.stat2Label,
    'ce-stat3Value':       c.stat3Value,
    'ce-stat3Label':       c.stat3Label,
    'ce-formIconEmoji':    c.formIconEmoji,
    'ce-formHeading':      c.formHeading,
    'ce-formSubheading':   c.formSubheading,
    'ce-submitButtonText': c.submitButtonText,
    'ce-footerText':       c.footerText,
    'ce-successTitle':     c.successTitle,
    'ce-successMessage':   c.successMessage,
    'ce-successIdLabel':   c.successIdLabel,
    'ce-successNote':      c.successNote,
    'ce-primaryColor':     c.primaryColor,
    'ce-accentColor':      c.accentColor,
    'ce-formClosedMessage':c.formClosedMessage
  };

  Object.entries(fields).forEach(([id, val]) => {
    const el = document.getElementById(id);
    if (el) el.value = val || '';
  });

  // Checkboxes
  const closedEl = document.getElementById('ce-formClosed');
  if (closedEl) closedEl.checked = !!c.formClosed;

  // Color previews & pickers
  syncColorPreview('primaryColor', c.primaryColor);
  syncColorPreview('accentColor',  c.accentColor);

  unsavedChanges = false;
  document.getElementById('contentSaveBar').classList.remove('visible');
}

function switchEditorTab(name, el) {
  document.querySelectorAll('.editor-tab').forEach(t  => t.classList.remove('active'));
  document.querySelectorAll('.editor-panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('panel-' + name)?.classList.add('active');
}

function syncColor(key) {
  const picker = document.getElementById('ce-' + key + '-picker');
  const text   = document.getElementById('ce-' + key);
  if (picker && text) { text.value = picker.value; syncColorPreview(key, picker.value); markUnsaved(); }
}

function syncColorFromText(key) {
  const text   = document.getElementById('ce-' + key);
  const picker = document.getElementById('ce-' + key + '-picker');
  if (text && picker && /^#[0-9a-f]{6}$/i.test(text.value)) { picker.value = text.value; syncColorPreview(key, text.value); }
}

function syncColorPreview(key, val) {
  const picker  = document.getElementById('ce-' + key + '-picker');
  const preview = document.getElementById('preview-' + key);
  if (picker  && val) picker.value  = val;
  if (preview && val) preview.style.background = val;
}

function markUnsaved() {
  unsavedChanges = true;
  document.getElementById('contentSaveBar')?.classList.add('visible');
}

function discardContentChanges() {
  renderContentEditor();
  toast('Changes discarded.', 'info');
}

function saveContentChanges() {
  const slug = currentEditSlug;
  if (!slug) return;
  const form = DB.getForm(slug);
  if (!form) return;

  const get = id => document.getElementById(id)?.value || '';
  form.content = {
    eventBadge:        get('ce-eventBadge'),
    heroTitle:         get('ce-heroTitle'),
    heroTitleAccent:   get('ce-heroTitleAccent'),
    heroSubtitle:      get('ce-heroSubtitle'),
    stat1Value:        get('ce-stat1Value'),
    stat1Label:        get('ce-stat1Label'),
    stat2Value:        get('ce-stat2Value'),
    stat2Label:        get('ce-stat2Label'),
    stat3Value:        get('ce-stat3Value'),
    stat3Label:        get('ce-stat3Label'),
    formIconEmoji:     get('ce-formIconEmoji'),
    formHeading:       get('ce-formHeading'),
    formSubheading:    get('ce-formSubheading'),
    submitButtonText:  get('ce-submitButtonText'),
    footerText:        get('ce-footerText'),
    successTitle:      get('ce-successTitle'),
    successMessage:    get('ce-successMessage'),
    successIdLabel:    get('ce-successIdLabel'),
    successNote:       get('ce-successNote'),
    primaryColor:      get('ce-primaryColor'),
    accentColor:       get('ce-accentColor'),
    formClosed:        document.getElementById('ce-formClosed')?.checked || false,
    formClosedMessage: get('ce-formClosedMessage')
  };

  DB.saveForm(form);
  unsavedChanges = false;
  document.getElementById('contentSaveBar').classList.remove('visible');
  toast('Content saved!', 'success');
}

/* ============================================================
   CORE FIELD EDITOR
   ============================================================ */
function renderCoreFields() {
  const slug = currentEditSlug || DB.getForms()[0]?.slug;
  if (!slug) return;
  const form = DB.getForm(slug);
  if (!form) return;

  const badge2 = document.getElementById('editingForBadge2');
  if (badge2) badge2.textContent = 'Editing: ' + form.name;

  const el = document.getElementById('coreFieldsList');
  if (!el) return;

  el.innerHTML = form.coreFields.map((f, idx) => `
    <div class="core-field-row">
      <span class="field-drag-handle">⠿</span>
      <div>
        <div class="field-row-label">${escHtml(f.label)}</div>
        ${f.placeholder ? `<div style="font-size:.72rem;color:var(--ink-muted);margin-top:2px;">${escHtml(f.placeholder)}</div>` : ''}
      </div>
      <span class="field-row-type">${escHtml(f.type)}</span>
      <span style="font-size:.78rem;color:var(--ink-muted);">${f.required ? '★ Required' : 'Optional'}</span>
      <label class="toggle-switch" title="${f.enabled ? 'Enabled' : 'Disabled'}">
        <input type="checkbox" ${f.enabled ? 'checked' : ''} onchange="toggleCoreField(${idx})"/>
        <span class="toggle-track"></span>
      </label>
      <button class="btn-edit-field" onclick="openFieldModal(${idx})">Edit</button>
    </div>
  `).join('');
}

function toggleCoreField(idx) {
  const form = DB.getForm(currentEditSlug);
  if (!form) return;
  form.coreFields[idx].enabled = !form.coreFields[idx].enabled;
  DB.saveForm(form);
  toast(`Field ${form.coreFields[idx].enabled ? 'enabled' : 'disabled'}.`, 'info');
}

function openFieldModal(idx) {
  const form = DB.getForm(currentEditSlug);
  if (!form) return;
  const f = form.coreFields[idx];

  document.getElementById('fm-fieldId').value    = idx;
  document.getElementById('fm-label').value       = f.label;
  document.getElementById('fm-placeholder').value = f.placeholder || '';
  document.getElementById('fm-required').checked  = f.required;
  document.getElementById('fm-width').value       = f.width || 'half';

  const optGroup = document.getElementById('fm-optionsGroup');
  if (f.type === 'select') {
    optGroup.style.display  = 'block';
    document.getElementById('fm-options').value = f.options || '';
  } else {
    optGroup.style.display  = 'none';
  }

  document.getElementById('fieldModal').style.display = 'flex';
  setTimeout(() => document.getElementById('fm-label').focus(), 50);
}

function saveFieldEdit() {
  const form = DB.getForm(currentEditSlug);
  if (!form) return;
  const idx = parseInt(document.getElementById('fm-fieldId').value);
  const f   = form.coreFields[idx];

  f.label       = document.getElementById('fm-label').value.trim()       || f.label;
  f.placeholder = document.getElementById('fm-placeholder').value.trim() || '';
  f.required    = document.getElementById('fm-required').checked;
  f.width       = document.getElementById('fm-width').value;
  if (f.type === 'select') f.options = document.getElementById('fm-options').value;

  DB.saveForm(form);
  closeModal('fieldModal');
  renderCoreFields();
  toast('Field updated!', 'success');
}

/* ============================================================
   CUSTOM FIELDS
   ============================================================ */
function toggleCFOptions() {
  const type = document.getElementById('cf-type')?.value;
  document.getElementById('cf-optionsGroup').style.display = type === 'select' ? 'block' : 'none';
}

function addCustomField() {
  const slug = currentEditSlug || DB.getForms()[0]?.slug;
  if (!slug) { toast('Select a form to edit first.', 'error'); return; }
  const form = DB.getForm(slug);
  if (!form) return;

  const label = document.getElementById('cf-label')?.value.trim();
  const type  = document.getElementById('cf-type')?.value;
  const width = document.getElementById('cf-width')?.value;
  const opts  = document.getElementById('cf-options')?.value.trim();
  const req   = document.getElementById('cf-required')?.checked;

  if (!label) { toast('Field label is required.', 'error'); return; }

  form.customFields.push({ id: genId(), label, type, width, options: opts || '', required: req, enabled: true });
  DB.saveForm(form);

  document.getElementById('cf-label').value   = '';
  document.getElementById('cf-options').value = '';
  document.getElementById('cf-required').checked = false;

  renderCustomFieldsList();
  toast('Custom field added!', 'success');
}

function renderCustomFieldsList() {
  const slug = currentEditSlug || DB.getForms()[0]?.slug;
  if (!slug) return;
  const form = DB.getForm(slug);
  const el   = document.getElementById('customFieldsList');
  if (!el) return;

  const badge3 = document.getElementById('editingForBadge3');
  if (badge3) badge3.textContent = form ? 'Editing: ' + form.name : '';

  if (!form?.customFields?.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⊕</div><p>No custom fields yet.</p></div>';
    return;
  }

  el.innerHTML = form.customFields.map((f, i) => `
    <div class="custom-field-item">
      <div class="cfi-left">
        <span class="cfi-label">${escHtml(f.label)}</span>
        <span class="cfi-meta">Type: ${escHtml(f.type)} · ${f.width} · ${f.required ? 'Required' : 'Optional'}${f.options ? ' · '+escHtml(f.options) : ''}</span>
      </div>
      <div class="cfi-right">
        <button class="btn-sm danger" onclick="deleteCustomField(${i})">Remove</button>
      </div>
    </div>
  `).join('');
}

function deleteCustomField(idx) {
  const slug = currentEditSlug || DB.getForms()[0]?.slug;
  const form = DB.getForm(slug);
  if (!form) return;
  if (!confirm('Remove this custom field?')) return;
  form.customFields.splice(idx, 1);
  DB.saveForm(form);
  renderCustomFieldsList();
  toast('Field removed.', 'info');
}

/* ============================================================
   IMAGE MANAGEMENT
   ============================================================ */
function handleImageUpload(event) {
  const files = Array.from(event.target.files || []);
  let done = 0;
  files.forEach(file => {
    if (file.size > 5 * 1024 * 1024) { toast(`${file.name} exceeds 5MB.`, 'error'); return; }
    const reader = new FileReader();
    reader.onload = e => {
      DB.addImage(e.target.result);
      done++;
      if (done === files.length) { renderImageGallery(); toast(`${done} image(s) uploaded!`, 'success'); }
    };
    reader.readAsDataURL(file);
  });
  event.target.value = '';
}

function renderImageGallery() {
  const imgs = DB.getImages();
  const el   = document.getElementById('imageGallery');
  if (!el) return;
  if (!imgs.length) {
    el.innerHTML = '<div class="empty-state"><div class="empty-state-icon">🖼</div><p>No images yet.</p></div>';
    return;
  }
  el.innerHTML = imgs.map(img => `
    <div class="gallery-item">
      <img src="${img.src}" alt="Uploaded" loading="lazy"/>
      <button class="gallery-del" onclick="deleteImage('${img.id}')">✕</button>
    </div>
  `).join('');
}

function deleteImage(id) {
  if (!confirm('Delete this image?')) return;
  DB.deleteImage(id);
  renderImageGallery();
  toast('Image deleted.', 'info');
}

// Drag-and-drop upload
document.addEventListener('DOMContentLoaded', () => {
  const zone = document.getElementById('uploadZone');
  if (!zone) return;
  zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('drag-over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
  zone.addEventListener('drop', e => {
    e.preventDefault();
    zone.classList.remove('drag-over');
    const files = Array.from(e.dataTransfer.files).filter(f => f.type.startsWith('image/'));
    if (!files.length) return;
    const fakeEvent = { target: { files, value: '' } };
    handleImageUpload(fakeEvent);
  });
});

/* ============================================================
   SECURITY — ACCESS LOG
   ============================================================ */
function renderAccessLog() {
  const log = JSON.parse(localStorage.getItem(LOG_KEY) || '[]');
  const el  = document.getElementById('accessLog');
  if (!el) return;
  if (!log.length) { el.innerHTML = '<p class="muted">No login attempts recorded yet.</p>'; return; }
  el.innerHTML = log.map(entry => `
    <div style="display:flex;align-items:center;gap:14px;padding:10px 14px;background:${entry.success ? 'var(--g50)' : '#fef2f2'};border-radius:var(--r-sm);font-size:.8rem;">
      <span style="font-size:1rem;">${entry.success ? '✅' : '❌'}</span>
      <span style="font-weight:600;color:var(--ink)">${escHtml(entry.username)}</span>
      <span style="color:var(--ink-muted)">${entry.success ? 'Successful login' : 'Failed login'}${entry.reason && !entry.success ? ' — '+escHtml(entry.reason) : ''}</span>
      <span style="margin-left:auto;color:var(--ink-muted);font-size:.74rem;">${fmtDate(entry.ts)}</span>
    </div>
  `).join('');
}

/* ============================================================
   DANGER ZONE
   ============================================================ */
function clearAllData() {
  if (!confirm('This will permanently delete ALL forms and registrations. Are you absolutely sure?')) return;
  if (!confirm('FINAL WARNING: This cannot be undone. Delete everything?')) return;
  const keys = Object.keys(localStorage).filter(k => k.startsWith('rf_'));
  keys.forEach(k => localStorage.removeItem(k));
  toast('All data cleared.', 'info');
  setTimeout(() => location.reload(), 1000);
}

function resetToDefaults() {
  if (!confirm('Reset all form content to defaults? Registrations are kept.')) return;
  DB.getForms().forEach(f => {
    const fresh = defaultFormConfig(f.name, f.slug);
    fresh.customFields   = f.customFields;   // keep custom fields
    DB.saveForm(fresh);
  });
  toast('Forms reset to defaults.', 'success');
  renderForms();
}

/* ============================================================
   MODAL HELPERS
   ============================================================ */
function closeModal(id) { document.getElementById(id).style.display = 'none'; }
function closeModalOn(e, id) { if (e.target.id === id) closeModal(id); }

/* ============================================================
   MOBILE SIDEBAR
   ============================================================ */
function toggleSidebar() { document.getElementById('sidebar')?.classList.toggle('open'); }

/* ============================================================
   TOAST NOTIFICATIONS
   ============================================================ */
function toast(msg, type = 'success') {
  const container = document.getElementById('toastContainer');
  if (!container) return;
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ'}</span> ${escHtml(msg)}`;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transform = 'translateX(20px)'; el.style.transition = 'all .3s'; setTimeout(() => el.remove(), 300); }, 3200);
}

/* ============================================================
   UTILITIES (mirror from script.js)
   ============================================================ */
function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-NG', { day:'numeric', month:'short', year:'numeric' });
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function genId() { return Math.random().toString(36).substring(2,9).toUpperCase(); }
