/**
 * RunFest — script.js
 * ─────────────────────────────────────────────────────────────
 * Shared data layer (localStorage) + dynamic form renderer.
 * Every piece of visible content is driven by admin config.
 * Multiple forms supported via ?form=SLUG in the URL.
 * ─────────────────────────────────────────────────────────────
 */

/* ============================================================
   DATA LAYER
   ============================================================ */
const DB = {
  getForms()          { return JSON.parse(localStorage.getItem('rf_forms') || '[]'); },
  saveForms(d)        { localStorage.setItem('rf_forms', JSON.stringify(d)); },
  getForm(slug)       { return this.getForms().find(f => f.slug === slug) || null; },
  saveForm(form) {
    const all = this.getForms();
    const idx = all.findIndex(f => f.slug === form.slug);
    if (idx >= 0) all[idx] = form; else all.push(form);
    this.saveForms(all);
  },
  deleteForm(slug) {
    this.saveForms(this.getForms().filter(f => f.slug !== slug));
    localStorage.removeItem('rf_regs_' + slug);
  },

  getRegistrations(slug)       { return JSON.parse(localStorage.getItem('rf_regs_' + slug) || '[]'); },
  saveRegistrations(slug, data){ localStorage.setItem('rf_regs_' + slug, JSON.stringify(data)); },
  addRegistration(slug, reg) {
    const all = this.getRegistrations(slug);
    if (all.find(r => r.email && r.email.toLowerCase() === (reg.email || '').toLowerCase()))
      throw new Error('This email address is already registered for this form.');
    if (reg.phone && all.find(r => r.phone === reg.phone))
      throw new Error('This phone number is already registered for this form.');
    all.push(reg);
    this.saveRegistrations(slug, all);
    return reg;
  },
  deleteRegistration(slug, id) {
    this.saveRegistrations(slug, this.getRegistrations(slug).filter(r => r.id !== id));
  },

  getImages()     { return JSON.parse(localStorage.getItem('rf_images') || '[]'); },
  saveImages(d)   { localStorage.setItem('rf_images', JSON.stringify(d)); },
  addImage(src) {
    const imgs = this.getImages();
    const img = { id: genId(), src, uploaded: new Date().toISOString() };
    imgs.push(img);
    this.saveImages(imgs);
    return img;
  },
  deleteImage(id) { this.saveImages(this.getImages().filter(i => i.id !== id)); }
};

/* ============================================================
   DEFAULT FORM CONFIG — everything editable via admin
   ============================================================ */
function defaultFormConfig(name, slug) {
  return {
    slug,
    name,
    createdAt: new Date().toISOString(),
    active: true,

    /* ── All user-visible content ── */
    content: {
      eventBadge:        '🏁 ' + name,
      heroTitle:         'Join the Race.',
      heroTitleAccent:   'Make History.',
      heroSubtitle:      'Register for the most electrifying campus marathon of the year. Lace up, show up, show out.',
      stat1Value:        '0',
      stat1Label:        'Registered',
      stat2Value:        '5km',
      stat2Label:        'Distance',
      stat3Value:        '🏆',
      stat3Label:        'Prizes',
      formIconEmoji:     '✦',
      formHeading:       'Register Now',
      formSubheading:    'Fill in your details below — takes less than 2 minutes.',
      submitButtonText:  'Register for ' + name,
      successTitle:      "You're In!",
      successMessage:    'Welcome to ' + name + ', {name}!',
      successIdLabel:    'Your Runner ID:',
      successNote:       "Save your Runner ID — you'll need it on race day.",
      footerText:        name + ' · Organized by the Students\' Union',
      primaryColor:      '#22883f',
      accentColor:       '#d4a832',
      formClosed:        false,
      formClosedMessage: 'Registration for this event is currently closed.'
    },

    /* ── Core fields (label, placeholder, required, enabled all editable) ── */
    coreFields: [
      { id:'fullName',       label:'Full Name',                   type:'text',     placeholder:'e.g. Amara Okafor',                     required:true,  enabled:true,  width:'full' },
      { id:'phone',          label:'Phone Number',                type:'tel',      placeholder:'08012345678',                           required:true,  enabled:true,  width:'half' },
      { id:'email',          label:'Email Address',               type:'email',    placeholder:'you@university.edu.ng',                 required:true,  enabled:true,  width:'half' },
      { id:'department',     label:'Department',                  type:'text',     placeholder:'e.g. Computer Science',                 required:true,  enabled:true,  width:'half' },
      { id:'level',          label:'Level',                       type:'select',   options:'100L,200L,300L,400L,500L,600L,Postgraduate',required:true,  enabled:true,  width:'half' },
      { id:'genotype',       label:'Genotype',                    type:'select',   options:'AA,AS,SS,AC,SC',                            required:true,  enabled:true,  width:'half' },
      { id:'hostel',         label:'Hostel Address',              type:'text',     placeholder:'e.g. Block C, Room 14, Sultan Hostel',  required:true,  enabled:true,  width:'full' },
      { id:'naqeeb',         label:'Hostel Rep / Naqeeb Phone',   type:'tel',      placeholder:"Hostel rep's phone number",             required:true,  enabled:true,  width:'full' },
      { id:'healthCondition',label:'Any Health Condition',        type:'textarea', placeholder:'Describe any condition. Leave blank if none.', required:false, enabled:true, width:'full' }
    ],

    customFields: []
  };
}

/* ============================================================
   UTILITIES
   ============================================================ */
function genId() { return Math.random().toString(36).substring(2,9).toUpperCase(); }

function genSlug(name) {
  return name.toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'')
    + '-' + Math.floor(1000 + Math.random()*9000);
}

function genRunnerId(existing = []) {
  let id;
  do { id = 'RUN-' + Math.floor(10000 + Math.random()*90000); } while (existing.includes(id));
  return id;
}

function fmtDate(iso) {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-NG', { day:'numeric', month:'short', year:'numeric' });
}

function escHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function formUrl(slug) {
  const path = window.location.pathname.replace(/admin\.html.*/, 'index.html');
  return window.location.origin + path + '?form=' + encodeURIComponent(slug);
}

/* ============================================================
   REGISTRATION FORM (index.html)
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('registrationForm');
  if (!form) return;

  const params = new URLSearchParams(window.location.search);
  const slug = params.get('form') || DB.getForms()[0]?.slug;

  if (!slug) { return showFormError('No form found. Please use the link provided by your organizer.'); }
  const cfg = DB.getForm(slug);
  if (!cfg)  { return showFormError('This form does not exist or has been removed.'); }

  form.dataset.slug = slug;
  applyContent(cfg);
  renderFormFields(cfg, form);
  updateLiveCount(slug, cfg);
  renderBannerImages();

  form.addEventListener('submit', e => handleSubmit(e, cfg));
  form.addEventListener('blur',   e => validateField(e.target), true);
  form.addEventListener('input',  e => { if (e.target.classList.contains('invalid')) validateField(e.target); });
});

function showFormError(msg) {
  const main = document.querySelector('main');
  if (main) main.innerHTML = `
    <div style="max-width:560px;margin:80px auto;padding:40px;background:#fff;border-radius:20px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.1)">
      <div style="font-size:3rem;margin-bottom:16px">⚠️</div>
      <h2 style="font-family:'Playfair Display',serif;margin-bottom:8px">Form Unavailable</h2>
      <p style="color:#6b8c73">${escHtml(msg)}</p>
    </div>`;
}

function applyContent(cfg) {
  const c = cfg.content;
  document.documentElement.style.setProperty('--green-500', c.primaryColor || '#22883f');
  document.documentElement.style.setProperty('--green-600', shadeColor(c.primaryColor || '#22883f', -15));
  document.documentElement.style.setProperty('--green-400', shadeColor(c.primaryColor || '#22883f', 15));
  document.documentElement.style.setProperty('--gold', c.accentColor || '#d4a832');
  document.documentElement.style.setProperty('--gold-light', shadeColor(c.accentColor || '#d4a832', 20));

  const set = (id, val) => { const el=document.getElementById(id); if(el&&val!=null) el.textContent=val; };
  set('heroBadge',       c.eventBadge);
  set('heroTitle',       c.heroTitle);
  set('heroTitleAccent', c.heroTitleAccent);
  set('heroSubtitle',    c.heroSubtitle);
  set('heroStat1Value',  c.stat1Value);
  set('heroStat1Label',  c.stat1Label);
  set('heroStat2Value',  c.stat2Value);
  set('heroStat2Label',  c.stat2Label);
  set('heroStat3Value',  c.stat3Value);
  set('heroStat3Label',  c.stat3Label);
  set('formIcon',        c.formIconEmoji);
  set('formHeading',     c.formHeading);
  set('formSubheading',  c.formSubheading);
  set('submitBtnText',   c.submitButtonText);
  set('successTitle',    c.successTitle);
  set('successIdLabel',  c.successIdLabel);
  set('successNote',     c.successNote);
  set('footerText',      c.footerText);

  document.title = (cfg.name || 'Registration') + ' — Registration';

  const formEl = document.getElementById('registrationForm');
  if (c.formClosed && formEl) {
    formEl.style.display = 'none';
    const closed = document.getElementById('formClosedMsg');
    if (closed) { closed.style.display = 'block'; closed.textContent = c.formClosedMessage; }
  }
}

// Simple hex color shade utility
function shadeColor(hex, pct) {
  try {
    let r = parseInt(hex.slice(1,3),16), g = parseInt(hex.slice(3,5),16), b = parseInt(hex.slice(5,7),16);
    r = Math.min(255, Math.max(0, r + Math.round(r*pct/100)));
    g = Math.min(255, Math.max(0, g + Math.round(g*pct/100)));
    b = Math.min(255, Math.max(0, b + Math.round(b*pct/100)));
    return '#'+[r,g,b].map(v=>v.toString(16).padStart(2,'0')).join('');
  } catch { return hex; }
}

function renderFormFields(cfg) {
  const container = document.getElementById('formFieldsContainer');
  if (!container) return;
  container.innerHTML = '';
  const allFields = [...cfg.coreFields.filter(f => f.enabled), ...cfg.customFields];

  allFields.forEach(f => {
    const group = document.createElement('div');
    group.className = 'field-group' + (f.width === 'full' ? ' full-width' : '');

    const label = document.createElement('label');
    label.htmlFor = 'field_' + f.id;
    label.innerHTML = escHtml(f.label) + (f.required ? ' <span class="req">*</span>' : '');
    group.appendChild(label);

    let input;
    if (f.type === 'textarea') {
      input = document.createElement('textarea');
      input.rows = 3;
      input.placeholder = f.placeholder || '';
    } else if (f.type === 'select') {
      input = document.createElement('select');
      const blank = document.createElement('option');
      blank.value = ''; blank.textContent = '— Select ' + f.label + ' —';
      input.appendChild(blank);
      (f.options || '').split(',').map(o=>o.trim()).filter(Boolean).forEach(o => {
        const opt = document.createElement('option');
        opt.value = o; opt.textContent = o; input.appendChild(opt);
      });
    } else {
      input = document.createElement('input');
      input.type = f.type || 'text';
      input.placeholder = f.placeholder || '';
    }

    input.id = 'field_' + f.id;
    input.name = f.id;
    input.dataset.fieldId = f.id;
    if (f.required) input.required = true;

    const err = document.createElement('span');
    err.className = 'field-error';
    err.id = 'err-field_' + f.id;

    group.appendChild(input);
    group.appendChild(err);
    container.appendChild(group);
  });
}

function updateLiveCount(slug, cfg) {
  const el = document.getElementById('heroStat1Value');
  if (el) el.textContent = DB.getRegistrations(slug).length;
}

function renderBannerImages() {
  const imgs = DB.getImages();
  const heroBar = document.getElementById('heroImageBar');
  const banner  = document.getElementById('bannerStrip');
  if (!imgs.length) return;
  if (heroBar) heroBar.innerHTML = imgs.slice(0,3).map(i=>`<img src="${i.src}" alt="Event photo" loading="lazy"/>`).join('');
  if (banner)  { banner.style.display='flex'; banner.innerHTML = imgs.map(i=>`<img src="${i.src}" alt="Event photo" loading="lazy"/>`).join(''); }
}

/* Validation */
function validateField(el) {
  if (!el || !el.id) return true;
  const errEl = document.getElementById('err-' + el.id);
  let msg = '';
  if (el.required && !el.value.trim()) msg = 'This field is required.';
  else if (el.type==='email'&&el.value&&!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(el.value)) msg = 'Enter a valid email address.';
  else if (el.type==='tel'&&el.value&&!/^\+?[\d\s\-]{7,15}$/.test(el.value)) msg = 'Enter a valid phone number.';
  el.classList.toggle('invalid', !!msg);
  if (errEl) errEl.textContent = msg;
  return !msg;
}

function validateAll(form) {
  let valid = true;
  form.querySelectorAll('input,select,textarea').forEach(el => { if (!validateField(el)) valid = false; });
  return valid;
}

/* Submit */
async function handleSubmit(e, cfg) {
  e.preventDefault();
  const form = e.target;
  const slug = form.dataset.slug;
  const errorBox = document.getElementById('errorBox');
  errorBox.style.display = 'none';

  if (!validateAll(form)) {
    errorBox.style.display = 'block';
    errorBox.textContent = 'Please fix the errors above before submitting.';
    form.querySelector('.invalid')?.scrollIntoView({ behavior:'smooth', block:'center' });
    return;
  }

  const btn = document.getElementById('submitBtn');
  btn.disabled = true;

  const values = {};
  form.querySelectorAll('[data-field-id]').forEach(el => {
    values[el.dataset.fieldId] = el.value.trim();
  });

  await new Promise(r => setTimeout(r, 700));

  try {
    const existing = DB.getRegistrations(slug).map(r => r.id);
    const reg = { id: genRunnerId(existing), ...values,
                  email: (values.email||'').toLowerCase(), registeredAt: new Date().toISOString() };
    DB.addRegistration(slug, reg);

    form.style.display = 'none';
    const box = document.getElementById('successBox');
    box.style.display = 'block';

    const firstName = (values.fullName||'Runner').split(' ')[0];
    const msg = (cfg.content.successMessage||'Welcome, {name}!').replace('{name}', firstName);
    const msgEl = document.getElementById('successMessage');
    if (msgEl) msgEl.textContent = msg;
    const idEl = document.getElementById('successId');
    if (idEl) idEl.textContent = reg.id;

    updateLiveCount(slug, cfg);
  } catch (err) {
    errorBox.style.display = 'block';
    errorBox.textContent = err.message;
    btn.disabled = false;
  }
}

function resetForm() {
  const form = document.getElementById('registrationForm');
  form.reset();
  form.style.display = 'block';
  form.querySelectorAll('.invalid').forEach(el => el.classList.remove('invalid'));
  form.querySelectorAll('.field-error').forEach(el => el.textContent = '');
  document.getElementById('submitBtn').disabled = false;
  document.getElementById('successBox').style.display = 'none';
  document.getElementById('errorBox').style.display = 'none';
}
