// The administrators' pages: Overview, Users and Sessions, read only. The data is the helper's (`waydesk-admin ... --json`), passed on by the portal at
// /api/admin/*; the portal asks the helper on every request whether the account is an administrator, so hiding the menu here is only convenience.
// Everything is put on the page with textContent (never innerHTML): a name from the machine's account list cannot become markup.

const el = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === false || v == null) continue;
    if (k === 'class') e.className = v;
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return e;
};
const chip = (text, tone = '') => el('span', { class: 'tag ' + tone }, text);
const dot = (tone = '') => el('span', { class: 'dot ' + tone });
const win = (title, ...body) => el('section', { class: 'win' }, el('div', { class: 'bar' }, el('span', { class: 't' }, title), el('span', { class: 'cap', 'aria-hidden': 'true' }, el('i', {}, '–'), el('i', {}, '□'), el('i', {}, '✕'))), el('div', { class: 'body' }, body));
const meter = (percent, warn = false) => el('div', { class: 'meter' }, el('i', { class: warn ? 'w' : '', style: `width:${Math.max(0, Math.min(100, Math.round(percent)))}%` }));
const gb = (mb) => (mb >= 1024 ? (mb / 1024).toFixed(mb >= 10240 ? 0 : 1) + ' GB' : Math.round(mb) + ' MB');
const table = (heads, rows, empty) => el('div', { class: 'tw' }, rows.length === 0 ? el('p', { class: 'muted' }, empty) : el('table', {}, el('thead', {}, el('tr', {}, heads.map((h) => el('th', { class: h.startsWith('>') ? 'n' : '' }, h.replace(/^>/, ''))))), el('tbody', {}, rows)));
const cell = (content, cls = '') => el('td', { class: cls }, content);
const sessionSince = (s) => (s ? s.replace(/^\w+ /, '').replace(/ [A-Z]{2,5}$/, '') : '');

async function get(kind) {
  const r = await fetch('/api/admin/' + kind, { cache: 'no-store' });
  if (r.status === 401) { const e = new Error('Your sign-in ended.'); e.signedOut = true; throw e; }
  if (r.status === 403) throw new Error('This page is for administrators.');
  if (!r.ok) throw new Error('The server could not be asked (' + r.status + ').');
  return r.json();
}

// ---- changes ----
// A change is one POST of one action from the closed list (src/adminaction.rs); the server checks the origin, the CSRF token and that the account is an
// administrator, and so does the helper behind it. `ctx` is { csrf(), reload(), flash(text, tone), signedOut() }.
let ctx = null;

async function act(action) {
  const r = await fetch('/api/admin/do', { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': ctx.csrf() }, body: JSON.stringify(action) });
  if (r.status === 401) { ctx.signedOut(); throw new Error('Your sign-in ended.'); }
  if (r.status === 403) throw new Error('Only administrators can do this.');
  if (r.status === 429) throw new Error('Too many changes in a minute. Wait a little.');
  let body = null;
  try { body = await r.json(); } catch { /* handled below */ }
  if (!body) throw new Error('The server could not do this (' + r.status + ').');
  if (!body.ok) throw new Error(body.error || 'It did not work.');
  return body.result || {};
}

// A window over the page: a title bar like every window, the content, and buttons. Closes on Escape or by its own buttons.
function modal(title, content, buttons) {
  const d = el('dialog', { class: 'win dlg', 'aria-label': title },
    el('div', { class: 'bar' }, el('span', { class: 't' }, title)),
    el('div', { class: 'body' }, content, el('div', { class: 'actions' }, buttons)));
  d.addEventListener('close', () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}
const button = (label, onClick, kind = '') => { const b = el('button', { type: 'button', class: 'btn ' + kind }, label); b.addEventListener('click', onClick); return b; };

// "Are you sure": resolves to true or false.
function confirmBox(title, text, label, danger = false, extra = null) {
  return new Promise((resolve) => {
    let answer = false;
    const d = modal(title, [el('p', {}, text), extra], [button('Cancel', () => d.close()), button(label, () => { answer = true; d.close(); }, danger ? 'danger' : 'primary')]);
    d.addEventListener('close', () => resolve(answer));
  });
}

// Runs a change, tells the administrator what happened, and reloads the page.
async function run(action, done) {
  try {
    const result = await act(action);
    ctx.flash(done(result) || 'Done.', 'ok');
  } catch (e) {
    ctx.flash(e.message, 'bad');
  }
  ctx.reload();
}

// A new password is shown once, here, and nowhere else (the server does not keep it).
function showPassword(who, password, why) {
  const box = el('code', { class: 'secret' }, password);
  const copy = button('Copy', async () => { try { await navigator.clipboard.writeText(password); copy.textContent = 'Copied'; } catch { copy.textContent = 'Select and copy it'; } });
  const d = modal(why + ': ' + who, [el('p', {}, 'The password is shown once. Give it to the person; they should change it at once (Change password, in the desktop\u2019s power menu).'), box], [copy, button('Done', () => d.close(), 'primary')]);
}

function addUser() {
  const name = el('input', { name: 'name', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: true, placeholder: 'frida' });
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' }, el('label', {}, 'Account name', name), el('p', { class: 'hint' }, 'Lower case letters, digits, _ and -. The account may use Waydesk at once; a first password is made and shown once.'), err);
  const d = modal('add user', form, [button('Cancel', () => d.close()), button('Create', () => form.requestSubmit(), 'primary')]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const r = await act({ action: 'user_add', name: name.value.trim() });
      d.close();
      ctx.flash('Made ' + r.name + '.', 'ok');
      ctx.reload();
      showPassword(r.name, r.password, 'first password');
    } catch (x) { err.textContent = x.message; }
  });
  name.focus();
}

function editUser(u) {
  const select = (label, name, options, current) => el('label', {}, label, el('select', { name }, options.map((o) => el('option', { value: o[0], selected: o[0] === current }, o[1]))));
  const desktop = select('Desktop', 'desktop', [['', 'no change'], ['default', 'server default'], ['sway', 'Sway'], ['plasma', 'Plasma'], ['cosmic', 'COSMIC'], ['hyprland', 'Hyprland']], '');
  const gpu = select('Graphics', 'gpu', [['', 'no change'], ['default', 'server default'], ['auto', 'auto'], ['balance', 'balance'], ['off', 'off (software)']], '');
  const memory = el('input', { name: 'memory', placeholder: 'e.g. 6G, or reset', autocomplete: 'off', spellcheck: 'false' });
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' }, desktop, gpu, el('label', {}, 'Memory limit of the session', memory), el('p', { class: 'hint' }, 'A running session keeps what it started with; the new setting applies from the next one.'), err);
  const d = modal('edit ' + u.name, form, [button('Cancel', () => d.close()), button('Save', () => form.requestSubmit(), 'primary')]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const dv = desktop.querySelector('select').value, gv = gpu.querySelector('select').value, mv = memory.value.trim();
    if (!dv && !gv && !mv) { err.textContent = 'Nothing to change.'; return; }
    try {
      if (dv || gv) await act({ action: 'user_set', name: u.name, desktop: dv || null, gpu: gv || null });
      if (mv) await act({ action: 'user_limit', name: u.name, memory: mv });
      d.close();
      ctx.flash('Saved ' + u.name + '.', 'ok');
      ctx.reload();
    } catch (x) { err.textContent = x.message; }
  });
}

async function disableUser(u) {
  const keep = el('input', { type: 'checkbox' });
  const extra = u.session === 'running' ? el('label', { class: 'check' }, keep, 'Keep the running session (it ends by itself when they disconnect)') : null;
  if (!(await confirmBox('Switch off ' + u.name + '?', u.name + ' will no longer be able to log in over RDP or the browser.', 'Switch off', true, extra))) return;
  run({ action: 'user_disable', name: u.name, keep_session: keep.checked }, () => u.name + ' may no longer log in.');
}

async function resetPassword(u) {
  if (!(await confirmBox('New password for ' + u.name + '?', 'The old password stops working at once. The new one is shown once.', 'Make a new password'))) return;
  try {
    const r = await act({ action: 'user_passwd', name: u.name });
    showPassword(u.name, r.password, 'new password');
  } catch (e) { ctx.flash(e.message, 'bad'); }
}

async function endSession(name) {
  if (!(await confirmBox('End the session of ' + name + '?', 'Their programs are closed and unsaved work is lost.', 'End session', true))) return;
  run({ action: 'session_end', name }, () => 'Ended the session of ' + name + '.');
}

function tile(label, value, unit, percent, warn) {
  return el('div', { class: 'tile' }, el('div', { class: 'k' }, label), el('div', { class: 'big' }, value, ' ', el('small', {}, unit)), percent == null ? null : meter(percent, warn));
}

const views = {
  async overview() {
    const s = await get('status');
    const m = s.machine || {};
    const a = s.admission || {};
    const gpus = s.gpus || [];
    const usedMb = (m.mem_total_mb || 0) - (m.mem_available_mb || 0);
    const memPct = m.mem_total_mb ? (usedMb / m.mem_total_mb) * 100 : 0;
    const swapTotal = m.swap_total_mb || 0;
    const sessionsNow = (s.users || []).filter((u) => u.session);
    const g0 = gpus[0];
    const tiles = el('div', { class: 'tiles' },
      tile('Sessions', a.sessions ?? sessionsNow.length, a.max_active_users ? 'of ' + a.max_active_users : 'running', a.max_active_users ? ((a.sessions ?? 0) / a.max_active_users) * 100 : null, a.max_active_users && (a.sessions ?? 0) / a.max_active_users > 0.8),
      tile('Memory', gb(usedMb), 'of ' + gb(m.mem_total_mb || 0), memPct, memPct > 80),
      tile('Swap', swapTotal ? gb(m.swap_used_mb || 0) : 'none', swapTotal ? 'of ' + gb(swapTotal) : '', swapTotal ? ((m.swap_used_mb || 0) / swapTotal) * 100 : null, swapTotal && (m.swap_used_mb || 0) / swapTotal > 0.5),
      g0 ? tile('GPU' + (gpus.length > 1 ? ' 1 of ' + gpus.length : ''), g0.busy_percent == null ? '-' : Math.round(g0.busy_percent), '% busy' + (g0.encoder_percent != null ? ' · encode ' + Math.round(g0.encoder_percent) + '%' : ''), g0.busy_percent, g0.busy_percent > 85) : tile('GPU', 'none', 'software rendering', null));
    const attention = [];
    if (a.open === false) attention.push(['full', 'bad', 'New sessions are refused: ' + (a.reason || 'the machine is full')]);
    for (const w of s.warnings || []) attention.push(['warning', 'warn', w]);
    const rows = sessionsNow.map((u) => el('tr', {}, cell(el('b', {}, u.name)), cell((u.video && u.video.compositor) || '-'), cell(u.video && u.video.encoder ? u.video.encoder : '-'), cell(gb(u.mem_mb || 0), 'n mono'), cell(Math.round(u.cpu_percent || 0) + '%', 'n mono')));
    return [
      el('div', { class: 'head' }, el('h1', {}, 'Overview'), el('span', { class: 'sp' }), el('span', { class: 'muted small' }, 'refreshes every 10 s · same numbers as ', el('code', {}, 'waydesk-admin status'))),
      tiles,
      el('div', { class: 'two' },
        win('sessions now', table(['Account', 'Desktop', 'Encoder', '>Memory', '>CPU'], rows, 'Nobody is logged in.')),
        el('div', { class: 'stack' },
          win('needs attention', attention.length ? el('div', { class: 'tw' }, el('table', { class: 'plain' }, el('tbody', {}, attention.map(([k, tone, text]) => el('tr', {}, cell(chip(k, tone)), cell(text)))))) : el('p', { class: 'ok' }, 'Nothing needs attention.')),
          win('machine', el('dl', { class: 'kv' },
            el('dt', {}, 'System'), el('dd', {}, m.os || '-'),
            el('dt', {}, 'Kernel'), el('dd', { class: 'mono' }, m.kernel || '-'),
            el('dt', {}, 'Load'), el('dd', { class: 'mono' }, (m.load || []).join(' ') + ' (' + (m.cores || '?') + ' cores)'),
            el('dt', {}, 'New sessions'), el('dd', { class: a.open === false ? 'bad' : 'ok' }, a.open === false ? 'refused' : 'accepted'),
            el('dt', {}, 'Desktop'), el('dd', {}, s.compositor_setting || '-'),
            el('dt', {}, 'Graphics'), el('dd', {}, s.gpu_setting || '-'))))),
    ];
  },

  async users() {
    const list = await get('users');
    const holder = el('div', {});
    const draw = (q) => {
      const shown = list.filter((u) => !q || u.name.toLowerCase().includes(q));
      holder.replaceChildren(win('accounts · ' + list.length, table(['Account', 'Desktop', 'Graphics', 'RDP', 'Admin', 'Session', ''],
        shown.map((u) => el('tr', {},
          cell(el('b', {}, u.name)),
          cell((u.desktop || '-') + (u.desktop_from === 'account' ? '*' : '')),
          cell(String(u.gpu || '-').split('/').pop() + (u.gpu_from === 'account' ? '*' : '')),
          cell(u.rdp ? chip('yes', 'ok') : chip('no', 'bad')),
          cell(u.sudo ? chip('admin') : el('span', { class: 'dim' }, '-')),
          cell(u.session === 'running' ? [dot(), 'running' + (u.desktop_running ? ' on ' + u.desktop_running : ''), u.session_since ? el('span', { class: 'dim' }, ' since ' + sessionSince(u.session_since)) : null] : [dot('off'), 'none']),
          cell(el('div', { class: 'acts' },
            button('Edit', () => editUser(u), 'sm'),
            button('Reset password', () => resetPassword(u), 'sm'),
            u.rdp ? button('Switch off', () => disableUser(u), 'sm danger') : button('Switch on', () => run({ action: 'user_enable', name: u.name }, () => u.name + ' may log in again.'), 'sm')), 'n'))),
        'No account matches.'), el('p', { class: 'hint' }, '* a setting of the account itself; the rest is the server’s setting. Removing an account, and giving administrator rights, stay on the command line.')));
    };
    const search = el('input', { type: 'search', placeholder: 'Search accounts', 'aria-label': 'Search accounts', style: 'width:14rem' });
    search.addEventListener('input', () => draw(search.value.trim().toLowerCase()));
    draw('');
    return [el('div', { class: 'head' }, el('h1', {}, 'Users'), el('span', { class: 'sp' }), search, button('Add user', addUser, 'primary')), holder];
  },

  async sessions() {
    const [list, s] = await Promise.all([get('sessions'), get('status')]);
    const by = new Map((s.users || []).map((u) => [u.name, u]));
    const rows = list.map((r) => {
      const u = by.get(r.name) || {};
      const v = u.video || {};
      return el('tr', {}, cell(el('b', {}, r.name)), cell([dot(), 'running']), cell(sessionSince(r.since)), cell(v.compositor || '-'), cell(v.encoder || '-'), cell(gb(u.mem_mb || 0), 'n mono'), cell(Math.round(u.cpu_percent || 0) + '%', 'n mono'), cell(el('div', { class: 'acts' }, button('End', () => endSession(r.name), 'sm danger')), 'n'));
    });
    const a = s.admission || {};
    return [
      el('div', { class: 'head' }, el('h1', {}, 'Sessions'), el('span', { class: 'sp' }), chip(rows.length + (a.max_active_users ? ' of ' + a.max_active_users : ' running'), 'ok')),
      win('running sessions', table(['Account', 'State', 'Since', 'Desktop', 'Encoder', '>Memory', '>CPU', ''], rows, 'No sessions running.')),
    ];
  },
};

let timer = 0;
// Draws `view` into `root`; the numbers refresh every 10 s while the page shows (not for Users, which is a list that does not change by the second).
export async function render(view, root, onSignedOut, csrf) {
  clearInterval(timer);
  const flashEl = document.getElementById('flash');
  ctx = {
    csrf,
    signedOut: onSignedOut,
    reload: () => draw(),
    flash: (text, tone) => { flashEl.textContent = text; flashEl.className = 'flash ' + tone; flashEl.hidden = false; clearTimeout(ctx.flashTimer); ctx.flashTimer = setTimeout(() => { flashEl.hidden = true; }, tone === 'bad' ? 12000 : 6000); },
  };
  flashEl.hidden = true;
  const draw = async () => {
    try {
      root.replaceChildren(...(await views[view]()));
    } catch (e) {
      if (e.signedOut) { clearInterval(timer); onSignedOut(); return; }
      root.replaceChildren(el('p', { class: 'bad' }, e.message || 'Something went wrong.'));
    }
  };
  root.replaceChildren(el('p', { class: 'muted' }, 'Loading…'));
  await draw();
  if (view !== 'users') timer = setInterval(() => { if (!document.hidden) draw(); }, 10000);
}
export const stop = () => clearInterval(timer);
export const known = (v) => Object.hasOwn(views, v);
