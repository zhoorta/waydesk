// The administrators' pages: Overview, Users and Sessions, read only. The data is the helper's (`waydesk-admin ... --json`), passed on by the portal at
// /api/admin/*; the portal asks the helper on every request whether the account is an administrator, so hiding the menu here is only convenience.
// Everything is put on the page with textContent (never innerHTML): a name from the machine's account list cannot become markup.
import { el, chip, dot, win, button, modal, confirmBox } from './ui.js';

const meter = (percent, warn = false) => el('div', { class: 'meter' }, el('i', { class: warn ? 'w' : '', style: `width:${Math.max(0, Math.min(100, Math.round(percent)))}%` }));
const gb = (mb) => (mb >= 1024 ? (mb / 1024).toFixed(mb >= 10240 ? 0 : 1) + ' GB' : Math.round(mb) + ' MB');
const table = (heads, rows, empty) => el('div', { class: 'tw' }, rows.length === 0 ? el('p', { class: 'muted' }, empty) : el('table', {}, el('thead', {}, el('tr', {}, heads.map((h) => el('th', { class: h.startsWith('>') ? 'n' : '' }, h.replace(/^>/, ''))))), el('tbody', {}, rows)));
const cell = (content, cls = '') => el('td', { class: cls }, content);
const sessionSince = (s) => (s ? s.replace(/^\w+ /, '').replace(/ [A-Z]{2,5}$/, '') : '');

// Which machine the pages are about: '' is the one the portal runs on, otherwise the id of a server that dialled in (see the picker). Kept for the tab.
let server = '';
// A portal account has nothing on the portal's own machine: the pages are about a server, never "this machine".
let portalOnly = false;
try { server = sessionStorage.getItem('wd-server') || ''; } catch { /* no storage: the portal's own machine */ }
const pick = (id) => { server = id; try { sessionStorage.setItem('wd-server', id); } catch { /* fine */ } };
const q = () => (server ? '?server=' + encodeURIComponent(server) : '');

// A select of the machines to look at, when any server has enrolled. Selecting one redraws the page.
async function picker() {
  let list = [];
  try { list = (await get('servers', true)).servers || []; } catch { return null; }
  const usable = list.filter((v) => v.state === 'online' || v.state === 'offline');
  if (!usable.length) { if (server) pick(''); return null; }
  if (server && !usable.some((v) => v.id === server)) pick('');
  if (portalOnly && !server) pick(usable.find((v) => v.state === 'online')?.id || usable[0].id);
  const s = el('select', { 'aria-label': 'Server' }, portalOnly ? null : el('option', { value: '' }, 'This machine'), usable.map((v) => el('option', { value: v.id, selected: v.id === server }, v.name + (v.state === 'online' ? '' : ' (offline)'))));
  s.value = server;
  s.addEventListener('change', () => { pick(s.value); ctx.reload(); });
  return s;
}

async function get(kind, local = false) {
  const r = await fetch('/api/admin/' + kind + (local ? '' : q()), { cache: 'no-store' });
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
  const r = await fetch('/api/admin/do' + q(), { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': ctx.csrf() }, body: JSON.stringify(action) });
  if (r.status === 401) { ctx.signedOut(); throw new Error('Your sign-in ended.'); }
  if (r.status === 403) throw new Error('Only administrators can do this.');
  if (r.status === 429) throw new Error('Too many changes in a minute. Wait a little.');
  let body = null;
  try { body = await r.json(); } catch { /* handled below */ }
  if (!body) throw new Error('The server could not do this (' + r.status + ').');
  if (!body.ok) throw new Error(body.error || 'It did not work.');
  return body.result || {};
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
  const d = modal(why + ': ' + who, [el('p', {}, 'The password is shown once. Give it to the person; they should change it at once (My account, or Change password in the desktop\u2019s power menu).'), box], [copy, button('Done', () => d.close(), 'primary')]);
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

// ---- people ----
async function peopleAct(body) {
  const r = await fetch('/api/admin/people', { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': ctx.csrf() }, body: JSON.stringify(body) });
  if (r.status === 401) { ctx.signedOut(); throw new Error('Your sign-in ended.'); }
  if (r.status === 403) throw new Error('Only administrators can do this.');
  if (r.status === 429) throw new Error('Too many changes in a minute. Wait a little.');
  let out = null;
  try { out = await r.json(); } catch { /* handled below */ }
  if (!out) throw new Error('The server could not do this (' + r.status + ').');
  if (!out.ok) throw new Error(out.error || 'It did not work.');
  return out;
}

async function personDo(body, done) {
  try {
    const out = await peopleAct(body);
    const warn = (out.warnings || []).map((w) => w.server + ': ' + w.error);
    ctx.flash(done + (warn.length ? ' Not done on: ' + warn.join('; ') : ''), warn.length ? 'bad' : 'ok');
  } catch (e) { ctx.flash(e.message, 'bad'); }
  ctx.reload();
}

function addPerson() {
  const name = el('input', { name: 'name', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: true, placeholder: 'frida' });
  const display = el('input', { name: 'display', autocomplete: 'off', maxlength: 60, placeholder: 'Frida Silva (optional)' });
  const admin = el('input', { type: 'checkbox' });
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' }, el('label', {}, 'Account name', name), el('label', {}, 'Name shown', display), el('label', { class: 'check' }, admin, 'Administrator of the portal'),
    el('p', { class: 'hint' }, 'Lower case letters, digits, _ and -. The name becomes the account name on every server they are assigned to. A first password is made and shown once.'), err);
  const d = modal('add person', form, [button('Cancel', () => d.close()), button('Create', () => form.requestSubmit(), 'primary')]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const r = await peopleAct({ action: 'add', name: name.value.trim(), display: display.value.trim(), admin: admin.checked });
      d.close();
      ctx.reload();
      showPassword(r.name, r.password, 'first password');
    } catch (x) { err.textContent = x.message; }
  });
  name.focus();
}

async function personPassword(p) {
  if (!(await confirmBox('New password for ' + p.name + '?', 'The old password stops working at once and their sign-ins end. The new one is shown once.', 'Make a new password'))) return;
  try { const r = await peopleAct({ action: 'passwd', name: p.name }); showPassword(p.name, r.password, 'new password'); } catch (e) { ctx.flash(e.message, 'bad'); }
}

async function personRemove(p) {
  if (!(await confirmBox('Remove ' + p.name + '?', 'Their portal account is deleted. Take their servers away first; the accounts on the servers are switched off, not deleted.', 'Remove', true))) return;
  personDo({ action: 'remove', name: p.name }, p.name + ' was removed.');
}

// The servers of one person: the ones they have, and a form to add one (or change its settings).
function personServers(p, servers) {
  const nameOf = (id) => (servers.find((v) => v.id === id) || {}).name || id;
  const current = p.servers.length ? el('div', { class: 'tw' }, el('table', { class: 'plain' }, el('tbody', {}, p.servers.map((a) => el('tr', {},
    cell(el('b', {}, nameOf(a.server))), cell([a.desktop || 'server default', a.gpu ? ' \u00b7 ' + a.gpu : '', a.memory ? ' \u00b7 ' + a.memory : '']),
    cell(button('Take away', async () => {
      d.close();
      if (!(await confirmBox('Take ' + nameOf(a.server) + ' from ' + p.name + '?', 'Their account on that server is switched off (not deleted). Their running session ends.', 'Take away', true))) return;
      personDo({ action: 'unassign', name: p.name, server: a.server }, nameOf(a.server) + ' was taken from ' + p.name + '.');
    }, 'sm danger'), 'n'))))) : el('p', { class: 'muted' }, 'No server yet.');
  const server = el('select', { name: 'server' }, servers.map((v) => el('option', { value: v.id }, v.name + (v.online ? '' : ' (offline)'))));
  const select = (label, name, options) => el('label', {}, label, el('select', { name }, options.map(([v, t]) => el('option', { value: v }, t))));
  const desktop = select('Desktop', 'desktop', [['', 'server default'], ['sway', 'Sway'], ['plasma', 'Plasma'], ['cosmic', 'COSMIC'], ['hyprland', 'Hyprland']]);
  const gpu = select('Graphics', 'gpu', [['', 'server default'], ['auto', 'auto'], ['balance', 'balance'], ['off', 'off (software)']]);
  const memory = el('input', { name: 'memory', placeholder: 'e.g. 6G (optional)', autocomplete: 'off', spellcheck: 'false' });
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' }, el('label', {}, 'Add a server', server), desktop, gpu, el('label', {}, 'Memory limit of the session', memory),
    el('p', { class: 'hint' }, 'The account is made on that server now, so the server has to be online. An account of that name that was already there is never taken over.'), err);
  const d = modal('servers of ' + p.name, [current, form], [button('Close', () => d.close()), button('Assign', () => form.requestSubmit(), 'primary')]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!server.value) { err.textContent = 'No server has enrolled yet.'; return; }
    try {
      await peopleAct({ action: 'assign', name: p.name, server: server.value, desktop: desktop.querySelector('select').value || null, gpu: gpu.querySelector('select').value || null, memory: memory.value.trim() || null });
      d.close();
      ctx.flash(p.name + ' may use ' + nameOf(server.value) + '.', 'ok');
      ctx.reload();
    } catch (x) { err.textContent = x.message; }
  });
}

// ---- servers ----
let fleetInfo = { portal: null, pin: null };
async function serverAct(body) {
  const r = await fetch('/api/admin/servers', { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': ctx.csrf() }, body: JSON.stringify(body) });
  if (r.status === 401) { ctx.signedOut(); throw new Error('Your sign-in ended.'); }
  if (r.status === 403) throw new Error('Only administrators can do this.');
  if (r.status === 429) throw new Error('Too many changes in a minute. Wait a little.');
  let out = null;
  try { out = await r.json(); } catch { /* handled below */ }
  if (!out) throw new Error('The server could not do this (' + r.status + ').');
  if (!out.ok) throw new Error(out.error || 'It did not work.');
  return out;
}

// The join code is shown once, here; the portal keeps only its hash.
function showCode(name, code, minutes) {
  // The address is the one this page was opened with unless the portal knows its public one; it has to be an address the server can reach.
  const url = fleetInfo.portal || location.origin;
  const cmd = 'waydesk-agent enrol ' + url + ' ' + code + (fleetInfo.pin ? ' --pin ' + fleetInfo.pin : '');
  const copy = button('Copy command', async () => { try { await navigator.clipboard.writeText(cmd); copy.textContent = 'Copied'; } catch { copy.textContent = 'Select and copy it'; } });
  const d = modal('join code: ' + name, [
    el('p', {}, 'The code is shown once and works once, for ' + minutes + ' minutes. Run this on the server, as root:'),
    el('code', { class: 'secret' }, cmd),
    el('p', { class: 'hint' }, 'The pin makes the server trust this portal\u2019s certificate and no other. Check that the address is one the server can reach (not a tunnel on your own computer).'),
  ], [copy, button('Done', () => d.close(), 'primary')]);
}

function addServer() {
  const name = el('input', { name: 'name', autocomplete: 'off', spellcheck: 'false', required: true, maxlength: 40, placeholder: 'Porto 1' });
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' }, el('label', {}, 'Name', name), el('p', { class: 'hint' }, 'Letters, digits, spaces, dots, dashes and underscores. It is only a label for people.'), err);
  const d = modal('add server', form, [button('Cancel', () => d.close()), button('Make a join code', () => form.requestSubmit(), 'primary')]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const r = await serverAct({ action: 'add', name: name.value.trim() });
      d.close();
      ctx.reload();
      showCode(name.value.trim(), r.code, Math.round(r.expires_in / 60));
    } catch (x) { err.textContent = x.message; }
  });
  name.focus();
}

async function newCode(v) {
  try {
    const r = await serverAct({ action: 'code', id: v.id });
    ctx.reload();
    showCode(v.name, r.code, Math.round(r.expires_in / 60));
  } catch (e) { ctx.flash(e.message, 'bad'); }
}

async function revokeServer(v) {
  if (!(await confirmBox('Revoke ' + v.name + '?', 'Its key stops working at once and it cannot connect. People assigned to it lose it until it is enrolled again.', 'Revoke', true))) return;
  try { await serverAct({ action: 'revoke', id: v.id }); ctx.flash(v.name + ' was revoked.', 'ok'); } catch (e) { ctx.flash(e.message, 'bad'); }
  ctx.reload();
}

async function removeServer(v) {
  if (!(await confirmBox('Remove ' + v.name + ' from the list?', 'Only the entry is deleted; nothing is changed on the server itself.', 'Remove', true))) return;
  try { await serverAct({ action: 'remove', id: v.id }); ctx.flash(v.name + ' was removed.', 'ok'); } catch (e) { ctx.flash(e.message, 'bad'); }
  ctx.reload();
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
      // How busy the CPUs were over the second the status measured; an older server that does not say falls back to the load average per core.
      (() => {
        const cores = m.cores || 1;
        const pct = m.cpu_percent != null ? m.cpu_percent : Math.min(100, ((parseFloat((m.load || [])[0]) || 0) / cores) * 100);
        return tile('CPU', Math.round(pct), '% busy \u00b7 ' + cores + (cores === 1 ? ' core' : ' cores'), pct, pct > 85);
      })(),
      g0 ? tile('GPU' + (gpus.length > 1 ? ' 1 of ' + gpus.length : ''), g0.busy_percent == null ? '-' : Math.round(g0.busy_percent), '% busy' + (g0.encoder_percent != null ? ' · encode ' + Math.round(g0.encoder_percent) + '%' : ''), g0.busy_percent, g0.busy_percent > 85) : tile('GPU', 'none', 'software rendering', null));
    const attention = [];
    if (a.open === false) attention.push(['full', 'bad', 'New sessions are refused: ' + (a.reason || 'the machine is full')]);
    for (const w of s.warnings || []) attention.push(['warning', 'warn', w]);
    const rows = sessionsNow.map((u) => el('tr', {}, cell(el('b', {}, u.name)), cell((u.video && u.video.compositor) || '-'), cell(u.video && u.video.encoder ? u.video.encoder : '-'), cell(gb(u.mem_mb || 0), 'n mono'), cell(Math.round(u.cpu_percent || 0) + '%', 'n mono')));
    return [
      el('div', { class: 'head' }, el('h1', {}, 'Overview'), el('span', { class: 'sp' }), await picker(), el('span', { class: 'muted small' }, 'refreshes every 10 s · same numbers as ', el('code', {}, 'waydesk-admin status'))),
      tiles,
      el('div', { class: 'two' },
        win('sessions now', table(['Account', 'Desktop', 'Encoder', '>Memory', '>CPU'], rows, 'Nobody is logged in.')),
        el('div', { class: 'colstack' },
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
    return [el('div', { class: 'head' }, el('h1', {}, 'Users'), el('span', { class: 'sp' }), await picker(), search, button('Add user', addUser, 'primary')), holder];
  },

  async audit() {
    const holder = el('div', {});
    const field = (label, control) => el('label', {}, label, control);
    const sel = (name, options) => el('select', { name }, options.map(([v, t]) => el('option', { value: v }, t)));
    const user = el('input', { name: 'user', placeholder: 'any', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Account' });
    const kind = sel('event', [['', 'all'], ['login', 'sign-ins'], ['session', 'sessions'], ['connection', 'connections'], ['admin', 'changes (admin)'], ['gpu', 'graphics'], ['audit', 'the log itself']]);
    const outcome = sel('outcome', [['', 'any'], ['ok', 'ok'], ['fail', 'failed'], ['refused', 'refused']]);
    const since = sel('since', [['1h', 'last hour'], ['24h', 'last 24 hours'], ['7d', 'last 7 days'], ['4w', 'last 4 weeks']]);
    since.value = '24h';
    const limit = sel('limit', [['100', '100 events'], ['200', '200 events'], ['500', '500 events']]);
    limit.value = '200';
    let rows = [];
    const csv = () => {
      // A cell that starts with = + - or @ would be a formula in a spreadsheet: it gets a quote in front.
      const cellText = (v) => { let s = v == null ? '' : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
      const cols = ['ts', 'event', 'outcome', 'user', 'actor', 'target', 'source', 'via', 'reason', 'detail', 'seconds'];
      const text = [cols.join(',')].concat(rows.map((r) => cols.map((c) => cellText(r[c])).join(','))).join('\r\n') + '\r\n';
      const url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
      const a = el('a', { href: url, download: 'waydesk-audit.csv' });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    };
    const tone = { ok: 'ok', fail: 'bad', refused: 'warn' };
    const draw = () => holder.replaceChildren(win('events \u00b7 ' + rows.length, table(['Time', 'Event', 'Outcome', 'Account', 'From', 'Details'],
      rows.map((r) => {
        // Who: the account the event is about; for a change, the administrator who made it and the account it was made to.
        const who = r.target ? [el('b', {}, r.target), el('span', { class: 'dim' }, ' by ' + (r.actor || '?') + (r.via && r.via !== 'portal' ? ' (' + r.via + ')' : ''))] : el('b', {}, r.user || r.actor || (r.user_invalid ? '(not a name)' : '-'));
        const details = [r.reason, r.detail, r.seconds != null ? r.seconds + ' s' : null, r.via === 'portal' ? 'portal' : null].filter(Boolean).join(' \u00b7 ');
        return el('tr', {}, cell(String(r.ts || '').replace('T', ' ').replace(/\.\d+Z$/, 'Z'), 'mono'), cell(r.event || '-'), cell(chip(r.outcome || '-', tone[r.outcome] || '')), cell(who), cell(r.source || '-', 'mono'), cell(details));
      }), 'No events match.')));
    const load = async () => {
      const q = new URLSearchParams({ since: since.value, limit: limit.value });
      for (const [k, v] of [['user', user.value.trim()], ['event', kind.value], ['outcome', outcome.value]]) if (v) q.set(k, v);
      holder.replaceChildren(el('p', { class: 'muted' }, 'Loading\u2026'));
      try {
        const r = await fetch('/api/admin/audit?' + q, { cache: 'no-store' });
        if (r.status === 401) { const e = new Error('Your sign-in ended.'); e.signedOut = true; throw e; }
        if (r.status === 403) throw new Error('This page is for administrators.');
        if (r.status === 400) { let m = 'Check the filters.'; try { m = (await r.json()).error || m; } catch { /* the default */ } throw new Error(m); }
        if (!r.ok) throw new Error('The server could not be asked (' + r.status + ').');
        rows = await r.json();
        draw();
      } catch (e) {
        if (e.signedOut) { ctx.signedOut(); return; }
        holder.replaceChildren(el('p', { class: 'bad' }, e.message));
      }
    };
    const form = el('form', { class: 'row' }, field('Account', user), field('Event', kind), field('Outcome', outcome), field('Time', since), field('Show', limit), button('Search', () => form.requestSubmit(), 'primary'), button('Export CSV', () => csv()));
    form.addEventListener('submit', (e) => { e.preventDefault(); load(); });
    await load();
    return [el('div', { class: 'head' }, el('h1', {}, 'Audit'), el('span', { class: 'sp' }), el('span', { class: 'muted small' }, 'read only \u00b7 same records as ', el('code', {}, 'waydesk-admin audit'))), win('filter', form), holder];
  },

  async settings() {
    const [s, access, cert] = await Promise.all([get('settings', true), get('access', true), get('cert', true)]);
    const p = s.portal || {};
    const pre = (text) => el('pre', { class: 'plainpre' }, text || '-');
    const policy = { off: 'off: the password is enough', optional: 'optional: asked of accounts that set one up', required: 'required: every account needs one' }[p.totp] || p.totp;
    const enrolled = s.enrolled || [];
    const currentMode = ((access.text || '').match(/\((local|lan|vpn|custom)\)/) || [])[1] || '';
    const words = { local: ['this machine only', 'the RDP port listens on this machine only (reach it through an SSH tunnel)'], lan: ['the local network', "the RDP port listens on this machine's local-network address, and only that network may connect"], vpn: ['the VPN', "the RDP port listens on the VPN's address, and only the VPN's addresses may connect (the VPN must be set up with `waydesk-admin vpn init`)"] };
    const changeAccess = async (mode, now) => {
      if (mode === now) return;
      const undo = now && now !== 'custom' ? 'sudo waydesk-admin access ' + now : 'sudo waydesk-admin access local';
      const ok = await confirmBox('Let ' + words[mode][0] + ' reach the desktop?', [
        el('p', {}, 'Afterwards ' + words[mode][1] + '.'),
        el('p', {}, 'The desktop daemon restarts: people connected over RDP or the browser stream reconnect, and their programs keep running.'),
        el('p', { class: 'hint' }, 'To undo it from a terminal on the server: ', el('code', {}, undo))], 'Change it', true);
      if (!ok) return;
      run({ action: 'access', mode }, (r) => (r.message || 'Done.').split('\n')[0]);
    };
    const removeTotp = async (name) => {
      if (!(await confirmBox('Remove the authenticator of ' + name + '?', name + ' will sign in with the password alone (where the policy allows it) and can set a new authenticator up.', 'Remove', true))) return;
      try {
        const r = await fetch('/api/admin/totp', { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': ctx.csrf() }, body: JSON.stringify({ action: 'remove', name }) });
        if (r.status === 401) { ctx.signedOut(); return; }
        if (!r.ok) throw new Error(r.status === 403 ? 'Only administrators can do this.' : 'It did not work (' + r.status + ').');
        ctx.flash('Removed the authenticator of ' + name + '.', 'ok');
      } catch (e) { ctx.flash(e.message, 'bad'); }
      ctx.reload();
    };
    return [
      el('div', { class: 'head' }, el('h1', {}, 'Settings'), el('span', { class: 'sp' }), el('span', { class: 'muted small' }, 'the rest is changed on the server with ', el('code', {}, 'waydesk-admin'), ' and ', el('code', {}, '/etc/default/waydesk'))),
      el('div', { class: 'two' },
        el('div', { class: 'colstack' },
          win('who can reach the desktop (RDP)', pre(access.text),
            el('div', { class: 'seg' }, ['local', 'lan', 'vpn'].map((m) => button({ local: 'This machine only', lan: 'Local network', vpn: 'VPN' }[m], () => changeAccess(m, currentMode), 'sm' + (currentMode === m ? ' on' : '')))),
            el('p', { class: 'hint' }, currentMode === 'custom' ? 'The setting is a custom one; pick one of these to replace it.' : 'Changing it restarts the desktop daemon: people connected over RDP or the browser reconnect. The certificate is changed with ', currentMode === 'custom' ? null : el('code', {}, 'waydesk-admin cert'), currentMode === 'custom' ? null : '.')),
          win('certificate', pre(cert.text), el('p', { class: 'hint' }, 'Reissue or replace it with ', el('code', {}, 'waydesk-admin cert'), '.'))),
        el('div', { class: 'colstack' },
          win('this portal', el('dl', { class: 'kv' },
            el('dt', {}, 'Listens on'), el('dd', { class: 'mono' }, (p.bind || '-') + (p.plain_http ? ' (plain HTTP behind a proxy)' : ' (HTTPS)')),
            el('dt', {}, 'Public address'), el('dd', {}, p.public_origin || 'the address people open'),
            el('dt', {}, 'Allowed from'), el('dd', { class: 'mono' }, p.allow_from || 'private networks (loopback: any)'),
            el('dt', {}, 'Idle sign-out'), el('dd', {}, (p.idle_minutes ?? '-') + ' minutes'),
            el('dt', {}, 'Longest sign-in'), el('dd', {}, (p.absolute_hours ?? '-') + ' hours'))),
          win('two-step sign-in', el('p', {}, el('b', {}, 'Policy: '), policy),
            enrolled.length ? table(['Account', ''], enrolled.map((n) => el('tr', {}, cell(el('b', {}, n)), cell(el('div', { class: 'acts' }, button('Remove', () => removeTotp(n), 'sm danger')), 'n'))), '') : el('p', { class: 'muted' }, 'No account has an authenticator set up.'),
            el('p', { class: 'hint' }, 'Remove one when somebody loses their phone. Setting one up is done on the server: ', el('code', {}, 'waydesk-web totp add ACCOUNT'), '.')))),
    ];
  },

  async servers() {
    const r = await get('servers', true);
    fleetInfo = { portal: r.portal, pin: r.pin };
    const list = r.servers || [];
    const tone = { online: 'ok', offline: 'warn', waiting: '', expired: 'warn', revoked: 'bad' };
    const label = { online: 'online', offline: 'offline', waiting: 'waiting for the server', expired: 'code expired', revoked: 'revoked' };
    const when = (t) => (t ? new Date(t * 1000).toLocaleString() : '-');
    const rows = list.map((v) => el('tr', {},
      cell(el('b', {}, v.name)),
      cell(chip(label[v.state] || v.state, tone[v.state] || '')),
      cell(when(v.enrolled), 'dim'),
      cell(v.last_seen ? when(v.last_seen) : '-', 'dim'),
      cell(el('div', { class: 'acts' },
        v.state === 'waiting' || v.state === 'expired' ? button('New code', () => newCode(v), 'sm') : null,
        v.state === 'online' || v.state === 'offline' ? button('Revoke', () => revokeServer(v), 'sm danger') : null,
        v.state === 'revoked' ? button('New code', () => newCode(v), 'sm') : null,
        v.state !== 'online' && v.state !== 'offline' ? button('Remove', () => removeServer(v), 'sm danger') : null), 'n')));
    return [
      el('div', { class: 'head' }, el('h1', {}, 'Servers'), el('span', { class: 'sp' }), button('Add server', addServer, 'primary')),
      win('servers \u00b7 ' + list.length, table(['Name', 'State', 'Enrolled', 'Last seen', ''], rows, 'No server yet. Add one to get a join code.'),
        el('p', { class: 'hint' }, 'A join code works once and for one hour. The server keeps its own key after it enrols; revoking takes that key away.')),
    ];
  },

  async people() {
    const r = await get('people', true);
    const servers = r.servers || [];
    const nameOf = (id) => (servers.find((v) => v.id === id) || {}).name || id;
    const rows = (r.people || []).map((p) => el('tr', {},
      cell([el('b', {}, p.name), p.display ? el('span', { class: 'dim' }, ' ' + p.display) : null]),
      cell(p.admin ? chip('admin') : el('span', { class: 'dim' }, '-')),
      cell(p.disabled ? chip('switched off', 'bad') : chip('active', 'ok')),
      cell(p.servers.length ? p.servers.map((a) => nameOf(a.server)).join(', ') : el('span', { class: 'dim' }, 'none')),
      cell(el('div', { class: 'acts' },
        button('Servers', () => personServers(p, servers), 'sm'),
        button('New password', () => personPassword(p), 'sm'),
        button(p.admin ? 'Not admin' : 'Make admin', () => personDo({ action: 'admin', name: p.name, on: !p.admin }, p.name + (p.admin ? ' is not an administrator any more.' : ' is an administrator now.')), 'sm'),
        button(p.disabled ? 'Switch on' : 'Switch off', () => personDo({ action: 'disable', name: p.name, on: !p.disabled }, p.name + (p.disabled ? ' may sign in again.' : ' was switched off.')), 'sm' + (p.disabled ? '' : ' danger')),
        button('Remove', () => personRemove(p), 'sm danger')), 'n')));
    return [
      el('div', { class: 'head' }, el('h1', {}, 'People'), el('span', { class: 'sp' }), button('Add person', addPerson, 'primary')),
      win('portal accounts \u00b7 ' + rows.length, table(['Name', 'Role', 'State', 'Servers', ''], rows, 'Nobody yet.'),
        el('p', { class: 'hint' }, 'These are accounts of the portal. Assigning a server makes the same account there, with a password nobody sees; the person makes an app password for RDP clients in My account.')),
    ];
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
      el('div', { class: 'head' }, el('h1', {}, 'Sessions'), el('span', { class: 'sp' }), await picker(), chip(rows.length + (a.max_active_users ? ' of ' + a.max_active_users : ' running'), 'ok')),
      win('running sessions', table(['Account', 'State', 'Since', 'Desktop', 'Encoder', '>Memory', '>CPU', ''], rows, 'No sessions running.')),
    ];
  },
};

let timer = 0;
// Draws `view` into `root`; the numbers refresh every 10 s while the page shows (not for Users, which is a list that does not change by the second).
export async function render(view, root, onSignedOut, csrf, portal = false) {
  clearInterval(timer);
  portalOnly = portal;
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
  if (view !== 'users' && view !== 'audit') timer = setInterval(() => { if (!document.hidden) draw(); }, 10000);
}
export const stop = () => clearInterval(timer);
export const known = (v) => Object.hasOwn(views, v);
