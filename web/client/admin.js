// The administrators' pages: Servers (each with Overview, Accounts, Sessions and Audit), Users (the portal's own), Audit and Settings. The data is the helper's (`waydesk-admin ... --json`), passed on by the portal at
// /api/admin/*; the portal asks the helper on every request whether the account is an administrator, so hiding the menu here is only convenience.
// Everything is put on the page with textContent (never innerHTML): a name from the machine's account list cannot become markup.
import { el, chip, dot, win, button, modal, confirmBox } from './ui.js';

const meter = (percent, warn = false, good = false) => el('div', { class: 'meter' + (good ? ' good' : '') }, el('i', { class: warn ? 'w' : '', style: `width:${Math.max(0, Math.min(100, Math.round(percent)))}%;--p:${Math.max(0, Math.min(100, Math.round(percent)))}` }));
const gb = (mb) => (mb >= 1024 ? (mb / 1024).toFixed(mb >= 10240 ? 0 : 1) + ' GB' : Math.round(mb) + ' MB');
const table = (heads, rows, empty) => el('div', { class: 'tw' }, rows.length === 0 ? el('p', { class: 'muted' }, empty) : el('table', {}, el('thead', {}, el('tr', {}, heads.map((h) => el('th', { class: h.startsWith('>') ? 'n' : '' }, h.replace(/^>/, ''))))), el('tbody', {}, rows)));
// A window with a count at the right end of its title bar.
const withCount = (w, text) => { w.querySelector('.bar').append(el('span', { class: 'act' }, text)); return w; };
const cell = (content, cls = '') => el('td', { class: cls }, content);
const sessionSince = (s) => (s ? s.replace(/^\w+ /, '').replace(/ [A-Z]{2,5}$/, '') : '');

// Which machine the pages are about: '' is the one the portal runs on, otherwise the id of a server that dialled in (see the picker). Kept for the tab.
let server = '';
// A virtual display adapter (a VM's virtio, QEMU, VMware ...) renders in software: a server with only those has no GPU, and nothing about graphics is shown for it.
const VIRTUAL_GPU = /virtio|bochs|qxl|vmwgfx|vboxvideo|cirrus|simpledrm|hyperv/i;
const realGpus = (status) => (status.gpus || []).filter((g) => !VIRTUAL_GPU.test(g.driver || ''));
// Whether the server whose page is open has a GPU; the overview and the accounts page set it, the dialogs read it.
let hasGpu = true;
// The real GPUs of that server: the Edit dialog offers each by name (the setting is its render node, "renderD128"), and the accounts page names them.
let serverGpus = [];
const nodeName = (g) => String(g.node || '').split('/').pop();
// "Intel Skylake-S GT2 [HD Graphics 530]" -> "HD Graphics 530"
const gpuName = (g) => { const m = /\[(.+)\]/.exec(g.model || ''); return m ? m[1] : (g.model || g.driver || 'GPU'); };
// A portal account has nothing on the portal's own machine: the pages are about a server, never "this machine".
let portalOnly = false;
// Whose audit log the page shows (null: not chosen yet).
let auditSource = null;
try { server = sessionStorage.getItem('wd-server') || ''; } catch { /* no storage: the portal's own machine */ }
const pick = (id) => { server = id; try { sessionStorage.setItem('wd-server', id); } catch { /* fine */ } };
const q = () => (server ? '?server=' + encodeURIComponent(server) : '');

// A select of the machines to look at, when any server has enrolled. Selecting one redraws the page.
// The machines that can be looked at; settles the chosen one first (a portal account has no "this machine", so a server must be chosen before any page asks for data).
async function settle() {
  let list = [];
  try { list = (await get('servers', true)).servers || []; } catch { return null; }
  const usable = list.filter((v) => v.state === 'online' || v.state === 'offline');
  if (!usable.length) { if (server) pick(''); return usable; }
  if (server && !usable.some((v) => v.id === server)) pick('');
  if (portalOnly && !server) pick(usable.find((v) => v.state === 'online')?.id || usable[0].id);
  return usable;
}

async function picker() {
  const usable = await settle();
  if (!usable || !usable.length) return null;
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
  const d = modal(why + ': ' + who, [el('p', {}, 'The password is shown once. Give it to the user; they should change it at once (My account, or Change password in the desktop\u2019s power menu).'), box], [copy, button('Done', () => d.close(), 'primary')]);
}

function addUser() {
  const name = el('input', { name: 'name', autocomplete: 'off', autocapitalize: 'none', spellcheck: 'false', required: true, placeholder: 'frida' });
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' }, el('label', {}, 'Account name', name), el('p', { class: 'hint' }, 'Lower case letters, digits, _ and -. The account may use Waydesk at once; a first password is made and shown once.'), err);
  const d = modal('add account', form, [button('Cancel', () => d.close()), button('Create', () => form.requestSubmit(), 'primary')]);
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
  const gpu = select('Graphics', 'gpu', [['', 'no change'], ['default', 'server default'], ['auto', 'auto'], ['balance', 'balance'], ['off', 'off (software)']].concat(serverGpus.map((g) => [nodeName(g), gpuName(g) + ' (' + nodeName(g) + ')'])), '');
  const memory = el('input', { name: 'memory', placeholder: 'e.g. 6G, or reset', autocomplete: 'off', spellcheck: 'false' });
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' }, desktop, hasGpu ? gpu : null, el('label', {}, 'Memory limit of the session', memory), el('p', { class: 'hint' }, 'A running session keeps what it started with; the new setting applies from the next one.'), err);
  const d = modal('edit ' + u.name, form, [button('Cancel', () => d.close()), button('Save', () => form.requestSubmit(), 'primary')]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const dv = desktop.querySelector('select').value, gv = hasGpu ? gpu.querySelector('select').value : '', mv = memory.value.trim();
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
  const d = modal('add user', form, [button('Cancel', () => d.close()), button('Create', () => form.requestSubmit(), 'primary')]);
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
      try {
        await peopleAct({ action: 'unassign', name: p.name, server: a.server });
        ctx.flash(nameOf(a.server) + ' was taken from ' + p.name + '.', 'ok');
      } catch (e) {
        // A server that cannot be reached (gone for good) must not keep the assignment forever: the administrator may drop it without the server.
        if (await confirmBox('Drop the assignment anyway?', e.message + ' Dropping it leaves the account on that server as it is.', 'Drop it', true)) {
          try { await peopleAct({ action: 'unassign', name: p.name, server: a.server, force: true }); ctx.flash('The assignment was dropped.', 'ok'); } catch (x) { ctx.flash(x.message, 'bad'); }
        }
      }
      ctx.reload();
    }, 'sm danger'), 'n')))))) : el('p', { class: 'muted' }, 'No server yet.');
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
  if (!(await confirmBox('Revoke ' + v.name + '?', 'Its key stops working at once and it cannot connect. Users assigned to it lose it until it is enrolled again.', 'Revoke', true))) return;
  try { await serverAct({ action: 'revoke', id: v.id }); ctx.flash(v.name + ' was revoked.', 'ok'); } catch (e) { ctx.flash(e.message, 'bad'); }
  ctx.reload();
}

async function removeServer(v) {
  if (!(await confirmBox('Remove ' + v.name + ' from the list?', 'Only the entry is deleted; nothing is changed on the server itself.', 'Remove', true))) return;
  try { await serverAct({ action: 'remove', id: v.id }); ctx.flash(v.name + ' was removed.', 'ok'); } catch (e) { ctx.flash(e.message, 'bad'); }
  ctx.reload();
}

function tile(label, value, unit, percent, warn, good = false) {
  return el('div', { class: 'tile' }, el('div', { class: 'k' }, label), el('div', { class: 'big' }, value, ' ', el('small', {}, unit)), percent == null ? null : meter(percent, warn, good));
}

// ---- one server: its page, with tabs ----
const TABS = [['overview', 'Overview'], ['accounts', 'Accounts'], ['sessions', 'Sessions'], ['audit', 'Audit']];
async function serverPage(id, tab) {
  const here = id === 'this';
  if (here && portalOnly) return [el('p', { class: 'bad' }, 'A portal account has nothing on the portal’s own machine.')];
  pick(here ? '' : id);
  tab = TABS.some((t) => t[0] === tab) ? tab : 'overview';
  const reg = await get('servers', true);
  const v = here ? { id: '', name: 'This machine', state: 'online' } : (reg.servers || []).find((x) => x.id === id);
  if (!v || !(v.state === 'online' || v.state === 'offline')) return [el('div', { class: 'crumb' }, el('a', { href: '#servers' }, 'Servers')), el('p', { class: 'bad' }, 'That server is not there (it may have been removed or revoked).')];
  const head = [
    el('div', { class: 'crumb' }, el('a', { href: '#servers' }, 'Servers'), ' › ', v.name),
    el('div', { class: 'head' }, el('h1', {}, v.name), chip(v.state === 'online' ? 'online' : 'offline', v.state === 'online' ? 'ok' : 'warn'), el('span', { class: 'sp' })),
    el('nav', { class: 'tabs', 'aria-label': 'Server' }, TABS.map(([k, t]) => el('a', { href: '#servers/' + id + '/' + k, 'aria-current': k === tab ? 'page' : false }, t))),
  ];
  if (v.state !== 'online') return [...head, el('p', { class: 'note' }, 'This server is offline: the portal cannot ask it anything. Its accounts and sessions show again when its agent reconnects.')];
  if (tab === 'audit') auditSource = here ? '' : id;
  const body = await views[tab]();
  // The page has its own title and the tabs say which server it is: the title and the server picker of the single-machine pages go.
  const first = body[0];
  if (first && first.classList && first.classList.contains('head')) {
    first.querySelector('h1')?.remove();
    first.querySelector('select[aria-label="Server"]')?.remove();
    // A title row with nothing left in it (only its spacer) would stay as an empty gap between the tabs and the table.
    if ([...first.children].every((c) => c.classList.contains('sp'))) body.shift();
  }
  return [...head, ...body];
}

const views = {
  async overview() {
    const s = await get('status');
    const m = s.machine || {};
    const a = s.admission || {};
    const gpus = realGpus(s);
    hasGpu = gpus.length > 0;
    serverGpus = gpus;
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
      g0 ? tile('GPU' + (gpus.length > 1 ? ' 1 of ' + gpus.length : ''), g0.busy_percent == null ? '-' : Math.round(g0.busy_percent), '% busy' + (g0.encoder_percent != null ? ' · encode ' + Math.round(g0.encoder_percent) + '%' : ''), g0.busy_percent, g0.busy_percent > 85) : null);
    const attention = [];
    if (a.open === false) attention.push(['full', 'bad', 'New sessions are refused: ' + (a.reason || 'the machine is full')]);
    for (const w of s.warnings || []) attention.push(['warning', 'warn', w]);
    // The GPU a session renders on: its render node, matched to the GPUs the server lists; "software" when it has none.
    // After the name: how much of the GPU the account's programs worked over the second the status measured (drawing, and encoding on the video engine).
    const gpuOf = (u) => {
      const node = u.video && u.video.render; const g = node && gpus.find((x) => x.node === node);
      if (!g) return el('span', { class: 'dim' }, 'software');
      const use = u.gpu_use;
      return [gpuName(g), use ? el('span', { class: 'dim mono' }, ' \u00b7 ' + Math.round(use.render_percent) + '% \u00b7 enc ' + Math.round(use.video_percent) + '%') : null];
    };
    const rows = sessionsNow.map((u) => el('tr', {}, cell(el('b', {}, u.name)), cell((u.video && u.video.compositor) || '-'), cell(u.video && u.video.encoder ? u.video.encoder : '-'), hasGpu ? cell(gpuOf(u)) : null, cell(gb(u.mem_mb || 0), 'n mono'), cell(Math.round(u.cpu_percent || 0) + '%', 'n mono')));
    return [
      el('div', { class: 'head' }, el('h1', {}, 'Overview'), el('span', { class: 'sp' }), await picker(), null),
      tiles,
      el('div', { class: 'two' },
        win('sessions now', table(['Account', 'Desktop', 'Encoder'].concat(hasGpu ? ['GPU'] : [], ['>Memory', '>CPU']), rows, 'Nobody is logged in.')),
        el('div', { class: 'colstack' },
          win('needs attention', attention.length ? el('div', { class: 'tw' }, el('table', { class: 'plain' }, el('tbody', {}, attention.map(([k, tone, text]) => el('tr', {}, cell(chip(k, tone)), cell(text)))))) : el('p', { class: 'ok' }, 'Nothing needs attention.')),
          win('machine', el('dl', { class: 'kv' },
            el('dt', {}, 'System'), el('dd', {}, m.os || '-'),
            el('dt', {}, 'Kernel'), el('dd', { class: 'mono' }, m.kernel || '-'),
            el('dt', {}, 'Load'), el('dd', { class: 'mono' }, (m.load || []).join(' ') + ' (' + (m.cores || '?') + ' cores)'),
            el('dt', {}, 'New sessions'), el('dd', { class: a.open === false ? 'bad' : 'ok' }, a.open === false ? 'refused' : 'accepted'),
            el('dt', {}, 'Desktop'), el('dd', {}, s.compositor_setting || '-'),
            hasGpu ? el('dt', {}, gpus.length > 1 ? 'GPUs' : 'GPU') : null, hasGpu ? el('dd', {}, gpus.map((g) => el('div', {}, gpuName(g), el('span', { class: 'dim' }, ' \u00b7 ' + (g.driver || '-') + (g.mem_total_mb ? ' \u00b7 ' + gb(g.mem_total_mb) : '') + ((g.sessions || []).length ? ' \u00b7 ' + g.sessions.length + (g.sessions.length === 1 ? ' session' : ' sessions') : ''))))) : null,
            hasGpu ? el('dt', {}, 'Graphics') : null, hasGpu ? el('dd', {}, s.gpu_setting || '-') : null)))),
    ];
  },

  // The list of servers: the registry (state, join codes) and the numbers of the ones online, one row each; a row opens the server's page.
  async servers() {
    const [reg, fl] = await Promise.all([get('servers', true), get('fleet', true).catch(() => ({ servers: [] }))]);
    fleetInfo = { portal: reg.portal, pin: reg.pin };
    const nums = new Map((fl.servers || []).map((v) => [v.id, v]));
    const list = reg.servers || [];
    const tone = { online: 'ok', offline: 'warn', waiting: '', expired: 'warn', revoked: 'bad' };
    const label = { online: 'online', offline: 'offline', waiting: 'waiting for the server', expired: 'code expired', revoked: 'revoked' };
    const numbers = (n) => [
      cell(n.sessions != null ? n.sessions + (n.max_sessions ? ' of ' + n.max_sessions : '') : '-', 'n mono'),
      cell(n.mem_percent != null ? el('div', { class: 'memcell' }, meter(n.mem_percent, n.mem_percent > 80), el('span', {}, Math.round(n.mem_percent) + '%')) : '-'),
      cell(n.cpu_percent != null ? Math.round(n.cpu_percent) + '%' : '-', 'n mono'),
      // The adapters of the server (the status leaves the virtual ones out): the name, and how busy it is when it says.
      cell(n.gpus == null ? '-' : n.gpus.length ? n.gpus.map((g) => g.name + (g.busy_percent != null ? ' \u00b7 ' + Math.round(g.busy_percent) + '%' : '')).join(', ') : el('span', { class: 'dim' }, 'none')),
      cell(n.warnings ? chip(n.warnings + (n.warnings === 1 ? ' warning' : ' warnings'), 'warn') : el('span', { class: 'dim' }, '-')),
    ];
    const open = (tr, id) => { tr.classList.add('row'); tr.addEventListener('click', (e) => { if (!e.target.closest('a,button')) location.hash = '#servers/' + id + '/overview'; }); return tr; };
    const rows = [];
    // The machine the portal runs on, for an administrator of that machine (a portal account has nothing there).
    if (!portalOnly) {
      let here = null;
      try { here = await get('status', true); } catch { /* not asked: no row */ }
      if (here) {
        const m = here.machine || {};
        const mem = m.mem_total_mb ? (((m.mem_total_mb || 0) - (m.mem_available_mb || 0)) / m.mem_total_mb) * 100 : null;
        const cores = m.cores || 1;
        const cpu = m.cpu_percent != null ? m.cpu_percent : Math.min(100, ((parseFloat((m.load || [])[0]) || 0) / cores) * 100);
        rows.push(open(el('tr', {}, cell(el('a', { href: '#servers/this/overview' }, el('b', {}, 'This machine'))), cell(chip('online', 'ok')),
          ...numbers({ sessions: (here.users || []).filter((u) => u.session).length, mem_percent: mem, cpu_percent: cpu, gpus: realGpus(here).map((g) => ({ name: gpuName(g), busy_percent: g.busy_percent })) }), cell('-', 'n'), cell('', 'n')), 'this'));
      }
    }
    for (const v of list) {
      const live = v.state === 'online' || v.state === 'offline';
      const n = nums.get(v.id) || {};
      const tr = el('tr', {},
        cell(live ? el('a', { href: '#servers/' + v.id + '/overview' }, el('b', {}, v.name)) : el('b', {}, v.name)),
        cell(chip(v.error ? 'not answering' : (label[v.state] || v.state), v.error ? 'warn' : (tone[v.state] || ''))),
        ...numbers(live ? n : {}),
        cell(live ? String(n.people || 0) : '-', 'n mono'),
        cell(el('div', { class: 'acts' },
          v.state === 'waiting' || v.state === 'expired' || v.state === 'revoked' ? button('New code', () => newCode(v), 'sm') : null,
          v.state === 'online' || v.state === 'offline' ? button('Revoke', () => revokeServer(v), 'sm danger') : null,
          !live ? button('Remove', () => removeServer(v), 'sm danger') : null), 'n'));
      rows.push(live ? open(tr, v.id) : tr);
    }
    const online = list.filter((v) => v.state === 'online').length + (rows.length > list.length ? 1 : 0);
    const total = rows.length;
    const sessions = list.reduce((n, v) => n + ((nums.get(v.id) || {}).sessions || 0), 0);
    return [
      el('div', { class: 'head' }, el('div', {}, el('h1', {}, 'Servers'), el('p', { class: 'sub' }, total + (total === 1 ? ' server' : ' servers') + ' \u00b7 ' + online + ' online \u00b7 ' + sessions + (sessions === 1 ? ' session' : ' sessions') + ' running')), el('span', { class: 'sp' }), button('Add server', addServer, 'primary')),
      el('div', { class: 'tiles' }, tile('Servers', online, 'of ' + total + ' online', total ? (online / total) * 100 : null, total > 0 && online < total, true), tile('Sessions', sessions, 'running now', null), tile('Users', fl.people || 0, 'in the portal', null)),
      win('servers · ' + total, table(['Server', 'State', '>Sessions', 'Memory', '>CPU', 'GPU', 'Attention', '>Users', ''], rows, 'No server yet. Add one to get a join code.'),
        el('p', { class: 'hint' }, 'Click a server for its details. A join code works once and for one hour; the server keeps its own key after it enrols, and revoking takes that key away.')),
    ];
  },

  async accounts() {
    const [list, st] = await Promise.all([get('users'), get('status').catch(() => null)]);
    if (st) { serverGpus = realGpus(st); hasGpu = serverGpus.length > 0; }
    const holder = el('div', {});
    const draw = () => {
      const shown = list;
      holder.replaceChildren(win('accounts · ' + list.length, table(['Account', 'Desktop'].concat(hasGpu ? ['Graphics'] : [], ['RDP', 'Admin', 'Session', '']),
        shown.map((u) => el('tr', {},
          cell(el('b', {}, u.name)),
          cell((u.desktop || '-') + (u.desktop_from === 'account' ? '*' : '')),
          hasGpu ? cell((() => { const node = String(u.gpu || '-').split('/').pop(); const g = serverGpus.find((x) => nodeName(x) === node); return (g ? gpuName(g) : node) + (u.gpu_from === 'account' ? '*' : ''); })()) : null,
          cell(u.rdp ? chip('yes', 'ok') : chip('no', 'bad')),
          cell(u.sudo ? chip('admin') : el('span', { class: 'dim' }, '-')),
          cell(u.session === 'running' ? [dot(), 'running' + (u.desktop_running ? ' on ' + u.desktop_running : ''), u.session_since ? el('span', { class: 'dim' }, ' since ' + sessionSince(u.session_since)) : null] : [dot('off'), 'none']),
          cell(el('div', { class: 'acts' },
            button('Edit', () => editUser(u), 'sm'),
            button('Reset password', () => resetPassword(u), 'sm'),
            u.rdp ? button('Switch off', () => disableUser(u), 'sm danger') : button('Switch on', () => run({ action: 'user_enable', name: u.name }, () => u.name + ' may log in again.'), 'sm')), 'n'))),
        'No account on this server yet.'), el('p', { class: 'hint' }, (server === '' && !portalOnly ? '' : 'New accounts come from the Users page: assign the user to this server. ') + '* a setting of the account itself; the rest is the server’s setting. Removing an account, and giving administrator rights, stay on the command line.')));
    };
    draw();
    return [el('div', { class: 'head' }, el('h1', {}, 'Accounts'), el('span', { class: 'sp' }), await picker(), server === '' && !portalOnly ? button('Add account', addUser, 'primary') : null), holder];
  },

  async audit() {
    const holder = el('div', {});
    const field = (label, control) => el('label', {}, label, control);
    const sel = (name, options) => el('select', { name }, options.map(([v, t]) => el('option', { value: v }, t)));
    // Whose log: this machine's (host administrators only), the portal's own, or a server's (asked of its agent).
    let servers = [];
    try { servers = (await get('servers', true)).servers.filter((v) => v.state === 'online' || v.state === 'offline'); } catch { /* only the portal's own then */ }
    const source = sel('source', [].concat(portalOnly ? [] : [['', 'This machine']], [['portal', 'The portal itself']], servers.map((v) => [v.id, v.name + (v.state === 'online' ? '' : ' (offline)')])));
    source.value = auditSource !== null && [...source.options].some((o) => o.value === auditSource) ? auditSource : (portalOnly ? 'portal' : '');
    const user = el('input', { name: 'user', placeholder: 'any', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'Account' });
    const kind = sel('event', [['', 'all'], ['login', 'sign-ins'], ['session', 'sessions'], ['connection', 'connections'], ['admin', 'changes (admin)'], ['server', 'servers (portal)'], ['account', 'accounts (portal)'], ['stream', 'desktops (portal)'], ['gpu', 'graphics'], ['audit', 'the log itself']]);
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
      auditSource = source.value;
      if (source.value) q.set('source', source.value);
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
    const form = el('form', { class: 'row' }, field('Log of', source), field('Account', user), field('Event', kind), field('Outcome', outcome), field('Time', since), field('Show', limit), button('Search', () => form.requestSubmit(), 'primary'), button('Export CSV', () => csv()));
    form.addEventListener('submit', (e) => { e.preventDefault(); load(); });
    await load();
    return [el('div', { class: 'head' }, el('h1', {}, 'Audit'), el('span', { class: 'sp' }), null), win('filter', form), holder];
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

  async users() {
    const r = await get('people', true);
    const servers = r.servers || [];
    const nameOf = (id) => (servers.find((v) => v.id === id) || {}).name || id;
    const rows = (r.people || []).map((p) => el('tr', {},
      cell([el('b', {}, p.name), p.display ? el('span', { class: 'dim' }, ' ' + p.display) : null]),
      cell(p.admin ? chip('admin') : el('span', { class: 'dim' }, '-')),
      cell(p.disabled ? chip('switched off', 'bad') : chip('active', 'ok')),
      cell(p.servers.length ? el('div', { class: 'chips' }, p.servers.map((a) => el('a', { class: 'chip', href: '#servers/' + a.server + '/accounts' }, nameOf(a.server)))) : el('span', { class: 'dim' }, 'none')),
      cell(el('div', { class: 'acts' },
        button('Servers', () => personServers(p, servers), 'sm'),
        button('New password', () => personPassword(p), 'sm'),
        button(p.admin ? 'Not admin' : 'Make admin', () => personDo({ action: 'admin', name: p.name, on: !p.admin }, p.name + (p.admin ? ' is not an administrator any more.' : ' is an administrator now.')), 'sm'),
        button(p.disabled ? 'Switch on' : 'Switch off', () => personDo({ action: 'disable', name: p.name, on: !p.disabled }, p.name + (p.disabled ? ' may sign in again.' : ' was switched off.')), 'sm' + (p.disabled ? '' : ' danger')),
        button('Remove', () => personRemove(p), 'sm danger')), 'n')));
    return [
      el('div', { class: 'head' }, el('div', {}, el('h1', {}, 'Users'), el('p', { class: 'sub' }, rows.length + (rows.length === 1 ? ' user' : ' users') + ' \u00b7 ' + (r.people || []).filter((p) => p.admin).length + ' admin')), el('span', { class: 'sp' }), button('Add user', addPerson, 'primary')),
      win('users of the portal \u00b7 ' + rows.length, table(['Name', 'Role', 'State', 'Servers', ''], rows, 'Nobody yet.'),
        el('p', { class: 'hint' }, 'These are the users of the portal. Assigning a server makes the same user\u2019s account on that server (see the Accounts tab of the server), with a password nobody sees; the user makes an app password for RDP clients in My account.')),
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
      el('div', { class: 'head' }, el('h1', {}, 'Sessions'), el('span', { class: 'sp' }), await picker()),
      withCount(win('running sessions', table(['Account', 'State', 'Since', 'Desktop', 'Encoder', '>Memory', '>CPU', ''], rows, 'No sessions running.')), rows.length + (a.max_active_users ? ' of ' + a.max_active_users : '')),
    ];
  },
};

let timer = 0;
// Draws `view` into `root`; the numbers refresh every 10 s while the page shows (not for Users, which is a list that does not change by the second).
export async function render(path, root, onSignedOut, csrf, portal = false) {
  const [view, sid, tab] = path.split('/');
  clearInterval(timer);
  portalOnly = portal;
  if (portalOnly) await settle();
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
      root.replaceChildren(...(view === 'servers' && sid ? await serverPage(sid, tab) : await views[view]()));
    } catch (e) {
      if (e.signedOut) { clearInterval(timer); onSignedOut(); return; }
      root.replaceChildren(el('p', { class: 'bad' }, e.message || 'Something went wrong.'));
    }
  };
  root.replaceChildren(el('p', { class: 'muted' }, 'Loading…'));
  await draw();
  if (!['users', 'audit'].includes(view === 'servers' && sid ? tab : view)) timer = setInterval(() => { if (!document.hidden) draw(); }, 10000);
}
export const stop = () => clearInterval(timer);
export const known = (path) => ['servers', 'users', 'audit', 'settings'].includes(path.split('/')[0]);
