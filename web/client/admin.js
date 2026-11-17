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
      holder.replaceChildren(win('accounts · ' + list.length, table(['Account', 'Desktop', 'Graphics', 'RDP', 'Admin', 'Session'],
        shown.map((u) => el('tr', {},
          cell(el('b', {}, u.name)),
          cell((u.desktop || '-') + (u.desktop_from === 'account' ? '*' : '')),
          cell(String(u.gpu || '-').split('/').pop() + (u.gpu_from === 'account' ? '*' : '')),
          cell(u.rdp ? chip('yes', 'ok') : chip('no', 'bad')),
          cell(u.sudo ? chip('admin') : el('span', { class: 'dim' }, '-')),
          cell(u.session === 'running' ? [dot(), 'running' + (u.desktop_running ? ' on ' + u.desktop_running : ''), u.session_since ? el('span', { class: 'dim' }, ' since ' + sessionSince(u.session_since)) : null] : [dot('off'), 'none']))),
        'No account matches.'), el('p', { class: 'hint' }, '* a setting of the account itself; the rest is the server’s setting. Adding, disabling and password resets come next.')));
    };
    const search = el('input', { type: 'search', placeholder: 'Search accounts', 'aria-label': 'Search accounts', style: 'width:14rem' });
    search.addEventListener('input', () => draw(search.value.trim().toLowerCase()));
    draw('');
    return [el('div', { class: 'head' }, el('h1', {}, 'Users'), el('span', { class: 'sp' }), search), holder];
  },

  async sessions() {
    const [list, s] = await Promise.all([get('sessions'), get('status')]);
    const by = new Map((s.users || []).map((u) => [u.name, u]));
    const rows = list.map((r) => {
      const u = by.get(r.name) || {};
      const v = u.video || {};
      return el('tr', {}, cell(el('b', {}, r.name)), cell([dot(), 'running']), cell(sessionSince(r.since)), cell(v.compositor || '-'), cell(v.encoder || '-'), cell(gb(u.mem_mb || 0), 'n mono'), cell(Math.round(u.cpu_percent || 0) + '%', 'n mono'));
    });
    const a = s.admission || {};
    return [
      el('div', { class: 'head' }, el('h1', {}, 'Sessions'), el('span', { class: 'sp' }), chip(rows.length + (a.max_active_users ? ' of ' + a.max_active_users : ' running'), 'ok')),
      win('running sessions', table(['Account', 'State', 'Since', 'Desktop', 'Encoder', '>Memory', '>CPU'], rows, 'No sessions running.'), el('p', { class: 'hint' }, 'Ending a session comes next.')),
    ];
  },
};

let timer = 0;
// Draws `view` into `root`; the numbers refresh every 10 s while the page shows (not for Users, which is a list that does not change by the second).
export async function render(view, root, onSignedOut) {
  clearInterval(timer);
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
