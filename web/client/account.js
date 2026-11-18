// "My account": change your own password, and see whether you have a second factor. The old password is checked by the server like a login (the
// same delay and lockout as a wrong password at sign-in), the new one is set by the server, and neither is kept here: the fields are cleared at once.

import { el, win, button, modal } from './ui.js';

async function post(path, csrf, body) {
  const r = await fetch(path, { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() }, body: body === undefined ? undefined : JSON.stringify(body) });
  let data = null;
  try { data = await r.json(); } catch { /* not JSON */ }
  return { status: r.status, data };
}

const codeInput = () => el('input', { name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', spellcheck: 'false', placeholder: '6 digits', required: true, 'aria-label': 'Code from your authenticator app' });

// Setting up an authenticator: the server makes a key and keeps it only in memory; nothing is saved until a code from the app proves the person has it.
async function setUp(csrf, onSignedOut, done) {
  const first = await post('/api/account/totp/start', csrf);
  if (first.status === 401) { onSignedOut(); return; }
  if (!first.data || !first.data.ok) { done((first.data && first.data.error) || 'The server could not start the setup.', 'bad'); return; }
  const secret = el('code', { class: 'secret' }, first.data.secret.replace(/(.{4})/g, '$1 ').trim());
  const code = codeInput();
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' },
    el('p', {}, 'Add this key to an authenticator app (Aegis, 1Password, Google Authenticator, Authy). On a phone you can also ', el('a', { href: first.data.uri }, 'open it in the app'), '.'),
    secret,
    el('p', { class: 'hint' }, 'Account name: Waydesk. Type of key: time based, 6 digits. Then type the code the app shows now.'),
    el('label', {}, 'Code', code), err);
  const d = modal('set up two-step sign-in', form, [button('Cancel', () => d.close()), button('Turn on', () => form.requestSubmit(), 'primary')]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    const r = await post('/api/account/totp/confirm', csrf, { code: code.value.trim() });
    if (r.status === 401) { d.close(); onSignedOut(); return; }
    if (r.status === 429) { err.textContent = 'Too many wrong codes. Wait a few minutes.'; return; }
    if (!r.data || !r.data.ok) { err.textContent = (r.data && r.data.error) || 'It did not work.'; code.value = ''; return; }
    // The recovery codes are shown once, here.
    const codes = el('code', { class: 'secret' }, r.data.recovery.join('\n'));
    codes.style.whiteSpace = 'pre';
    const copy = button('Copy', async () => { try { await navigator.clipboard.writeText(r.data.recovery.join('\n')); copy.textContent = 'Copied'; } catch { copy.textContent = 'Select and copy them'; } });
    d.replaceChildren(el('div', { class: 'bar' }, el('span', { class: 't' }, 'recovery codes')),
      el('div', { class: 'body' }, el('p', {}, 'Two-step sign-in is on. Keep these recovery codes somewhere safe: each works once if you lose your phone. They are not shown again.'), codes,
        el('div', { class: 'actions' }, copy, button('I have saved them', () => d.close(), 'primary'))));
    d.addEventListener('close', () => done('Two-step sign-in is on.', 'ok'), { once: true });
  });
  code.focus();
}

function turnOff(csrf, onSignedOut, done) {
  const code = codeInput();
  const err = el('p', { class: 'bad', role: 'alert' });
  const form = el('form', { class: 'form' }, el('p', {}, 'Type a code from your authenticator app (or a recovery code) to turn it off.'), el('label', {}, 'Code', code), err);
  const d = modal('turn off two-step sign-in', form, [button('Cancel', () => d.close()), button('Turn off', () => form.requestSubmit(), 'danger')]);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    const r = await post('/api/account/totp/remove', csrf, { code: code.value.trim() });
    if (r.status === 401) { d.close(); onSignedOut(); return; }
    if (r.status === 429) { err.textContent = 'Too many wrong codes. Wait a few minutes.'; return; }
    if (!r.data || !r.data.ok) { err.textContent = (r.data && r.data.error) || 'It did not work.'; code.value = ''; return; }
    d.close();
    done('Two-step sign-in is off.', 'ok');
  });
  code.focus();
}

export async function render(root, csrf, onSignedOut, flash) {
  let info = { account: '', totp: 'off', enrolled: false };
  try {
    const r = await fetch('/api/account', { cache: 'no-store' });
    if (r.status === 401) { onSignedOut(); return; }
    if (r.ok) info = await r.json();
  } catch { /* the page still works without it */ }

  const field = (label, name, autocomplete) => el('input', { type: 'password', name, autocomplete, required: true, 'aria-label': label });
  const oldPw = field('Current password', 'old', 'current-password');
  const newPw = field('New password', 'new', 'new-password');
  const repeat = field('New password again', 'again', 'new-password');
  const err = el('p', { class: 'bad', role: 'alert' });
  const go = el('button', { type: 'submit', class: 'btn primary' }, 'Change password');
  const form = el('form', { class: 'form' },
    el('label', {}, 'Current password', oldPw),
    el('label', {}, 'New password', newPw),
    el('label', {}, 'New password again', repeat),
    el('p', { class: 'hint' }, 'At least 8 characters. Your programs keep running; the new password is used the next time you sign in.'),
    err, el('div', {}, go));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    if (newPw.value !== repeat.value) { err.textContent = 'The two new passwords are not the same.'; return; }
    if (newPw.value.length < 8) { err.textContent = 'The new password must be at least 8 characters.'; return; }
    go.disabled = true;
    try {
      const r = await fetch('/api/account/password', { method: 'POST', cache: 'no-store', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf() }, body: JSON.stringify({ old: oldPw.value, new: newPw.value }) });
      if (r.status === 401) { onSignedOut(); return; }
      if (r.status === 429) throw new Error('Too many attempts. Wait a minute.');
      let body = null;
      try { body = await r.json(); } catch { /* handled below */ }
      if (!r.ok || !body || !body.ok) throw new Error((body && body.error) || 'The server could not change the password (' + r.status + ').');
      flash('Your password was changed.', 'ok');
      form.reset();
    } catch (x) {
      err.textContent = x.message;
    } finally {
      oldPw.value = '';
      newPw.value = '';
      repeat.value = '';
      go.disabled = false;
    }
  });

  const policy = { off: 'This server does not ask for a code, so there is nothing to set up.', optional: 'This server asks for a code from accounts that set one up.', required: 'This server asks every account for a code.' }[info.totp] || '';
  const again = () => render(root, csrf, onSignedOut, flash);
  const finished = (text, tone) => { flash(text, tone); again(); };
  const twoStepBody = [el('p', {}, el('span', { class: 'tag ' + (info.enrolled ? 'ok' : '') }, info.enrolled ? 'set up' : 'not set up')), el('p', { class: 'muted' }, policy)];
  if (info.enrolled) {
    twoStepBody.push(info.totp === 'required' ? el('p', { class: 'hint' }, 'Because it is required, it cannot be turned off here. If you lose your phone, ask an administrator.') : el('div', {}, button('Turn off', () => turnOff(csrf, onSignedOut, finished), 'danger')));
    twoStepBody.push(el('p', { class: 'hint' }, 'If you lose your phone, use a recovery code, or ask an administrator to remove it and set a new one up.'));
  } else if (info.totp !== 'off') {
    twoStepBody.push(el('div', {}, button('Set up', () => setUp(csrf, onSignedOut, finished), 'primary')));
  }
  root.replaceChildren(
    el('div', { class: 'head' }, el('h1', {}, 'My account'), el('span', { class: 'sp' }), el('span', { class: 'muted small' }, info.account)),
    el('div', { class: 'two' }, win('password', form), win('two-step sign-in', ...twoStepBody)),
  );
}
