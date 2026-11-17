// "My account": change your own password, and see whether you have a second factor. The old password is checked by the server like a login (the
// same delay and lockout as a wrong password at sign-in), the new one is set by the server, and neither is kept here: the fields are cleared at once.

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
const win = (title, ...body) => el('section', { class: 'win' }, el('div', { class: 'bar' }, el('span', { class: 't' }, title)), el('div', { class: 'body' }, body));

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
  const again = field('New password again', 'again', 'new-password');
  const err = el('p', { class: 'bad', role: 'alert' });
  const go = el('button', { type: 'submit', class: 'btn primary' }, 'Change password');
  const form = el('form', { class: 'form' },
    el('label', {}, 'Current password', oldPw),
    el('label', {}, 'New password', newPw),
    el('label', {}, 'New password again', again),
    el('p', { class: 'hint' }, 'At least 8 characters. Your programs keep running; the new password is used the next time you sign in.'),
    err, el('div', {}, go));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    err.textContent = '';
    if (newPw.value !== again.value) { err.textContent = 'The two new passwords are not the same.'; return; }
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
      again.value = '';
      go.disabled = false;
    }
  });

  const policy = { off: 'This server does not ask for a code.', optional: 'A code is asked of accounts that set one up.', required: 'This server asks every account for a code.' }[info.totp] || '';
  root.replaceChildren(
    el('div', { class: 'head' }, el('h1', {}, 'My account'), el('span', { class: 'sp' }), el('span', { class: 'muted small' }, info.account)),
    el('div', { class: 'two' },
      win('password', form),
      win('two-step sign-in', el('p', {}, el('span', { class: 'tag ' + (info.enrolled ? 'ok' : '') }, info.enrolled ? 'set up' : 'not set up')), el('p', { class: 'muted' }, policy),
        el('p', { class: 'hint' }, info.enrolled ? 'If you lose your phone, ask an administrator to remove it, then set a new one up.' : 'Ask an administrator to set one up for you.'))),
  );
}
