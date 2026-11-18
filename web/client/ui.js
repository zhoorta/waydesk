// Pieces every page of the portal uses: building elements (never innerHTML), windows, buttons, dialogs.

export const el = (tag, props = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === false || v == null) continue;
    if (k === 'class') e.className = v;
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  return e;
};

export const chip = (text, tone = '') => el('span', { class: 'tag ' + tone }, text);
export const dot = (tone = '') => el('span', { class: 'dot ' + tone });
export const win = (title, ...body) => el('section', { class: 'win' }, el('div', { class: 'bar' }, el('span', { class: 't' }, title)), el('div', { class: 'body' }, body));

// A window over the page: a title bar like every window, the content, and buttons. Closes on Escape or by its own buttons.
export function modal(title, content, buttons) {
  const d = el('dialog', { class: 'win dlg', 'aria-label': title },
    el('div', { class: 'bar' }, el('span', { class: 't' }, title)),
    el('div', { class: 'body' }, content, el('div', { class: 'actions' }, buttons)));
  d.addEventListener('close', () => d.remove());
  document.body.append(d);
  d.showModal();
  return d;
}

export const button = (label, onClick, kind = '') => { const b = el('button', { type: 'button', class: 'btn ' + kind }, label); b.addEventListener('click', onClick); return b; };

// "Are you sure": resolves to true or false.
export function confirmBox(title, text, label, danger = false, extra = null) {
  return new Promise((resolve) => {
    let answer = false;
    const d = modal(title, [typeof text === 'string' ? el('p', {}, text) : text, extra], [button('Cancel', () => d.close()), button(label, () => { answer = true; d.close(); }, danger ? 'danger' : 'primary')]);
    d.addEventListener('close', () => resolve(answer));
  });
}
