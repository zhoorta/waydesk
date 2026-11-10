// The Waydesk desktop in the page: the daemon's browser stream (src/webstream.rs) on a canvas. H.264 pictures go to the browser's own decoder
// (WebCodecs); keys, mouse and the window size go back as small messages. No dependencies.
//
// Messages are binary WebSocket messages, little endian, first byte the tag.
//   browser -> daemon: 1 Start(w16 h16 scale16) 2 Resize(w16 h16 scale16) 3 Key(code, down) 4 Move(x32 y32) 5 Button(n, down)
//                      6 Wheel(f32 f32) 7 Ack(n16) 8 RequestFull 9 Clipboard(UTF-8 text, the rest) 255 Bye        (strings: u16 length + UTF-8)
//   daemon -> browser: 1 Ready(w16 h16) 2 Resized(w16 h16) 3 Frame(key8 ts32 annexb...) 4 Cursor(name) 5 Error(code8 text) 6 Clipboard(UTF-8 text) 7 CursorImage(hotx16 hoty16 w16 h16 BGRA premultiplied)

const enc = new TextEncoder();
const dec = new TextDecoder();

const u16 = (n) => [n & 255, (n >> 8) & 255];
const u32 = (n) => [n & 255, (n >>> 8) & 255, (n >>> 16) & 255, (n >>> 24) & 255];
const f32 = (n) => [...new Uint8Array(new Float32Array([n]).buffer)];
const str = (s) => { const b = enc.encode(s); return [...u16(b.length), ...b]; };

// A cursor name from the session: only plain CSS names are used, anything else is the arrow.
const CURSOR = /^[a-z-]{1,30}$/;

// On a Mac the Command key is the shortcut key: Cmd+C is Ctrl+C on the desktop. Command alone (the Super key) is still sent when it is let go on its own.
const MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform || '');
const SHORTCUT = /^Key[ACVXZFS]$/;

/** Whether this browser can show the stream. */
export async function supported() {
  if (typeof VideoDecoder === 'undefined' || typeof EncodedVideoChunk === 'undefined') return false;
  try {
    const r = await VideoDecoder.isConfigSupported({ codec: 'avc1.640033', optimizeForLatency: true });
    return !!r.supported;
  } catch { return false; }
}

/** The `avc1.PPCCLL` codec string of the first SPS in an Annex B picture, or null. */
export function codecOf(data) {
  for (let i = 0; i + 6 < data.length; i++) {
    if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 1 && (data[i + 3] & 0x1f) === 7) {
      const hex = (b) => b.toString(16).padStart(2, '0');
      return 'avc1.' + hex(data[i + 4]) + hex(data[i + 5]) + hex(data[i + 6]);
    }
  }
  return null;
}

export class Desk {
  /**
   * @param canvas the canvas the picture is drawn on
   * @param handlers { ready(w,h), ended(message, isError), cursor(name) }
   */
  constructor(canvas, handlers) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d', { alpha: false, desynchronized: true });
    this.on = handlers;
    this.ws = null;
    this.decoder = null;
    this.codec = '';
    this.needKey = true;
    this.ended = false;
    this.pressed = new Set();
    this.buttons = new Set();
    this.pending = null; // the latest pointer position, sent once per animation frame
    this.stats = { frames: 0, bytes: 0, received: 0, keys: 0, dropped: 0, resets: 0 };
    this.listeners = [];
    this.clip = ''; // the last clipboard text that went either way (an echo is not sent back)
    this.hold = null; // while the clipboard is read for a paste, the keys wait behind it
    this.copyWait = null; // a copy asked for: the clipboard of the page is filled when the desktop's text arrives
    this.pasteSeen = null;
    this.metaHeld = new Set(); // Command keys down (Mac), not yet sent
    this.metaSent = new Set();
    this.metaUsed = false;
    this.tapped = new Set(); // keys sent as a whole tap (their key-up is not sent again)
  }

  connect({ width, height, scale }) {
    const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/stream';
    const ws = new WebSocket(url);
    ws.binaryType = 'arraybuffer';
    this.ws = ws;
    ws.onopen = () => this.send([1, ...u16(width), ...u16(height), ...u16(scale)]);
    ws.onmessage = (e) => this.message(new Uint8Array(e.data));
    ws.onclose = () => this.end(this.ready ? 'Session ended.' : 'Could not connect.', !this.ready);
    ws.onerror = () => {};
  }

  send(bytes) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.send(new Uint8Array(bytes));
  }

  message(m) {
    if (m[0] === 3) { this.stats.received += 1; if (m[1] === 1) this.stats.keys += 1; }
    switch (m[0]) {
      case 1: // Ready
        this.ready = true;
        this.size(m[1] | (m[2] << 8), m[3] | (m[4] << 8));
        this.attachInput();
        this.on.ready(this.canvas.width, this.canvas.height);
        break;
      case 2: // Resized: the picture has another size; the decoder starts again at the next key picture
        this.size(m[1] | (m[2] << 8), m[3] | (m[4] << 8));
        this.resetDecoder();
        break;
      case 3: // Frame
        this.frame(m[1] === 1, (m[2] | (m[3] << 8) | (m[4] << 16) | (m[5] << 24)) >>> 0, m.subarray(6));
        break;
      case 4: { // Cursor
        const name = dec.decode(m.subarray(1));
        this.canvas.style.cursor = CURSOR.test(name) ? (name === 'default' ? 'default' : name) : 'default';
        break;
      }
      case 7: // CursorImage: a pointer an application drew itself
        this.cursorImage(m);
        break;
      case 6: { // Clipboard: the desktop copied text
        const text = dec.decode(m.subarray(1));
        this.clip = text;
        if (this.copyWait) {
          // Safari lets a page fill the clipboard only inside the key press that asked for it: that press handed over a promise for this text.
          this.copyWait.resolve(text);
          this.copyWait = null;
        } else {
          try { navigator.clipboard.writeText(text).catch(() => {}); } catch { /* no clipboard access here */ }
        }
        break;
      }
      case 5: // Error
        this.end(dec.decode(m.subarray(2)) || 'The connection ended.', true);
        break;
      default:
        break;
    }
  }

  cursorImage(m) {
    const hx = m[1] | (m[2] << 8), hy = m[3] | (m[4] << 8), w = m[5] | (m[6] << 8), h = m[7] | (m[8] << 8);
    const px = m.subarray(9);
    if (w < 1 || h < 1 || w > 32 || h > 32 || px.length !== w * h * 4) { this.canvas.style.cursor = 'default'; return; }
    // BGRA premultiplied -> RGBA straight, for ImageData
    const out = new Uint8ClampedArray(w * h * 4);
    for (let i = 0; i < out.length; i += 4) {
      const a = px[i + 3];
      const un = (c) => (a === 255 ? c : a === 0 ? 0 : Math.min(255, Math.round((c * 255) / a)));
      out[i] = un(px[i + 2]); out[i + 1] = un(px[i + 1]); out[i + 2] = un(px[i]); out[i + 3] = a;
    }
    try {
      const c = document.createElement('canvas');
      c.width = w; c.height = h;
      c.getContext('2d').putImageData(new ImageData(out, w, h), 0, 0);
      this.canvas.style.cursor = `url(${c.toDataURL('image/png')}) ${Math.min(hx, w - 1)} ${Math.min(hy, h - 1)}, default`;
    } catch { this.canvas.style.cursor = 'default'; }
  }

  size(w, h) {
    if (this.canvas.width !== w || this.canvas.height !== h) {
      this.canvas.width = w;
      this.canvas.height = h;
    }
  }

  resetDecoder() {
    this.stats.resets += 1;
    if (this.decoder && this.decoder.state !== 'closed') { try { this.decoder.close(); } catch { /* gone */ } }
    this.decoder = null;
    this.codec = '';
    this.needKey = true;
    this.send([8]);
  }

  frame(key, ts, data) {
    if (this.ended) return;
    if (key) {
      const codec = codecOf(data);
      if (codec && codec !== this.codec) {
        if (this.decoder && this.decoder.state !== 'closed') { try { this.decoder.close(); } catch { /* gone */ } }
        this.codec = codec;
        this.decoder = new VideoDecoder({
          output: (f) => {
            if (!this.stats.last) this.stats.last = `display ${f.displayWidth}x${f.displayHeight} coded ${f.codedWidth}x${f.codedHeight} visible ${f.visibleRect ? f.visibleRect.width + 'x' + f.visibleRect.height : '?'}`;
            // The encoder codes whole blocks of 16 pixels (1296x640 for a 1280x614 desktop) and does not say where the picture ends, so only the
            // desktop's own pixels are copied: scaling the whole frame would squeeze the padding in as a black band.
            this.ctx.drawImage(f, 0, 0, this.canvas.width, this.canvas.height, 0, 0, this.canvas.width, this.canvas.height);
            f.close();
            this.stats.frames += 1;
            this.send([7, 1, 0]); // shown: the daemon may send one more
          },
          error: (e) => this.end('The video decoder stopped: ' + String(e.message || e).slice(0, 120), true),
        });
        this.decoder.configure({ codec, optimizeForLatency: true });
        this.needKey = true;
      }
      if (this.decoder) this.needKey = false;
    }
    if (!this.decoder || this.needKey) {
      this.stats.dropped += 1;
      this.send([7, 1, 0]); // nothing to show yet; give the credit back so the daemon keeps sending
      return;
    }
    this.stats.bytes += data.length;
    try {
      this.decoder.decode(new EncodedVideoChunk({ type: key ? 'key' : 'delta', timestamp: ts * 1000, data }));
    } catch (e) {
      this.end('The video decoder stopped: ' + String(e.message || e).slice(0, 120), true);
    }
  }

  end(message, isError) {
    if (this.ended) return;
    this.ended = true;
    this.detachInput();
    if (this.decoder && this.decoder.state !== 'closed') { try { this.decoder.close(); } catch { /* gone */ } }
    if (this.ws) {
      try { if (this.ws.readyState === WebSocket.OPEN) this.ws.send(new Uint8Array([255])); this.ws.close(); } catch { /* gone */ }
    }
    this.on.ended(message, isError);
  }

  disconnect() { this.end('Disconnected.', false); }

  resize(width, height, scale) { this.send([2, ...u16(width), ...u16(height), ...u16(scale)]); }

  ctrlAltDel() {
    for (const code of ['ControlLeft', 'AltLeft', 'Delete']) this.send([3, ...str(code), 1]);
    for (const code of ['Delete', 'AltLeft', 'ControlLeft']) this.send([3, ...str(code), 0]);
  }

  // ---- input ----

  attachInput() {
    const c = this.canvas;
    const on = (target, type, fn, opts) => { target.addEventListener(type, fn, opts); this.listeners.push([target, type, fn, opts]); };
    on(window, 'keydown', (e) => this.key(e, true), { capture: true });
    on(window, 'keyup', (e) => this.key(e, false), { capture: true });
    on(window, 'blur', () => this.releaseAll());
    on(window, 'focus', () => { this.syncClipboard(); });
    // The browser hands over its clipboard with a paste (no permission asked, and Safari allows nothing else).
    on(window, 'paste', (e) => {
      const text = e.clipboardData && e.clipboardData.getData('text/plain');
      if (text) this.sendClipboard(text);
      e.preventDefault();
      if (this.pasteSeen) this.pasteSeen();
    }, { capture: true });
    on(c, 'pointermove', (e) => this.move(e));
    on(c, 'pointerdown', (e) => { c.setPointerCapture(e.pointerId); this.move(e); this.button(e, true); e.preventDefault(); });
    on(c, 'pointerup', (e) => { this.button(e, false); e.preventDefault(); });
    on(c, 'pointercancel', () => this.releaseAll());
    on(c, 'contextmenu', (e) => e.preventDefault());
    on(c, 'wheel', (e) => this.wheel(e), { passive: false });
  }

  detachInput() {
    for (const [t, type, fn, opts] of this.listeners) t.removeEventListener(type, fn, opts);
    this.listeners = [];
  }

  key(e, down) {
    if (this.ended || !e.code || e.code === 'Unidentified') return;
    e.stopPropagation();
    const isMeta = e.code === 'MetaLeft' || e.code === 'MetaRight';
    if (MAC && isMeta) { e.preventDefault(); this.metaKey(e.code, down); return; }
    const cmd = MAC && e.metaKey && !e.ctrlKey && SHORTCUT.test(e.code); // Cmd+letter: the shortcut of the desktop is Ctrl+letter
    const ctrl = e.ctrlKey || cmd;
    const paste = down && ((e.code === 'KeyV' && ctrl) || (e.code === 'Insert' && e.shiftKey));
    const copy = down && (e.code === 'KeyC' || e.code === 'KeyX') && ctrl;
    if (!paste) e.preventDefault(); // a paste needs the key's own effect: the page then gets a paste event with the clipboard
    if (MAC && this.metaHeld.size) {
      this.metaUsed = true;
      if (!cmd && down) for (const m of this.metaHeld) if (!this.metaSent.has(m)) { this.metaSent.add(m); this.emit([[m, 1]]); }
    }
    let keys;
    if (cmd) {
      if (!down) { this.tapped.delete(e.code); return; } // a Mac sends no key-up under Command anyway
      this.tapped.add(e.code);
      keys = [['ControlLeft', 1], [e.code, 1], [e.code, 0], ['ControlLeft', 0]];
    } else {
      if (down) this.pressed.add(e.code); else this.pressed.delete(e.code);
      keys = [[e.code, down ? 1 : 0]];
    }
    if (copy) this.armCopy();
    if (paste) {
      // What the browser's clipboard holds goes first, then the key (and any key after it keeps its order).
      const seen = new Promise((resolve) => {
        this.pasteSeen = () => { this.pasteSeen = null; resolve(true); };
        setTimeout(() => resolve(false), 250);
      });
      this.after(seen.then((got) => (got ? null : this.syncClipboard())).then(() => { this.sendKeys(keys); }));
    } else {
      this.emit(keys);
    }
  }

  // Command keys (Mac) wait: with a letter they make a Ctrl shortcut, with another key they are Super, alone they are a tap of Super.
  metaKey(code, down) {
    if (down) {
      if (!this.metaHeld.has(code)) this.metaHeld.add(code);
      return;
    }
    if (this.metaSent.has(code)) { this.metaSent.delete(code); this.emit([[code, 0]]); }
    else if (this.metaHeld.has(code) && !this.metaUsed) this.emit([[code, 1], [code, 0]]);
    this.metaHeld.delete(code);
    if (!this.metaHeld.size) this.metaUsed = false;
  }

  sendKeys(keys) {
    for (const [code, d] of keys) this.send([3, ...str(code), d]);
  }

  emit(keys) {
    if (this.hold) this.after(this.hold.then(() => { this.sendKeys(keys); }));
    else this.sendKeys(keys);
  }

  // A copy: the page's clipboard is filled by this very key press with a promise of the text the desktop is about to announce (Safari allows no
  // other way). When nothing arrives the promise fails and the clipboard stays as it was.
  armCopy() {
    if (!navigator.clipboard || !navigator.clipboard.write || typeof ClipboardItem === 'undefined') return;
    if (this.copyWait) this.copyWait.reject(new Error('another copy'));
    const text = new Promise((resolve, reject) => {
      this.copyWait = { resolve, reject };
      setTimeout(() => { if (this.copyWait && this.copyWait.resolve === resolve) { this.copyWait = null; } reject(new Error('nothing copied')); }, 1500);
    });
    try {
      navigator.clipboard.write([new ClipboardItem({ 'text/plain': text.then((t) => new Blob([t], { type: 'text/plain' })) })]).catch(() => {});
    } catch { this.copyWait = null; }
  }

  after(p) {
    this.hold = p;
    p.then(() => { if (this.hold === p) this.hold = null; });
  }

  /** Sends the browser's clipboard text to the desktop when it is not what both sides already have. Needs the browser's leave to read. */
  async syncClipboard() {
    try {
      const text = await Promise.race([navigator.clipboard.readText(), new Promise((_, no) => setTimeout(no, 300))]);
      if (text && text !== this.clip && enc.encode(text).length < 1024 * 1024) {
        this.sendClipboard(text);
      }
    } catch { /* not allowed, empty, or not text: the desktop keeps its own */ }
  }

  sendClipboard(text) {
    const body = enc.encode(text);
    if (!text || body.length >= 1024 * 1024) return;
    this.clip = text;
    const m = new Uint8Array(1 + body.length);
    m[0] = 9;
    m.set(body, 1);
    this.send(m);
  }

  // Where a pointer event is on the desktop, in its pixels. The picture is fitted into the canvas element (letterboxed when the shapes differ).
  point(e) {
    const r = this.canvas.getBoundingClientRect();
    const sx = r.width / this.canvas.width;
    const sy = r.height / this.canvas.height;
    const s = Math.min(sx, sy);
    const offX = (r.width - this.canvas.width * s) / 2;
    const offY = (r.height - this.canvas.height * s) / 2;
    const x = Math.round((e.clientX - r.left - offX) / s);
    const y = Math.round((e.clientY - r.top - offY) / s);
    return [Math.max(0, Math.min(this.canvas.width - 1, x)), Math.max(0, Math.min(this.canvas.height - 1, y))];
  }

  move(e) {
    this.pending = this.point(e);
    if (this.raf) return;
    this.raf = requestAnimationFrame(() => {
      this.raf = 0;
      if (this.pending && !this.ended) this.send([4, ...u32(this.pending[0]), ...u32(this.pending[1])]);
      this.pending = null;
    });
  }

  button(e, down) {
    if (this.ended) return;
    if (down) this.buttons.add(e.button); else this.buttons.delete(e.button);
    // The position first, so that a click lands where the pointer is.
    const [x, y] = this.point(e);
    this.send([4, ...u32(x), ...u32(y)]);
    this.send([5, e.button, down ? 1 : 0]);
  }

  wheel(e) {
    if (this.ended) return;
    e.preventDefault();
    // Notches: a browser reports pixels (about 100 to a notch), lines (3 to a notch) or pages.
    const unit = e.deltaMode === 1 ? 1 / 3 : e.deltaMode === 2 ? 10 : 1 / 100;
    this.send([6, ...f32(e.deltaY * unit), ...f32(e.deltaX * unit)]);
  }

  // When the page loses the focus the keys and buttons held down are let go, or the desktop would see them held for ever.
  releaseAll() {
    for (const code of this.pressed) this.send([3, ...str(code), 0]);
    for (const b of this.buttons) this.send([5, b, 0]);
    this.pressed.clear();
    this.buttons.clear();
    for (const m of this.metaSent) this.send([3, ...str(m), 0]);
    this.metaSent.clear();
    this.metaHeld.clear();
    this.metaUsed = false;
  }
}
