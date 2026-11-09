// The Waydesk web client: a login form, then the remote desktop in the page. The RDP login is made inside the connection by the client
// (the page sends the password only into it); the gateway hands out a one-time token for starting the session.
import { ConfigBuilder } from './iron-remote-desktop.js';
import * as rdp from './iron-remote-desktop-rdp.js';

const { Backend, init, enableCredssp } = rdp;

const $ = (id) => document.getElementById(id);
const say = (text, error = false) => { $('msg').textContent = text; $('msg').className = error ? 'error' : ''; };

await init('warn');
// H.264 through the browser's own decoder, when this client build has it and the browser can decode it (?h264=0 turns it off, for comparing).
let useH264 = typeof rdp.h264Supported === 'function' && new URLSearchParams(location.search).get('h264') !== '0' && (await rdp.h264Supported());
document.documentElement.dataset.h264 = String(useH264);
// Set when the browser's decoder gives up in a session (see the decoder's options below): the next connection does without H.264.
let decoderFailure = '';
$('go').disabled = false;
$('go').textContent = 'Connect';

let current = null; // { el, ui }

// The desktop is asked for in device pixels, and told the scale: on a Retina screen (a ratio of 2) the server makes a picture twice as wide and
// high and scales its interface by 200 %, so each of its pixels is one of the screen's, not a blurred pair. But four times the pixels is four times
// the work for the server (drawing and encoding), and a full-screen Retina window is seven million of them, more than a small server can make in
// time. So the picture is kept within a budget of pixels (4 million, about 2560x1600, unless `?maxpx=N`; 0 means no limit) by lowering the
// ratio in steps of a quarter, and a sysadmin with a GPU server can raise it. `?dpr=1` asks for the plain size.
const MAX_PIXELS = (() => {
  const given = new URLSearchParams(location.search).get('maxpx');
  return given === null ? 4_000_000 : Math.max(0, Number(given) || 0);
})();

function pixelRatio(cssWidth, cssHeight) {
  const forced = Number(new URLSearchParams(location.search).get('dpr'));
  let ratio = forced >= 1 && forced <= 4 ? forced : window.devicePixelRatio || 1;
  ratio = Math.min(4, Math.max(1, ratio));
  if (MAX_PIXELS > 0 && cssWidth > 0 && cssHeight > 0) {
    const fits = Math.floor(Math.sqrt(MAX_PIXELS / (cssWidth * cssHeight)) * 4) / 4;
    ratio = Math.max(1, Math.min(ratio, fits));
  }
  return ratio;
}

function screenSize() {
  const r = $('screen').getBoundingClientRect();
  const ratio = pixelRatio(r.width, r.height);
  // Whole, even numbers of pixels, and not smaller than what the desktop needs.
  const even = (cssPixels, least) => Math.max(least, Math.round(cssPixels * ratio) & ~1);
  return { width: even(r.width, 640), height: even(r.height, 480), scale: Math.round(ratio * 100) };
}

function showSession(on) {
  $('login').hidden = on;
  $('session').hidden = !on;
}

function end(message, isError = false) {
  if (decoderFailure || /H\.264/.test(message)) {
    // The video decoder stopped; the session cannot go on without it. The next connection does without H.264 (slower, but it works).
    useH264 = false;
    document.documentElement.dataset.h264 = 'false';
    message = 'The video decoder stopped (' + (decoderFailure || message).replace(/^.*H\.264 decoding failed: ?/, '').slice(0, 120) + '). Connect again: it will use compatibility mode, which is slower.';
    isError = true;
    decoderFailure = '';
  }
  if (current) {
    try { current.ui.shutdown(); } catch { /* already gone */ }
    current.el.remove();
    current = null;
  }
  if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
  showSession(false);
  $('go').disabled = false;
  $('pass').value = '';
  $('code').value = '';
  say(message, isError);
  $('user').focus();
}

async function token(user, code) {
  const r = await fetch('/api/session', {
    method: 'POST',
    cache: 'no-store',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: user, code }),
  });
  if (r.status === 401) {
    let why = 'Sign-in refused. Check the account and the code.';
    try { why = (await r.json()).error || why; } catch { /* the plain text will do */ }
    throw new Error(why);
  }
  if (r.status === 429) throw new Error('Too many attempts from this address. Wait a minute and try again.');
  if (r.status === 503) throw new Error('The server is busy. Try again in a moment.');
  if (!r.ok) throw new Error('The gateway refused the request (' + r.status + ').');
  return (await r.json()).token;
}

// What the client says when the daemon refuses the login ("The server denied the connection"), and when it cannot be reached.
const REFUSED = /denied|credential|logon|authentic|password/i;

function friendly(text) {
  return REFUSED.test(text)
    ? 'Sign-in refused. Check the account and the password.'
    : 'Could not connect. ' + String(text).split('\n')[0].slice(0, 160);
}

function describe(err) {
  const text = (err && (err.message || (typeof err.backtrace === 'function' && err.backtrace()))) || String(err);
  if (/Too many|busy|refused the request|Sign-in refused/.test(text)) return text;
  return friendly(text);
}

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('go').disabled = true;
  say('Connecting…');
  const user = $('user').value.trim();
  const pass = $('pass').value;
  let el;
  try {
    const t = await token(user, $('code').value.replace(/\s+/g, ''));
    showSession(true); // the canvas needs a size before it is created
    el = document.createElement('iron-remote-desktop');
    el.module = Backend; // the component takes it when it is created
    el.setAttribute('scale', 'fit');
    el.setAttribute('flexcenter', 'true');
    $('screen').append(el);
    const ui = await new Promise((resolve) => el.addEventListener('ready', (ev) => resolve(ev.detail.irgUserInteraction), { once: true }));
    ui.setVisibility(true);
    const size = screenSize();
    let builder = new ConfigBuilder()
      .withUsername(user)
      .withPassword(pass)
      .withDestination('127.0.0.1:3389') // the gateway connects to its own daemon and ignores this
      .withProxyAddress((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws')
      .withAuthToken(t)
      .withDesktopSize(new Backend.DesktopSize(size.width, size.height))
      .withExtension(rdp.displayControl(true)) // lets the page resize the desktop when the window changes
      .withExtension(enableCredssp(false)); // the daemon checks the account password itself (plain TLS login, no NLA)
    if (useH264) {
      builder = builder
        .withExtension(rdp.graphicsPipeline(true))
        // A frame that the decoder has not shown after 15 s fails it (3 s is the library's default, too short for a busy small server or a slow link).
        .withExtension(rdp.h264Decoder(new rdp.WebCodecsH264Decoder({
          stallMs: 15000,
          onFailure: (why) => { decoderFailure = String(why); console.warn('H.264 decoder failed: ' + why); },
        })));
    }
    const config = builder.build();
    current = { el, ui };
    $('pass').value = '';
    const info = await ui.connect(config);
    say('');
    const started = Date.now();
    lastSize = '';
    sentSinceConnect = 0;
    for (const ms of [1000, 2500]) setTimeout(sendSize, ms);
    for (const ms of [300, 800]) setTimeout(refit, ms);
    info.run().then((r) => {
      const why = r && typeof r.reason === 'function' ? r.reason() : '';
      // A refused login ends the session within seconds; a session that ran is simply over.
      if (Date.now() - started < 20000 && REFUSED.test(why)) end(friendly(why), true);
      else end('Session ended' + (why ? ': ' + why : '.'));
    }, (err) => end(describe(err), true));
  } catch (err) {
    if (!current && el) el.remove();
    end(describe(err), true);
  }
});

$('end').addEventListener('click', () => end('Disconnected.'));
$('cad').addEventListener('click', () => current && current.ui.ctrlAltDel());
$('fs').addEventListener('click', async () => {
  await $('session').requestFullscreen();
  // In fullscreen the browser lets a page take keys such as Alt+Tab and Ctrl+W (Chromium).
  if (navigator.keyboard && navigator.keyboard.lock) navigator.keyboard.lock().catch(() => {});
});
document.addEventListener('fullscreenchange', () => {
  if (!document.fullscreenElement && navigator.keyboard && navigator.keyboard.unlock) navigator.keyboard.unlock();
});

// The component fits the picture to the page when its canvas changes size, but not always when the size comes back the same, so the page asks
// for the fit itself (1 is ScreenScale.Fit): at once when the window changes, and again after the server has made the new picture.
const FIT = 1;
function refit() {
  try { if (current) current.ui.setScale(FIT); } catch { /* the session is going away */ }
}

// Tells the server the size and scale of the page now, unless it is what the server was told last (each request makes the server set its screen up
// again). The first two requests after connecting are sent whatever was sent before: the server opens the display channel a moment after the session
// starts, and a request sent before that is dropped.
let lastSize = '';
let sentSinceConnect = 0;
function sendSize() {
  if (!current) return;
  const { width, height, scale } = screenSize();
  const now = `${width}x${height}@${scale}`;
  if (now === lastSize && sentSinceConnect >= 2) {
    refit();
    return;
  }
  lastSize = now;
  sentSinceConnect += 1;
  try { current.ui.resize(width, height, scale); } catch { /* the session is going away */ }
  for (const ms of [500, 1500]) setTimeout(refit, ms);
}

let resizeTimer = 0;
function resizeSoon() {
  refit();
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(sendSize, 250);
}
window.addEventListener('resize', resizeSoon);
document.addEventListener('fullscreenchange', resizeSoon);
