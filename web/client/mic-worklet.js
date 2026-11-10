// Microphone capture for the desktop (loaded by desk.js as an AudioWorklet): turns what the browser records, at whatever rate its audio
// context runs, into 16 bit mono PCM at 48000 Hz in chunks of exactly 20 ms (960 samples), and posts each chunk to the page.
const OUT_RATE = 48000;
const CHUNK = 960;

class MicCapture extends AudioWorkletProcessor {
  constructor() {
    super();
    this.step = sampleRate / OUT_RATE; // input samples per output sample
    this.pos = 0; // position in the input, in input samples, of the next output sample
    this.last = 0; // the last sample of the block before, for the interpolation across blocks
    this.out = new Int16Array(CHUNK);
    this.n = 0;
  }

  process(inputs) {
    const ch = inputs[0] && inputs[0][0];
    if (!ch) return true;
    // Linear interpolation; index -1 is the last sample of the previous block.
    while (this.pos < ch.length) {
      const i = Math.floor(this.pos);
      const f = this.pos - i;
      const a = i < 0 ? this.last : ch[i];
      const b = i + 1 < ch.length ? ch[i + 1] : ch[i];
      const v = Math.max(-1, Math.min(1, a + (b - a) * f));
      this.out[this.n++] = v < 0 ? v * 32768 : v * 32767;
      if (this.n === CHUNK) {
        const copy = this.out.slice();
        this.port.postMessage(copy.buffer, [copy.buffer]);
        this.n = 0;
      }
      this.pos += this.step;
    }
    this.pos -= ch.length;
    this.last = ch[ch.length - 1];
    return true;
  }
}

registerProcessor('waydesk-mic', MicCapture);
