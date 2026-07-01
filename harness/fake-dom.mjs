// fake-dom.mjs — minimal headless DOM/localStorage/window for exercising the
// shared runtime WITHOUT a browser. Mirrors the fake DOM both home isolation
// harnesses (Seafarer bundled_plugin_isolation_harness.mjs, On Board
// plugin_isolation_harness.mjs) already use, so the shared contract test runs
// against the same surface the homes assert against.
//
// The iframe shim (SHIM_SRC) does NOT execute here — there is no real frame.
// The frame side is SIMULATED by the test: it reads the per-mount token from the
// iframe srcdoc and posts frame->host messages via emit(). Host->frame messages
// are captured in framePosts. This is exactly how the home harnesses drive it.

export function installFakeDom() {
  const noop = () => {};
  const framePosts = [];
  const msgHandlers = [];
  const store = new Map();

  function makeIframe() {
    return {
      _tag: 'iframe', attrs: {}, style: {}, srcdoc: '', parentNode: null,
      setAttribute(k, v) { this.attrs[k] = v; },
      getAttribute(k) { return this.attrs[k] ?? null; },
      contentWindow: { postMessage: (m) => framePosts.push(m) },
      appendChild: noop, remove: noop,
    };
  }
  const genEl = () => ({
    innerHTML: '', textContent: '', style: {}, attrs: {},
    classList: { add: noop, remove: noop, toggle: noop },
    setAttribute: noop, getAttribute: () => null, appendChild: noop, remove: noop,
  });

  globalThis.localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => store.set(k, String(v)),
    removeItem: (k) => store.delete(k),
  };
  globalThis.document = {
    getElementById: () => genEl(), querySelector: () => null, querySelectorAll: () => [],
    createElement: (t) => (t === 'iframe' ? makeIframe() : genEl()),
    head: genEl(), body: genEl(),
    documentElement: { getAttribute: () => 'dark', setAttribute: noop },
  };
  globalThis.window = globalThis;
  globalThis.addEventListener = (type, fn) => { if (type === 'message') msgHandlers.push(fn); };

  // deliver a frame->host message to every registered handler
  const emit = (data) => msgHandlers.forEach((fn) => { try { fn({ data }); } catch (e) {} });
  const tick = () => new Promise((r) => setTimeout(r, 0));

  // a mount container that records the iframe the runtime appends
  const makeMountEl = () => ({
    innerHTML: '', _child: null,
    appendChild(c) { this._child = c; c.parentNode = this; },
    removeChild(c) { if (this._child === c) this._child = null; },
  });

  return { framePosts, store, emit, tick, makeMountEl };
}
