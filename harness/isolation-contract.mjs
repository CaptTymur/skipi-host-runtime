// isolation-contract.mjs — the shared §1 isolation contract, as executable asserts.
//
// This is the SINGLE place the §1 invariants are encoded. Each home keeps a thin
// *_isolation_harness.mjs that calls runIsolationContract() with its own loader +
// host adapters, so no home can drift below the shared boundary.
//
// It exercises the REAL runtime (dist/plugin-host-bridge.js, falling back to
// src/runtime.js) against a fake loader + fake host, and asserts — WITHOUT
// weakening any Seafarer/On Board invariant:
//   - mount goes through a sandboxed iframe (allow-scripts, NO allow-same-origin → opaque origin);
//   - frame srcdoc carries a strict default-deny CSP (default-src 'none'; connect-src 'none');
//   - a per-mount capability token gates EVERY bridge message (forged token ignored);
//   - the host's secret NEVER appears in the srcdoc or in any frame message;
//   - init carries the verified plugin code + granted permissions, no host secret;
//   - storage round-trips through the bridge, persisted HOST-side + namespaced;
//   - an ungranted capability is denied + audited (default-deny);
//   - integrity failure is fail-closed (stage:integrity, no mount);
//   - the feature flag (enabled:false) is a kill switch (no frame created);
//   - teardown removes the active frame/state.
//
//   node harness/isolation-contract.mjs        # run the self-test (built-in fixtures)
//   import { runIsolationContract } from '.../isolation-contract.mjs'   # reuse per home

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { installFakeDom } from './fake-dom.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

function defaultRuntimeSource() {
  const dist = path.join(ROOT, 'dist', 'plugin-host-bridge.js');
  const src = path.join(ROOT, 'src', 'runtime.js');
  return fs.readFileSync(fs.existsSync(dist) ? dist : src, 'utf8');
}

// inert fixture plugin pack (the SHIM never runs here; js is asserted as text only)
function defaultLoader(slug, permissions) {
  const js = "/* SKIPI_FIXTURE_PLUGIN */ window.SkipiPlugins=window.SkipiPlugins||{};"
    + "window.SkipiPlugins['" + slug + "']={manifest:{id:'" + slug + "'},mount:function(){},unmount:function(){}};";
  return {
    async install(s) {
      return {
        ok: true, source: 'fixture',
        pack: {
          entrypoints: { ui: 'index.js', style: 'index.css' },
          files: { 'index.js': js, 'index.css': '/* fixture */' },
          permissions: permissions.slice(),
        },
      };
    },
  };
}

// fake host bound to the SAME backing store the host secret lives in, so we can
// prove the plugin write namespaces away from (and never reads) the secret key.
function defaultHost(storeMap) {
  const nk = (slug, k) => 'skipi_plugin_' + slug + '_' + k;
  return {
    id: 'testhome',
    storage: {
      get: (slug, k) => (storeMap.has(nk(slug, k)) ? storeMap.get(nk(slug, k)) : null),
      set: (slug, k, v) => storeMap.set(nk(slug, k), String(v)),
      remove: (slug, k) => storeMap.delete(nk(slug, k)),
    },
    theme: { get: () => 'dark', subscribe: () => () => {} },
    navigation: { setTitle: () => {}, closePlugin: () => {} },
  };
}

export async function runIsolationContract(opts = {}) {
  const slug = opts.slug || 'fixture-plugin';
  const secretKey = opts.secretKey || 'skipi_session_token';
  const secretVal = opts.secretVal || 'SECRET-HOST-VAULT-TOKEN-DO-NOT-LEAK';
  const runtimeSource = opts.runtimeSource || defaultRuntimeSource();
  const log = opts.silent ? () => {} : (s) => console.log(s);

  let pass = 0, fail = 0;
  const ok = (c, m) => { if (c) { pass++; log('  ✓ ' + m); } else { fail++; console.error('  ✗ ' + m); } };
  const section = (t) => log('\n# ' + t);

  const ctx = installFakeDom();
  const makeLoader = opts.makeLoader || ((perms) => defaultLoader(slug, perms));
  const makeHost = opts.makeHost || (() => defaultHost(ctx.store));

  // load the runtime into the fake window
  try { new Function(runtimeSource)(); }
  catch (e) { console.error('runtime load failed:', e); return { pass, fail: fail + 1 }; }
  ok(typeof globalThis.SkipiPluginRuntime?.create === 'function', 'runtime exposes window.SkipiPluginRuntime.create');

  // a host secret that must never reach the frame
  ctx.store.set(secretKey, secretVal);

  const host = makeHost();
  const rt = globalThis.SkipiPluginRuntime.create({
    enabled: true, loader: makeLoader(['local_storage']), host, bridgeTimeoutMs: 6000,
  });
  ok(rt.enabled === true, 'runtime constructed enabled');

  section('open() builds an isolated, opaque-origin frame');
  const mountEl = ctx.makeMountEl();
  const opened = rt.open(slug, mountEl);                 // not awaited — frame is created synchronously
  const ifr = mountEl._child;
  ok(ifr && ifr._tag === 'iframe', 'an iframe was mounted into the container');
  ok(ifr.attrs.sandbox === 'allow-scripts', 'sandbox="allow-scripts"');
  ok(!/allow-same-origin/.test(ifr.attrs.sandbox || ''), 'NO allow-same-origin (opaque cross-origin)');
  ok(/default-src 'none'/.test(ifr.srcdoc) && /connect-src 'none'/.test(ifr.srcdoc), "frame srcdoc carries strict default-deny CSP (default-src 'none'; connect-src 'none')");
  ok(/script-src 'nonce-[0-9a-f]+' 'wasm-unsafe-eval';/.test(ifr.srcdoc) && !/'unsafe-eval'/.test(ifr.srcdoc) && !/'unsafe-inline'/.test(ifr.srcdoc),
    "script-src is nonce + 'wasm-unsafe-eval' only (v1.1) — no 'unsafe-eval', no 'unsafe-inline'");
  ok(/__SKIPI_TOKEN__=/.test(ifr.srcdoc), 'frame boots with a per-mount capability token');
  ok(!ifr.srcdoc.includes(secretVal), 'host secret is NOT in the frame srcdoc');
  const tokMatch = ifr.srcdoc.match(/__SKIPI_TOKEN__=("[0-9a-f]+")/);
  const token = tokMatch ? JSON.parse(tokMatch[1]) : null;
  ok(!!token && token.length >= 16, 'capability token is random + non-trivial');

  section('init handshake — verified code to frame, no secret');
  await ctx.tick(); await ctx.tick();                    // let loader.install() resolve
  ctx.framePosts.length = 0;
  ctx.emit({ ch: 'skipi-plugin', v: 1, token, type: 'ready' });
  await ctx.tick();
  const init = ctx.framePosts.find((m) => m.type === 'init');
  ok(!!init, 'host sends init after frame ready + install ok');
  ok(init && typeof init.js === 'string' && init.js.indexOf('SKIPI_FIXTURE_PLUGIN') >= 0, 'init carries the verified plugin js (runs in frame, not host)');
  ok(init && Array.isArray(init.permissions) && init.permissions.indexOf('local_storage') >= 0, 'init grants the manifest permissions');
  ok(init && JSON.stringify(init).indexOf(secretVal) < 0, 'init message contains NO host secret');

  section('token gating — forged token is ignored');
  ctx.framePosts.length = 0;
  ctx.emit({ ch: 'skipi-plugin', v: 1, token: 'WRONG', type: 'storage.get', id: 91, key: 'x' });
  await ctx.tick();
  ok(ctx.framePosts.length === 0, 'message with wrong token is dropped (no response)');

  section('host API via bridge — storage round-trip, host-side namespaced');
  ctx.framePosts.length = 0;
  ctx.emit({ ch: 'skipi-plugin', v: 1, token, type: 'storage.set', key: 'k1', value: '42' });
  ctx.emit({ ch: 'skipi-plugin', v: 1, token, type: 'storage.get', id: 5, key: 'k1' });
  await ctx.tick();
  const got = ctx.framePosts.find((m) => m.type === 'storage.result' && m.id === 5);
  ok(got && got.value === '42', 'storage.set then storage.get returns 42 via the bridge');
  ok(ctx.store.get('skipi_plugin_' + slug + '_k1') === '42', 'value persisted in HOST-side namespaced storage (frame has none)');
  ok(ctx.store.get(secretKey) === secretVal, 'plugin write did NOT touch the host secret key');

  section('mount self-check recorded, then no-secret-leak across session');
  ctx.emit({ ch: 'skipi-plugin', v: 1, token, type: 'mounted', height: 240, selfcheck: { parentDomAccess: false, storageBlocked: true, fetchBlocked: true } });
  const res = await opened;
  ok(res && res.ok, 'open() resolves ok after frame reports mounted');
  const act = rt._active();
  ok(act && act.selfcheck && act.selfcheck.parentDomAccess === false && act.selfcheck.storageBlocked === true, 'host records frame self-check (no parent DOM, storage blocked)');
  ok(!ctx.framePosts.some((m) => JSON.stringify(m).indexOf(secretVal) >= 0), 'no frame message ever contained the host secret');

  section('teardown');
  rt.close();
  ok(rt._active() === null, 'close() tears down the active frame');

  section('default-deny — ungranted capability is denied + audited');
  const rtNoPerm = globalThis.SkipiPluginRuntime.create({ enabled: true, loader: makeLoader([]), host });
  const me3 = ctx.makeMountEl();
  const op3 = rtNoPerm.open(slug, me3);
  const tok3 = JSON.parse(me3._child.srcdoc.match(/__SKIPI_TOKEN__=("[0-9a-f]+")/)[1]);
  await ctx.tick(); await ctx.tick();
  ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok3, type: 'ready' });
  await ctx.tick();
  ctx.framePosts.length = 0;
  ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok3, type: 'storage.set', key: 'kx', value: 'zzz' });
  ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok3, type: 'storage.get', id: 7, key: 'kx' });
  await ctx.tick();
  const got3 = ctx.framePosts.find((m) => m.type === 'storage.result' && m.id === 7);
  ok(got3 && got3.value === null, 'ungranted storage.get returns null (denied)');
  ok(ctx.store.get('skipi_plugin_' + slug + '_kx') === undefined, 'ungranted storage.set did NOT write to host storage');
  ok(rtNoPerm._audit().some((a) => /DENY storage/.test(a)), 'denied capability is logged to audit (default-deny)');
  ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok3, type: 'mounted', height: 120, selfcheck: {} });
  await op3; rtNoPerm.close();

  section('integrity is fail-closed');
  const rtBad = globalThis.SkipiPluginRuntime.create({
    enabled: true, host,
    loader: { async install() { return { ok: false, stage: 'integrity', reason: 'sha256 mismatch' }; } },
  });
  const rBad = await rtBad.open(slug, ctx.makeMountEl());
  ok(rBad && rBad.ok === false && rBad.stage === 'integrity', 'integrity failure is fail-closed (stage:integrity, no mount)');

  section('feature flag is a kill switch');
  const rtOff = globalThis.SkipiPluginRuntime.create({ enabled: false, loader: makeLoader(['local_storage']), host });
  const meOff = ctx.makeMountEl();
  const rOff = await rtOff.open(slug, meOff);
  ok(rOff && rOff.ok === false && rOff.stage === 'flag', 'disabled runtime returns stage:flag');
  ok(meOff._child === null, 'disabled runtime created NO frame (boot untouched)');

  // ---------------------------------------------------------------- v1.1 --
  // Host-mediated network + files. The frame CSP is unchanged (asserted above);
  // what is asserted here is the HOST side of the bridge: grant, signed allowlist,
  // safe request shape, and that an answer only goes back to the mount that asked.
  const netPack = (perms, allow) => ({
    async install() {
      return { ok: true, source: 'fixture', pack: {
        entrypoints: { ui: 'index.js', style: 'index.css' }, files: { 'index.js': '/* net fixture */', 'index.css': '' },
        permissions: perms.slice(), network: allow ? { allow } : undefined,
      } };
    },
  });
  async function bootNet(perms, allow, hostExtra) {
    const calls = [];
    const h = Object.assign({}, host, hostExtra ? hostExtra(calls) : {});
    const rtN = globalThis.SkipiPluginRuntime.create({ enabled: true, loader: netPack(perms, allow), host: h });
    const me = ctx.makeMountEl();
    const op = rtN.open(slug, me);
    const tok = JSON.parse(me._child.srcdoc.match(/__SKIPI_TOKEN__=("[0-9a-f]+")/)[1]);
    await ctx.tick(); await ctx.tick();
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok, type: 'ready' });
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok, type: 'mounted', height: 100, selfcheck: {} });
    await op;
    const ask = async (msg) => {
      ctx.framePosts.length = 0;
      ctx.emit(Object.assign({ ch: 'skipi-plugin', v: 1, token: tok }, msg));
      await ctx.tick(); await ctx.tick();
      return ctx.framePosts.find((m) => m.type === 'rpc.result' && m.id === msg.id);
    };
    return { rt: rtN, calls, ask, tok };
  }
  const API = 'https://api.example.test/draft-survey/v1';
  const fakeNet = (calls) => ({ net: { fetch: async (s, req) => { calls.push({ slug: s, req }); return { ok: true, status: 200, headers: { 'content-type': 'application/json' }, text: '{"pong":1}' }; } } });

  section('v1.1 net.fetch — refused without the grant, without the host, outside the allowlist');
  {
    const a = await bootNet([], [API], fakeNet);
    const r = await a.ask({ type: 'net.fetch', id: 1, url: API + '/ships/1' });
    ok(r && r.ok === false && a.calls.length === 0, 'no `network` permission → refused, the host transport is never called');
    ok(a.rt._audit().some((x) => /DENY net\.fetch/.test(x)), 'and the refusal is audited');
    a.rt.close();
    const b = await bootNet(['network'], [API], null);
    const r2 = await b.ask({ type: 'net.fetch', id: 2, url: API + '/ships/1' });
    ok(r2 && r2.ok === false && /not available/.test(r2.error), 'granted, but the home did not opt in (no host.net) → refused');
    b.rt.close();
    const c = await bootNet(['network'], undefined, fakeNet);
    const r3 = await c.ask({ type: 'net.fetch', id: 3, url: API + '/ships/1' });
    ok(r3 && r3.ok === false && c.calls.length === 0, 'granted, but the pack declares no allowlist → refused');
    c.rt.close();
  }
  {
    const a = await bootNet(['network'], [API], fakeNet);
    const bad = [
      'http://api.example.test/draft-survey/v1/ships/1',            // not https
      'https://evil.example.test/draft-survey/v1/ships/1',          // other origin
      'https://api.example.test.evil.test/draft-survey/v1/x',       // suffix trick
      'https://api.example.test/draft-survey/v1x/ships',            // prefix trick
      'https://api.example.test/draft-survey/v1/../../api/app/login', // traversal out of the prefix
      'https://api.example.test/other',                             // other path
      'https://user:pw@api.example.test/draft-survey/v1/ships/1',   // userinfo
      'https://api.example.test:8443/draft-survey/v1/ships/1',      // other port
      'file:///etc/passwd', 'javascript:alert(1)', 'not a url',
    ];
    let id = 10, allRefused = true;
    for (const u of bad) { const r = await a.ask({ type: 'net.fetch', id: ++id, url: u }); if (!(r && r.ok === false)) { allRefused = false; console.error('    not refused: ' + u); } }
    ok(allRefused && a.calls.length === 0, 'every URL outside the signed allowlist is refused (scheme, origin, port, path prefix, traversal, userinfo)');
    const rm = await a.ask({ type: 'net.fetch', id: 40, url: API + '/ships/1', method: 'TRACE' });
    ok(rm && rm.ok === false && a.calls.length === 0, 'a method outside GET/POST/PUT/PATCH/DELETE is refused');

    section('v1.1 net.fetch — an allowed request reaches the host transport cleaned, and the answer returns');
    const r = await a.ask({ type: 'net.fetch', id: 41, url: API + '/ships/9074729?x=1', method: 'post', body: '{"a":1}',
      headers: { 'Content-Type': 'application/json', 'X-App-Key': 'k', Cookie: 'sid=1', Host: 'evil', 'Sec-Fetch-Site': 'x', 'Bad\nName': 'v', 'X-Inject': 'a\r\nb' } });
    ok(r && r.ok === true && r.value && r.value.status === 200 && r.value.text === '{"pong":1}', 'allowed URL → the plugin gets {ok,status,headers,text}');
    const call = a.calls[0] || { req: {} };
    ok(a.calls.length === 1 && call.slug === slug && call.req.url === API + '/ships/9074729?x=1' && call.req.method === 'POST' && call.req.body === '{"a":1}', 'the transport receives the validated url, an upper-cased method and the body');
    const hk = Object.keys(call.req.headers || {});
    ok(hk.includes('Content-Type') && hk.includes('X-App-Key') && !hk.some((k) => /cookie|host|sec-|bad|inject/i.test(k)), 'cookie / host / sec-* and malformed headers are dropped; the plugin\'s own headers pass');
    ok(JSON.stringify(call.req).indexOf(secretVal) < 0 && JSON.stringify(r).indexOf(secretVal) < 0, 'no host secret in the outgoing request or in the answer');
    a.rt.close();
  }

  section('v1.1 default transport — the host fetch is called with credentials omitted and redirects refused');
  {
    const seen = [];
    const prevFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => { seen.push({ url, init }); return { ok: true, status: 201, headers: { get: () => 'application/json; charset=utf-8' }, arrayBuffer: async () => new TextEncoder().encode('{"id":7}').buffer }; };
    try {
      const a = await bootNet(['network'], [API + '/'], () => ({ net: {} }));
      const r = await a.ask({ type: 'net.fetch', id: 50, url: API + '/ships', method: 'POST', bodyBase64: Buffer.from('hello').toString('base64') });
      const i0 = (seen[0] || {}).init || {};
      ok(r && r.ok === true && r.value.status === 201 && r.value.text === '{"id":7}', 'default transport returns the response to the plugin');
      ok(seen.length === 1 && i0.credentials === 'omit' && i0.redirect === 'error' && i0.referrerPolicy === 'no-referrer', "fetch options are fixed by the runtime: credentials 'omit', redirect 'error', no referrer");
      ok(i0.body instanceof Uint8Array && Buffer.from(i0.body).toString() === 'hello', 'a base64 body is sent as bytes');
      a.rt.close();
    } finally { globalThis.fetch = prevFetch; }
  }

  section('v1.1 an answer never crosses mounts');
  {
    let release;
    const slow = () => ({ net: { fetch: () => new Promise((r) => { release = () => r({ ok: true, status: 200, headers: {}, text: 'late' }); }) } });
    const a = await bootNet(['network'], [API], slow);
    ctx.framePosts.length = 0;
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: a.tok, type: 'net.fetch', id: 60, url: API + '/ships/1' });
    await ctx.tick();
    a.rt.close();
    // the SAME runtime instance now hosts another mount (new token)
    const me2 = ctx.makeMountEl();
    const op2 = a.rt.open(slug, me2);
    const tok2 = JSON.parse(me2._child.srcdoc.match(/__SKIPI_TOKEN__=("[0-9a-f]+")/)[1]);
    await ctx.tick(); await ctx.tick();
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok2, type: 'ready' });
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok2, type: 'mounted', height: 100, selfcheck: {} });
    await op2;
    ok(tok2 !== a.tok && a.rt._active() !== null, 'a second mount is active on the same runtime, with a new token');
    ctx.framePosts.length = 0;
    release(); await ctx.tick(); await ctx.tick();
    ok(!ctx.framePosts.some((m) => m.type === 'rpc.result'), 'a response that arrives after the plugin was closed is NOT delivered to the next mount');
    a.rt.close();
  }

  section('v1.1 files.save / files.pick — by grant, through the home, with a safe file name');
  {
    const withFiles = (calls) => ({ files: {
      save: async (s, f) => { calls.push({ op: 'save', slug: s, f }); return { saved: true }; },
      pick: async (s, o) => { calls.push({ op: 'pick', slug: s, o }); return [{ name: 'a.json', mime: 'application/json', base64: 'e30=' }]; },
    } });
    const a = await bootNet(['file_save'], null, withFiles);
    const r1 = await a.ask({ type: 'files.save', id: 70, name: '../../etc/passwd', mime: 'application/pdf', base64: 'JVBERg==' });
    ok(r1 && r1.ok === true && r1.value.saved === true, 'files.save with the grant reaches the home');
    ok(a.calls.length === 1 && a.calls[0].slug === slug && !/[\\/]/.test(a.calls[0].f.name) && !/^\./.test(a.calls[0].f.name), 'the file name is reduced to a plain name (no path, no leading dots)');
    const r2 = await a.ask({ type: 'files.pick', id: 71, accept: 'image/*' });
    ok(r2 && r2.ok === false && a.calls.length === 1, 'files.pick without ITS grant is refused (file_save does not imply file_pick)');
    a.rt.close();
    const b = await bootNet(['file_pick'], null, withFiles);
    const r3 = await b.ask({ type: 'files.pick', id: 72, accept: 'image/*', multiple: true });
    ok(r3 && r3.ok === true && Array.isArray(r3.value) && r3.value[0].name === 'a.json' && b.calls[0].o.multiple === true, 'files.pick with the grant returns what the user chose');
    b.rt.close();
    const c = await bootNet(['file_save', 'file_pick'], null, null);
    const r4 = await c.ask({ type: 'files.save', id: 73, name: 'x.txt', text: 'x' });
    ok(r4 && r4.ok === false, 'granted, but the home has no files adapter → refused');
    c.rt.close();
  }

  section('v1.1 the frame side — hostApi.net / hostApi.files exist and stay shut without the grant');
  {
    const shim = (runtimeSource.match(/var SHIM_SRC = `([\s\S]*?)`;/) || [])[1] || '';
    ok(shim.length > 0, 'the frame shim source was found');
    const posts = []; let onMsg = null; let hostApi = null;
    const frameWin = {
      __SKIPI_TOKEN__: 'T', SkipiPlugins: {}, parent: { postMessage: (m) => posts.push(m) },
      addEventListener: (t, fn) => { if (t === 'message') onMsg = fn; },
      localStorage: { getItem() { throw new Error('blocked'); } },
    };
    const frameDoc = { head: { appendChild() {} }, body: { scrollHeight: 10 }, createElement: () => ({}) };
    new Function('window', 'document', 'parent', 'fetch', 'setTimeout', 'ResizeObserver', shim)(
      frameWin, frameDoc, frameWin.parent, () => Promise.reject(new Error('csp')), setTimeout, undefined);
    const mountWith = async (perms) => {
      frameWin.SkipiPlugins[slug] = { mount: (el, api) => { hostApi = api; } };
      onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'init', slug, css: '', js: '', permissions: perms, nonce: 'n', hostId: 'h' } });
      await ctx.tick(); await ctx.tick();
    };
    await mountWith([]);
    ok(hostApi && typeof hostApi.net.fetch === 'function' && typeof hostApi.files.save === 'function' && typeof hostApi.files.pick === 'function', 'hostApi carries net.fetch, files.save and files.pick');
    posts.length = 0;
    let rejected = 0;
    await hostApi.net.fetch(API + '/x').catch(() => rejected++);
    await hostApi.files.save({ name: 'a', text: 'b' }).catch(() => rejected++);
    await hostApi.files.pick({}).catch(() => rejected++);
    ok(rejected === 3 && posts.length === 0, 'without grants all three reject in the frame and post nothing to the host');
    await mountWith(['network']);
    posts.length = 0;
    const pr = hostApi.net.fetch(API + '/x', { method: 'POST', body: '{}' });
    const sent = posts.find((m) => m.type === 'net.fetch');
    ok(sent && sent.token === 'T' && sent.url === API + '/x' && sent.method === 'POST', 'with the grant net.fetch posts a token-stamped net.fetch message');
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'rpc.result', id: sent.id, ok: true, value: { ok: true, status: 200, text: 'hi' } } });
    ok((await pr).text === 'hi', 'and the promise resolves with the host answer');
    const pr2 = hostApi.net.fetch(API + '/y');
    const sent2 = posts.filter((m) => m.type === 'net.fetch')[1];
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'rpc.result', id: sent2.id, ok: false, error: 'url is not in the plugin allowlist' } });
    ok(await pr2.then(() => false, (e) => /allowlist/.test(e.message)), 'a host refusal rejects the promise with the reason');
  }

  // ---------------------------------------------------------------- v1.2 --
  // Host-mediated motion sensors + keep-awake. The frame gets no sensor access of its own
  // (sandbox / CSP asserted above are unchanged); the HOST reads the sensors and pushes rows.
  const fakeMotion = (calls) => ({
    motion: {
      start: async (s, o, push) => { calls.push({ op: 'start', slug: s, o, push }); return { ok: true, rateHz: o.rateHz, source: 'fake', platform: 'test' }; },
      stop: (s) => { calls.push({ op: 'stop', slug: s }); },
    },
    screen: { keepAwake: async (s, on) => { calls.push({ op: 'awake', slug: s, on }); return { ok: true }; } },
  });

  section('v1.2 motion / keep-awake — refused without the grant or without the home');
  {
    const a = await bootNet([], null, fakeMotion);
    const r = await a.ask({ type: 'motion.start', id: 80, rateHz: 50 });
    const r2 = await a.ask({ type: 'screen.keepAwake', id: 81, on: true });
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: a.tok, type: 'motion.stop' });
    ok(r && r.ok === false && r2 && r2.ok === false && a.calls.length === 0, 'no `motion` / `keep_awake` grant → refused, the home sensors are never started');
    ok(a.rt._audit().some((x) => /DENY motion\.start/.test(x)) && a.rt._audit().some((x) => /DENY screen\.keepAwake/.test(x)) && a.rt._audit().some((x) => /DENY motion\.stop/.test(x)), 'and the refusals are audited');
    a.rt.close();
    ok(a.calls.length === 0, 'closing a plugin that never started sensors does not call the home');
    const b = await bootNet(['motion', 'keep_awake'], null, null);
    const r3 = await b.ask({ type: 'motion.start', id: 82 });
    const r4 = await b.ask({ type: 'screen.keepAwake', id: 83, on: true });
    ok(r3 && r3.ok === false && /not available/.test(r3.error) && r4 && r4.ok === false && /not available/.test(r4.error), 'granted, but the home did not opt in (no host.motion / host.screen) → refused');
    b.rt.close();
    const c = await bootNet(['motion'], null, fakeMotion);
    const r5 = await c.ask({ type: 'screen.keepAwake', id: 84, on: true });
    ok(r5 && r5.ok === false && c.calls.length === 0, '`motion` does not imply `keep_awake`');
    c.rt.close();
  }

  section('v1.2 motion — rows reach only the mount that started the sensors, cleaned; close() stops everything');
  {
    const a = await bootNet(['motion', 'keep_awake'], null, fakeMotion);
    const r = await a.ask({ type: 'motion.start', id: 90, rateHz: 5000 });
    const st = a.calls.find((c) => c.op === 'start') || { o: {} };
    ok(r && r.ok === true && r.value.ok === true && st.slug === slug && st.o.rateHz === 100, 'motion.start reaches the home with the rate clamped to 1–100 Hz, and the answer returns');
    ctx.framePosts.length = 0;
    const good7 = [1000, 0.1, 0.2, 9.81, 0.01, 0.02, 0.03], good4 = [1010, 0.1, 0.2, 9.81], noGyro = [1020, 0, 0, 9.81, null, null, null];
    const delivered = st.push([good7, good4, noGyro, [1, 2, 3], 'x', [1, NaN, 0, 0], [1, null, 0, 0], [1, 0, 0, 9.8, 'a', 0, 0], { t: 1 }]);
    const batch = ctx.framePosts.find((m) => m.type === 'motion.batch');
    ok(delivered === true && batch && batch.seq === 1 && JSON.stringify(batch.samples) === JSON.stringify([good7, good4, noGyro]), 'only well-formed rows (4 or 7 finite numbers; null allowed for the gyro only) are forwarded, seq starts at 1');
    ctx.framePosts.length = 0;
    st.push(Array.from({ length: 800 }, (_, i) => [i, 0, 0, 9.81]));
    const big = ctx.framePosts.find((m) => m.type === 'motion.batch');
    ok(big && big.samples.length === 500 && big.seq === 2, 'a batch is capped at 500 rows; seq grows by 1');
    ctx.framePosts.length = 0;
    st.push([]); st.push('junk');
    ok(!ctx.framePosts.some((m) => m.type === 'motion.batch'), 'an empty or malformed push sends nothing');
    const r2 = await a.ask({ type: 'screen.keepAwake', id: 91, on: 1 });
    ok(r2 && r2.ok === true && a.calls.some((c) => c.op === 'awake' && c.on === true && c.slug === slug), 'screen.keepAwake with the grant reaches the home as a boolean');
    a.rt.close();
    ok(a.calls.some((c) => c.op === 'stop' && c.slug === slug) && a.calls.some((c) => c.op === 'awake' && c.on === false), 'close() itself stops the sensors and releases keep-awake, whatever the plugin did');
    // the same runtime now hosts another mount: the old push must be inert
    const me2 = ctx.makeMountEl();
    const op2 = a.rt.open(slug, me2);
    const tok2 = JSON.parse(me2._child.srcdoc.match(/__SKIPI_TOKEN__=("[0-9a-f]+")/)[1]);
    await ctx.tick(); await ctx.tick();
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok2, type: 'ready' });
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok2, type: 'mounted', height: 100, selfcheck: {} });
    await op2;
    ctx.framePosts.length = 0;
    const late = st.push([good7]);
    ok(late === false && !ctx.framePosts.some((m) => m.type === 'motion.batch'), 'after close the old push is inert: nothing reaches the next mount');
    a.rt.close();
  }
  {
    const a = await bootNet(['motion'], null, fakeMotion);
    await a.ask({ type: 'motion.start', id: 95 });
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: a.tok, type: 'motion.stop' });
    ok(a.calls.filter((c) => c.op === 'stop').length === 1, 'motion.stop from the plugin stops the home sensors');
    a.rt.close();
    ok(a.calls.filter((c) => c.op === 'stop').length === 1 && !a.calls.some((c) => c.op === 'awake'), 'and close() does not stop them a second time nor touch keep-awake that was never taken');
  }

  section('v1.2 the frame side — hostApi.motion / hostApi.screen stay shut without the grant; batches reach subscribers');
  {
    const shim = (runtimeSource.match(/var SHIM_SRC = `([\s\S]*?)`;/) || [])[1] || '';
    const posts = []; let onMsg = null; let hostApi = null;
    const frameWin = {
      __SKIPI_TOKEN__: 'T', SkipiPlugins: {}, parent: { postMessage: (m) => posts.push(m) },
      addEventListener: (t, fn) => { if (t === 'message') onMsg = fn; },
      localStorage: { getItem() { throw new Error('blocked'); } },
    };
    const frameDoc = { head: { appendChild() {} }, body: { scrollHeight: 10 }, createElement: () => ({}) };
    new Function('window', 'document', 'parent', 'fetch', 'setTimeout', 'ResizeObserver', shim)(
      frameWin, frameDoc, frameWin.parent, () => Promise.reject(new Error('csp')), setTimeout, undefined);
    const mountWith = async (perms) => {
      frameWin.SkipiPlugins[slug] = { mount: (el, api) => { hostApi = api; } };
      onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'init', slug, css: '', js: '', permissions: perms, nonce: 'n', hostId: 'h' } });
      await ctx.tick(); await ctx.tick();
    };
    await mountWith([]);
    posts.length = 0;
    let rejected = 0;
    await hostApi.motion.start({ rateHz: 50 }).catch(() => rejected++);
    await hostApi.screen.keepAwake(true).catch(() => rejected++);
    hostApi.motion.stop();
    ok(rejected === 2 && posts.length === 0, 'without grants motion.start / screen.keepAwake reject in the frame and nothing is posted to the host');
    await mountWith(['motion', 'keep_awake']);
    posts.length = 0;
    const got = [];
    const off = hostApi.motion.onSamples((b) => got.push(b));
    const pr = hostApi.motion.start({ rateHz: 50 });
    const sent = posts.find((m) => m.type === 'motion.start');
    ok(sent && sent.token === 'T' && sent.rateHz === 50, 'with the grant motion.start posts a token-stamped message');
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'rpc.result', id: sent.id, ok: true, value: { ok: true, rateHz: 50 } } });
    ok((await pr).rateHz === 50, 'and resolves with the host answer');
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'motion.batch', seq: 1, samples: [[1, 0, 0, 9.81]] } });
    onMsg({ data: { ch: 'skipi-plugin', token: 'BAD', type: 'motion.batch', seq: 2, samples: [[2, 0, 0, 9.81]] } });
    ok(got.length === 1 && got[0].seq === 1 && got[0].samples[0][3] === 9.81, 'a motion.batch reaches onSamples subscribers; a batch with a wrong token is ignored');
    off();
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'motion.batch', seq: 3, samples: [[3, 0, 0, 9.81]] } });
    ok(got.length === 1, 'unsubscribe stops delivery');
    hostApi.motion.stop();
    ok(posts.some((m) => m.type === 'motion.stop'), 'motion.stop posts to the host');
  }

  // ---------------------------------------------------------------- v1.3 --
  // Host-mediated device capabilities: camera, microphone, location (pushed streams), speech and
  // vibration (calls). Each behind its own grant; the home opts in per capability.
  const fakeDevice = (calls) => {
    const stream = (name) => ({
      start: async (s, o, push) => { calls.push({ op: name + '.start', slug: s, o, push }); return { ok: true }; },
      stop: (s) => { calls.push({ op: name + '.stop', slug: s }); },
    });
    return {
      camera: stream('camera'), microphone: stream('microphone'), location: stream('location'),
      speech: { speak: async (s, r) => { calls.push({ op: 'speak', slug: s, r }); return { ok: true }; }, stop: (s) => { calls.push({ op: 'speech.stop', slug: s }); } },
      haptics: { vibrate: async (s, p) => { calls.push({ op: 'vibrate', slug: s, p }); return { ok: true }; } },
    };
  };
  const JPEG = Buffer.from([0xff, 0xd8, 0xff, 0xd9]).toString('base64');

  section('v1.3 device capabilities — each one is refused without ITS grant, and without the home');
  {
    const a = await bootNet(['motion', 'keep_awake', 'local_storage', 'network'], null, fakeDevice);
    const asks = [
      { type: 'camera.start', id: 100, opts: {} }, { type: 'microphone.start', id: 101, opts: {} }, { type: 'location.start', id: 102, opts: {} },
      { type: 'speech.speak', id: 103, text: 'hello' }, { type: 'haptics.vibrate', id: 104, pattern: [100] },
    ];
    let refused = 0;
    for (const m of asks) { const r = await a.ask(m); if (r && r.ok === false && /permission not granted/.test(r.error)) refused++; }
    for (const t of ['camera.stop', 'microphone.stop', 'location.stop', 'speech.stop']) ctx.emit({ ch: 'skipi-plugin', v: 1, token: a.tok, type: t });
    ok(refused === 5 && a.calls.length === 0, 'camera / microphone / location / speech / vibrate are refused without their own grant (other grants do not imply them)');
    ok(['camera.start', 'microphone.start', 'location.start', 'speech.speak', 'haptics.vibrate', 'camera.stop', 'speech.stop'].every((t) => a.rt._audit().some((x) => x.indexOf('DENY ' + t) === 0)), 'and every refusal is audited');
    a.rt.close();
    ok(a.calls.length === 0, 'closing a plugin that used no device capability does not call the home');
    const b = await bootNet(['camera', 'microphone', 'location', 'speech', 'vibrate'], null, null);
    let unavailable = 0;
    for (const m of asks) { const r = await b.ask(Object.assign({}, m, { id: m.id + 100 })); if (r && r.ok === false && /not available/.test(r.error)) unavailable++; }
    ok(unavailable === 5, 'granted, but the home did not opt in (no host.camera / microphone / location / speech / haptics) → refused');
    b.rt.close();
    const c = await bootNet(['camera'], null, fakeDevice);
    const r1 = await c.ask({ type: 'microphone.start', id: 300, opts: {} });
    const r2 = await c.ask({ type: 'location.start', id: 301, opts: {} });
    ok(r1 && r1.ok === false && r2 && r2.ok === false && c.calls.length === 0, '`camera` implies neither `microphone` nor `location`');
    c.rt.close();
  }

  section('v1.3 streams — options are clamped, items are cleaned and reach only the mount that started them');
  {
    const a = await bootNet(['camera', 'microphone', 'location'], null, fakeDevice);
    const r = await a.ask({ type: 'camera.start', id: 310, opts: { facing: 'sideways', width: 99999, fps: 500, quality: 7, deviceId: 'x' } });
    const cam = a.calls.find((c) => c.op === 'camera.start') || { o: {} };
    ok(r && r.ok === true && JSON.stringify(cam.o) === JSON.stringify({ facing: 'environment', width: 1280, fps: 15, quality: 0.95 }), 'camera.start reaches the home with facing / width / fps / quality clamped and nothing else');
    await a.ask({ type: 'camera.start', id: 311, opts: 'junk' });
    ok(JSON.stringify(a.calls.filter((c) => c.op === 'camera.start')[1].o) === JSON.stringify({ facing: 'environment', width: 320, fps: 2, quality: 0.6 }), 'malformed options fall back to the defaults (320 px, 2 fps)');
    ctx.framePosts.length = 0;
    cam.push({ t: 1000, width: 320, height: 240, base64: JPEG, extra: 'dropped', mime: 'text/html' });
    cam.push({ t: 1001, width: 320, height: 240, base64: 'not base64 <script>' });
    cam.push({ t: 1002, base64: '' }); cam.push(null); cam.push('junk');
    const frames = ctx.framePosts.filter((m) => m.type === 'stream.data');
    ok(frames.length === 1 && frames[0].stream === 'camera' && frames[0].seq === 1 && JSON.stringify(frames[0].data) === JSON.stringify({ t: 1000, width: 320, height: 240, mime: 'image/jpeg', base64: JPEG }),
      'a camera frame is forwarded as {t, width, height, mime:image/jpeg, base64}; malformed frames and foreign fields are dropped');
    ctx.framePosts.length = 0;
    cam.push({ t: 1, width: 1, height: 1, base64: 'A'.repeat(2800004) });
    ok(!ctx.framePosts.some((m) => m.type === 'stream.data'), 'an oversized frame is dropped');

    await a.ask({ type: 'microphone.start', id: 312, opts: { chunkMs: 5 } });
    const mic = a.calls.find((c) => c.op === 'microphone.start');
    ctx.framePosts.length = 0;
    mic.push({ t: 5, sampleRate: 48000, level: 3, pcm: 'AAAA' }); mic.push({ pcm: {} });
    const chunks = ctx.framePosts.filter((m) => m.type === 'stream.data');
    ok(mic.o.chunkMs === 50 && chunks.length === 1 && chunks[0].stream === 'microphone' && JSON.stringify(chunks[0].data) === JSON.stringify({ t: 5, sampleRate: 48000, level: 1, pcm: 'AAAA' }), 'a microphone chunk is forwarded as {t, sampleRate, level 0..1, pcm}; chunkMs is clamped');

    await a.ask({ type: 'location.start', id: 313, opts: { highAccuracy: 1 } });
    const loc = a.calls.find((c) => c.op === 'location.start');
    ctx.framePosts.length = 0;
    loc.push({ t: 7, lat: 59.93, lon: 30.31, accuracy: 12, speed: NaN, heading: 'north', altitude: null, address: 'dropped' });
    loc.push({ lat: 123, lon: 0 }); loc.push({ lat: '59', lon: 30 });
    const fixes = ctx.framePosts.filter((m) => m.type === 'stream.data');
    ok(loc.o.highAccuracy === true && fixes.length === 1 && JSON.stringify(fixes[0].data) === JSON.stringify({ t: 7, lat: 59.93, lon: 30.31, accuracy: 12, altitude: null, speed: null, heading: null }), 'a position is forwarded as numbers or null; impossible coordinates are dropped');

    ctx.emit({ ch: 'skipi-plugin', v: 1, token: a.tok, type: 'camera.stop' });
    ok(a.calls.filter((c) => c.op === 'camera.stop').length === 1, 'camera.stop from the plugin stops the home camera');
    a.rt.close();
    ok(a.calls.filter((c) => c.op === 'camera.stop').length === 1 && a.calls.some((c) => c.op === 'microphone.stop') && a.calls.some((c) => c.op === 'location.stop'), 'close() itself stops the streams the plugin left on, and does not stop the camera twice');
    const me2 = ctx.makeMountEl();
    const op2 = a.rt.open(slug, me2);
    const tok2 = JSON.parse(me2._child.srcdoc.match(/__SKIPI_TOKEN__=("[0-9a-f]+")/)[1]);
    await ctx.tick(); await ctx.tick();
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok2, type: 'ready' });
    ctx.emit({ ch: 'skipi-plugin', v: 1, token: tok2, type: 'mounted', height: 100, selfcheck: {} });
    await op2;
    ctx.framePosts.length = 0;
    const late = [mic.push({ t: 9, sampleRate: 48000, level: 0.1, pcm: 'AAAA' }), loc.push({ lat: 1, lon: 1 })];
    ok(late[0] === false && late[1] === false && !ctx.framePosts.some((m) => m.type === 'stream.data'), 'after close the old pushes are inert: no audio or position reaches the next plugin');
    a.rt.close();
  }

  section('v1.3 speech and vibration — cleaned requests, released on close');
  {
    const a = await bootNet(['speech', 'vibrate'], null, fakeDevice);
    const r = await a.ask({ type: 'speech.speak', id: 320, text: 'x'.repeat(900), lang: 'ru-RU"; rm -rf', rate: 99, pitch: 'high' });
    const sp = a.calls.find((c) => c.op === 'speak') || { r: {} };
    ok(r && r.ok === true && sp.slug === slug && sp.r.text.length === 500 && sp.r.lang === '' && sp.r.rate === 2 && sp.r.pitch === 1, 'speech.speak: text capped at 500 chars, a malformed language dropped, rate / pitch clamped');
    await a.ask({ type: 'speech.speak', id: 321, text: 'Левый борт, двенадцать', lang: 'ru-RU' });
    ok(a.calls.filter((c) => c.op === 'speak')[1].r.lang === 'ru-RU', 'a well-formed language tag passes');
    const r2 = await a.ask({ type: 'speech.speak', id: 322, text: '   ' });
    ok(r2 && r2.ok === false && a.calls.filter((c) => c.op === 'speak').length === 2, 'an empty phrase is refused');
    const r3 = await a.ask({ type: 'haptics.vibrate', id: 323, pattern: [100, 50, 99999, -5, 'x'].concat(new Array(40).fill(10)) });
    const vb = a.calls.find((c) => c.op === 'vibrate') || { p: [] };
    ok(r3 && r3.ok === true && vb.p.length === 16 && vb.p[2] === 2000 && vb.p[3] === 0 && vb.p[4] === 0, 'haptics.vibrate: at most 16 steps, each 0–2000 ms');
    await a.ask({ type: 'haptics.vibrate', id: 324, pattern: 300 });
    ok(JSON.stringify(a.calls.filter((c) => c.op === 'vibrate')[1].p) === '[300]', 'a single duration is accepted');
    a.rt.close();
    ok(a.calls.some((c) => c.op === 'speech.stop'), 'close() stops speech the plugin started');
  }

  section('v1.3 the frame side — hostApi.camera / microphone / location / speech / haptics');
  {
    const shim = (runtimeSource.match(/var SHIM_SRC = `([\s\S]*?)`;/) || [])[1] || '';
    const posts = []; let onMsg = null; let hostApi = null;
    const frameWin = {
      __SKIPI_TOKEN__: 'T', SkipiPlugins: {}, parent: { postMessage: (m) => posts.push(m) },
      addEventListener: (t, fn) => { if (t === 'message') onMsg = fn; },
      localStorage: { getItem() { throw new Error('blocked'); } },
    };
    const frameDoc = { head: { appendChild() {} }, body: { scrollHeight: 10 }, createElement: () => ({}) };
    new Function('window', 'document', 'parent', 'fetch', 'setTimeout', 'ResizeObserver', shim)(
      frameWin, frameDoc, frameWin.parent, () => Promise.reject(new Error('csp')), setTimeout, undefined);
    const mountWith = async (perms) => {
      frameWin.SkipiPlugins[slug] = { mount: (el, api) => { hostApi = api; } };
      onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'init', slug, css: '', js: '', permissions: perms, nonce: 'n', hostId: 'h' } });
      await ctx.tick(); await ctx.tick();
    };
    await mountWith([]);
    posts.length = 0;
    let rejected = 0;
    for (const call of [() => hostApi.camera.start({}), () => hostApi.microphone.start(), () => hostApi.location.start(), () => hostApi.speech.speak('hi'), () => hostApi.haptics.vibrate(100)]) await call().catch(() => rejected++);
    hostApi.camera.stop(); hostApi.microphone.stop(); hostApi.location.stop(); hostApi.speech.stop();
    ok(rejected === 5 && posts.length === 0, 'without grants every call rejects in the frame and nothing is posted to the host');
    await mountWith(['camera', 'location', 'speech', 'vibrate']);
    posts.length = 0;
    const frames = [], fixes = [];
    const off = hostApi.camera.onFrame((f) => frames.push(f));
    hostApi.location.onPosition((p) => fixes.push(p));
    const pr = hostApi.camera.start({ facing: 'user', fps: 1 });
    const sent = posts.find((m) => m.type === 'camera.start');
    ok(sent && sent.token === 'T' && sent.opts.facing === 'user', 'with the grant camera.start posts a token-stamped message with the options');
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'rpc.result', id: sent.id, ok: true, value: { ok: true, width: 320, height: 240 } } });
    ok((await pr).width === 320, 'and resolves with the host answer');
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'stream.data', stream: 'camera', seq: 1, data: { t: 1, width: 320, height: 240, mime: 'image/jpeg', base64: JPEG } } });
    onMsg({ data: { ch: 'skipi-plugin', token: 'BAD', type: 'stream.data', stream: 'camera', seq: 2, data: { base64: JPEG } } });
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'stream.data', stream: 'location', seq: 1, data: { lat: 1, lon: 2 } } });
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'stream.data', stream: 'nonsense', seq: 1, data: {} } });
    ok(frames.length === 1 && frames[0].seq === 1 && frames[0].base64 === JPEG && fixes.length === 1 && fixes[0].lon === 2, 'frames reach onFrame, positions reach onPosition; a wrong token or an unknown stream is ignored');
    off();
    onMsg({ data: { ch: 'skipi-plugin', token: 'T', type: 'stream.data', stream: 'camera', seq: 3, data: { base64: JPEG } } });
    ok(frames.length === 1, 'unsubscribe stops delivery');
    hostApi.speech.speak({ text: 'Новый максимум', lang: 'ru-RU' }).catch(() => {});
    hostApi.haptics.vibrate([100, 50, 100]).catch(() => {});
    const sp = posts.find((m) => m.type === 'speech.speak'), vb = posts.find((m) => m.type === 'haptics.vibrate');
    ok(sp && sp.text === 'Новый максимум' && sp.lang === 'ru-RU' && vb && vb.pattern.length === 3, 'speech.speak and haptics.vibrate post their requests');
  }

  return { pass, fail };
}

// run as a self-test when invoked directly
const invoked = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invoked) {
  runIsolationContract().then((r) => {
    console.log('\n' + (r.fail === 0 ? 'ALL GREEN' : 'FAILURES') + ': ' + r.pass + ' passed, ' + r.fail + ' failed');
    process.exit(r.fail === 0 ? 0 : 1);
  }).catch((e) => { console.error(e); process.exit(1); });
}
