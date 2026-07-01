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
