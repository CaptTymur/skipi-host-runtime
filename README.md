# @skipi/host-runtime

Shared **§1 isolated plugin host runtime** for all Skipi homes (Seafarer, On Board, Crewing, Broker,
Management). One source → two delivery shapes, so no home copy-pastes the security boundary.

- A plugin runs inside a **sandboxed, opaque-origin iframe** (`allow-scripts`, no `allow-same-origin`) with a
  strict default-deny CSP (`connect-src 'none'`), reached only through a **per-mount token-gated postMessage
  bridge**. No host DOM, no network, no host storage/tokens in the frame.
- Since 1.1 a plugin with the `network` grant can ask the **host** to make a request (`hostApi.net.fetch`) to the
  `https` addresses listed in its verified pack, and with `file_save` / `file_pick` can save or pick a file through
  the platform dialog. The frame itself stays closed.
- The runtime is **loader-agnostic** and **host-injection-agnostic**: a home supplies `cfg.loader`
  (bundled bytes or signed pack) and `cfg.host` (id / namespaced storage / theme / navigation). The runtime
  owns the frame, CSP, token, shim, and wire schema.

Full API in [`CONTRACT.md`](./CONTRACT.md).

## Status

**Additive package, v1.0.0. No home is migrated yet.** `dist/plugin-host-bridge.js` is byte-identical to the
live Seafarer `dist/plugin-host-bridge.js` (sha256 `93c8eff8…`), so adopting it is a no-op swap for Seafarer.
Migration order and rationale: `Документы…/05 Разработка плагинов и программ/2026-06-30 — Decision — Shared
Plugin Host Runtime Extraction.md` (Crewing first, then back-port Seafarer/On Board, each behind its own GO +
green isolation harness).

## Layout

```
src/runtime.js            single source (verbatim Seafarer baseline; edit HERE, never in a home)
dist/plugin-host-bridge.js   emit: standalone <script src> form (file homes, e.g. Seafarer) — byte-identical to src
dist/runtime.inline.html     emit: marker-wrapped <script> block for single-file homes (On Board / Crewing)
dist/RUNTIME_VERSION         emit: "<version>\nsha256:<hex>" of the canonical runtime
tools/emit.js             deterministic generator (no Date/random/network)
harness/isolation-contract.mjs   reusable §1 contract test (run standalone or import per home)
harness/fake-dom.mjs      headless DOM/localStorage/window helper
CONTRACT.md / CHANGELOG.md
```

## Use (per home)

A home embeds the matching emit and constructs the runtime with its own adapters:

```js
// file home (Seafarer): <script src="plugin-host-bridge.js"></script>
// single-file home (On Board / Crewing): splice dist/runtime.inline.html between markers in index.html
var rt = window.SkipiPluginRuntime.create({
  enabled: FEATURE_FLAG,                 // kill switch
  loader: homeLoader,                    // install(slug) -> {ok, pack:{entrypoints,files,permissions}, source}
  host:   { id: 'seafarer',
            storage: homeStore,          // get(slug,k)/set(slug,k,v)/remove(slug,k), home-namespaced
            theme: homeTheme,            // get()/subscribe(fn)
            navigation: homeNav },       // setTitle(s)/closePlugin()
});
var res = await rt.open(slug, mountEl);  // mounts the isolated frame
```

The home keeps a thin `*_isolation_harness.mjs` that reuses the shared contract with its real adapters:

```js
import { runIsolationContract } from '.../_host-runtime/harness/isolation-contract.mjs';
const { pass, fail } = await runIsolationContract({
  runtimeSource: fs.readFileSync('<home runtime>', 'utf8'),
  makeLoader: (perms) => homeLoaderFixture(perms),
  makeHost: () => homeHostAdapter(store),
  secretKey: 'onboard_token', secretVal: '…',
});
```

## Build & verify

```bash
node tools/emit.js                       # regenerate dist/*
node harness/isolation-contract.mjs      # run the shared §1 contract self-test (27 assertions)
npm run check                            # node --check on src + tools + harness
```

`emit` is deterministic: same `src/runtime.js` + same `version` → identical `dist/*` bytes. CI should fail if a
home's embedded runtime diverges from `dist/RUNTIME_VERSION`.
