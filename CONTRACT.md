# Skipi Plugin Host Runtime — Contract (v1.3)

Canonical contract for the shared §1 isolated plugin runtime. The runtime is the
**single source** every Skipi home embeds; this document is the API it guarantees.

> Source of truth: `src/runtime.js`. Emitted by `tools/emit.js` to
> `dist/plugin-host-bridge.js` (file homes) and `dist/runtime.inline.html` (single-file homes).
> A home supplies `loader` + `host`; it never edits the runtime.

## Global

```js
window.SkipiPluginRuntime = { create: function (cfg) -> api };
```

## `cfg` — input (supplied by the home)

| Field | Type | Required | Meaning |
|---|---|---|---|
| `enabled` | boolean | yes | Kill switch. `false` → `open()` returns `{ok:false, stage:'flag'}` and **no frame is created** (host boot untouched). |
| `loader` | object | yes | Source of verified plugin code. See **Loader contract**. |
| `host` | object | yes | Host-injected identity + namespaced storage + theme + navigation. See **Host injection**. |
| `bridgeTimeoutMs` | number | no | Handshake timeout (default `6000`) → `{ok:false, stage:'timeout'}`. |
| `noCsp` | boolean | no | **Test-only.** Omits the frame CSP `<meta>`. **MUST be falsy / absent in any production host config.** |

## `api` — output (used by the home glue)

| Member | Returns | Meaning |
|---|---|---|
| `enabled` | boolean | mirror of `cfg.enabled`. |
| `open(slug, mountEl)` | `Promise<{ok, ...}>` | Creates the sandboxed iframe **synchronously before any await** (frame-first boot), then `loader.install(slug)`, then sends `init`. Resolves `{ok:true, source, selfcheck}` on `mounted`, else `{ok:false, stage, reason}`. Failure stages: `flag` / `install` / `timeout` / loader stages (`integrity`/`compat`/`policy`/…) / `mount`. |
| `close()` | — | Posts `unmount`, removes the frame, clears active state. |
| `pushTheme(theme)` | — | Forwards a theme change into the active frame. |
| `_active()` / `_audit()` / `_dbg()` / `_store()` | — | Diagnostics / test hooks (not product API). |

## Loader contract (home-specific implementation, shared shape)

```
loader.install(slug) -> Promise<
    { ok:true,  pack:{ entrypoints:{ ui, style }, files:{ <name>:string }, permissions:string[],
                       network?:{ allow:string[] } }, source:string }
  | { ok:false, stage:'install'|'integrity'|'compat'|'policy'|..., reason?:string } >
```

The runtime reads `pack.files[pack.entrypoints.ui]` (JS) and `pack.files[pack.entrypoints.style]` (CSS),
and `pack.permissions`. `entrypoints` defaults to `{ ui:'index.js', style:'index.css' }` if absent.
A non-`ok` result is **fail-closed**: surfaced verbatim, no mount.

`pack.network.allow` (v1.1) is the plugin's network allowlist: `https://` URL prefixes (origin + path prefix,
no query/fragment/userinfo). It is part of the **verified** pack, so for a signed pack it is covered by the
signature. The loader's policy step decides whether a plugin may declare one at all; the runtime enforces it
on every request.

- Bundled first-party loader: reads on-disk artifact bytes, sha256 vs `checksums.json`.
- Signed-pack loader: verify(sig) → compat(semver) → policy(perms) → integrity(sha256) → cache.

## Host injection (home-specific implementation, shared shape)

```
host = {
  id:         string,                                   // non-secret home id ('seafarer'|'onboard'|...)
  storage:  { get(slug, k), set(slug, k, v), remove(slug, k) },   // home namespaces (e.g. skipi_plugin_<slug>_<k>)
  theme:    { get() -> string, subscribe(fn) -> unsubscribe },
  navigation:{ setTitle(s), closePlugin() },
  net?:     { fetch?(slug, req) -> Promise<res> },       // v1.1, OPT-IN: absent → every net.fetch is refused
  files?:   { save?(slug, file) -> Promise<{saved}>,     // v1.1, OPT-IN: absent → files.* are refused
              pick?(slug, {accept, multiple}) -> Promise<[{name, mime, base64}]> },
  motion?:  { start(slug, {rateHz}, push) -> Promise<{ok, rateHz, source, platform} | {ok:false, reason}>,
              stop(slug) },                              // v1.2, OPT-IN: absent → motion.* are refused
  screen?:  { keepAwake(slug, on) -> Promise<{ok}> },    // v1.2, OPT-IN: absent → screen.* are refused
  // v1.3, each OPT-IN (absent → that capability is refused):
  camera?:     { start(slug, {facing, width, fps, quality}, push) -> Promise<{ok, ...}>, stop(slug) },
  microphone?: { start(slug, {chunkMs}, push) -> Promise<{ok, ...}>, stop(slug) },
  location?:   { start(slug, {highAccuracy}, push) -> Promise<{ok, ...}>, stop(slug) },
  speech?:     { speak(slug, {text, lang, rate, pitch}) -> Promise<{ok}>, stop(slug) },
  haptics?:    { vibrate(slug, pattern:number[]) -> Promise<{ok}> }
}
```

Notes:
- Storage methods receive the active **slug** as first arg; the home is responsible for namespacing and for
  keeping host secrets out of the plugin namespace. The runtime only relays `storage.*` for plugins that were
  **granted** `local_storage`; ungranted access is denied + audited.
- Capability methods beyond storage/theme/navigation (e.g. `media.pick`, `workflow.submit`) are layered by the
  **home** on top of this object per the plugin's role grants — they are not part of the runtime.
- The host's secrets/tokens are NEVER placed in any object handed to the plugin and are unreachable from the frame.

### Host-mediated network (v1.1)

A plugin never opens a connection itself — the frame CSP stays `connect-src 'none'`. It calls
`hostApi.net.fetch(url, {method, headers, body | bodyBase64})`; the **host** performs the request and returns
`{ ok, status, headers:{'content-type'}, text | base64 }`. The runtime refuses (and audits) the call unless
**all** hold:

1. the plugin was granted the `network` permission;
2. the home opted in (`cfg.host.net` is present);
3. the URL is `https:`, has no userinfo, and falls inside `pack.network.allow` (same origin incl. port, and the
   normalized path is under the declared prefix — `..` cannot escape it);
4. the method is `GET` / `POST` / `PUT` / `PATCH` / `DELETE`; bodies are capped at 16 MB each way.

Request headers are filtered: `cookie`, `host`, `origin`, `referer`, `connection`, `content-length`, `proxy-*`,
`sec-*` and malformed names/values are dropped. The plugin's own headers (e.g. its API key) pass.

Transport: with `cfg.host.net = {}` the runtime uses the host document's `fetch` with options it fixes itself —
`credentials:'omit'`, `redirect:'error'` (a redirect could leave the allowlist), `cache:'no-store'`,
`referrerPolicy:'no-referrer'`, 60 s timeout. A home may supply `cfg.host.net.fetch(slug, req)` instead (e.g. a
native command where CORS blocks the web transport); it receives the **already validated** `req =
{url, method, headers, body | bodyBase64}` and MUST keep the same rules: no cookies/credentials, no redirects,
no host token or session header added.

### Host-mediated files (v1.1)

`hostApi.files.save({name, mime, text | base64})` (permission `file_save`) and
`hostApi.files.pick({accept, multiple})` (permission `file_pick`) are relayed to `cfg.host.files`. The home
implements them with the platform's own save / share / open dialog: the plugin gets only the bytes the user
picked, and can write only where the user chose. The runtime reduces `name` to a plain file name (no path
separators, no leading dots, ≤120 chars) and caps a file at 32 MB. The two grants are independent.

### Host-mediated motion sensors and keep-awake (v1.2)

The frame has no sensor and no wake-lock access of its own (opaque origin, no `allow` attribute). The **home**
reads the device sensors and the runtime forwards the rows:

```js
hostApi.motion.start({ rateHz })   // -> Promise<{ ok, rateHz, source, platform } | { ok:false, reason }>
hostApi.motion.onSamples(cb)       // -> unsubscribe; cb({ seq, samples })
hostApi.motion.stop()
hostApi.screen.keepAwake(on)       // -> Promise<{ ok }>
```

- Grants: `motion` for `hostApi.motion.*`, `keep_awake` for `hostApi.screen.keepAwake`; they are independent.
  Without the grant the call is refused in the frame; the host refuses (and audits) it again, and also when the
  home did not opt in (`cfg.host.motion` / `cfg.host.screen` absent — e.g. a desktop home without sensors may
  instead answer `{ ok:false, reason:'no-sensors' }`).
- A sample row is `[t_ms, ax, ay, az, wx, wy, wz]`, or `[t_ms, ax, ay, az]` when there is no gyroscope
  (`null` is also accepted in the three gyro positions). `t_ms` — monotonic milliseconds of the measurement;
  `a` — specific force **including gravity**, m/s², device axes x right / y to the top of the device / z out of
  the screen, so a device lying screen-up reads `az ≈ +9.81` **on every platform** (the home normalises signs);
  `w` — angular rate, rad/s, right-handed about the same axes.
- `rateHz` is clamped to 1–100; the home reports the actual rate in its answer. The home calls `push(rows)`
  about every 100 ms; the runtime drops malformed rows, caps a batch at 500 rows and numbers batches with `seq`
  (+1 each) so a plugin sees gaps.
- `push` delivers **only to the mount that started the sensors**; after `close()` it is inert and returns
  `false` (the home should then stop). `close()` itself calls `host.motion.stop(slug)` and
  `host.screen.keepAwake(slug, false)` if the plugin left them on.
- The home stops the sensors when the app goes to the background.

### Host-mediated device capabilities (v1.3)

The frame gets no media, geolocation or device API of its own. The **home** captures, speaks and vibrates; the
runtime checks the grant, cleans what passes and delivers pushed data only to the mount that asked.

| `hostApi` | Grant | In the frame |
|---|---|---|
| `camera.start({facing, width, fps, quality})` · `camera.onFrame(cb)` · `camera.stop()` | `camera` | `cb({seq, t, width, height, mime:'image/jpeg', base64})` |
| `microphone.start({chunkMs})` · `microphone.onChunk(cb)` · `microphone.stop()` | `microphone` | `cb({seq, t, sampleRate, level, pcm})` — `pcm` is base64 of mono 16-bit little-endian samples, `level` is the chunk RMS 0..1 |
| `location.start({highAccuracy})` · `location.onPosition(cb)` · `location.stop()` | `location` | `cb({seq, t, lat, lon, accuracy, altitude, speed, heading})` — metres, m/s, degrees; unknown → `null` |
| `speech.speak({text, lang, rate, pitch})` (or a string) · `speech.stop()` | `speech` | resolves when the phrase was handed to the system voice |
| `haptics.vibrate(ms \| [on, off, on, …])` | `vibrate` | resolves `{ok}` |

- Grants are independent: none implies another. Without the grant the call is refused in the frame and again by
  the host (audited); with the grant but without the home's adapter it is refused as "not available".
- Limits fixed by the runtime: camera `facing` `user`/`environment` (default `environment`), `width` 64–1280
  (default 320), `fps` 0.2–15 (default 2), `quality` 0.1–0.95; a frame ≤ 2.8 MB of base64, always `image/jpeg`.
  Microphone `chunkMs` 50–1000 (default 250). Speech text ≤ 500 characters, `rate`/`pitch` 0.5–2, `lang` a plain
  language tag. Vibration ≤ 16 steps of 0–2000 ms.
- `start` resolves with the home's answer (`{ok:true, …}` or `{ok:false, reason}` — e.g. the user refused the
  system permission, or the device has no camera).
- `push` is inert after `close()` and returns `false`. `close()` itself stops the camera, the microphone, the
  position watch and any speech the plugin left on.
- A home SHOULD ask the user before the first use of `camera`, `microphone` and `location` by a given plugin, and
  MUST stop capture when the app goes to the background.

## postMessage wire schema (fixed by the runtime)

Channel envelope on every message: `{ ch:'skipi-plugin', v:1, token }`. The host validates
`token === active.token` on **every** message (opaque-origin frames have unreliable `source` identity);
mismatches are dropped.

Host → frame:
- `init` `{ type:'init', slug, manifest, css, js, theme, permissions, nonce, hostId }`
- `theme` `{ type:'theme', theme }`
- `storage.result` `{ type:'storage.result', id, value }`
- `rpc.result` `{ type:'rpc.result', id, ok:true, value }` | `{ …, ok:false, error }` (v1.1) — answer to
  `net.fetch` / `files.*`; delivered only to the mount (token) that asked.
- `motion.batch` `{ type:'motion.batch', seq, samples }` (v1.2) — only to the mount that started the sensors;
  a 1.1 frame ignores it.
- `stream.data` `{ type:'stream.data', stream:'camera'|'microphone'|'location', seq, data }` (v1.3) — only to
  the mount that started that stream.
- `unmount` `{ type:'unmount' }`

Frame → host:
- `ready` `{ type:'ready' }`
- `mounted` `{ type:'mounted', height, selfcheck:{ parentDomAccess, storageBlocked, fetchBlocked } }`
- `resize` `{ type:'resize', height }`
- `storage.get` `{ type:'storage.get', id, key }` · `storage.set` `{ key, value }` · `storage.remove` `{ key }`
- `nav.setTitle` `{ type:'nav.setTitle', title }` · `nav.close` `{ type:'nav.close' }`
- `net.fetch` `{ type:'net.fetch', id, url, method?, headers?, body? | bodyBase64? }` (v1.1)
- `files.save` `{ type:'files.save', id, name, mime?, text? | base64? }` · `files.pick` `{ type:'files.pick', id, accept?, multiple? }` (v1.1)
- `motion.start` `{ type:'motion.start', id, rateHz? }` · `motion.stop` `{ type:'motion.stop' }` ·
  `screen.keepAwake` `{ type:'screen.keepAwake', id, on }` (v1.2; answers come as `rpc.result`)
- `camera.start` / `microphone.start` / `location.start` `{ type, id, opts }` · `camera.stop` / `microphone.stop` /
  `location.stop` `{ type }` · `speech.speak` `{ type, id, text, lang?, rate?, pitch? }` · `speech.stop` ·
  `haptics.vibrate` `{ type, id, pattern }` (v1.3; answers come as `rpc.result`)
- `error` `{ type:'error', message }`

**Default-deny:** unknown `type`, wrong `token`, a `storage.*` without granted `local_storage`, a `net.fetch`
without `network` / outside the allowlist, a `files.*` without its grant, or a `motion.*` / `screen.*` without
its grant → refused + recorded in the audit log.

## Frame isolation (fixed by the runtime — do not weaken)

- `iframe sandbox="allow-scripts"` with **no** `allow-same-origin` (opaque origin, cross-origin to host),
  `referrerpolicy="no-referrer"`.
- Frame `srcdoc` CSP: `default-src 'none'; script-src 'nonce-…' 'wasm-unsafe-eval'; style-src 'nonce-…';
  img-src data:; connect-src 'none'; base-uri 'none'; form-action 'none'`. No eval, no unsafe-inline (nonce'd
  injection). `'wasm-unsafe-eval'` (v1.1) allows a plugin to instantiate a WebAssembly module carried inside its
  own verified pack; it grants no network and nothing the plugin's JS could not already do.
- Per-mount capability **token** + per-mount **nonce** (16 random bytes each via `crypto.getRandomValues`).
- No host DOM, no network, no host storage/tokens in the frame. v1.1 does **not** change this: `net.fetch` and
  `files.*` are requests to the host, not capabilities of the frame. Neither does v1.2: the iframe gets no
  `allow` attribute; sensor rows and keep-awake are served by the host.

## Versioning rule (semver)

- The runtime carries a semver `version` (`package.json`) + sha256 stamp (`dist/RUNTIME_VERSION`).
- **MAJOR** — any breaking change to the wire schema or the `cfg`/`api`/loader/host shapes above.
- **MINOR** — additive capability (new optional field, new message type that older frames ignore safely).
- **PATCH** — non-behavioral fix.
- A home records which `RUNTIME_VERSION` it embeds. Drift between a home's embedded runtime and this source
  is a CI failure, not a silent fork.

## `noCsp` test-only rule

`cfg.noCsp` exists solely so headless harnesses can inspect the frame without a CSP `<meta>` interfering. It
**must never** be set in a production host config. A release gate should assert the host's runtime config does
not enable `noCsp`.
