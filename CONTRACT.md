# Skipi Plugin Host Runtime — Contract (v1.1)

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
              pick?(slug, {accept, multiple}) -> Promise<[{name, mime, base64}]> }
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
- `unmount` `{ type:'unmount' }`

Frame → host:
- `ready` `{ type:'ready' }`
- `mounted` `{ type:'mounted', height, selfcheck:{ parentDomAccess, storageBlocked, fetchBlocked } }`
- `resize` `{ type:'resize', height }`
- `storage.get` `{ type:'storage.get', id, key }` · `storage.set` `{ key, value }` · `storage.remove` `{ key }`
- `nav.setTitle` `{ type:'nav.setTitle', title }` · `nav.close` `{ type:'nav.close' }`
- `net.fetch` `{ type:'net.fetch', id, url, method?, headers?, body? | bodyBase64? }` (v1.1)
- `files.save` `{ type:'files.save', id, name, mime?, text? | base64? }` · `files.pick` `{ type:'files.pick', id, accept?, multiple? }` (v1.1)
- `error` `{ type:'error', message }`

**Default-deny:** unknown `type`, wrong `token`, a `storage.*` without granted `local_storage`, a `net.fetch`
without `network` / outside the allowlist, or a `files.*` without its grant → refused + recorded in the audit log.

## Frame isolation (fixed by the runtime — do not weaken)

- `iframe sandbox="allow-scripts"` with **no** `allow-same-origin` (opaque origin, cross-origin to host),
  `referrerpolicy="no-referrer"`.
- Frame `srcdoc` CSP: `default-src 'none'; script-src 'nonce-…'; style-src 'nonce-…'; img-src data:;
  connect-src 'none'; base-uri 'none'; form-action 'none'`. No eval, no unsafe-inline (nonce'd injection).
- Per-mount capability **token** + per-mount **nonce** (16 random bytes each via `crypto.getRandomValues`).
- No host DOM, no network, no host storage/tokens in the frame. v1.1 does **not** change this: `net.fetch` and
  `files.*` are requests to the host, not capabilities of the frame.

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
