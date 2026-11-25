# Changelog — @skipi/host-runtime

Semver per `CONTRACT.md`: MAJOR = breaking wire/`cfg`/`api`/loader/host change;
MINOR = additive; PATCH = backwards-compatible bug fix.

## 1.2.0 — 2026-11-25

Additive (MINOR). Owner decision 25.11.2026: the marine clinometer is to run as a Skipi plugin on the phone's
sensors (marine-clinometer issue #2; proposal `docs/HOST_MOTION_PROPOSAL.md` in that repository).

- `hostApi.motion.start / onSamples / stop` — **host-mediated** motion sensors, grant `motion`. The home reads
  the accelerometer and gyroscope and pushes rows `[t_ms, ax, ay, az, wx, wy, wz]`; the runtime validates rows,
  caps a batch at 500, numbers batches and delivers them only to the mount that started the sensors.
- `hostApi.screen.keepAwake(on)` — keep the screen on, grant `keep_awake`.
- Both are opt-in per home (`cfg.host.motion`, `cfg.host.screen`). `close()` stops the sensors and releases
  keep-awake itself.
- New wire messages `motion.start`, `motion.stop`, `screen.keepAwake` (frame → host) and `motion.batch`
  (host → frame). Frame isolation is unchanged: no `allow` attribute, same sandbox and CSP.
- A home on 1.1.x is unaffected: without the new host adapters and grants every new call is refused.
- Contract test: 53 → 74 assertions.

## 1.1.0 — 2026-11-24

Additive (MINOR). Owner decision 24.11.2026: plugins may use the network, if it is safe and breaks nothing.

- `hostApi.net.fetch` — **host-mediated** network. The frame CSP is unchanged (`connect-src 'none'`); the host
  performs the request only with the `network` grant, only to `https` URLs inside the verified pack's
  `network.allow`, without cookies/credentials and without following redirects. Opt-in per home (`cfg.host.net`).
- `hostApi.files.save` / `hostApi.files.pick` — host-mediated files, grants `file_save` / `file_pick`, relayed to
  `cfg.host.files` (opt-in per home).
- Frame CSP `script-src` gains `'wasm-unsafe-eval'`: a plugin may run a WebAssembly module from its own verified
  pack (Draft Survey's calculation core is the Rust core compiled to wasm). No eval, no network.
- New wire messages `net.fetch`, `files.save`, `files.pick` (frame → host) and `rpc.result` (host → frame). An
  answer is delivered only to the mount that asked.
- A home on 1.0.x is unaffected: without `cfg.host.net` / `cfg.host.files` and without the new grants every new
  call is refused. Existing plugins never send the new messages.
- Contract test: 27 → 53 assertions (allowlist escapes, header filtering, default transport options,
  cross-mount answers, frame-side shim).

## 1.0.1 — 2026-06-30

Bug fix:

- Make plugin-initiated `nav.close` idempotent when a home's `host.navigation.closePlugin()`
  closes/unmounts the runtime itself. This prevents a double-close null dereference while preserving
  the same wire schema and API contract.

## 1.0.0 — 2026-06-30

First shared source. **Additive only — no home migrated in this release.**

- Seeded `src/runtime.js` **verbatim** from Seafarer `dist/plugin-host-bridge.js`
  (sha256 `93c8eff840d6de252dc3c76f03e7a4a0823ed4907f67a28dc92b3e46214a98c7`).
  `dist/plugin-host-bridge.js` is **byte-identical** to the live Seafarer file → the public runtime
  contract (`window.SkipiPluginRuntime.create(cfg)`) is unchanged.
- `tools/emit.js`: deterministic generator → standalone `dist/plugin-host-bridge.js`,
  inline `dist/runtime.inline.html`, and `dist/RUNTIME_VERSION` (version + sha256).
- `CONTRACT.md`: `cfg`/`api`/loader/host/wire schema + semver + `noCsp` test-only rule.
- `harness/isolation-contract.mjs` + `harness/fake-dom.mjs`: reusable §1 contract test (27 assertions,
  all green) capturing the Seafarer + On Board invariants without weakening them. Homes call
  `runIsolationContract({ runtimeSource, makeLoader, makeHost, secretKey, secretVal })`.

Not done in 1.0.0 (separate GOs): migrating Seafarer / On Board / Crewing / Broker / Management to consume
this package. See `2026-06-30 — Decision — Shared Plugin Host Runtime Extraction`.
