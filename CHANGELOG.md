# Changelog — @skipi/host-runtime

Semver per `CONTRACT.md`: MAJOR = breaking wire/`cfg`/`api`/loader/host change;
MINOR = additive; PATCH = backwards-compatible bug fix.

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
