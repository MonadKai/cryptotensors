# Changelog

This file tracks changes in this private fork only. For upstream cryptotensors
history, see [RELEASE.md](RELEASE.md) and the upstream repo at
https://github.com/aiyah-meloken/cryptotensors.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project uses a fork-local version suffix (`-ext`, `-ext.2`, ...) on
top of the upstream tag we branched from.

## [v0.2.3-ext] — 2026-04-22

Forked from upstream `v0.2.3`. First fork release.

### Added

- **Extensible provider public key whitelist** in `safetensors/src/registry.rs`.
  Third-party native providers (loaded via `load_provider_native`) can now be
  trusted without editing the `PROVIDER_PUBLIC_KEYS_BUILTIN` const, via two
  opt-in external sources:
  - `CRYPTOTENSOR_TRUSTED_PROVIDERS_FILE` — path to a JSON file of the form
    `{ "providers": [ { "name": "...", "pubkey": "<base64 Ed25519>", "note": "..." } ] }`.
    On Unix the file must not be world-writable, or loading is refused.
  - `CRYPTOTENSOR_TRUSTED_PROVIDER_PUBKEYS` — inline
    `"name1=base64pubkey1,name2=base64pubkey2"` for container / debug use.
- New public function `cryptotensors::registry::resolve_provider_pubkey(name)`
  encapsulates the built-in → extensions lookup used by
  `verify_library_signature`.
- Every successful extension match writes a stderr `WARNING` line tagged with
  `name=` and a short sha256 fingerprint of the pubkey for auditability.
- Integration tests in `safetensors/tests/ext_provider_keys_test.rs`
  (7 cases covering: no-config parity, file-based load, invalid-base64
  rejection, env-var load, file/env conflict detection, world-writable
  rejection, built-in shadowing of extensions).

### Semantics

- **Off by default.** Neither env var being set means behavior is byte-for-byte
  identical to upstream `v0.2.3`.
- **Built-in always wins.** An extension entry whose `name` collides with a
  `PROVIDER_PUBLIC_KEYS_BUILTIN` entry is silently shadowed, so built-in
  trust guarantees cannot be weakened at runtime.
- **Loud on conflict.** If the same name appears in both the file and the env
  var with *different* pubkeys, resolution fails with a clear error rather
  than silently preferring one source.

### Rationale

This fork exists to host `cryptotensors-provider-resultscloud-license` as an
independent repository. Upstream gates `.so` loading on a hardcoded
Ed25519 whitelist in `registry.rs`; without an extension mechanism, every
new third-party provider would require patching that const. The runtime
extension path keeps the upstream security posture (built-in whitelist,
signature verification) while letting private deployments register their
own provider pubkey through operator-controlled config.

### Unchanged

- All upstream encryption / signing / registry public API is preserved.
- Python bindings are untouched — the extension path is Rust-only, driven by
  process env and a config file.
- Upstream `PROVIDER_PUBLIC_KEYS_BUILTIN` entries (e.g. `koalavault-vllm`)
  still resolve exactly as they did in v0.2.3.
