# CryptoTensors — Design Notes

This document covers cross-cutting design decisions that don't fit
neatly into the format spec ([FORMAT.md](../FORMAT.md)) or the
key-management user guide. Right now its main subject is the
**path-based, language-agnostic provider loader**, which is the seam
between cryptotensors' Rust core and third-party key-source plugins
(licensing engines, KMS bridges, HSM clients, …).

---

## 1. Provider registry — what the Rust core owns

The global registry lives in [`safetensors/src/registry.rs`][registry].
It holds an ordered list of `KeyProvider` trait objects, each tagged
with a priority and an optional handle to the dynamic library that
created it (kept alive via `Arc<libloading::Library>`):

```rust
struct ProviderEntry {
    provider: Box<dyn KeyProvider>,
    priority: i32,
    enabled: bool,
    _lib: Option<Arc<libloading::Library>>,
}

static PROVIDERS: OnceLock<RwLock<Vec<ProviderEntry>>> = OnceLock::new();
```

Built-in providers (`EnvKeyProvider`, `FileKeyProvider`) are inserted on
first access. Direct providers registered from Python live at the top
of the priority order; native cdylibs sit at `PRIORITY_NATIVE = 50`;
file/env defaults at the bottom. `get_master_key` / `get_verify_key` /
`get_signing_key` walk the list in priority-descending order and return
the first match.

The point: **all bookkeeping is in Rust**. Bindings (Python, future C,
Go, etc.) are thin call-throughs. There is no Python-side cache, no
Python-side discovery protocol, no separate "list of installed
providers" — the registry's `list_registered_providers()` is the single
source of truth for "what is loaded right now."

[registry]: ../safetensors/src/registry.rs

---

## 2. Why path-based loading

An earlier version split responsibility: Python discovered cdylibs by
walking `importlib.metadata.entry_points(group="cryptotensors.providers")`
and asked the matching wrapper module for `get_native_lib_path()`; Rust
then loaded and verified the path. That coupled three things that
shouldn't be coupled:

1. **A discovery protocol baked into Python's packaging machinery** —
   non-Python callers (a future `cryptotensors-cli`, a Go sidecar, a C
   embedding) couldn't reuse any of it.
2. **A caller-supplied provider name** — Rust trusted the name passed
   from Python to look up the right pubkey, so the keypair didn't
   actually authenticate the *identity* of the cdylib, only that
   *some* signing happened.
3. **Two equally-authoritative views of "what's available"** — the
   entry_points list (installed but maybe not loaded) and the Rust
   registry (loaded right now), with no enforced relationship between
   them.

The current design collapses all three by making the loader take a
single argument:

```rust
pub fn load_provider_native(
    lib_path: &str,
    config_json: &str,
) -> Result<(), CryptoTensorsError>;
```

A caller in any language passes a filesystem path; everything else —
signature verification, identity binding, registration — happens
inside Rust.

---

## 3. Signature flow and identity binding

Trust is rooted in a small compile-time table:

```rust
const PROVIDER_PUBLIC_KEYS: &[(&str, &str)] = &[
    ("koalavault-vllm", "vM5cRuHaIyKt3RAELcqc4+nXbSbCh53ABYt2/lOGqw8="),
    // ... one entry per blessed provider, base64 Ed25519 pubkey
];
```

When `load_provider_native(lib_path, config_json)` runs, it does five
things in this order, and any failure aborts before any provider code
executes:

```
┌─────────────────────────────────────────────────────────────────────┐
│ load_provider_native(lib_path, config_json)                         │
├─────────────────────────────────────────────────────────────────────┤
│ 1. Read <lib_path> and <lib_path>.sig from disk.                    │
│                                                                     │
│ 2. For each (name_i, pubkey_i) in PROVIDER_PUBLIC_KEYS:             │
│       try ED25519::verify(pubkey_i, lib_bytes, sig_bytes).          │
│    First key that verifies → trusted_name = name_i.                 │
│    No key verifies → reject with                                    │
│       "no trusted public key matched the signature".                │
│                                                                     │
│ 3. dlopen the cdylib (libloading::Library::new).                    │
│                                                                     │
│ 4. dlsym `cryptotensors_create_provider`, call it, take ownership   │
│    of the returned Box<dyn KeyProvider>, run                        │
│    provider.initialize(config_json).                                │
│                                                                     │
│ 5. Cross-check: if provider.name() != trusted_name, reject with     │
│       "Provider name mismatch: cdylib reports X, signing key is Y". │
│    Otherwise register it at PRIORITY_NATIVE.                        │
└─────────────────────────────────────────────────────────────────────┘
```

The two-step identity binding (step 2 + step 5) is the load-bearing
property:

- **Step 2** says "this binary was signed by someone we trust." It
  doesn't yet say *who* among the trusted set.
- **Step 5** says "the cdylib self-reports as the same identity that
  the signing key is registered under." A keypair holder cannot ship
  a cdylib that masquerades as some other provider — the name has to
  match the row in the table that pubkey lives in.

Trying every pubkey in the table (rather than indexing by a
caller-supplied name) is what removes the name parameter from the
loader. The table is hardcoded at compile time and has < 10 entries in
practice, so the linear scan costs microseconds.

### Tampering and rotation

- **Tampered cdylib**: Ed25519 verify fails; load aborts at step 2.
- **Tampered `.sig`**: same — sig is the input to verify, any change
  breaks it.
- **Stripped `.sig` (file missing)**: explicit "Signature file
  missing" error, also at step 2.
- **Adversary substitutes a *different* validly-signed provider**
  (e.g. swap `libprovider_a.so` for `libprovider_b.so` from a
  different vendor we also trust): step 2 succeeds with `name_b`,
  step 4 produces a `provider_b` instance whose `name()` is `"b"`,
  step 5 succeeds — and the registry now has provider B instead of
  provider A. The caller chose the path; if it pointed at the wrong
  file, the wrong provider is loaded. Mitigation lives in the
  caller's deployment (e.g. our reference autoload hook resolves the
  path via `importlib.resources` from inside the same wheel that owns
  the `.sig`, so the substitution would have to happen at install
  time, not at runtime).
- **Trusted pubkey compromise**: rotate by editing the
  `PROVIDER_PUBLIC_KEYS` row, releasing a new cryptotensors version,
  and reissuing each affected provider with a freshly-signed cdylib.
  Keep the old row in place for one minor version if you need
  parallel deployment, then drop it.

---

## 4. Bindings, in concentric layers

```
┌────────────────────────────────────────────────────────────────┐
│  Python user code: cryptotensors.init_key_provider(path, **cfg)│
└─────────────────────────────┬──────────────────────────────────┘
                              │ json.dumps(cfg)
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  PyO3:  py_load_provider_native(lib_path, config_json)         │
│         → registry::load_provider_native(...)                  │
└─────────────────────────────┬──────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  Rust core: load_provider_native — verify, dlopen, register    │
└────────────────────────────────────────────────────────────────┘
                              ▲
                              │ extern "C" cryptotensors_create_provider
                              │
┌────────────────────────────────────────────────────────────────┐
│  Provider cdylib (e.g. libct_resultscloud_license.dylib)       │
│  — third-party Rust crate, signed at release time              │
└────────────────────────────────────────────────────────────────┘
```

The Rust ↔ cdylib boundary uses a single C extern (`cryptotensors_create_provider`)
that returns `*mut dyn KeyProvider`. That's not strictly FFI-safe (a Rust
trait object is involved), but it's only crossed between two Rust crates
that share a `cryptotensors` dependency at the *same* major version, so
the layout matches. Mixing a cdylib built against `cryptotensors v0.2`
with a runtime built against `v0.3` is undefined behaviour — version
pinning across both crates is a hard requirement of the loader contract.

### Public Python API

```python
def init_key_provider(lib_path: str, **config) -> None: ...
def list_key_providers() -> list[str]: ...
def disable_provider(name: str) -> None: ...

# in-process direct registration (separate path, no cdylib):
def register_direct_key_provider(*, files=None, keys=None) -> None: ...
```

`init_key_provider` returns `None` on success and raises on any of:
sig file missing, sig verification failure, library open failure,
missing `cryptotensors_create_provider` symbol, `initialize()` failure,
or the step-5 name mismatch.

`list_key_providers` returns the names of currently-registered, enabled
providers in priority order (highest first). It reflects the Rust
registry, not "what's installable in the venv."

---

## 5. Provider package contract

A package that wants to ship a cdylib for cryptotensors needs to:

1. **Build a `cdylib` Rust crate** that exports
   `extern "C" fn cryptotensors_create_provider() -> *mut dyn KeyProvider`,
   linked against the same `cryptotensors` major version that runtime
   users will deploy.

2. **Sign the resulting `.so` / `.dylib` / `.dll`** with the Ed25519
   private key whose public half is registered in
   `PROVIDER_PUBLIC_KEYS`. Drop the base64 signature into
   `<lib>.sig` next to the cdylib.

3. **Bundle the cdylib + `.sig` into the wheel** at a deterministic
   location, and expose a helper that resolves that location:

   ```python
   def get_native_lib_path() -> str: ...
   ```

   `importlib.resources.files(...)` is the right tool — it works
   under both editable installs and zipped wheels.

4. (Optional but recommended) **Ship a `.pth` autoload hook** so that
   the consumer doesn't need code changes. The hook should:
   - check an opt-in env var (so other Python processes pay nothing);
   - check an opt-out env var (kill switch for ops);
   - call `cryptotensors.init_key_provider(get_native_lib_path())`;
   - swallow all exceptions with a single stderr warning, never raise.

5. **Do NOT declare `[project.entry-points."cryptotensors.providers"]`
   in `pyproject.toml`.** The runtime no longer reads that group;
   leaving the declaration in just adds dead metadata that misleads
   future readers.

The reference implementation lives in
[`cryptotensors-provider-resultscloud-license`](https://github.com/aiyah-meloken/cryptotensors-provider-resultscloud-license).
Its `python/ct_resultscloud_license/_autoload.py` is a good template
for the autoload pattern.

---

## 6. Threat model — what the loader does and doesn't defend against

| Threat                                                  | Defence                                                          |
| ------------------------------------------------------- | ---------------------------------------------------------------- |
| Unsigned cdylib                                         | step 2 of load: no `.sig` → reject.                              |
| Cdylib signed by an untrusted key                       | step 2: no row in `PROVIDER_PUBLIC_KEYS` matches.                |
| Cdylib signed correctly but name forged                 | step 5: cdylib's `provider.name()` ≠ trusted name → reject.      |
| Caller passes a *path* to a different blessed cdylib    | out of scope at the loader; the caller chose the path.           |
| Tampered `<lib>.sig`                                    | Ed25519 verify fails on first byte change.                       |
| Trusted private key leaked                              | rotate by editing `PROVIDER_PUBLIC_KEYS` and shipping a new      |
|                                                         | cryptotensors release. No revocation channel.                    |
| Memory attacks after load (rooted attacker)             | out of scope — once a provider returns a key, it lives in        |
|                                                         | process memory and a debugger can pull it.                       |
| Cdylib calls back into cryptotensors with a forged path | the registry doesn't accept loads from inside provider code;     |
|                                                         | initialize is the only entry the cdylib gets.                    |

The loader is a **trust boundary**, not a sandbox. After step 5
succeeds, the cdylib runs with full process privileges. Don't accept
provider crates from anyone whose private key you haven't audited the
provenance of.

---

## 7. Future work

- A way to register a trusted pubkey at *install time* rather than
  *compile time*, gated by a separate signed `trusted.json` whose
  vetting key is itself compiled in. (The provider-resultscloud-license
  repo's `CRYPTOTENSOR_TRUSTED_PROVIDERS_FILE` is an early sketch of
  this — but the runtime currently reads pubkeys only from
  `PROVIDER_PUBLIC_KEYS`.)
- Versioning the cdylib ABI explicitly (a `cryptotensors_provider_abi_version`
  symbol the loader could check) so that mismatched cryptotensors and
  provider versions fail loudly instead of through trait-object UB.
- Non-Python bindings (C, Go) for the loader — the API is already
  shaped for them; what's missing is the FFI surface.
