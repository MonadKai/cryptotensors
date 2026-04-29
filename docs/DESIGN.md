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

When `load_provider_native(lib_path, config_json)` runs, it does six
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
│ 4. dlsym `cryptotensors_provider_abi_version`, call it, compare     │
│    against CRYPTOTENSORS_PROVIDER_ABI_VERSION. Mismatch (or symbol  │
│    missing on a pre-handshake cdylib) → reject with                 │
│       "Provider ABI version mismatch".                              │
│    This guard runs BEFORE we instantiate anything from the cdylib,  │
│    because doing so on a vtable-incompatible build is undefined     │
│    behaviour.                                                       │
│                                                                     │
│ 5. dlsym `cryptotensors_create_provider`, call it, take ownership   │
│    of the returned Box<dyn KeyProvider>, run                        │
│    provider.initialize(config_json).                                │
│                                                                     │
│ 6. Cross-check: if provider.name() != trusted_name, reject with     │
│       "Provider name mismatch: cdylib reports X, signing key is Y". │
│    Otherwise register it at PRIORITY_NATIVE.                        │
└─────────────────────────────────────────────────────────────────────┘
```

The two-step identity binding (step 2 + step 6) is the load-bearing
trust property:

- **Step 2** says "this binary was signed by someone we trust." It
  doesn't yet say *who* among the trusted set.
- **Step 6** says "the cdylib self-reports as the same identity that
  the signing key is registered under." A keypair holder cannot ship
  a cdylib that masquerades as some other provider — the name has to
  match the row in the table that pubkey lives in.

Trying every pubkey in the table (rather than indexing by a
caller-supplied name) is what removes the name parameter from the
loader. The table is hardcoded at compile time and has < 10 entries in
practice, so the linear scan costs microseconds.

Step 4 — the **ABI handshake** — is a separate kind of safety check.
The cdylib and runtime both depend on `cryptotensors`, and
`cryptotensors_create_provider` returns a `*mut dyn KeyProvider` whose
vtable layout depends on whatever cryptotensors version each side was
compiled against. If those versions disagree on the trait's method
table, calling any method through the trait object is UB. The
handshake symbol forwards `CRYPTOTENSORS_PROVIDER_ABI_VERSION` from
the cdylib's compiled-in cryptotensors crate; the runtime compares it
to its own constant; mismatched versions abort cleanly here. Bump the
constant on every breaking change to the `KeyProvider` trait or the
extern signatures.

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
# Canonical, language-agnostic — Rust does all the trust work.
def init_key_provider(lib_path: str, **config) -> None: ...
def list_key_providers() -> list[str]: ...           # what's loaded right now
def disable_provider(name: str) -> None: ...

# Python-only convenience layer over entry_points discovery.
def init_key_provider_by_name(name: str, **config) -> None: ...
def list_installed_providers() -> list[str]: ...     # what's installable

# in-process direct registration (separate path, no cdylib):
def register_direct_key_provider(*, files=None, keys=None) -> None: ...
```

`init_key_provider` returns `None` on success and raises on any of:
sig file missing, sig verification failure, library open failure,
missing `cryptotensors_provider_abi_version` symbol or version
mismatch, missing `cryptotensors_create_provider` symbol,
`initialize()` failure, or the step-6 name mismatch.

`list_key_providers` returns the names of currently-registered, enabled
providers in priority order (highest first). It reflects the Rust
registry, not "what's installable in the venv."

#### The convenience layer is not a trust channel

`init_key_provider_by_name` and `list_installed_providers` both read
the `cryptotensors.providers` entry_points group. **That group is a
catalog, not a trust signal.** A provider package can declare an
entry_point with any name; the runtime never trusts the name. Trust
is decided exclusively in step 2 of the loader (signature verifies
against a compile-time-blessed key) and step 6 (cdylib's self-reported
name matches the trusted name). The convenience layer's only job is
"Python user typed a string, find the corresponding `.so` path on
disk, hand it to the real loader." If you delete the entry_points
declaration from a provider package, that package becomes invisible
to `list_installed_providers` / `init_key_provider_by_name` but
remains perfectly loadable via `init_key_provider(<explicit path>)` —
trust is unaffected.

This explicit non-coupling is what lets non-Python callers bypass the
convenience layer entirely. A Go sidecar, a CLI, a C embedding all
talk to the Rust loader directly with a path string and never touch
entry_points.

---

## 5. Provider package contract

A package that wants to ship a cdylib for cryptotensors needs to:

1. **Build a `cdylib` Rust crate** that exports two symbols:
   - `extern "C" fn cryptotensors_create_provider() -> *mut dyn KeyProvider`
     — the factory the loader calls in step 5.
   - `extern "C" fn cryptotensors_provider_abi_version() -> u32` —
     should forward `cryptotensors::CRYPTOTENSORS_PROVIDER_ABI_VERSION`
     from the cryptotensors crate it depends on. The runtime reads
     this in step 4 of the load sequence and rejects the cdylib if it
     doesn't match its own constant.

   Linked against the same `cryptotensors` major version that runtime
   users will deploy. The ABI handshake will catch most mismatches at
   load time, but a deliberately-faked version number would still let
   you build something that passes the handshake and then UBs on the
   first trait-method call — don't do that.

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
| Cdylib signed correctly but name forged                 | step 6: cdylib's `provider.name()` ≠ trusted name → reject.      |
| Cdylib built against an incompatible cryptotensors ver  | step 4: `cryptotensors_provider_abi_version` mismatch → reject  |
|                                                         | before any trait-object call.                                    |
| Caller passes a *path* to a different blessed cdylib    | out of scope at the loader; the caller chose the path.           |
| Tampered `<lib>.sig`                                    | Ed25519 verify fails on first byte change.                       |
| Trusted private key leaked                              | rotate by editing `PROVIDER_PUBLIC_KEYS` and shipping a new      |
|                                                         | cryptotensors release. No revocation channel.                    |
| Memory attacks after load (rooted attacker)             | out of scope — once a provider returns a key, it lives in        |
|                                                         | process memory and a debugger can pull it.                       |
| Cdylib calls back into cryptotensors with a forged path | the registry doesn't accept loads from inside provider code;     |
|                                                         | initialize is the only entry the cdylib gets.                    |

The loader is a **trust boundary**, not a sandbox. After step 6
succeeds, the cdylib runs with full process privileges. Don't accept
provider crates from anyone whose private key you haven't audited the
provenance of.

---

## 7. Future work

- **Install-time signed trust file**: replace cryptotensors'
  compile-time `PROVIDER_PUBLIC_KEYS` with a signed `trusted.json`
  whose vetting-of-vetting key is itself compiled in. That would let
  us enroll new providers without releasing a new cryptotensors
  wheel. Sketch of the structure:
  - cryptotensors compiles in a single **vetting pubkey** instead of a
    table of provider pubkeys.
  - At runtime, cryptotensors reads `trusted.json` from a known path
    (env var or fixed location), verifies its signature against the
    vetting pubkey, and uses its contents as the table of trusted
    provider pubkeys (i.e. takes over the role of today's
    `PROVIDER_PUBLIC_KEYS`).
  - Adding a new provider to the ecosystem becomes "ship a signed
    `trusted.json` row," not "release a new cryptotensors version."
  - Vetting pubkey rotation still requires a cryptotensors release,
    but it's a much rarer event than provider enrolment.
- **Non-Python bindings** (C, Go) for the loader — the API is already
  shaped for them; what's missing is the FFI surface and an example
  callsite. The hardest part (language-agnostic discovery) is solved;
  the remaining work is mechanical.
