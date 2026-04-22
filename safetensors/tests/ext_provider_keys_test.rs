//! Integration tests for the extensible provider public key whitelist
//! (fork-only feature, v0.2.3-ext).
//!
//! See `safetensors/src/registry.rs` — these tests drive `resolve_provider_pubkey`
//! via the public API and cover the full matrix of extension configuration
//! sources (config file + env var) plus their failure modes.
//!
//! IMPORTANT: every test mutates process-global env vars, so they must run
//! serially. The shared `TEST_ENV_LOCK` + `EnvGuard` RAII wrapper enforces
//! that, and restores a clean env on drop so tests are order-independent.

use cryptotensors::registry::resolve_provider_pubkey;
use once_cell::sync::Lazy;
use std::io::Write;
use std::sync::Mutex;
use tempfile::NamedTempFile;

static TEST_ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

const FILE_ENV: &str = "CRYPTOTENSOR_TRUSTED_PROVIDERS_FILE";
const INLINE_ENV: &str = "CRYPTOTENSOR_TRUSTED_PROVIDER_PUBKEYS";

const BUILTIN_NAME: &str = "koalavault-vllm";
const BUILTIN_PUBKEY: &str = "vM5cRuHaIyKt3RAELcqc4+nXbSbCh53ABYt2/lOGqw8=";

// Two arbitrary, distinct, syntactically-valid Ed25519 pubkeys (32 bytes each).
const EXT_PUBKEY_A: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const EXT_PUBKEY_B: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=";

/// RAII guard: holds the global lock and clears both env vars, so every
/// test starts from a known-clean state and can't leak state to its peers.
struct EnvGuard<'a> {
    _lock: std::sync::MutexGuard<'a, ()>,
}

impl<'a> EnvGuard<'a> {
    fn new() -> Self {
        let lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(FILE_ENV);
        std::env::remove_var(INLINE_ENV);
        Self { _lock: lock }
    }
}

impl<'a> Drop for EnvGuard<'a> {
    fn drop(&mut self) {
        std::env::remove_var(FILE_ENV);
        std::env::remove_var(INLINE_ENV);
    }
}

/// Write a trusted-providers JSON file to a tempfile and return its path.
/// The file is retained via the returned `NamedTempFile` (caller must keep it alive).
fn write_trusted_file(body: &str) -> NamedTempFile {
    let mut tmp = NamedTempFile::new().expect("create tempfile");
    tmp.write_all(body.as_bytes()).expect("write tempfile");
    tmp.flush().expect("flush tempfile");
    tmp
}

// ---------------------------------------------------------------------------
// 1. No configuration: behavior identical to upstream v0.2.3.
// ---------------------------------------------------------------------------
#[test]
fn no_config_builtin_still_works() {
    let _g = EnvGuard::new();

    // Built-in provider resolves.
    let resolved = resolve_provider_pubkey(BUILTIN_NAME).expect("resolve must not error");
    assert_eq!(resolved.as_deref(), Some(BUILTIN_PUBKEY));

    // Unknown provider returns None (not an error).
    let unknown = resolve_provider_pubkey("definitely-not-registered").expect("no error");
    assert!(unknown.is_none());
}

// ---------------------------------------------------------------------------
// 2. JSON config file: a matching extension entry resolves.
// ---------------------------------------------------------------------------
#[test]
fn json_config_loads_extension_pubkey() {
    let _g = EnvGuard::new();

    let body = format!(
        r#"{{ "providers": [ {{ "name": "resultscloud-license", "pubkey": "{}" }} ] }}"#,
        EXT_PUBKEY_A
    );
    let tmp = write_trusted_file(&body);
    std::env::set_var(FILE_ENV, tmp.path());

    let resolved = resolve_provider_pubkey("resultscloud-license").expect("resolve must not error");
    assert_eq!(resolved.as_deref(), Some(EXT_PUBKEY_A));

    // Unknown still returns None.
    assert!(resolve_provider_pubkey("unknown").expect("no error").is_none());
}

// ---------------------------------------------------------------------------
// 3. JSON config with malformed base64 pubkey is rejected.
//    (This exercises the same validation path that protects against
//    operator-side mis-configuration — a stand-in for the "pubkey does not
//    match" class of failures, which at the verify_library_signature layer
//    is covered by the upstream regression tests we leave untouched.)
// ---------------------------------------------------------------------------
#[test]
fn json_config_with_invalid_pubkey_errors() {
    let _g = EnvGuard::new();

    let body = r#"{ "providers": [ { "name": "bad-provider", "pubkey": "this-is-not-base64!!" } ] }"#;
    let tmp = write_trusted_file(body);
    std::env::set_var(FILE_ENV, tmp.path());

    let err = resolve_provider_pubkey("bad-provider").expect_err("invalid base64 must error");
    let msg = format!("{}", err);
    assert!(
        msg.contains("Invalid base64") || msg.contains("base64"),
        "error should mention base64, got: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// 4. Env var (inline) config: a matching extension entry resolves.
// ---------------------------------------------------------------------------
#[test]
fn env_var_loads_extension_pubkey() {
    let _g = EnvGuard::new();

    std::env::set_var(
        INLINE_ENV,
        format!("resultscloud-license={}", EXT_PUBKEY_A),
    );

    let resolved = resolve_provider_pubkey("resultscloud-license").expect("resolve must not error");
    assert_eq!(resolved.as_deref(), Some(EXT_PUBKEY_A));
}

// ---------------------------------------------------------------------------
// 5. Conflict between config file and env var (same name, different pubkey)
//    → resolve fails loudly. Same name + same pubkey is fine (idempotent).
// ---------------------------------------------------------------------------
#[test]
fn file_and_env_conflict_errors() {
    let _g = EnvGuard::new();

    // File says pubkey A; env var says pubkey B.
    let body = format!(
        r#"{{ "providers": [ {{ "name": "resultscloud-license", "pubkey": "{}" }} ] }}"#,
        EXT_PUBKEY_A
    );
    let tmp = write_trusted_file(&body);
    std::env::set_var(FILE_ENV, tmp.path());
    std::env::set_var(
        INLINE_ENV,
        format!("resultscloud-license={}", EXT_PUBKEY_B),
    );

    let err = resolve_provider_pubkey("resultscloud-license")
        .expect_err("conflict must surface as an error");
    let msg = format!("{}", err);
    assert!(
        msg.contains("Conflicting") && msg.contains("resultscloud-license"),
        "error should cite the conflicting name; got: {}",
        msg
    );

    // --- sanity: same pubkey in both sources is NOT an error ---
    std::env::set_var(
        INLINE_ENV,
        format!("resultscloud-license={}", EXT_PUBKEY_A),
    );
    let resolved =
        resolve_provider_pubkey("resultscloud-license").expect("consistent duplicate must not error");
    assert_eq!(resolved.as_deref(), Some(EXT_PUBKEY_A));
}

// ---------------------------------------------------------------------------
// 6. World-writable config file is refused (Unix only).
//    On non-Unix platforms this check is a no-op, so we skip the test.
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[test]
fn world_writable_config_file_refused() {
    use std::os::unix::fs::PermissionsExt;
    let _g = EnvGuard::new();

    let body = format!(
        r#"{{ "providers": [ {{ "name": "resultscloud-license", "pubkey": "{}" }} ] }}"#,
        EXT_PUBKEY_A
    );
    let tmp = write_trusted_file(&body);

    // Set mode 0666 — world-writable.
    let mut perms = std::fs::metadata(tmp.path()).unwrap().permissions();
    perms.set_mode(0o666);
    std::fs::set_permissions(tmp.path(), perms).unwrap();

    std::env::set_var(FILE_ENV, tmp.path());

    let err = resolve_provider_pubkey("resultscloud-license")
        .expect_err("world-writable file must be refused");
    let msg = format!("{}", err);
    assert!(
        msg.contains("world-writable"),
        "error should mention world-writable, got: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// 7. Built-in wins: an extension cannot override a built-in name. Even if
//    the user tries to re-define "koalavault-vllm" with a different pubkey,
//    resolve still returns the built-in value.
// ---------------------------------------------------------------------------
#[test]
fn extension_cannot_override_builtin() {
    let _g = EnvGuard::new();

    std::env::set_var(INLINE_ENV, format!("{}={}", BUILTIN_NAME, EXT_PUBKEY_A));

    let resolved = resolve_provider_pubkey(BUILTIN_NAME).expect("resolve must not error");
    // Built-in pubkey, NOT the EXT_PUBKEY_A we tried to inject.
    assert_eq!(resolved.as_deref(), Some(BUILTIN_PUBKEY));
    assert_ne!(resolved.as_deref(), Some(EXT_PUBKEY_A));
}
