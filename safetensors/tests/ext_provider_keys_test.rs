//! Fork-local integration tests for cryptotensors v0.2.3-ext.
//!
//! Covers two independently-added features:
//!   1. The runtime-extensible provider public key whitelist (this file's
//!      original content).
//!   2. JWK field decoding that accepts both padded-standard-base64 and
//!      unpadded-base64url — see `jwk_b64_accepts_url_safe_unpadded` and
//!      friends at the bottom.
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

// ---------------------------------------------------------------------------
// JWK base64 dialect tolerance (v0.2.3-ext, second batch).
//
// RFC 7517 says JWK `k`/`x`/`d` fields are unpadded base64url. Upstream
// cryptotensors decodes them with padded STANDARD base64, which silently
// rejects any standards-compliant JWK. The fork's `decode_jwk_b64`
// helper accepts both dialects — test both ends of that through the
// public `KeyMaterial` constructors.
// ---------------------------------------------------------------------------

use base64::engine::general_purpose::{STANDARD as _B64_STD, URL_SAFE_NO_PAD as _B64_URL};
use base64::Engine as _;
use cryptotensors::key::KeyMaterial;

#[test]
fn enc_key_accepts_padded_standard_base64() {
    // 32 bytes of deterministic key material.
    let raw: [u8; 32] = [0xAB; 32];
    let k_std = _B64_STD.encode(raw);           // padded, `+/`
    let km = KeyMaterial::new_enc_key(
        Some(k_std),
        Some("aes256gcm".into()),
        Some("test-std".into()),
        None,
    )
    .expect("KeyMaterial must parse padded standard base64");
    assert_eq!(km.get_master_key_bytes().unwrap(), raw.to_vec());
}

#[test]
fn enc_key_accepts_unpadded_base64url() {
    let raw: [u8; 32] = [0xCD; 32];
    // Simulate what resultscloud-license-cli (RFC 7517-compliant) emits:
    // URL_SAFE alphabet, no `=` padding.
    let k_url = _B64_URL.encode(raw);
    assert!(!k_url.contains('='), "precondition: unpadded");
    let km = KeyMaterial::new_enc_key(
        Some(k_url),
        Some("aes256gcm".into()),
        Some("test-url".into()),
        None,
    )
    .expect("KeyMaterial must parse unpadded base64url");
    assert_eq!(km.get_master_key_bytes().unwrap(), raw.to_vec());
}

#[test]
fn sign_key_accepts_unpadded_base64url_on_both_x_and_d() {
    let priv_raw: [u8; 32] = [0x11; 32];
    // Derive pub from priv so the kp is internally consistent.
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&priv_raw).unwrap();
    let pub_raw = ring::signature::KeyPair::public_key(&kp).as_ref().to_vec();

    let km = KeyMaterial::new_sign_key(
        Some(_B64_URL.encode(&pub_raw)),
        Some(_B64_URL.encode(priv_raw)),
        Some("ed25519".into()),
        Some("test-sign-url".into()),
        None,
    )
    .expect("KeyMaterial must parse unpadded base64url for both x and d");
    assert_eq!(km.get_public_key_bytes().unwrap(), pub_raw);
    assert_eq!(km.get_private_key_bytes().unwrap(), priv_raw.to_vec());
}

#[test]
fn truly_invalid_base64_still_errors() {
    // Neither dialect can decode this; must NOT be silently accepted.
    let err = KeyMaterial::new_enc_key(
        Some("this!is?not^valid*base64".into()),
        Some("aes256gcm".into()),
        Some("bad".into()),
        None,
    )
    .expect_err("garbage input must not parse");
    let msg = format!("{}", err);
    assert!(msg.contains("Invalid base64"), "got: {}", msg);
}

// ---------------------------------------------------------------------------
// JOSE alg-name tolerance (v0.2.3-ext, third batch).
//
// RFC 7518 prescribes JOSE header alg names (A128GCM / A256GCM / EdDSA)
// for JWKs. Upstream cryptotensors' parsers only recognised its own
// lowercase names (aes256gcm / ed25519). JOSE-compliant tooling (our
// resultscloud-license-cli among them) therefore produced JWKs that the
// runtime rejected with "InvalidAlgorithm" at the first attempt to
// build a KeyMaterial. The fork now accepts both forms.
// ---------------------------------------------------------------------------

use cryptotensors::encryption::EncryptionAlgorithm;
use cryptotensors::signing::SignatureAlgorithm;

#[test]
fn enc_alg_accepts_jose_short_names() {
    assert_eq!(
        "A128GCM".parse::<EncryptionAlgorithm>().unwrap(),
        EncryptionAlgorithm::Aes128Gcm
    );
    assert_eq!(
        "A256GCM".parse::<EncryptionAlgorithm>().unwrap(),
        EncryptionAlgorithm::Aes256Gcm
    );
    // Lower-case JOSE names also parse (we normalise case).
    assert_eq!(
        "a256gcm".parse::<EncryptionAlgorithm>().unwrap(),
        EncryptionAlgorithm::Aes256Gcm
    );
}

#[test]
fn enc_alg_keeps_native_names_working() {
    assert_eq!(
        "aes256gcm".parse::<EncryptionAlgorithm>().unwrap(),
        EncryptionAlgorithm::Aes256Gcm
    );
    assert_eq!(
        "AES-256-GCM".parse::<EncryptionAlgorithm>().unwrap(),
        EncryptionAlgorithm::Aes256Gcm
    );
    assert_eq!(
        "chacha20poly1305".parse::<EncryptionAlgorithm>().unwrap(),
        EncryptionAlgorithm::ChaCha20Poly1305
    );
}

#[test]
fn enc_alg_still_rejects_garbage() {
    assert!("not-an-alg".parse::<EncryptionAlgorithm>().is_err());
    assert!("".parse::<EncryptionAlgorithm>().is_err());
    assert!("A192GCM".parse::<EncryptionAlgorithm>().is_err()); // unsupported size
}

#[test]
fn sign_alg_accepts_jose_eddsa_alias() {
    assert_eq!(
        "EdDSA".parse::<SignatureAlgorithm>().unwrap(),
        SignatureAlgorithm::Ed25519
    );
    assert_eq!(
        "EDDSA".parse::<SignatureAlgorithm>().unwrap(),
        SignatureAlgorithm::Ed25519
    );
    assert_eq!(
        "eddsa".parse::<SignatureAlgorithm>().unwrap(),
        SignatureAlgorithm::Ed25519
    );
}

#[test]
fn sign_alg_keeps_native_names_working() {
    assert_eq!(
        "ed25519".parse::<SignatureAlgorithm>().unwrap(),
        SignatureAlgorithm::Ed25519
    );
    assert_eq!(
        "ED25519".parse::<SignatureAlgorithm>().unwrap(),
        SignatureAlgorithm::Ed25519
    );
}
