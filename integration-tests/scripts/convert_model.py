#!/usr/bin/env python3
"""
Convert a safetensors model to an encrypted cryptotensors model.

Three input modes for the keys:

1. **ResultsCloud license-cli workflow (recommended)** — two separate files:

       python convert_model.py --model Qwen/Qwen2-0.5B \
           --output ./encrypted \
           --dek         /secure/dek.jwk              \
           --vendor-priv /secure/vendor_sign.priv.jwk \
           --encrypt-all

   `dek.jwk` is produced by `resultscloud-license-cli gen-dek` and
   MUST be the same file whose `k` bytes are later embedded in a
   license.jwt — otherwise customers decrypting with the license get
   a kid match but the AEAD tag fails. `vendor_sign.priv.jwk` comes
   from `resultscloud-license-cli gen-vendor-key`.

2. **Legacy JWK-set file** — a JSON file containing a
   `{"keys": [oct_jwk, okp_jwk]}` pair, e.g. produced by
   `integration-tests/utils/write_jwk.py`:

       python convert_model.py --model ... --output ... \
           --key-file /path/to/keys.jwk

3. **No key file** — falls back to the built-in deterministic test
   keys from `utils/write_jwk.py`. Useful for local smoke tests where
   you just want to see that encryption runs; not suitable for any
   real deployment because the keys are public.

### alg field normalisation

cryptotensors' `EncryptionAlgorithm::from_str` in Rust accepts
`aes128gcm` / `aes256gcm` / `chacha20poly1305`, and
`SignatureAlgorithm::from_str` accepts `ed25519` (case-insensitive,
hyphens ignored) — not the JOSE-standard names `A128GCM` / `A256GCM`
/ `EdDSA` that resultscloud-license-cli writes out. This script
translates on the way in so the rest of the pipeline stays purely
JOSE-compliant and only the on-disk tensor header sees
cryptotensors' preferred names.
"""

import argparse
import json
import os
import random
import shutil
import sys
from pathlib import Path
from typing import Optional

# Ensure we can import from utils directory
# Try multiple possible paths (for local and Docker environments)
utils_paths = [
    Path("/app/utils"),  # Docker: /app/utils (copied directly)
    Path(__file__).parent.parent / "utils",  # Local: integration-tests/utils
    Path("/app/src/integration-tests/utils"),  # Docker: /app/src/integration-tests/utils
    Path("/app/integration-tests/utils"),  # Alternative Docker path
]

for utils_path in utils_paths:
    if utils_path.exists():
        sys.path.insert(0, str(utils_path))
        break

from write_jwk import generate_test_keys


# ----- alg-name compatibility shim ---------------------------------------
# Maps JOSE-standard alg names (what resultscloud-license-cli emits) to
# the forms cryptotensors' Rust parsers accept. Other values pass through
# unchanged so hand-written JWKs using the cryptotensors-native names
# (`aes256gcm`, `ed25519`) are also fine.
_ALG_ALIASES = {
    "A128GCM": "aes128gcm",
    "A192GCM": "aes192gcm",  # not used today but cheap to list
    "A256GCM": "aes256gcm",
    "CHACHA20-POLY1305": "chacha20poly1305",
    "EDDSA": "ed25519",
}


def _normalize_alg(jwk: dict, kind: str) -> dict:
    """Return a shallow copy of `jwk` with `alg` translated for cryptotensors.

    `kind` is "enc" or "sign"; used only for a clearer error message.
    """
    alg_raw = jwk.get("alg")
    if alg_raw is None:
        raise ValueError(f"{kind} JWK is missing the 'alg' field")
    alg_key = str(alg_raw).upper()
    mapped = _ALG_ALIASES.get(alg_key, alg_raw)
    if mapped != alg_raw:
        print(f"  normalising {kind}_key alg: {alg_raw!r} -> {mapped!r}")
    out = dict(jwk)
    out["alg"] = mapped
    return out


# ----- JWK loaders --------------------------------------------------------
def _load_single_jwk(path: Path, *, required_kty: str, label: str) -> dict:
    """Load a single-JWK file (NOT a {"keys": [...]} set) and sanity-check it."""
    with open(path) as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"{label} ({path}) must contain a single JWK object")
    if obj.get("kty") != required_kty:
        raise ValueError(
            f"{label} ({path}) must have kty={required_kty!r}, "
            f"got {obj.get('kty')!r}"
        )
    if not obj.get("kid"):
        raise ValueError(
            f"{label} ({path}) must have a non-empty 'kid' — this is what "
            "LicenseProvider matches against at decrypt time"
        )
    return obj


def _load_jwk_set(path: Path) -> tuple[dict, dict]:
    """Load a legacy {"keys": [enc_jwk, sign_jwk]} file."""
    with open(path) as f:
        obj = json.load(f)
    keys = obj.get("keys") if isinstance(obj, dict) else None
    if not isinstance(keys, list):
        raise ValueError(f"{path} is not a JWK set ({{'keys': [...]}} format)")
    enc = next((k for k in keys if k.get("kty") == "oct"), None)
    sign = next((k for k in keys if k.get("kty") == "okp"), None)
    if enc is None or sign is None:
        raise ValueError(
            f"{path} must contain one oct (enc) key and one okp (sign) key"
        )
    return enc, sign


def _resolve_keys_from_paths(
    dek: Optional[str],
    vendor_priv: Optional[str],
    key_file: Optional[str],
) -> tuple[dict, dict]:
    """Pick the right loader and apply alg normalisation.

    Resolution order — *exactly* one of these three cases fires:

      1. `dek` AND `vendor_priv` both given → license-cli workflow.
      2. `key_file` given (and exists on disk) → legacy JWK-set path.
      3. Neither → fall back to the built-in deterministic test keys.

    Callers that want to reject the fallback (production pipelines)
    should validate their args *before* calling this.
    """
    if dek or vendor_priv:
        if not (dek and vendor_priv):
            raise ValueError("--dek and --vendor-priv must be provided together")
        enc_key = _load_single_jwk(Path(dek), required_kty="oct", label="--dek")
        sign_key = _load_single_jwk(
            Path(vendor_priv), required_kty="okp", label="--vendor-priv"
        )
        print(
            "Using license-cli-produced keys: "
            f"dek kid={enc_key['kid']!r}, vendor sign kid={sign_key['kid']!r}"
        )
    elif key_file and os.path.exists(key_file):
        enc_key, sign_key = _load_jwk_set(Path(key_file))
        print(
            f"Using JWK set from {key_file}: "
            f"enc kid={enc_key.get('kid')!r}, sign kid={sign_key.get('kid')!r}"
        )
    else:
        enc_key, sign_key = generate_test_keys()
        print("Using built-in deterministic TEST keys (NOT for production).")

    return _normalize_alg(enc_key, "enc"), _normalize_alg(sign_key, "sign")


# ----- model walking ------------------------------------------------------
def find_safetensors_files(model_dir: Path) -> list[Path]:
    """Find all safetensors files in a model directory."""
    files = list(model_dir.glob("*.safetensors"))
    if not files:
        files = list(model_dir.glob("model-*.safetensors"))
    return sorted(files)


def convert_model(
    model_path: str,
    output_path: str,
    *,
    dek: Optional[str] = None,
    vendor_priv: Optional[str] = None,
    key_file: Optional[str] = None,
    encrypt_ratio: float = 0.1,
    encrypt_all: bool = False,
) -> str:
    """Convert a safetensors model to encrypted cryptotensors format.

    Programmatic API consumed by `convert_and_save.py` and
    `run_full_test.py`. For CLI use, see `main()` below.

    Args:
        model_path: HuggingFace model ID or local directory.
        output_path: Directory to write the encrypted model into.
        dek / vendor_priv: license-cli workflow key files
            (single-JWK each; see module docstring). Must be provided
            together or not at all.
        key_file: Legacy JWK-set file path. Mutually exclusive with
            `dek` / `vendor_priv`.
        encrypt_ratio: Fraction of tensors to encrypt when not
            `encrypt_all`. Ignored when `encrypt_all=True`.
        encrypt_all: Encrypt every tensor.

    Returns:
        Absolute path of the output directory on success.
    """
    from cryptotensors.torch import load_file, save_file
    from huggingface_hub import snapshot_download

    # Download model if it's a HuggingFace ID
    if not os.path.exists(model_path):
        print(f"Downloading model from HuggingFace: {model_path}")
        model_dir = Path(snapshot_download(model_path))
    else:
        model_dir = Path(model_path)

    print(f"Model directory: {model_dir}")

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Copy non-safetensors files (config, tokenizer, etc.)
    for f in model_dir.iterdir():
        if f.is_file() and not f.name.endswith(".safetensors"):
            dest = output_dir / f.name
            if not dest.exists():
                shutil.copy2(f, dest)
                print(f"Copied: {f.name}")

    safetensors_files = find_safetensors_files(model_dir)
    if not safetensors_files:
        raise FileNotFoundError(f"No safetensors files found in {model_dir}")
    print(f"Found {len(safetensors_files)} safetensors file(s)")

    enc_key, sign_key = _resolve_keys_from_paths(dek, vendor_priv, key_file)

    for sf_file in safetensors_files:
        print(f"\nProcessing: {sf_file.name}")

        tensors = load_file(str(sf_file))
        tensor_names = list(tensors.keys())
        print(f"  Total tensors: {len(tensor_names)}")

        if encrypt_all:
            tensors_to_encrypt = tensor_names
        else:
            num_to_encrypt = max(1, int(len(tensor_names) * encrypt_ratio))
            tensors_to_encrypt = random.sample(tensor_names, num_to_encrypt)

        print(f"  Encrypting {len(tensors_to_encrypt)} tensors:")
        for name in tensors_to_encrypt[:5]:
            print(f"    - {name}")
        if len(tensors_to_encrypt) > 5:
            print(f"    ... and {len(tensors_to_encrypt) - 5} more")

        config = {
            "tensors": tensors_to_encrypt,
            "enc_key": enc_key,
            "sign_key": sign_key,
        }
        metadata = {"format": "pt"}

        output_file = output_dir / sf_file.name
        save_file(tensors, str(output_file), config=config, metadata=metadata)
        print(f"  Saved: {output_file}")

    print(f"\nEncrypted model saved to: {output_dir}")
    return str(output_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Convert safetensors model to encrypted cryptotensors format"
    )
    parser.add_argument(
        "--model", "-m",
        required=True,
        help="HuggingFace model ID or local path",
    )
    parser.add_argument(
        "--output", "-o",
        required=True,
        help="Output directory for encrypted model",
    )
    parser.add_argument(
        "--encrypt-ratio",
        type=float,
        default=0.1,
        help="Ratio of tensors to encrypt (0.0-1.0, default: 0.1). "
             "Ignored when --encrypt-all is set.",
    )
    parser.add_argument(
        "--encrypt-all",
        action="store_true",
        help="Encrypt every tensor in the model, not just a sampled subset",
    )

    # Mode-1 args (resultscloud license-cli workflow)
    parser.add_argument(
        "--dek",
        help="Path to the symmetric DEK JWK produced by "
             "`resultscloud-license-cli gen-dek`. The SAME file whose bytes "
             "will be embedded in license.jwt; otherwise customers get a "
             "kid match but AEAD tag failure at decrypt time.",
    )
    parser.add_argument(
        "--vendor-priv",
        help="Path to the Ed25519 private JWK produced by "
             "`resultscloud-license-cli gen-vendor-key`. Used to sign the "
             "tensor header.",
    )

    # Mode-2 arg (legacy JWK-set file)
    parser.add_argument(
        "--key-file",
        help="Path to a legacy {'keys': [oct_jwk, okp_jwk]} JSON file. "
             "Mutually exclusive with --dek / --vendor-priv.",
    )

    args = parser.parse_args()

    # Conflict detection
    using_licensecli = bool(args.dek or args.vendor_priv)
    if using_licensecli and args.key_file:
        parser.error(
            "--key-file cannot be combined with --dek / --vendor-priv; "
            "pick one key-input mode."
        )

    try:
        convert_model(
            model_path=args.model,
            output_path=args.output,
            dek=args.dek,
            vendor_priv=args.vendor_priv,
            key_file=args.key_file,
            encrypt_ratio=args.encrypt_ratio,
            encrypt_all=args.encrypt_all,
        )
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
