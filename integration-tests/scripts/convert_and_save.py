#!/usr/bin/env python3
"""
Convert a model to encrypted format and save it.

Thin wrapper around `convert_model.convert_model()` that also prints a
human-friendly banner and routes exceptions through a non-zero exit
code. Two key-input modes, passed through verbatim:

1. **ResultsCloud license-cli workflow**:
       python convert_and_save.py --model ... --output ... \\
           --dek dek.jwk --vendor-priv vendor_sign.priv.jwk --encrypt-all

2. **Legacy JWK-set file** (upstream test fixture):
       python convert_and_save.py --model ... --output ... \\
           --key-file keys.jwk

Defaults (model=`Qwen/Qwen2-0.5B`, output=`/app/models/encrypted`) are
preserved so the upstream Docker flow keeps working unchanged.
"""

import argparse
import os
import sys
from pathlib import Path

# Ensure we can import convert_model from the same directory.
sys.path.insert(0, str(Path(__file__).parent))

# Add utils directory to path (same layout logic as convert_model.py — both
# local and Docker paths are covered)
_utils_candidates = [
    Path("/app/utils"),
    Path(__file__).parent.parent / "utils",
    Path("/app/src/integration-tests/utils"),
    Path("/app/integration-tests/utils"),
]
for _p in _utils_candidates:
    if _p.exists():
        sys.path.insert(0, str(_p))
        break

from convert_model import convert_model


def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Convert model to encrypted format and save"
    )
    parser.add_argument(
        "--model", "-m",
        default="Qwen/Qwen2-0.5B",
        help="HuggingFace model ID to convert (default: Qwen/Qwen2-0.5B)",
    )
    parser.add_argument(
        "--output", "-o",
        default="/app/models/encrypted",
        help="Output directory for encrypted model (default: /app/models/encrypted)",
    )
    parser.add_argument(
        "--encrypt-all",
        action="store_true",
        help="Encrypt all tensors (default: encrypt --encrypt-ratio of them)",
    )
    parser.add_argument(
        "--encrypt-ratio",
        type=float,
        default=0.3,
        help="Ratio of tensors to encrypt (0.0-1.0, default: 0.3)",
    )
    parser.add_argument(
        "--dek",
        help="Path to license-cli-produced DEK JWK (ResultsCloud workflow)",
    )
    parser.add_argument(
        "--vendor-priv",
        help="Path to license-cli-produced Ed25519 private JWK "
             "(ResultsCloud workflow; must pair with --dek)",
    )
    parser.add_argument(
        "--key-file",
        help="Legacy JWK-set file. Mutually exclusive with --dek / --vendor-priv.",
    )

    args = parser.parse_args()

    if (args.dek or args.vendor_priv) and args.key_file:
        parser.error(
            "--key-file cannot be combined with --dek / --vendor-priv; "
            "pick one key-input mode."
        )

    print("=" * 60)
    print("CryptoTensors Model Conversion")
    print("=" * 60)
    print(f"Model       : {args.model}")
    print(f"Output      : {args.output}")
    if args.dek or args.vendor_priv:
        print(f"Key mode    : license-cli (--dek, --vendor-priv)")
    elif args.key_file:
        print(f"Key mode    : legacy JWK-set ({args.key_file})")
    else:
        print(f"Key mode    : built-in test keys (NOT for production)")
    print(f"Encrypt all : {args.encrypt_all}")
    if not args.encrypt_all:
        print(f"Encrypt ratio: {args.encrypt_ratio}")
    print()

    try:
        output_path = convert_model(
            model_path=args.model,
            output_path=args.output,
            dek=args.dek,
            vendor_priv=args.vendor_priv,
            key_file=args.key_file,
            encrypt_ratio=args.encrypt_ratio,
            encrypt_all=args.encrypt_all,
        )
        print("\n" + "=" * 60)
        print("Model conversion completed successfully")
        print(f"  Encrypted model saved to: {output_path}")
        print("=" * 60)
        return True
    except Exception as e:
        print(f"\nFailed to convert model: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
