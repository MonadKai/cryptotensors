#!/usr/bin/env python3
"""
Full integration test (upstream FileKeyProvider path).

Chains `convert_model → load_and_test` so one command exercises:

    HuggingFace → encrypt → save → load with transformers → compare

**Scope**: this script tests the **legacy / upstream FileKeyProvider**
workflow, because `load_and_test.py` uses a transformers `pipeline`
which resolves the DEK through `CRYPTOTENSOR_KEY_JKU` + `jku` metadata
in the encrypted header. That's NOT the ResultsCloud license workflow
(which goes through `LicenseProvider` and a `license.jwt`); for that,
see `resultscloud_e2e.py` in this same directory.

Usage:
    python run_full_test.py --model Qwen/Qwen2-0.5B
"""

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

# Ensure we can import convert_model / load_and_test from this directory.
sys.path.insert(0, str(Path(__file__).parent))

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
from load_and_test import run_test


def main() -> bool:
    parser = argparse.ArgumentParser(
        description="Run full integration test: convert -> save -> load -> compare "
                    "(upstream FileKeyProvider path)"
    )
    parser.add_argument(
        "--model", "-m",
        default="Qwen/Qwen2-0.5B",
        help="HuggingFace model ID (default: Qwen/Qwen2-0.5B)",
    )
    parser.add_argument(
        "--encrypt-all",
        action="store_true",
        help="Encrypt all tensors (default: --encrypt-ratio of them)",
    )
    parser.add_argument(
        "--encrypt-ratio",
        type=float,
        default=0.3,
        help="Ratio of tensors to encrypt (0.0-1.0, default: 0.3)",
    )
    parser.add_argument(
        "--save-path",
        default=None,
        help="Persistent output dir for the encrypted model. "
             "Default: an auto-cleaned temp directory.",
    )
    parser.add_argument(
        "--key-file",
        help="Legacy JWK-set file (enc+sign pair). Falls back to built-in "
             "test keys when omitted.",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("CryptoTensors Full Integration Test (upstream FileKeyProvider)")
    print("=" * 60)
    print(f"Model: {args.model}")
    print()

    if args.save_path:
        encrypted_model_path = args.save_path
        temp_dir = None
    else:
        temp_dir = tempfile.mkdtemp(prefix="cryptotensors_test_")
        encrypted_model_path = os.path.join(temp_dir, "encrypted_model")
        print(f"Using temporary directory: {temp_dir}")

    try:
        # Step 1: Convert and save
        print("\n" + "=" * 60)
        print("Step 1: Convert model to encrypted format")
        print("=" * 60)
        output_path = convert_model(
            model_path=args.model,
            output_path=encrypted_model_path,
            key_file=args.key_file,
            encrypt_ratio=args.encrypt_ratio,
            encrypt_all=args.encrypt_all,
        )
        print(f"\nEncrypted model saved to: {output_path}")

        # Step 2: Load and compare
        print("\n" + "=" * 60)
        print("Step 2: Load encrypted model and compare with original")
        print("=" * 60)
        success = run_test(model_id=args.model, encrypted_model_path=output_path)

        print("\n" + "=" * 60)
        print(f"Full integration test {'PASSED' if success else 'FAILED'}")
        print("=" * 60)
        return success

    except Exception as e:
        print(f"\nTest failed with error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return False
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
