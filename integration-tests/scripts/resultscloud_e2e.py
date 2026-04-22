#!/usr/bin/env python3
"""
End-to-end smoke for the ResultsCloud license workflow.

Does, in one command:

  1. (optional) generate a throwaway vendor keypair + DEK using
     `resultscloud-license-cli` if `--mint-keys` is passed;
  2. encrypt a model with those keys via
     `convert_model.convert_model(... dek=..., vendor_priv=...)`;
  3. (optional) issue a license bound to the current host and write
     a `trusted.json` snippet;
  4. (optional) exercise cryptotensors' load path against the
     encrypted model, so you catch license/provider bugs BEFORE
     handing the artefacts to vLLM.

It does NOT replace `run_full_test.py` — that one tests the upstream
FileKeyProvider path via transformers. This one tests the Repo B
LicenseProvider path end-to-end without needing vLLM.

Typical usage on a vendor dev host that already has
resultscloud-license-cli and cryptotensors-provider-resultscloud-license
installed:

    python resultscloud_e2e.py \\
        --model Qwen/Qwen2-0.5B \\
        --workdir ./e2e-out \\
        --mint-keys \\
        --issue-license \\
        --verify-load

Leaving off `--mint-keys` expects `--dek` and `--vendor-priv` to point
at pre-existing JWK files (the normal production path).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
_utils_candidates = [
    Path(__file__).parent.parent / "utils",
    Path("/app/utils"),
    Path("/app/integration-tests/utils"),
    Path("/app/src/integration-tests/utils"),
]
for _p in _utils_candidates:
    if _p.exists():
        sys.path.insert(0, str(_p))
        break

from convert_model import convert_model


def _run(cmd: list[str], *, cwd: str | None = None, env_extra: dict | None = None) -> str:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    print(f"$ {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise RuntimeError(f"command failed (exit {proc.returncode}): {' '.join(cmd)}")
    return proc.stdout


def mint_keys(workdir: Path, cli: str) -> tuple[Path, Path, Path]:
    """Run resultscloud-license-cli to mint a fresh vendor keypair + DEK."""
    vendor_dir = workdir / "vendor"
    vendor_dir.mkdir(parents=True, exist_ok=True)
    _run([cli, "gen-vendor-key", "--out", str(vendor_dir), "--kid", "vendor"])
    dek_path = workdir / "dek.jwk"
    _run([cli, "gen-dek", "--alg", "A256GCM", "--kid", "model-v1", "--out", str(dek_path)])
    return (
        dek_path,
        vendor_dir / "vendor_sign.priv.jwk",
        vendor_dir / "vendor_sign.pub.jwk",
    )


def issue_license(
    cli: str,
    dek: Path,
    vendor_priv: Path,
    out_path: Path,
    *,
    days: int,
    customer_id: str,
    machine_id: str | None = None,
) -> None:
    """Call resultscloud-license-cli to bind a license to this host."""
    if machine_id is None:
        machine_id = _run([cli, "fingerprint"]).strip()
        print(f"detected local machine fingerprint: {machine_id}")
    _run(
        [
            cli, "issue",
            "--dek", str(dek),
            "--vendor-priv", str(vendor_priv),
            "--machine-id", machine_id,
            "--days", str(days),
            "--customer-id", customer_id,
            "--out", str(out_path),
        ]
    )


def write_trusted_json(cli: str, vendor_pub: Path, out_path: Path) -> None:
    """Materialise the trusted.json cryptotensors consumes on the customer side."""
    _run(
        [
            cli, "export-pubkey-for-trusted-json",
            "--vendor-pub", str(vendor_pub),
            "--json",
            "--out", str(out_path),
        ]
    )


def verify_load(encrypted_model_dir: Path, license_path: Path, trusted_json: Path) -> bool:
    """Try to decrypt the model locally with the full runtime env set.

    Mimics the customer-side startup: LicenseProvider auto-registers
    (if the .pth hook is installed), DEK flows through, and the first
    encrypted tensor in the model is read back. Any failure here is
    representative of what vLLM would hit.
    """
    env = os.environ.copy()
    env["CRYPTOTENSOR_LICENSE_PATH"] = str(license_path)
    env["CRYPTOTENSOR_TRUSTED_PROVIDERS_FILE"] = str(trusted_json)
    env.setdefault("RESULTSCLOUD_AUTO_REGISTER_DEBUG", "1")

    # Find any .safetensors file inside the encrypted model dir.
    files = sorted(encrypted_model_dir.glob("*.safetensors"))
    if not files:
        files = sorted(encrypted_model_dir.glob("model-*.safetensors"))
    if not files:
        raise FileNotFoundError(f"no safetensors under {encrypted_model_dir}")
    target = files[0]

    # Probe: open header + read one tensor.
    probe = (
        "import os, cryptotensors\n"
        f"cryptotensors.init_key_provider('resultscloud-license')\n"
        "from cryptotensors.torch import load_file\n"
        f"model = load_file({str(target)!r})\n"
        "names = list(model.keys())\n"
        "print('decrypted', len(names), 'tensors, first name:', names[0])\n"
    )
    print(f"\n--- verify-load probe on {target.name} ---")
    result = subprocess.run(
        [sys.executable, "-c", probe],
        env=env,
        capture_output=True,
        text=True,
    )
    print(result.stdout)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr)
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end smoke for the ResultsCloud license workflow"
    )
    parser.add_argument("--model", "-m", default="Qwen/Qwen2-0.5B",
                        help="HuggingFace model ID or local path")
    parser.add_argument("--workdir", "-w", type=Path, default=Path("./rc-e2e-out"),
                        help="Directory that will hold keys, the encrypted model, and the license")
    parser.add_argument("--mint-keys", action="store_true",
                        help="Generate a throwaway vendor keypair + DEK via license-cli "
                             "instead of using --dek / --vendor-priv")
    parser.add_argument("--dek",
                        help="Pre-existing DEK JWK (skipped when --mint-keys)")
    parser.add_argument("--vendor-priv",
                        help="Pre-existing vendor signing JWK (skipped when --mint-keys)")
    parser.add_argument("--vendor-pub",
                        help="Corresponding public JWK; only needed for --issue-license or --verify-load")
    parser.add_argument("--issue-license", action="store_true",
                        help="Invoke license-cli to issue a license bound to this host")
    parser.add_argument("--license-days", type=int, default=30,
                        help="Validity window for the issued license in days (default: 30)")
    parser.add_argument("--customer-id", default="e2e-smoke",
                        help="sub claim for the issued license (default: e2e-smoke)")
    parser.add_argument("--verify-load", action="store_true",
                        help="After encryption + optional license issuance, run a probe that "
                             "decrypts one tensor end-to-end via LicenseProvider")
    parser.add_argument("--license-cli", default="resultscloud-license-cli",
                        help="Path or name of the license-cli executable "
                             "(default: resultscloud-license-cli on PATH)")
    parser.add_argument("--encrypt-all", action="store_true", default=True,
                        help="Encrypt every tensor (default for e2e so the probe always exercises AEAD)")
    parser.add_argument("--keep-workdir", action="store_true",
                        help="Leave --workdir in place on completion (default: keep; there's nothing "
                             "to clean unless you pass --cleanup)")
    parser.add_argument("--cleanup", action="store_true",
                        help="Remove --workdir on success")

    args = parser.parse_args()

    args.workdir = args.workdir.resolve()
    args.workdir.mkdir(parents=True, exist_ok=True)

    # 1. Resolve keys
    if args.mint_keys:
        dek, vendor_priv, vendor_pub = mint_keys(args.workdir, args.license_cli)
    else:
        if not (args.dek and args.vendor_priv):
            parser.error(
                "either pass --mint-keys OR provide both --dek and --vendor-priv"
            )
        dek = Path(args.dek).resolve()
        vendor_priv = Path(args.vendor_priv).resolve()
        vendor_pub = Path(args.vendor_pub).resolve() if args.vendor_pub else None
        if (args.issue_license or args.verify_load) and vendor_pub is None:
            parser.error(
                "--issue-license / --verify-load require --vendor-pub when not using --mint-keys"
            )

    # 2. Encrypt
    encrypted_dir = args.workdir / "encrypted"
    print("\n=== encrypt ===")
    convert_model(
        model_path=args.model,
        output_path=str(encrypted_dir),
        dek=str(dek),
        vendor_priv=str(vendor_priv),
        encrypt_all=args.encrypt_all,
    )

    # 3. Optional: issue a license
    license_path: Path | None = None
    if args.issue_license:
        print("\n=== issue license ===")
        license_path = args.workdir / "license.jwt"
        issue_license(
            args.license_cli,
            dek,
            vendor_priv,
            license_path,
            days=args.license_days,
            customer_id=args.customer_id,
        )

    # 4. Optional: write trusted.json for the runtime
    trusted_json: Path | None = None
    if args.verify_load or args.issue_license:
        if vendor_pub is None:
            print("WARN: no --vendor-pub available, skipping trusted.json emission")
        else:
            print("\n=== write trusted.json ===")
            trusted_json = args.workdir / "trusted.json"
            write_trusted_json(args.license_cli, vendor_pub, trusted_json)

    # 5. Optional: verify a full decrypt works against the live provider
    if args.verify_load:
        if not (license_path and trusted_json):
            print("ERROR: --verify-load requires --issue-license (for license.jwt) "
                  "and a reachable --vendor-pub (for trusted.json)",
                  file=sys.stderr)
            return 1
        print("\n=== verify load ===")
        ok = verify_load(encrypted_dir, license_path, trusted_json)
        print(f"\nverify-load: {'PASS' if ok else 'FAIL'}")
        if not ok:
            return 1

    # 6. Summary
    print("\n=== summary ===")
    print(f"workdir        : {args.workdir}")
    print(f"encrypted model: {encrypted_dir}")
    print(f"DEK            : {dek}")
    print(f"vendor priv    : {vendor_priv}")
    if vendor_pub:
        print(f"vendor pub     : {vendor_pub}")
    if license_path:
        print(f"license        : {license_path}")
    if trusted_json:
        print(f"trusted.json   : {trusted_json}")

    if args.cleanup:
        print(f"\ncleaning up {args.workdir}")
        shutil.rmtree(args.workdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
