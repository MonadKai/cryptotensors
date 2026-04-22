# Integration tests

This directory holds end-to-end scripts for verifying that cryptotensors
encrypts and decrypts real models correctly. There are **two distinct
workflows** exercised here; they share `convert_model.py` but diverge
on how the DEK gets back into the runtime.

```
                                 ┌───────────────────────────────────────────────────┐
                                 │  encryption (shared by both workflows)            │
scripts/convert_model.py  ─────► │  save_file(tensors, config={enc_key, sign_key})  │
                                 └───────────────────────────────────────────────────┘
                                                  │
                                                  ▼
                           ┌──────────────────────┴──────────────────────┐
                           │                                             │
                           ▼                                             ▼
      upstream FileKeyProvider workflow                 ResultsCloud LicenseProvider workflow
      ────────────────────────────────                  ─────────────────────────────────────
      tensor header carries jku="file://..."            tensor header carries only kid="..."
      CRYPTOTENSOR_KEY_JKU points at a JWK set          CRYPTOTENSOR_LICENSE_PATH → license.jwt
      at decrypt, FileKeyProvider reads that file       at decrypt, LicenseProvider extracts the
                                                        DEK from the signed license payload
      ▼                                                 ▼
      run_full_test.py (transformers pipeline)          resultscloud_e2e.py
      Dockerfile.transformers  +  run_tests.sh          (or the manual 3-repo flow)
```

## Which script for which job

| Script                                  | Workflow            | What it does                                                                                  |
| --------------------------------------- | ------------------- | --------------------------------------------------------------------------------------------- |
| `scripts/convert_model.py`              | **both**            | CLI + programmatic `convert_model(...)` function. Accepts license-cli JWKs (`--dek` / `--vendor-priv`), a legacy JWK set (`--key-file`), or falls back to built-in test keys. |
| `scripts/convert_and_save.py`           | **both**            | Thin wrapper around `convert_model` with a human-friendly banner and the default Docker paths. Pass-through for every key-input flag. |
| `scripts/load_and_test.py`              | upstream only       | Transformers `pipeline` loads both the original and encrypted model and diffs outputs. Relies on `CRYPTOTENSOR_KEY_JKU` + the header's `jku`. |
| `scripts/run_full_test.py`              | upstream only       | Chains `convert_model → load_and_test` for a single-command smoke (the one `run_tests.sh` / Docker use by default). |
| `scripts/resultscloud_e2e.py`           | ResultsCloud only   | Optionally mints a throwaway vendor keypair + DEK via `resultscloud-license-cli`, encrypts, issues a license bound to the local machine, emits `trusted.json`, and (with `--verify-load`) probes `LicenseProvider` end-to-end. |
| `utils/write_jwk.py`                    | upstream only       | Writes a deterministic `{keys: [oct, okp]}` JWK set for the test flow.                          |
| `utils/print_metadata.py`               | both                | Standalone debug tool: dumps `__metadata__`, `__encryption__`, `__signature__`, `__policy__` out of any safetensors/cryptotensors file. Handy when investigating mismatched `kid` / `alg` / `jku`. |
| `run_tests.sh` + `Dockerfile.transformers` | upstream only   | Runs `run_full_test.py` inside a pinned Docker image. Use for CI of the core crate, not for the license provider. |

## Quick commands

### Upstream FileKeyProvider (Docker, isolated, verifies encrypt-decrypt transparency)

```bash
./run_tests.sh                          # full build + convert + load + compare
./run_tests.sh --model Qwen/Qwen2-1.5B  # larger model
./run_tests.sh --build-only             # just cache the image
./run_tests.sh --cn                     # PRC mirror
```

Outside Docker, the same flow is:

```bash
python scripts/run_full_test.py --model Qwen/Qwen2-0.5B
```

### ResultsCloud LicenseProvider (requires Repo B + Repo C installed)

Local smoke that mints ephemeral keys, encrypts, and verifies decrypt:

```bash
python scripts/resultscloud_e2e.py \
    --model Qwen/Qwen2-0.5B \
    --workdir ./rc-e2e-out \
    --mint-keys \
    --issue-license \
    --verify-load
```

Using pre-existing vendor keys (the normal production path):

```bash
python scripts/resultscloud_e2e.py \
    --model Qwen/Qwen2-0.5B \
    --workdir ./rc-e2e-out \
    --dek /secure/dek.jwk \
    --vendor-priv /secure/vendor_sign.priv.jwk \
    --vendor-pub /secure/vendor_sign.pub.jwk \
    --issue-license --verify-load
```

Just the encryption step (the command you'd run on a real vendor host
before scp'ing to a customer):

```bash
python scripts/convert_model.py \
    --model /opt/modelscope/hub/models/Qwen/Qwen3-0___6B \
    --output /opt/models/Qwen3-0.6B-Enc \
    --dek /secure/dek.jwk \
    --vendor-priv /secure/vendor_sign.priv.jwk \
    --encrypt-all
```

## Debugging mismatches

`utils/print_metadata.py` dumps the header of an encrypted model — the
quickest way to see what `kid` / `alg` / `jku` was actually baked in:

```bash
python utils/print_metadata.py /path/to/model.cryptotensors -t
# or as JSON:
python utils/print_metadata.py /path/to/model.cryptotensors -j | jq .
```

Common findings and their implications:

| Symptom in the header                              | Workflow-level diagnosis                                                                        |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Each tensor's `__encryption__.key.kid` is `model-v1` but the license payload shows a different kid | Wrong DEK at encrypt time — rebuild model with the license's DEK.                               |
| `alg: "A256GCM"` sitting in the header             | Old `convert_model.py` without the JOSE → native normalisation. Re-run with the current script. |
| `jku` present on every tensor                      | Upstream FileKeyProvider layout; the ResultsCloud runtime ignores it but it's harmless.         |
| `jku` absent AND `kid` present                     | ResultsCloud layout, as intended.                                                                |
| No `__signature__` block                           | Forgot `--vendor-priv` at encrypt time. LicenseProvider's `get_verify_key` path won't trigger.   |

## File layout

```
integration-tests/
├── README.md                    ← this file
├── run_tests.sh                 ← upstream-flow Docker runner
├── Dockerfile.transformers      ← upstream-flow Docker image
├── scripts/
│   ├── __init__.py
│   ├── convert_model.py         ← core encryption entry (both flows)
│   ├── convert_and_save.py      ← convenience wrapper, both flows
│   ├── load_and_test.py         ← upstream-flow loader + diff
│   ├── run_full_test.py         ← upstream-flow one-shot
│   └── resultscloud_e2e.py      ← ResultsCloud-flow one-shot
└── utils/
    ├── __init__.py
    ├── write_jwk.py             ← upstream test-key generator
    └── print_metadata.py        ← debug: dump the encrypted header
```

Secrets — `*.jwk`, `*.jwt`, `vendor/`, `rc-e2e-out/` — are ignored by
the directory-local `.gitignore`. Never commit a produced key or
license.
