
# CryptoTensors

This repository implements **CryptoTensors**, an LLM file format for secure model distribution. This implementation extends [safetensors](https://github.com/huggingface/safetensors) with encryption, signing, and access control capabilities while maintaining full backward compatibility with safetensors.

**CryptoTensors** provides:
- 🔐 **Encryption**: AES-GCM and ChaCha20-Poly1305 encryption for tensor data
- ✍️ **Signing**: Ed25519 signature verification for file integrity  
- 🔑 **Key Management**: Flexible key provider system (environment variables, files, programmatic)
- 🛡️ **Access Policy**: Rego-based policy engine for fine-grained access control
- 🔄 **Transparent Integration**: Works seamlessly with transformers, vLLM, and other ML frameworks

This project is a derivative work based on [safetensors](https://github.com/huggingface/safetensors) by Hugging Face. See [NOTICE](NOTICE) for details.

> This implementation is based on the idea of the following research paper: [Zhu, H., Li, S., Li, Q., & Jin, Y. (2025). CryptoTensors: A Light-Weight Large Language Model File Format for Highly-Secure Model Distribution. arXiv:2512.04580.](https://arxiv.org/pdf/2512.04580)



# Installation
## Pip

You can install cryptotensors via the pip manager:

```bash
pip install cryptotensors
```

#### For backward compatibility

If you want to load encrypted CryptoTensors models without modifying your code, you can use the compatible package released on [GitHub Releases](https://github.com/aiyah-meloken/cryptotensors/releases):

```bash
# Uninstall the original safetensors package
pip uninstall safetensors

# Install the compatible package directly from GitHub release
# Replace {tag} with the release tag (e.g., v0.1.0)
pip install https://github.com/aiyah-meloken/cryptotensors/releases/download/{tag}/safetensors-0.7.0-py3-none-any.whl

# Example for v0.1.0:
# pip install https://github.com/aiyah-meloken/cryptotensors/releases/download/v0.1.0/safetensors-0.7.0-py3-none-any.whl
```

After installation, your existing code will transparently support both regular safetensors files and encrypted CryptoTensors files without any code changes. The compatible package uses the `safetensors` namespace but internally depends on `cryptotensors`, enabling seamless encryption support.

## From source

For the sources, you need Rust

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Make sure it's up to date and using stable channel
rustup update
git clone https://github.com/aiyah-meloken/cryptotensors
cd cryptotensors/bindings/python
pip install setuptools_rust
pip install -e .
```

# Getting started

## Basic Usage (Encryption and Decryption)

### 🆕 v0.2 New Config API

CryptoTensors 0.2 introduces a new, more flexible configuration system:

```python
import torch
from cryptotensors import SerializeCryptoConfig, save_file
from cryptotensors.torch import load_file

tensors = {
   "weight1": torch.zeros((1024, 1024)),
   "weight2": torch.zeros((1024, 1024))
}

# Method 1: Direct keys (simple scenarios)
config = SerializeCryptoConfig(
    enc_key={"alg": "aes256gcm", "kid": "my-enc", "k": "base64-encoded-key"},
    sign_key={"alg": "ed25519", "kid": "my-sign", "x": "...", "d": "..."}
)
save_file(tensors, "model.cryptotensors", config=config.to_dict())

# Method 2: Using kid/jku (with global Registry)
from cryptotensors import register_direct_key_provider

register_direct_key_provider(files=["keys.jwk"])  # Register keys once
config = SerializeCryptoConfig(enc_kid="my-enc", sign_kid="my-sign")
save_file(tensors, "model.cryptotensors", config=config.to_dict())

# Load encrypted file (keys auto-retrieved from Registry)
tensors = load_file("model.cryptotensors")
```

### Classic API (Still Supported)

The classic dict-based configuration is still fully supported:

```python
# Old API still works
config = {
    "enc_key": enc_key,    # JWK format encryption key
    "sign_key": sign_key,  # JWK format signing key
}
save_file(tensors, "model.cryptotensors", config=config)
```

See [`KEY_MANAGEMENT_GUIDE.md`](KEY_MANAGEMENT_GUIDE.md) for detailed key management guide and [documentation](https://aiyah-meloken.github.io/cryptotensors/) for more examples.

## Backward Compatibility (Safetensors Compatible)

You can use `cryptotensors` as a drop-in replacement for `safetensors` in most cases, where you can save and load unencrypted models as usual.

```python
import torch
from cryptotensors import safe_open
from cryptotensors.torch import save_file

tensors = {
   "weight1": torch.zeros((1024, 1024)),
   "weight2": torch.zeros((1024, 1024))
}
save_file(tensors, "model.safetensors")

tensors = {}
with safe_open("model.safetensors", framework="pt", device="cpu") as f:
   for key in f.keys():
       tensors[key] = f.get_tensor(key)
```


## Native Key Providers (path-based loader)

Beyond the built-in `EnvKeyProvider` and `FileKeyProvider`, third parties
can ship signed Rust cdylibs that plug into the global key registry —
e.g. licensing engines, KMS bridges, HSM clients. Loading is **path-based
and language-agnostic**: any binding (Python, C, Go, future ones) just
hands the Rust core a filesystem path and the cdylib's identity is
derived from its signing keypair, not from anything the caller passes in.

```python
import cryptotensors

# Load a signed provider cdylib by path.
# - <lib_path>.sig must live next to the .so/.dylib/.dll.
# - The cdylib is rejected unless its signature verifies against one of
#   cryptotensors' compiled-in trusted public keys AND its self-reported
#   name matches the trusted name bound to that key.
# - The cdylib must export `cryptotensors_provider_abi_version` and that
#   value must equal `cryptotensors::CRYPTOTENSORS_PROVIDER_ABI_VERSION`,
#   so a provider built against a different cryptotensors version is
#   rejected at load time instead of crashing on a vtable mismatch.
cryptotensors.init_key_provider(
    "/path/to/libmy_provider.so",
    # provider-specific config kwargs are JSON-encoded and forwarded to
    # the cdylib's initialize()
    license_path="/etc/myprovider/license.jwt",
)

# What's loaded right now (canonical view; lives in the Rust registry)
cryptotensors.list_key_providers()
# → ['my-provider', 'env', 'file']

# Remove a registered provider by name
cryptotensors.disable_provider("my-provider")
```

### Python convenience: name-based loading

`init_key_provider` is the canonical, language-agnostic API. For Python
deployments where the provider is `pip install`ed and you'd rather not
hand-write a path, there's a convenience wrapper that resolves the
`.so` path via the `cryptotensors.providers` entry_points group and
then delegates to `init_key_provider`:

```python
import cryptotensors

# Resolves "resultscloud-license" via entry_points → bundled .so path,
# then runs the same path-based loader. Trust is still decided by the
# signing keypair on the cdylib, never by this name argument.
cryptotensors.init_key_provider_by_name("resultscloud-license", license_path="...")

# Catalog of provider packages installed in this environment (entry_points
# discovery, NOT the Rust registry). Distinct from list_key_providers().
cryptotensors.list_installed_providers()
# → ['resultscloud-license']
```

`list_installed_providers()` and `init_key_provider_by_name()` are
**Python-only convenience layers**. The `cryptotensors.providers`
entry_points group is a pure inventory channel — declarations there
do **not** grant trust. Trust is decided exclusively by Rust-side
signature verification at load time. Non-Python callers (a Go sidecar,
a C embedding, a future CLI) just call `init_key_provider(path)` and
manage their own discovery.

Provider packages should still ship a `.pth` autoload hook that calls
`init_key_provider(get_native_lib_path())` at interpreter startup when
an opt-in env var is set, so most users never call any of the above
manually. See
[`cryptotensors-provider-resultscloud-license`](https://github.com/aiyah-meloken/cryptotensors-provider-resultscloud-license)
for a reference implementation, and [`docs/DESIGN.md`](docs/DESIGN.md)
for the full provider-loading architecture, signature flow, ABI
handshake, and threat model.

# Additional Information

## File Format

The file format is the same as the safetensors format, with the following additional fields:

- 8 bytes: `N`, an unsigned little-endian 64-bit integer, containing the size of the header
- N bytes: a JSON UTF-8 string representing the header.
  - The header data MUST begin with a `{` character (0x7B).
  - The header data MAY be trailing padded with whitespace (0x20).
  - The header is a dict like `{"TENSOR_NAME": {"dtype": "F16", "shape": [1, 16, 256], "data_offsets": [BEGIN, END]}, "NEXT_TENSOR_NAME": {...}, ...}`,
    - `data_offsets` point to the tensor data relative to the beginning of the byte buffer (i.e. not an absolute position in the file),
      with `BEGIN` as the starting offset and `END` as the one-past offset (so total tensor byte size = `END - BEGIN`).
  - A special key `__metadata__` is allowed to contain free form string-to-string map. Arbitrary JSON is not allowed, all values must be strings.
  - **Cryptotensors add the following fields to the `__metadata__` section**:
    - `__encryption__`: JSON string containing per-tensor encryption information (algorithm, IVs, tags, wrapped keys, etc.). The format of this field depends on the `version` specified in `__crypto_keys__`.
    - `__crypto_keys__`: JSON string containing key material information in the format `{"version": "1"|"2", "chunk_size": 2097152, "enc": {...}, "sign": {...}}`. `version` "1" uses monolithic encryption, while "2" uses chunked encryption. `chunk_size` is only present in version "2". No secrets are stored in this field, and the metadata is used to retrieve the keys from the key providers.
    - `__signature__`: Base64-encoded Ed25519 signature of the file header (excluding the signature itself) for integrity verification
    - `__policy__`: JSON string containing access control policy in Rego format
  
  For detailed format specifications and the differences between v1 and v2, please refer to [FORMAT.md](FORMAT.md).

- Rest of the file: byte-buffer.

### Notes & Benefits

- Two stages of encryption: the entire header is encrypted using the master decryption key, and the tensor data is encrypted using the per-tensor encryption keys.
- **Lazy decryption**: Encrypted tensors are decrypted on-demand when accessed, maintaining the
  benefits of lazy loading while ensuring security. This allows loading large encrypted models
  without decrypting all tensors upfront, preserving memory efficiency and supporting distributed
  settings where only specific tensors are needed.
- **Zero-copy buffer passing**: Decrypted tensor data is exposed to Python via the buffer protocol,
  allowing frameworks like PyTorch and NumPy to reference the memory directly without an extra copy.
  - *Note: Zero-copy buffer protocol support requires Python 3.11+ and is disabled on PyPy due to C-API constraints.*
- **Python Support**: Supports 3.11, 3.12, and 3.13.
  - *Note: Python 3.14 (preview) is not yet supported due to upstream dependency constraints.*

**Note: Unless otherwise specified, all other notes, features, and benefits of the cryptotensors format are the same as the [safetensors format](https://github.com/huggingface/safetensors#file-format).**

License: Apache-2.0
