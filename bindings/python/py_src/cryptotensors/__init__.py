# MODIFIED: Added encryption/decryption support for CryptoTensors
# This is a derivative work based on the safetensors project by Hugging Face Inc.
import json
from ._safetensors_rust import (  # noqa: F401
    SafetensorError,
    __version__,
    deserialize,
    safe_open,
    _safe_open_handle,
    serialize,
    serialize_file,
    rewrap_file,
    rewrap_header,
    rewrap,
    disable_provider,
    py_load_provider_native as _load_provider_native,
    py_list_registered_providers as _list_registered_providers,
    _register_key_provider_internal,
)


def init_key_provider(lib_path: str, **config) -> None:
    """Load and register a native provider cdylib by filesystem path.

    The provider's identity (name) comes from the cdylib itself, validated
    against the trusted signing keypair built into cryptotensors. No name
    parameter is accepted from the caller — that decouples discovery from
    loading and lets any binding (Python, C, Go, …) register a provider just
    by passing a path.

    Args:
        lib_path: Absolute path to the provider .so/.dylib/.dll. The
            companion ``<lib_path>.sig`` (Ed25519 signature, base64) must
            live next to it.
        **config: Provider-specific config keyword args; serialised to JSON
            and passed to the cdylib's ``initialize``.

    Raises:
        Exception: signature missing or untrusted, library missing the
            ``cryptotensors_create_provider`` symbol, or initialize() failure.
    """
    _load_provider_native(lib_path, json.dumps(config))


def list_key_providers() -> list:
    """Names of providers currently registered and enabled in the Rust
    registry, in priority order (highest first).

    NOTE: This reflects what is *loaded right now*, not what is *installable*.
    A provider package installed in the environment but never loaded via
    :func:`init_key_provider` will not appear here.
    """
    return _list_registered_providers()


def register_direct_key_provider(*, files=None, keys=None):
    """
    Register direct key provider (highest priority)

    Creates a DirectKeyProvider and registers it to the global Registry with highest priority.

    Args:
        files: List of key file paths, Python handles reading and parsing
        keys: JWK list or JWK Set dict

    Only one of 'files' or 'keys' can be specified.
    """
    if files is not None and keys is not None:
        raise ValueError("Cannot specify both 'files' and 'keys'")
    if files is None and keys is None:
        raise ValueError("Must specify either 'files' or 'keys'")

    final_keys = []
    if files is not None:
        # Python handles file reading
        for path in files:
            with open(path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                if "keys" in data:
                    final_keys.extend(data["keys"])  # JWK Set
                elif "kty" in data:
                    final_keys.append(data)  # Single JWK
                else:
                    raise ValueError(f"Invalid JWK format in {path}")
            elif isinstance(data, list):
                final_keys.extend(data)
            else:
                raise ValueError(f"Invalid JWK format in {path}")

    elif keys is not None:
        if isinstance(keys, dict):
            if "keys" in keys:
                final_keys = keys["keys"]  # JWK Set format
            elif "kty" in keys:
                final_keys = [keys]  # Single JWK
            else:
                raise ValueError("Invalid keys format")
        elif isinstance(keys, list):
            final_keys = keys
        else:
            raise ValueError("keys must be a list or a dict")

    # Pass to Rust
    _register_key_provider_internal(final_keys)


# Backward compatibility alias
register_tmp_key_provider = register_direct_key_provider


class SerializeCryptoConfig:
    """
    Serialization encryption configuration

    Key loading (two paths):
    1. Direct keys (enc_key/sign_key) - if provided, use as-is and ignore enc_kid/enc_jku/sign_kid/sign_jku
    2. Registry lookup (enc_kid/enc_jku/sign_kid/sign_jku) - when no direct keys, lookup from Registry
       - Use register_direct_key_provider() to register keys to global Registry first
    """

    def __init__(
        self,
        enc_key=None,
        sign_key=None,
        enc_kid=None,
        enc_jku=None,
        sign_kid=None,
        sign_jku=None,
        policy=None,
        tensors=None,
        chunk_size=None,
        version=None,
    ):
        """
        Initialize SerializeCryptoConfig

        Args:
            enc_key (dict, optional): Encryption key (JWK format)
            sign_key (dict, optional): Signing key (JWK format)
            enc_kid (str, optional): Encryption key identifier
            enc_jku (str, optional): Encryption key JWK URL
            sign_kid (str, optional): Signing key identifier
            sign_jku (str, optional): Signing key JWK URL
            policy (dict, optional): Access policy {"local": "...", "remote": "..."}
            tensors (list, optional): List of tensor names to encrypt (None = all)
            chunk_size (int, optional): Size in bytes for chunked encryption. If None, uses default 2MB.
            version (str, optional): CryptoTensors format version ("1" or "2"). If None, uses default V2.
        """
        self.config = {
            "enc_key": enc_key,
            "sign_key": sign_key,
            "enc_kid": enc_kid,
            "enc_jku": enc_jku,
            "sign_kid": sign_kid,
            "sign_jku": sign_jku,
            "policy": policy,
            "tensors": tensors,
            "chunk_size": chunk_size,
            "version": version,
        }
        # Remove None values
        self.config = {k: v for k, v in self.config.items() if v is not None}

    def to_dict(self):
        """Convert to dict for internal use"""
        return self.config


class DeserializeCryptoConfig:
    """
    Deserialization decryption configuration (optional)

    Key loading (two paths):
    1. Direct keys (enc_key/sign_key) - if provided, use as-is and ignore kid/jku from header
    2. Registry lookup - when no direct keys, lookup by kid/jku from header
       - Use register_direct_key_provider() to register keys to global Registry first

    Note: kid/jku are read from header for registry lookup, no need to specify here
    """

    def __init__(self, enc_key=None, sign_key=None):
        """
        Initialize DeserializeCryptoConfig

        Args:
            enc_key (dict, optional): Encryption key (JWK format)
            sign_key (dict, optional): Signing key (JWK format)
        """
        self.config = {
            "enc_key": enc_key,
            "sign_key": sign_key,
        }
        # Remove None values
        self.config = {k: v for k, v in self.config.items() if v is not None}

    def to_dict(self):
        """Convert to dict for internal use"""
        return self.config


__all__ = [
    "SafetensorError",
    "__version__",
    "deserialize",
    "safe_open",
    "_safe_open_handle",
    "serialize",
    "serialize_file",
    "rewrap_file",
    "rewrap_header",
    "rewrap",
    "disable_provider",
    "register_direct_key_provider",
    "register_tmp_key_provider",  # Backward compatibility alias
    "init_key_provider",
    "list_key_providers",
    "SerializeCryptoConfig",
    "DeserializeCryptoConfig",
]
