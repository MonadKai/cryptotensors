import os
import json
import tempfile
import unittest
import numpy as np
import cryptotensors
from cryptotensors.numpy import save_file, load_file
from crypto_utils import generate_test_keys


class TestRegistry(unittest.TestCase):
    def setUp(self):
        self.keys = generate_test_keys()
        self.data = {
            "weight": np.random.randn(2, 2).astype(np.float32),
            "bias": np.random.randn(2).astype(np.float32),
        }

    def test_register_tmp_key_provider_dict(self):
        # Register keys directly
        cryptotensors.register_tmp_key_provider(
            keys=[self.keys["enc_key"], self.keys["sign_key"]]
        )

        with tempfile.NamedTemporaryFile(suffix=".cryptotensors", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Use config for saving to ensure it works, then load using registry
            config = {
                "enc_key": self.keys["enc_key"],
                "sign_key": self.keys["sign_key"],
            }
            save_file(self.data, tmp_path, config=config)

            # Load using registry
            loaded = load_file(tmp_path)
            np.testing.assert_allclose(loaded["weight"], self.data["weight"])

            # Clear registry and try to load (should fail)
            cryptotensors.disable_provider("DirectKeyProvider")
            with self.assertRaises(Exception):
                load_file(tmp_path)

        finally:
            cryptotensors.disable_provider("DirectKeyProvider")
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_register_direct_key_provider_files(self):
        # Save keys to a file
        with tempfile.NamedTemporaryFile(
            suffix=".jwk", mode="w", delete=False
        ) as tmp_jwk:
            jwk_path = tmp_jwk.name
            json.dump({"keys": [self.keys["enc_key"], self.keys["sign_key"]]}, tmp_jwk)

        try:
            cryptotensors.register_direct_key_provider(files=[jwk_path])

            with tempfile.NamedTemporaryFile(
                suffix=".cryptotensors", delete=False
            ) as tmp:
                tmp_path = tmp.name

            try:
                config = {
                    "enc_key": self.keys["enc_key"],
                    "sign_key": self.keys["sign_key"],
                }
                save_file(self.data, tmp_path, config=config)

                # Load using file provider registered in temp
                loaded = load_file(tmp_path)
                np.testing.assert_allclose(loaded["weight"], self.data["weight"])

            finally:
                cryptotensors.disable_provider("DirectKeyProvider")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        finally:
            if os.path.exists(jwk_path):
                os.remove(jwk_path)

    def test_list_key_providers_reflects_registry(self):
        # Baseline: a freshly registered direct provider must appear; after
        # disabling it, it must disappear. This is the canonical test that
        # the Python list now reflects the *Rust* registry rather than
        # entry_points metadata.
        cryptotensors.disable_provider("DirectKeyProvider")
        names_before = cryptotensors.list_key_providers()
        self.assertNotIn("DirectKeyProvider", names_before)

        cryptotensors.register_tmp_key_provider(
            keys=[self.keys["enc_key"], self.keys["sign_key"]]
        )
        try:
            names_after = cryptotensors.list_key_providers()
            self.assertIn("DirectKeyProvider", names_after)
        finally:
            cryptotensors.disable_provider("DirectKeyProvider")

        names_final = cryptotensors.list_key_providers()
        self.assertNotIn("DirectKeyProvider", names_final)

    def test_init_key_provider_by_name_unknown_raises(self):
        # Convenience wrapper: a name with no matching entry_point must
        # raise rather than fall through to a Rust-side error. This is
        # purely a Python-layer contract — the Rust loader is never
        # invoked because resolution fails first.
        with self.assertRaises(ValueError) as cm:
            cryptotensors.init_key_provider_by_name("definitely-not-installed")
        self.assertIn("definitely-not-installed", str(cm.exception))

    def test_list_installed_providers_is_catalog_view(self):
        # list_installed_providers is a pure inventory channel that
        # reads entry_points; it must NOT depend on whether a provider
        # is currently loaded into the registry. Returning a list (even
        # an empty one) on a venv with no provider packages installed
        # is the correct behaviour.
        result = cryptotensors.list_installed_providers()
        self.assertIsInstance(result, list)
        # All entries must be strings — the entry_point name.
        for name in result:
            self.assertIsInstance(name, str)

    def test_env_provider(self):
        # Set environment variable
        os.environ["CRYPTOTENSOR_KEYS"] = json.dumps(
            {"keys": [self.keys["enc_key"], self.keys["sign_key"]]}
        )

        with tempfile.NamedTemporaryFile(suffix=".cryptotensors", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            config = {
                "enc_key": self.keys["enc_key"],
                "sign_key": self.keys["sign_key"],
            }
            save_file(self.data, tmp_path, config=config)

            # Load using env provider
            loaded = load_file(tmp_path)
            np.testing.assert_allclose(loaded["weight"], self.data["weight"])

            # Disable env provider
            cryptotensors.disable_provider("env")
            with self.assertRaises(Exception):
                load_file(tmp_path)

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            if "CRYPTOTENSOR_KEYS" in os.environ:
                del os.environ["CRYPTOTENSOR_KEYS"]


if __name__ == "__main__":
    unittest.main()
