"""Tests for AES-128-CBC crypto helpers."""

import pytest

from custom_components.aegis_ajax.api.hts.crypto import decrypt, encrypt


class TestEncryptDecrypt:
    def test_roundtrip_single_block(self) -> None:
        plaintext = b"0123456789abcdef"  # exactly 16 bytes
        assert decrypt(encrypt(plaintext)) == plaintext

    def test_roundtrip_multi_block(self) -> None:
        plaintext = b"0123456789abcdef" * 2  # 32 bytes
        assert decrypt(encrypt(plaintext)) == plaintext

    def test_decrypt_known_vector(self) -> None:
        """Encrypt a known plaintext and verify decrypt inverts it."""
        plaintext = b"AjaxProtegimHTS!"  # 16 bytes
        ciphertext = encrypt(plaintext)
        # ciphertext must differ from plaintext
        assert ciphertext != plaintext
        assert decrypt(ciphertext) == plaintext

    def test_encrypt_not_aligned_raises(self) -> None:
        with pytest.raises(ValueError, match="multiple of 16"):
            encrypt(b"short")

    def test_decrypt_not_aligned_raises(self) -> None:
        with pytest.raises(ValueError, match="multiple of 16"):
            decrypt(b"tooshort_data123x")  # 17 bytes
