"""AES-128-CBC encryption/decryption for the Ajax HTS binary protocol."""

from Crypto.Cipher import AES

_KEY = b"We@zEd;80Z1@pc2Y"
_IV = b"V:e<*tMv6qVU#WRC"


def encrypt(data: bytes) -> bytes:
    """AES-128-CBC encrypt data.

    Args:
        data: Plaintext bytes. Must be a multiple of 16 bytes.

    Returns:
        Ciphertext bytes of the same length.

    Raises:
        ValueError: If len(data) is not a multiple of 16.
    """
    if len(data) % 16 != 0:
        raise ValueError(f"Input length {len(data)} is not a multiple of 16 (AES block size)")
    cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
    return cipher.encrypt(data)


def decrypt(data: bytes) -> bytes:
    """AES-128-CBC decrypt data.

    Args:
        data: Ciphertext bytes. Must be a multiple of 16 bytes.

    Returns:
        Plaintext bytes of the same length.

    Raises:
        ValueError: If len(data) is not a multiple of 16.
    """
    if len(data) % 16 != 0:
        raise ValueError(f"Input length {len(data)} is not a multiple of 16 (AES block size)")
    cipher = AES.new(_KEY, AES.MODE_CBC, _IV)
    return cipher.decrypt(data)
