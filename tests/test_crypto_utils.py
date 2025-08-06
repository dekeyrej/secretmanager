import pytest
from secretmanager._crypto_utils import encode_data, decode_data


def test_encode_decode_roundtrip():
    original = "sensitive-data-123"
    encoded = encode_data(original)
    decoded = decode_data(encoded)
    assert decoded == original


def test_encode_empty_string():
    encoded = encode_data("")
    assert encoded == ""
    decoded = decode_data(encoded)
    assert decoded == ""


def test_decode_invalid_base64_raises():
    invalid_data = "!!!not_base64@@@"
    with pytest.raises(
        Exception
    ):  # Could be ValueError or binascii.Error depending on Python version
        decode_data(invalid_data)


def test_encode_unicode_characters():
    original = "秘密🔐"
    encoded = encode_data(original)
    decoded = decode_data(encoded)
    assert decoded == original
