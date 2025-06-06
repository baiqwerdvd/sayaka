import pathlib
import sayaka

current_dir = pathlib.Path(__file__).parent.absolute()


def test_decompress_buffer():
    compressed_file_path = current_dir / "compressed_data.bin"
    expected_file_path = current_dir / "decompressed_data.bin"

    with open(compressed_file_path, "rb") as f:
        compressed_bytes = f.read()
        compressed_data = memoryview(compressed_bytes)
        uncompressed = sayaka.decompress_buffer(compressed_data, 9796)
        with open(expected_file_path, "rb") as expected_file:
            expected_data = expected_file.read()

        assert uncompressed == expected_data, (
            "Decompressed data does not match expected data"
        )


def test_miki_decrypt():
    encrypted_file_path = current_dir / "miki_encrypted.bin"
    expected_file_path = current_dir / "miki_decrypted.bin"

    with open(encrypted_file_path, "rb") as f:
        encrypted_bytes = f.read()
        decrypted = sayaka.miki_decrypt(encrypted_bytes)
        with open(expected_file_path, "rb") as expected_file:
            expected_data = expected_file.read()

        assert decrypted == expected_data, "Decrypted data does not match expected data"


def test_miki_decrypt_old():
    encrypted_file_path = current_dir / "miki_old_encrypted.bin"
    expected_file_path = current_dir / "miki_old_decrypted.bin"

    with open(encrypted_file_path, "rb") as f:
        encrypted_bytes = f.read()
        decrypted = sayaka.miki_decrypt_old(encrypted_bytes)
        with open(expected_file_path, "rb") as expected_file:
            expected_data = expected_file.read()

        assert decrypted == expected_data, "Decrypted data does not match expected data"


def test_chacha20():
    key = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    nonce = bytes.fromhex("000000000000000000000000")
    counter = 1
    chacha = sayaka.ChaCha20(key, nonce, counter)

    plaintext = b"Hello, World!"
    encrypted = chacha.work_bytes(plaintext)
    excepted = "d7 62 8b d2 3a 7d 18 2d f7 c8 fb 18 52"

    expected_bytes = bytes.fromhex(excepted)
    assert encrypted == expected_bytes, "Encrypted data does not match expected data"
