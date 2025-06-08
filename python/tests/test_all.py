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


def test_hgmmap():
    hgmmap = sayaka.ManifestDataBinary()

    mmap_file = current_dir / "manifest.hgmmap"
    is_success = hgmmap.init_binary(mmap_file.as_posix())
    assert is_success, "Failed to initialize hgmmap"

    output_file = current_dir / "manifest.hgmmap.json"
    is_success = hgmmap.save_to_json_file(output_file.as_posix())
    # assert is_success, "Failed to save hgmmap to JSON file"
    output_file.unlink(missing_ok=True)


def test_small_ab():
    ab = "ebaaf86643.ab"
    with open(current_dir / ab, "rb") as f:
        data = f.read()

    from enum import IntFlag
    import UnityPy
    from UnityPy.helpers.CompressionHelper import DECOMPRESSION_MAP
    import UnityPy.enums.BundleFile as UnityPyEnumsBundleFile

    class CompressionFlags(IntFlag):
        NONE = 0
        LZMA = 1
        LZ4 = 2
        LZ4HC = 3
        LZHAM = 4
        LZ4BYD = 5

    UnityPyEnumsBundleFile.CompressionFlags = CompressionFlags
    DECOMPRESSION_MAP[CompressionFlags.LZ4BYD] = sayaka.miki_decrypt_old_and_decompress

    env = UnityPy.load(data)

    assert len(env.objects) == 3, "No objects found in the .ab file"  # pyright: ignore[reportUnknownArgumentType, reportUnknownMemberType]


def test_enc_ab():
    ab = "0a3ae60ce8.ab"
    with open(current_dir / ab, "rb") as f:
        data = f.read()

    from enum import IntFlag
    import UnityPy
    from UnityPy.helpers.CompressionHelper import DECOMPRESSION_MAP
    import UnityPy.enums.BundleFile as UnityPyEnumsBundleFile

    class CompressionFlags(IntFlag):
        NONE = 0
        LZMA = 1
        LZ4 = 2
        LZ4HC = 3
        LZHAM = 4
        LZ4BYD = 5

    UnityPyEnumsBundleFile.CompressionFlags = CompressionFlags
    DECOMPRESSION_MAP[CompressionFlags.LZ4BYD] = sayaka.miki_decrypt_old_and_decompress

    env = UnityPy.load(data)

    assert len(env.objects) == 3, "No objects found in the .ab file"  # pyright: ignore[reportUnknownArgumentType, reportUnknownMemberType]
