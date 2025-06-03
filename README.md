# Sayaka

Sayaka is a Rust-backed Python module for decrypting and decompressing data for an anime game. It leverages [PyO3](https://pyo3.rs/) to provide a high-performance decompression function directly from Python.

## Installation

### Prerequisites

- Rust (edition 2024)
- Python (version 3.12 or higher)
- [maturin](https://github.com/PyO3/maturin) for building the extension module

### Build and Install

1. Clone the repository:

   ```powershell
   git clone https://github.com/baiqwerdvd/sayaka.git
   cd sayaka
   ```

2. Build the module using maturin:

   ```powershell
   uv sync
   uv run maturin develop --release
   ```

## Usage

Import the module in your Python code to decrypt or decompress data. The module provides three main functions:
- `decompress_buffer`: Decompresses data using LZ4 compression.
- `miki_decrypt`: Decrypts data encrypted with the Miki algorithm.
- `miki_decrypt_old`: Decrypts data encrypted with the old Miki algorithm.
- `miki_decrypt_and_decompress`: Combines decryption and decompression in one step.
- `miki_decrypt_and_decompress_old`: Combines decryption and decompression for the old Miki algorithm.

The function accepts any object implementing Buffer protocol (for example `bytes`, `bytearray`, `memoryview`) as input for the data.

```python
import sayaka

with open("compressed_data.bin", "rb") as f:
    compressed_data = f.read()

decompressed_size = 9796
decompressed_data = sayaka.decompress_buffer(compressed_data, decompressed_size)
```

```python
import sayaka

with open("miki_encrypted.bin", "rb") as f:
    encrypted_data = f.read()

decrypted_data = sayaka.miki_decrypt(encrypted_data)
```

```python
import sayaka

with open("miki_old_encrypted.bin", "rb") as f:
    encrypted_data = f.read()

decrypted_data = sayaka.miki_decrypt_old(encrypted_data)
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [PyO3](https://github.com/PyO3/pyo3) for making Python/Rust interop simple.
- The LZ4 compression library for inspiration.
- [Lz4Inv](https://github.com/MooncellWiki/lz4inv) for providing a reference implementation.
- [YarikStudio](https://github.com/FrothierNine346/YarikStudio) for decryption logic.
