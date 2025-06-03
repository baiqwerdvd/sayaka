use std::{cmp::min, fmt::Display};

use pyo3::PyErr;

#[derive(Debug)]
pub enum MikiDecryptError {
    InvalidBlockIndex,
    InvalidTypeValue,
    BufferSizeMismatch { expected: usize, actual: usize },
}

impl Display for MikiDecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MikiDecryptError::InvalidBlockIndex => write!(f, "Invalid block index"),
            MikiDecryptError::InvalidTypeValue => write!(f, "Invalid type value"),
            MikiDecryptError::BufferSizeMismatch { expected, actual } => {
                write!(
                    f,
                    "Buffer size mismatch: expected {}, actual {}",
                    expected, actual
                )
            }
        }
    }
}

impl From<MikiDecryptError> for PyErr {
    fn from(err: MikiDecryptError) -> PyErr {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string())
    }
}

pub fn decrypt_to(src: &mut [u8], dst: &mut [u8]) -> Result<(), MikiDecryptError> {
    if src.len() != dst.len() {
        return Err(MikiDecryptError::BufferSizeMismatch {
            expected: src.len(),
            actual: dst.len(),
        });
    }

    decrypt(src)?;
    dst.copy_from_slice(src);

    Ok(())
}

pub fn decrypt(bytes: &mut [u8]) -> Result<(), MikiDecryptError> {
    let encrypted_offset = 0;
    let encrypted_size = min(0x500, bytes.len());

    if encrypted_size < 0x20 {
        return Ok(());
    }

    let encrypted = &mut bytes[encrypted_offset..encrypted_offset + encrypted_size];

    // Convert bytes to u32 slice for manipulation
    let encrypted_ints = bytes_to_u32_slice(encrypted);

    // XOR first 0x20 bytes with 0xA6
    for i in 0..0x20 {
        if i < encrypted.len() {
            encrypted[i] ^= 0xA6;
        }
    }

    // Generate seed parts
    let seed_part0 = encrypted_ints[2] ^ encrypted_ints[6] ^ 0x226a61b9;
    let seed_part1 = encrypted_ints[3] ^ encrypted_ints[0] ^ 0x7a39d018 ^ (encrypted_size as u32);
    let seed_part2 = encrypted_ints[1] ^ encrypted_ints[5] ^ 0x18f6d8aa ^ (encrypted_size as u32);
    let seed_part3 = encrypted_ints[0] ^ encrypted_ints[7] ^ 0xaa255fb1;
    let seed_part4 = encrypted_ints[4] ^ encrypted_ints[7] ^ 0xf78dd8eb;

    let seed_ints = [seed_part0, seed_part1, seed_part2, seed_part3, seed_part4];
    let mut seed_bytes = u32_array_to_bytes(&seed_ints);

    let seed = generate_seed(&seed_bytes);
    let seed_buffer = seed.to_le_bytes();
    let seed = Crc::calculate_digest(&seed_buffer, 0, seed_buffer.len() as u32);

    let key = seed_ints[0]
        ^ seed_ints[1]
        ^ seed_ints[2]
        ^ seed_ints[3]
        ^ seed_ints[4]
        ^ (encrypted_size as u32);

    rc4(&mut seed_bytes, &key.to_le_bytes());
    let seed_ints = bytes_to_u32_slice(&seed_bytes);

    let key_seed = Crc::calculate_digest(&seed_bytes, 0, seed_bytes.len() as u32);
    let key_seed_bytes = key_seed.to_le_bytes();
    let key_seed = generate_seed(&key_seed_bytes);

    let key_part0 = seed_ints[3].wrapping_sub(0x1C26B82D) ^ key_seed;
    let key_part1 = seed_ints[2].wrapping_add(0x3F72EAF3) ^ seed;
    let key_part2 = seed_ints[0] ^ 0x82C57E3C ^ key_seed;
    let key_part3 = seed_ints[1].wrapping_add(0x6F2A7347) ^ seed;
    let key_vector = [key_part0, key_part1, key_part2, key_part3];

    if encrypted.len() > 0x20 {
        let block = &mut encrypted[0x20..];
        if block.len() >= 0x80 {
            rc4(&mut block[..0x60], &seed.to_le_bytes());

            for i in 0..min(0x60, block.len()) {
                block[i] ^= (seed ^ 0x6E) as u8;
            }

            if block.len() > 0x60 {
                let block = &mut block[0x60..];
                let block_size = (encrypted_size - 0x80) / 4;

                #[allow(clippy::needless_range_loop)]
                for i in 0..4 {
                    let block_offset = i * block_size;

                    if block_offset >= block.len() {
                        break;
                    }

                    let block_key = match i {
                        0 => 0x6142756Eu32,
                        1 => 0x62496E66u32,
                        2 => 0x1304B000u32,
                        3 => 0x6E8E30ECu32,
                        _ => return Err(MikiDecryptError::InvalidBlockIndex),
                    };

                    let end_offset = min(block_offset + block_size, block.len());
                    if block_offset < end_offset {
                        rc4(&mut block[block_offset..end_offset], &seed.to_le_bytes());

                        // Process as u32 chunks
                        let chunk_len = (end_offset - block_offset) / 4 * 4;
                        if chunk_len > 0 {
                            for j in (0..chunk_len).step_by(4) {
                                if block_offset + j + 4 <= block.len() {
                                    let mut block_int = u32::from_le_bytes([
                                        block[block_offset + j],
                                        block[block_offset + j + 1],
                                        block[block_offset + j + 2],
                                        block[block_offset + j + 3],
                                    ]);

                                    let xor_val = seed ^ key_vector[i] ^ block_key;
                                    block_int ^= xor_val;

                                    let bytes = block_int.to_le_bytes();
                                    block[block_offset + j..block_offset + j + 4]
                                        .copy_from_slice(&bytes);
                                }
                            }
                        }
                    }
                }
            }
        } else {
            rc4(block, &seed.to_le_bytes());
        }
    }

    Ok(())
}

pub fn decrypt_old_to(src: &mut [u8], dst: &mut [u8]) -> Result<(), MikiDecryptError> {
    if src.len() != dst.len() {
        return Err(MikiDecryptError::BufferSizeMismatch {
            expected: src.len(),
            actual: dst.len(),
        });
    }

    decrypt_old(src)?;
    dst.copy_from_slice(src);

    Ok(())
}

pub fn decrypt_old(bytes: &mut [u8]) -> Result<(), MikiDecryptError> {
    let encrypted_size = min(0x500, bytes.len());

    if encrypted_size < 0x20 {
        return Ok(());
    }

    let enc_data = &mut bytes[..encrypted_size];
    let enc_length = enc_data.len();
    let enc_data_int = bytes_to_u32_slice(&enc_data[..min(32, enc_data.len())]);

    let mut enc_block1 = [0u32; 4];
    enc_block1[0] = enc_data_int[2] ^ enc_data_int[5] ^ 0x3F72EAF3u32;
    enc_block1[1] = enc_data_int[3] ^ enc_data_int[7] ^ (enc_length as u32);
    enc_block1[2] = enc_data_int[1] ^ enc_data_int[4] ^ (enc_length as u32) ^ 0x753BDCAAu32;
    enc_block1[3] = enc_data_int[0] ^ enc_data_int[6] ^ 0xE3D947D3u32;

    let enc_block2_key_bytes = u32_array_to_bytes(&enc_block1);
    let enc_block2_key = generate_seed(&enc_block2_key_bytes).to_le_bytes();
    let enc_block2_key_int = u32::from_le_bytes(enc_block2_key);

    let enc_block1_key = (enc_length as u32)
        ^ enc_block1[0]
        ^ enc_block1[1]
        ^ enc_block1[2]
        ^ enc_block1[3]
        ^ 0x5E8BC918u32;

    let mut enc_block1_bytes = u32_array_to_bytes(&enc_block1);
    rc4(&mut enc_block1_bytes, &enc_block1_key.to_le_bytes());

    // Update enc_block1 from the modified bytes
    for (i, chunk) in enc_block1_bytes.chunks(4).enumerate() {
        if i < 4 && chunk.len() == 4 {
            enc_block1[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
    }

    let crc =
        Crc::calculate_digest(&enc_block1_bytes, 0, enc_block1_bytes.len() as u32).wrapping_sub(2);

    // XOR first 32 bytes with 0xb7
    for i in 0..32 {
        if i < enc_data.len() {
            enc_data[i] ^= 0xb7;
        }
    }

    if enc_length == 32 {
        return Ok(());
    }

    if enc_length < 0x9f {
        if enc_data.len() > 32 {
            rc4(&mut enc_data[32..], &enc_block2_key);
        }
        return Ok(());
    }

    let mut key_material2 = [0u32; 4];
    key_material2[0] = enc_block1[3].wrapping_add(0x6F1A36D8u32) ^ (crc.wrapping_add(0x2));
    key_material2[1] = enc_block1[2].wrapping_sub(0x7E9A2C76u32) ^ enc_block2_key_int;
    key_material2[2] = enc_block1[0] ^ 0x840CF7D0u32 ^ (crc.wrapping_add(0x2));
    key_material2[3] = enc_block1[1].wrapping_add(0x48D0E844) ^ enc_block2_key_int;

    let key_material2_bytes = u32_array_to_bytes(&key_material2);
    let key_block_key = generate_seed(&key_material2_bytes);

    if enc_data.len() > 0x20 + 0x80 {
        let enc_block2 = &mut enc_data[0x20..0x20 + 0x80];
        let mut key_block = enc_block2.to_vec();

        rc4(&mut key_block, &key_block_key.to_le_bytes());
        rc4(enc_block2, &key_material2_bytes[..12]);

        let key_table2 = [
            0x88558046u32,
            key_material2[3],
            0x5C7782C2u32,
            0x38922E17u32,
            key_material2[0],
            key_material2[1],
            0x44B38670u32,
            key_material2[2],
            0x6B07A514u32,
        ];

        if enc_data.len() > 0xa0 {
            let enc_block3 = &mut enc_data[0xa0..];
            let remaining_enc_section = enc_length - 0xa0;
            let remaining_non_aligned = enc_length - (remaining_enc_section & 0xffffff80) - 0xa0;

            if enc_length >= 0x120 {
                let key_block_int = bytes_to_u32_slice(&key_block);

                const BLOCK_SIZE: usize = 0x20;
                for i in 0..(remaining_enc_section / 0x80) {
                    let start_offset = i * BLOCK_SIZE * 4;
                    let end_offset = min(start_offset + BLOCK_SIZE * 4, enc_block3.len());

                    if start_offset >= enc_block3.len() {
                        break;
                    }

                    let type_val = key_table2[i % 9] & 3;

                    for idx in 0..BLOCK_SIZE {
                        let byte_offset = start_offset + idx * 4;
                        if byte_offset + 4 <= end_offset && idx < key_block_int.len() {
                            let key_block_val = key_block_int[idx];

                            let val = match type_val {
                                0 => {
                                    key_block_val
                                        ^ key_table2[(key_material2[idx & 3] % 9) as usize]
                                        ^ ((BLOCK_SIZE - idx) as u32)
                                }
                                1 => {
                                    key_block_val
                                        ^ key_material2[(key_block_val & 3) as usize]
                                        ^ key_table2[(key_block_val % 9) as usize]
                                }
                                2 => {
                                    key_block_val
                                        ^ key_material2[(key_block_val & 3) as usize]
                                        ^ (idx as u32)
                                }
                                3 => {
                                    key_block_val
                                        ^ key_material2[(key_table2[idx % 9] & 3) as usize]
                                        ^ ((BLOCK_SIZE - idx) as u32)
                                }
                                _ => return Err(MikiDecryptError::InvalidTypeValue),
                            };

                            if byte_offset + 4 <= enc_block3.len() {
                                let mut current_val = u32::from_le_bytes([
                                    enc_block3[byte_offset],
                                    enc_block3[byte_offset + 1],
                                    enc_block3[byte_offset + 2],
                                    enc_block3[byte_offset + 3],
                                ]);
                                current_val ^= val;
                                let bytes = current_val.to_le_bytes();
                                enc_block3[byte_offset..byte_offset + 4].copy_from_slice(&bytes);
                            }
                        }
                    }
                }
            }

            if remaining_non_aligned > 0 {
                let total_remaining_offset = remaining_enc_section - remaining_non_aligned;
                for i in 0..remaining_non_aligned {
                    let offset = total_remaining_offset + i;
                    if offset < enc_block3.len() && i < key_block.len() {
                        enc_block3[offset] ^= (i
                            ^ (key_block[i & 0x7f] as usize)
                            ^ ((key_table2[(key_material2[i & 3] % 9) as usize] % 0xff) as usize))
                            as u8;
                    }
                }
            }
        }
    }

    Ok(())
}

fn generate_seed(bytes: &[u8]) -> u32 {
    let mut state = [0xC1646153u32, 0x78DA0550u32, 0x2947E56Bu32];

    for &b in bytes.iter() {
        state[0] = 0x21u32.wrapping_mul(state[0]).wrapping_add(b as u32);

        if (state[0] & 0xF) >= 0xB {
            state[0] = (state[0] ^ rotate_is_set(state[2], 6)).wrapping_sub(0x2CD86315);
            state[0] &= 0xFFFFFFFF;
        } else if ((state[0] & 0xF0) >> 4) > 0xE {
            state[0] = (state[1] ^ 0xAB4A010B).wrapping_add(state[0] ^ rotate_is_set(state[2], 9));
            state[0] &= 0xFFFFFFFF;
        } else if ((state[0] & 0xF00) >> 8) < 2 {
            state[1] = ((state[2] >> 3).wrapping_sub(0x55EEAB7B)) ^ state[0];
            state[1] &= 0xFFFFFFFF;
        } else if (state[1].wrapping_add(0x567A)) >= 0xAB5489E4 {
            state[1] = (state[1] >> 16) ^ state[0];
            state[1] &= 0xFFFFFFFF;
        } else if (state[1] ^ 0x738766FA) <= state[2] {
            state[1] = (state[1] >> 8) ^ state[2];
            state[1] &= 0xFFFFFFFF;
        } else if state[1] == 0x68F53AA6 {
            if (state[1] ^ (state[0].wrapping_add(state[2]))) > 0x594AF86E {
                state[1] = state[1].wrapping_sub(0x08CA292E);
            } else {
                state[2] = state[2].wrapping_sub(0x760A1649);
            }
        } else {
            if state[0] > 0x865703AF {
                state[1] = state[2] ^ (state[0].wrapping_sub(0x564389D7));
            } else {
                state[1] = (state[1].wrapping_sub(0x12B9DD92)) ^ state[0];
            }
            state[1] &= 0xFFFFFFFF;
            state[0] ^= rotate_is_set(state[1], 8);
            state[0] &= 0xFFFFFFFF;
        }
    }

    state[0]
}

fn rotate_is_set(value: u32, count: i32) -> u32 {
    if (value >> count) != 0 || (value << (32 - count)) != 0 {
        1
    } else {
        0
    }
}

fn bytes_to_u32_slice(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|chunk| {
            if chunk.len() == 4 {
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            } else {
                let mut padded = [0u8; 4];
                padded[..chunk.len()].copy_from_slice(chunk);
                u32::from_le_bytes(padded)
            }
        })
        .collect()
}

fn u32_array_to_bytes(ints: &[u32]) -> Vec<u8> {
    ints.iter().flat_map(|&i| i.to_le_bytes()).collect()
}

fn rc4(data: &mut [u8], key: &[u8]) {
    let mut s = [0i32; 0x100];
    for (i, item) in s.iter_mut().enumerate() {
        *item = i as i32;
    }

    let mut t = [0i32; 0x100];
    if key.len() == 0x100 {
        for i in 0..0x100 {
            t[i] = key[i] as i32;
        }
    } else {
        for i in 0..0x100 {
            t[i] = key[i % key.len()] as i32;
        }
    }

    let mut j = 0i32;
    for i in 0..0x100 {
        j = (j + s[i] + t[i]) % 0x100;
        s.swap(i, j as usize);
    }

    let mut i = 0i32;
    j = 0;
    for byte in data.iter_mut() {
        i = (i + 1) % 0x100;
        j = (j + s[i as usize]) % 0x100;
        s.swap(i as usize, j as usize);

        let k_val = s[((s[j as usize] + s[i as usize]) % 0x100) as usize] as u32;
        let k = ((k_val << 1) | (k_val >> 7)) as u8;
        *byte ^= k.wrapping_sub(0x61);
    }
}

pub struct Crc {
    table: [u32; 256],
    value: u32,
}

impl Crc {
    pub fn new() -> Self {
        let mut table = [0u32; 256];
        const K_POLY: u32 = 0xD35E417E;

        for (i, item) in table.iter_mut().enumerate() {
            let mut r = i as u32;
            for _ in 0..8 {
                if (r & 1) != 0 {
                    r = (r >> 1) ^ K_POLY;
                } else {
                    r >>= 1;
                }
            }
            *item = r;
        }

        Crc {
            table,
            value: 0xFFFFFFFF,
        }
    }

    pub fn update(&mut self, data: &[u8], offset: u32, size: u32) {
        for i in 0..size {
            let idx = offset as usize + i as usize;
            if idx < data.len() {
                self.value = (self.table[(self.value as u8 ^ data[idx]) as usize]
                    ^ (self.value >> 9))
                    .wrapping_add(0x5B);
            }
        }
    }

    pub fn get_digest(&self) -> u32 {
        (!self.value).wrapping_sub(0x41607A3D)
    }

    pub fn calculate_digest(data: &[u8], offset: u32, size: u32) -> u32 {
        let mut crc = Crc::new();
        crc.update(data, offset, size);
        crc.get_digest()
    }
}
