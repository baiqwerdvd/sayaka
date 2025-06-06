use std::{fmt::Display, mem};

use pyo3::{
    Bound, PyAny, PyErr, PyResult, Python, exceptions::PyBufferError, ffi, pyclass, pymethods,
    types::PyBytes,
};

const ALLOWED_KEY_LENGTH: usize = 32;
const ALLOWED_NONCE_LENGTH: usize = 12;
const STATE_LENGTH: usize = 16;
const KEYSTREAM_SIZE: usize = STATE_LENGTH * 4;

#[derive(Debug)]
pub enum ChaCha20Error {
    InvalidKeyLength { expected: usize, actual: usize },
    InvalidNonceLength { expected: usize, actual: usize },
}

impl Display for ChaCha20Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChaCha20Error::InvalidKeyLength { expected, actual } => {
                write!(
                    f,
                    "Invalid key length: expected {}, actual {}",
                    expected, actual
                )
            }
            ChaCha20Error::InvalidNonceLength { expected, actual } => {
                write!(
                    f,
                    "Invalid nonce length: expected {}, actual {}",
                    expected, actual
                )
            }
        }
    }
}

impl From<ChaCha20Error> for PyErr {
    fn from(err: ChaCha20Error) -> PyErr {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string())
    }
}

#[derive(Copy, Clone)]
#[pyclass]
pub struct ChaCha20 {
    state: [u32; STATE_LENGTH],
    keystream: [u8; KEYSTREAM_SIZE],
    keystream_block_idx: usize,
}

#[pymethods]
impl ChaCha20 {
    #[new]
    pub fn new(key: &[u8], nonce: &[u8], counter: u32) -> PyResult<Self> {
        if key.len() != ALLOWED_KEY_LENGTH {
            return Err(ChaCha20Error::InvalidKeyLength {
                expected: ALLOWED_KEY_LENGTH,
                actual: key.len(),
            }.into());
        }
        if nonce.len() != ALLOWED_NONCE_LENGTH {
            return Err(ChaCha20Error::InvalidNonceLength {
                expected: ALLOWED_NONCE_LENGTH,
                actual: nonce.len(),
            }.into());
        }

        let mut state = [0u32; STATE_LENGTH];
        init_state(&mut state, key, nonce, counter);
        let keystream = chacha20_block(&mut state);

        Ok(ChaCha20 {
            state,
            keystream,
            keystream_block_idx: 0,
        })
    }

    pub fn work_bytes<'py>(
        &mut self,
        py: pyo3::Python<'py>,
        encrypted: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        // https://github.com/milesgranger/cramjam/blob/c09d2aea008dcc445bf16f1ee7350e25c50163a8/src/io.rs#L265
        let mut buf = Box::new(mem::MaybeUninit::uninit());
        let rc = unsafe {
            ffi::PyObject_GetBuffer(encrypted.as_ptr(), buf.as_mut_ptr(), ffi::PyBUF_CONTIG_RO)
        };
        if rc != 0 {
            return Err(PyBufferError::new_err(
                "Failed to get buffer, is it C contiguous, and shape is not null?",
            ));
        }
        let mut buf = unsafe { mem::MaybeUninit::<ffi::Py_buffer>::assume_init(*buf) };
        if buf.shape.is_null() {
            return Err(PyBufferError::new_err("shape is null"));
        }
        let is_c_contiguous = unsafe {
            ffi::PyBuffer_IsContiguous(&buf as *const ffi::Py_buffer, b'C' as std::os::raw::c_char)
                == 1
        };
        if !is_c_contiguous {
            return Err(PyBufferError::new_err("Buffer is not C contiguous"));
        }
        let encrypted =
            unsafe { std::slice::from_raw_parts_mut(buf.buf as *mut u8, buf.len as usize) };

        let result = PyBytes::new_with(py, encrypted.len(), |data| {
            self.work_bytes_inner(encrypted);
            data.copy_from_slice(encrypted);
            Ok(())
        });

        Python::with_gil(|_| unsafe { ffi::PyBuffer_Release(&mut buf) });
        result
    }
}

impl ChaCha20 {
    fn work_bytes_inner(&mut self, data: &mut [u8]) {
        let mut data_ptr = data.as_mut_ptr();
        let mut remaining = data.len();
        let keystream_ptr = self.keystream.as_ptr();

        unsafe {
            while remaining > 0 {
                if self.keystream_block_idx == 64 {
                    self.keystream = chacha20_block(&mut self.state);
                    self.keystream_block_idx = 0;
                }

                let available = 64 - self.keystream_block_idx;
                let block_size = available.min(remaining);

                let keystream_ptr = keystream_ptr.add(self.keystream_block_idx);

                for i in 0..block_size {
                    *data_ptr.add(i) ^= *keystream_ptr.add(i);
                }

                data_ptr = data_ptr.add(block_size);
                self.keystream_block_idx += block_size;
                remaining -= block_size;
            }
        }
    }
}

impl std::fmt::Debug for ChaCha20 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChaCha20")
            .field("state", &self.state)
            .field("keystream", &self.keystream)
            .field("keystream_block_idx", &self.keystream_block_idx)
            .finish()
    }
}

fn init_state(state: &mut [u32; STATE_LENGTH], key: &[u8], nonce: &[u8], counter: u32) {
    unsafe {
        *state.get_unchecked_mut(0) = 0x61707865u32;
        *state.get_unchecked_mut(1) = 0x3320646eu32;
        *state.get_unchecked_mut(2) = 0x79622d32u32;
        *state.get_unchecked_mut(3) = 0x6b206574u32;

        let key_ptr = key.as_ptr() as *const u32;
        let state_ptr = state.as_mut_ptr().add(4);

        for i in 0..8 {
            *state_ptr.add(i) = key_ptr.add(i).read_unaligned();
        }

        *state.get_unchecked_mut(12) = counter;
        let state_ptr = state.as_mut_ptr().add(13);

        let nonce_ptr = nonce.as_ptr() as *const u32;
        for i in 0..3 {
            *state_ptr.add(i) = nonce_ptr.add(i).read_unaligned();
        }
    }
}

fn chacha20_block(initial_state: &mut [u32; STATE_LENGTH]) -> [u8; KEYSTREAM_SIZE] {
    let mut x = *initial_state;
    let mut keystream_block = [0u8; KEYSTREAM_SIZE];

    for _ in 0..10 {
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 1, 5, 9, 13);
        quarter_round(&mut x, 2, 6, 10, 14);
        quarter_round(&mut x, 3, 7, 11, 15);

        quarter_round(&mut x, 0, 5, 10, 15);
        quarter_round(&mut x, 1, 6, 11, 12);
        quarter_round(&mut x, 2, 7, 8, 13);
        quarter_round(&mut x, 3, 4, 9, 14);
    }

    for (i, (s, x_val)) in initial_state.iter().zip(x.iter()).enumerate() {
        let val = s.wrapping_add(*x_val);
        keystream_block[i * 4..(i + 1) * 4].copy_from_slice(&val.to_le_bytes());
    }

    let (new_counter, _) = initial_state[12].overflowing_add(1);
    initial_state[12] = new_counter;

    if new_counter == 0 {
        initial_state[13] = initial_state[13].wrapping_add(1);
    }

    keystream_block
}

#[inline]
fn quarter_round(x: &mut [u32], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);

    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}
