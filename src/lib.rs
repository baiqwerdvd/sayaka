mod miki;
mod lz4inv;

use pyo3::prelude::*;

#[pymodule]
mod sayaka {
    use std::mem;

    use pyo3::{exceptions::PyBufferError, ffi, types::PyBytes};

    use crate::miki::{decrypt_old_to, decrypt_to};
    use crate::lz4inv::decompress_impl;

    use super::*;

    #[pyfunction]
    fn miki_decrypt_and_decompress<'py>(
        py: pyo3::Python<'py>,
        encrypted: &Bound<'py, PyAny>,
        decompressed_size: usize,
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyBytes>> {
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

        let result = PyBytes::new_with(py, decompressed_size, |decompressed| {
            miki::decrypt(encrypted)?;
            decompress_impl(encrypted, decompressed)?;
            Ok(())
        });

        Python::with_gil(|_| unsafe { ffi::PyBuffer_Release(&mut buf) });
        result
    }

    #[pyfunction]
    fn miki_decrypt_old_and_decompress<'py>(
        py: pyo3::Python<'py>,
        encrypted: &Bound<'py, PyAny>,
        decompressed_size: usize,
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyBytes>> {
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

        let result = PyBytes::new_with(py, decompressed_size, |decompressed| {
            miki::decrypt_old(encrypted)?;
            decompress_impl(encrypted, decompressed)?;
            Ok(())
        });

        Python::with_gil(|_| unsafe { ffi::PyBuffer_Release(&mut buf) });
        result
    }

    #[pyfunction]
    fn miki_decrypt<'py>(
        py: pyo3::Python<'py>,
        encrypted: &Bound<'py, PyAny>,
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyBytes>> {
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

        let result = PyBytes::new_with(py, encrypted.len(), |decrypted| {
            decrypt_to(encrypted, decrypted)?;

            Ok(())
        });

        Python::with_gil(|_| unsafe { ffi::PyBuffer_Release(&mut buf) });
        result
    }

    #[pyfunction]
    fn miki_decrypt_old<'py>(
        py: pyo3::Python<'py>,
        encrypted: &Bound<'py, PyAny>,
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyBytes>> {
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

        let result = PyBytes::new_with(py, encrypted.len(), |decrypted| {
            decrypt_old_to(encrypted, decrypted)?;

            Ok(())
        });

        Python::with_gil(|_| unsafe { ffi::PyBuffer_Release(&mut buf) });
        result
    }

    #[pyfunction]
    fn decompress_buffer<'py>(
        py: pyo3::Python<'py>,
        compressed: &Bound<'py, PyAny>,
        decompressed_size: usize,
    ) -> PyResult<pyo3::Bound<'py, pyo3::types::PyBytes>> {
        // https://github.com/milesgranger/cramjam/blob/c09d2aea008dcc445bf16f1ee7350e25c50163a8/src/io.rs#L265
        let mut buf = Box::new(mem::MaybeUninit::uninit());
        let rc = unsafe {
            ffi::PyObject_GetBuffer(compressed.as_ptr(), buf.as_mut_ptr(), ffi::PyBUF_CONTIG_RO)
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
        let compressed =
            unsafe { std::slice::from_raw_parts(buf.buf as *const u8, buf.len as usize) };
        let result = PyBytes::new_with(py, decompressed_size, |decompressed| {
            decompress_impl(compressed, decompressed)?;
            Ok(())
        });
        Python::with_gil(|_| unsafe { ffi::PyBuffer_Release(&mut buf) });
        result
    }
}
