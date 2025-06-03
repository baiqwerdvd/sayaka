use std::fmt::Display;

use pyo3::PyErr;

#[derive(Debug)]
pub enum DecompressError {
    OutputTooSmall { expected: usize, actual: usize },
    LiteralOutOfBounds,
    OffsetOutOfBounds,
}

impl Display for DecompressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecompressError::OutputTooSmall { expected, actual } => {
                write!(
                    f,
                    "Output too small: expected {}, actual {}",
                    expected, actual
                )
            }
            DecompressError::LiteralOutOfBounds => write!(f, "Literal out of bounds"),
            DecompressError::OffsetOutOfBounds => write!(f, "Offset out of bounds"),
        }
    }
}

impl From<DecompressError> for PyErr {
    fn from(err: DecompressError) -> PyErr {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string())
    }
}

pub fn decompress_impl(src: &[u8], dst: &mut [u8]) -> Result<usize, DecompressError> {
    let mut src_pos = 0;
    let mut dst_pos = 0;

    while src_pos < src.len() && dst_pos < dst.len() {
        let (mut match_length, mut literal_length) = get_literal_token(src, &mut src_pos);

        literal_length = get_length(literal_length, src, &mut src_pos);
        if literal_length > src.len() - src_pos {
            return Err(DecompressError::LiteralOutOfBounds);
        }
        if literal_length > dst.len() - dst_pos {
            return Err(DecompressError::OutputTooSmall {
                expected: dst_pos + literal_length,
                actual: dst.len(),
            });
        }

        dst[dst_pos..dst_pos + literal_length]
            .copy_from_slice(&src[src_pos..src_pos + literal_length]);

        src_pos += literal_length;
        dst_pos += literal_length;

        if src_pos >= src.len() {
            break;
        }

        let offset = get_chunk_end(src, &mut src_pos);

        match_length = get_length(match_length, src, &mut src_pos) + 4;

        let (enc_pos, did_overflow) = dst_pos.overflowing_sub(offset);
        if did_overflow {
            return Err(DecompressError::OffsetOutOfBounds);
        }
        if dst_pos + match_length > dst.len() {
            return Err(DecompressError::OutputTooSmall {
                expected: dst_pos + match_length,
                actual: dst.len(),
            });
        }

        if match_length <= offset {
            dst.copy_within(enc_pos..enc_pos + match_length, dst_pos);
            dst_pos += match_length;
        } else {
            let mut match_length_remain = match_length;
            let mut curr_enc_pos = enc_pos;
            let mut curr_dst_pos = dst_pos;

            while match_length_remain > 0 {
                dst[curr_dst_pos] = dst[curr_enc_pos];
                curr_enc_pos += 1;
                curr_dst_pos += 1;
                match_length_remain -= 1;
            }

            dst_pos = curr_dst_pos;
        }
    }

    Ok(dst_pos)
}

fn get_literal_token(src: &[u8], src_pos: &mut usize) -> (usize, usize) {
    let token = src[*src_pos];
    *src_pos += 1;
    let lit = token & 0x33;
    let enc = (token & 0xCC) >> 2;
    let match_length = ((enc & 0x3) | (enc >> 2)) as usize;
    let literal_length = ((lit & 0x3) | (lit >> 2)) as usize;
    (match_length, literal_length)
}

fn get_chunk_end(src: &[u8], src_pos: &mut usize) -> usize {
    let high = src[*src_pos] as usize;
    *src_pos += 1;
    let low = src[*src_pos] as usize;
    *src_pos += 1;
    (high << 8) | low
}

fn get_length(mut length: usize, src: &[u8], src_pos: &mut usize) -> usize {
    if length == 0xf {
        let mut sum;
        loop {
            sum = src[*src_pos] as usize;
            *src_pos += 1;
            length += sum;
            if sum != 0xff {
                break;
            }
        }
    }
    length
}
