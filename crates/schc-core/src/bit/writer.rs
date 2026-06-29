use crate::error::{Result, SchcError};

/// MSB-first bit writer backed by an owned byte buffer.
#[derive(Debug, Clone, Default)]
pub struct BitWriter {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl BitWriter {
    /// Creates an empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of bits written.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    /// Writes the low `bits` bits of `value`, most significant bit first.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::InvalidBitLength`] when `bits` is zero, greater than
    /// 64, or when `value` does not fit in `bits`.
    pub fn write_bits(&mut self, value: u64, bits: usize) -> Result<()> {
        validate_bit_width("write_bits", bits)?;
        if !value_fits(value, bits) {
            return Err(SchcError::InvalidBitLength {
                operation: "write_bits",
                bits,
            });
        }

        for shift in (0..bits).rev() {
            self.write_bit(((value >> shift) & 1) as u8);
        }

        Ok(())
    }

    /// Truncates the buffer to `bits` bits.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::BitOutOfBounds`] when `bits` is greater than the
    /// current bit length.
    pub fn truncate_bits(&mut self, bits: usize) -> Result<()> {
        if bits > self.bit_len {
            return Err(SchcError::BitOutOfBounds {
                position: self.bit_len,
                requested: bits - self.bit_len,
                available: 0,
            });
        }

        self.bit_len = bits;
        self.bytes.truncate(bits.div_ceil(8));
        if bits % 8 != 0 {
            let last = self.bytes.len() - 1;
            let keep_mask = u8::MAX << (8 - (bits % 8));
            self.bytes[last] &= keep_mask;
        }

        Ok(())
    }

    /// Returns the written bytes with the final byte padded by zero bits.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = self.bytes.clone();
        bytes.truncate(self.bit_len.div_ceil(8));
        if self.bit_len % 8 != 0 {
            let last = bytes.len() - 1;
            let keep_mask = u8::MAX << (8 - (self.bit_len % 8));
            bytes[last] &= keep_mask;
        }
        bytes
    }

    fn write_bit(&mut self, bit: u8) {
        if self.bit_len % 8 == 0 {
            self.bytes.push(0);
        }

        if bit == 1 {
            let byte_index = self.bit_len / 8;
            let shift = 7 - (self.bit_len % 8);
            self.bytes[byte_index] |= 1 << shift;
        }

        self.bit_len += 1;
    }
}

fn validate_bit_width(operation: &'static str, bits: usize) -> Result<()> {
    if bits == 0 || bits > 64 {
        return Err(SchcError::InvalidBitLength { operation, bits });
    }

    Ok(())
}

fn value_fits(value: u64, bits: usize) -> bool {
    bits == 64 || value < (1_u64 << bits)
}
