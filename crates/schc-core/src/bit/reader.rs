use crate::error::{Result, SchcError};

/// MSB-first bit reader over a borrowed byte slice.
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> BitReader<'a> {
    /// Creates a reader at bit position zero.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Returns the current bit position.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the total number of readable bits.
    pub fn bit_len(&self) -> usize {
        self.bytes.len() * 8
    }

    /// Returns the number of bits remaining from the current position.
    pub fn remaining(&self) -> usize {
        self.bit_len() - self.position
    }

    /// Sets the current bit position.
    pub fn set_position(&mut self, position: usize) -> Result<()> {
        if position > self.bit_len() {
            return Err(SchcError::BitOutOfBounds {
                position,
                requested: 0,
                available: self.bit_len(),
            });
        }

        self.position = position;
        Ok(())
    }

    /// Reads up to 64 bits as a `u64`, most significant bit first.
    pub fn read_bits(&mut self, bits: usize) -> Result<u64> {
        validate_bit_width("read_bits", bits)?;
        self.ensure_available(bits)?;

        let mut value = 0;
        for _ in 0..bits {
            value = (value << 1) | u64::from(self.read_bit());
        }

        Ok(value)
    }

    /// Reads bits into bytes and pads the final byte with zero bits.
    pub fn read_bytes_padded(&mut self, bits: usize) -> Result<Vec<u8>> {
        self.ensure_available(bits)?;

        let mut out = vec![0; bits.div_ceil(8)];
        for bit_index in 0..bits {
            if self.read_bit() == 1 {
                out[bit_index / 8] |= 1 << (7 - (bit_index % 8));
            }
        }

        Ok(out)
    }

    fn ensure_available(&self, bits: usize) -> Result<()> {
        if bits > self.remaining() {
            return Err(SchcError::BitOutOfBounds {
                position: self.position,
                requested: bits,
                available: self.remaining(),
            });
        }

        Ok(())
    }

    fn read_bit(&mut self) -> u8 {
        let byte = self.bytes[self.position / 8];
        let shift = 7 - (self.position % 8);
        self.position += 1;
        (byte >> shift) & 1
    }
}

fn validate_bit_width(operation: &'static str, bits: usize) -> Result<()> {
    if bits == 0 || bits > 64 {
        return Err(SchcError::InvalidBitLength { operation, bits });
    }

    Ok(())
}
