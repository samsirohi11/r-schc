use crate::bit::BitWriter;
use crate::error::{Result, SchcError};

/// MSB-first bit reader over a borrowed byte slice.
#[derive(Debug, Clone)]
pub struct BitReader<'a> {
    bytes: &'a [u8],
    position: usize,
    bit_len: usize,
}

impl<'a> BitReader<'a> {
    /// Creates a reader at bit position zero.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            position: 0,
            bit_len: bytes.len() * 8,
        }
    }

    /// Creates a reader limited to the meaningful prefix of a byte slice.
    ///
    /// The unused bits in the final byte are not readable. This is used by
    /// SCHC datagrams, whose wire representation may contain zero padding.
    ///
    /// # Errors
    ///
    /// Returns an error when `bit_len` exceeds the backing byte slice.
    pub fn with_bit_len(bytes: &'a [u8], bit_len: usize) -> Result<Self> {
        if bit_len > bytes.len() * 8 {
            return Err(SchcError::BitOutOfBounds {
                position: 0,
                requested: bit_len,
                available: bytes.len() * 8,
            });
        }
        Ok(Self {
            bytes,
            position: 0,
            bit_len,
        })
    }

    /// Returns the current bit position.
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the total number of readable bits.
    #[must_use]
    pub const fn bit_len(&self) -> usize {
        self.bit_len
    }

    /// Returns the number of bits remaining from the current position.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bit_len - self.position
    }

    /// Sets the current bit position.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::BitOutOfBounds`] if `position` is past the end of the
    /// backing byte slice.
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
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::InvalidBitLength`] when `bits` is zero or greater than
    /// 64.
    /// Returns [`SchcError::BitOutOfBounds`] when the requested bits are not
    /// available.
    pub fn read_bits(&mut self, bits: usize) -> Result<u64> {
        validate_bit_width("read_bits", bits)?;
        self.ensure_available(bits)?;

        let mut value = 0;
        for _ in 0..bits {
            value = (value << 1) | u64::from(self.read_bit());
        }

        Ok(value)
    }

    /// Copies up to `bits` bits to an MSB-first bit writer.
    ///
    /// Unlike [`Self::read_bits`], this operation is not limited to 64 bits.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::BitOutOfBounds`] when the requested bits are not
    /// available.
    pub(crate) fn copy_to(&mut self, writer: &mut BitWriter, bits: usize) -> Result<()> {
        self.ensure_available(bits)?;
        for _ in 0..bits {
            writer.write_bit(self.read_bit() != 0);
        }
        Ok(())
    }

    /// Reads bits into bytes and pads the final byte with zero bits.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::BitOutOfBounds`] when the requested bits are not
    /// available.
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
