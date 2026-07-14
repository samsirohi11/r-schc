//! Packet field values shared by compression and decompression.

use crate::bit::{BitReader, BitWriter};
use crate::error::{Result, SchcError};
use crate::rule::FieldRef;

/// Packet nesting scope used internally while traversing a packet.
///
/// This is deliberately separate from SCHC field position. Field position
/// continues to identify repeated occurrences of a field, while scope records
/// whether the occurrence belongs to the outer packet or an embedded packet.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) enum PacketScope {
    Outer,
    Embedded,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[allow(dead_code)]
pub(crate) struct FieldKey {
    field: FieldRef,
    field_position: usize,
    entry_index: usize,
    scope: PacketScope,
}

impl FieldKey {
    #[allow(dead_code)]
    pub(crate) fn new(field: FieldRef, field_position: usize, entry_index: usize) -> Self {
        Self::with_scope(field, field_position, entry_index, PacketScope::Outer)
    }

    pub(crate) fn with_scope(
        field: FieldRef,
        field_position: usize,
        entry_index: usize,
        scope: PacketScope,
    ) -> Self {
        Self {
            field,
            field_position,
            entry_index,
            scope,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn field(&self) -> &FieldRef {
        &self.field
    }

    #[allow(dead_code)]
    pub(crate) const fn entry_index(&self) -> usize {
        self.entry_index
    }

    #[allow(dead_code)]
    pub(crate) const fn field_position(&self) -> usize {
        self.field_position
    }

    pub(crate) const fn scope(&self) -> PacketScope {
        self.scope
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct FieldStore {
    values: Vec<(FieldKey, FieldValue)>,
}

impl FieldStore {
    #[allow(dead_code)]
    pub(crate) fn insert(&mut self, key: FieldKey, value: FieldValue) {
        self.values.push((key, value));
    }

    #[allow(dead_code)]
    pub(crate) fn get(&self, key: &FieldKey) -> Option<&FieldValue> {
        self.values
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
    }

    #[allow(dead_code)]
    pub(crate) fn by_entry_index(&self, entry_index: usize) -> Option<&FieldValue> {
        self.values
            .iter()
            .find_map(|(key, value)| (key.entry_index() == entry_index).then_some(value))
    }

    #[allow(dead_code)]
    pub(crate) fn by_field<'a>(
        &'a self,
        field: &'a FieldRef,
    ) -> impl Iterator<Item = (&'a FieldKey, &'a FieldValue)> + 'a {
        self.values
            .iter()
            .filter_map(move |(key, value)| (key.field() == field).then_some((key, value)))
    }

    #[allow(dead_code)]
    pub(crate) fn first_by_field(&self, field: &FieldRef) -> Option<&FieldValue> {
        self.values
            .iter()
            .find_map(|(key, value)| (key.field() == field).then_some(value))
    }

    /// Returns the first stored value for `field` at a specific field position.
    ///
    /// Field position remains available for existing position-based vectors;
    /// packet nesting is represented separately by [`PacketScope`].
    #[allow(dead_code)]
    pub(crate) fn first_by_field_position(
        &self,
        field: &FieldRef,
        position: usize,
    ) -> Option<&FieldValue> {
        self.values.iter().find_map(|(key, value)| {
            (key.field() == field && key.field_position() == position).then_some(value)
        })
    }

    /// Returns the first stored value for `field` in a packet scope.
    pub(crate) fn first_by_field_scope(
        &self,
        field: &FieldRef,
        scope: PacketScope,
    ) -> Option<&FieldValue> {
        self.values.iter().find_map(|(key, value)| {
            (key.field() == field && key.scope() == scope).then_some(value)
        })
    }

    /// Returns true when a field is present in a packet scope.
    pub(crate) fn contains_field_scope(&self, field: &FieldRef, scope: PacketScope) -> bool {
        self.first_by_field_scope(field, scope).is_some()
    }

    /// Iterates over all stored fields in insertion (rule entry) order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&FieldKey, &FieldValue)> {
        self.values.iter().map(|(key, value)| (key, value))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct FieldValue {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl FieldValue {
    pub(crate) fn from_bytes(bytes: Vec<u8>, bit_len: usize) -> Result<Self> {
        if bit_len > bytes.len() * 8 {
            return Err(SchcError::InvalidBitLength {
                operation: "field_value_from_bytes",
                bits: bit_len,
            });
        }
        let mut bytes = bytes;
        bytes.truncate(bit_len.div_ceil(8));
        if bit_len == 0 {
            bytes.clear();
            return Ok(Self { bytes, bit_len });
        }
        let unused_bits = bytes.len() * 8 - bit_len;
        if unused_bits > 0 {
            let mask = (1_u8 << unused_bits) - 1;
            if bytes.last().is_some_and(|last| last & mask != 0) {
                return Err(SchcError::InvalidResidue(
                    "field value has non-zero unused bits".to_owned(),
                ));
            }
        }
        Ok(Self { bytes, bit_len })
    }

    pub(crate) fn from_u64(value: u64, bit_len: usize) -> Result<Self> {
        if bit_len > 64 {
            return Err(SchcError::InvalidBitLength {
                operation: "field_value_from_u64",
                bits: bit_len,
            });
        }
        if bit_len < 64 && value >= (1_u64 << bit_len) {
            return Err(SchcError::InvalidBitLength {
                operation: "field_value_from_u64_fit",
                bits: bit_len,
            });
        }
        let mut writer = BitWriter::new();
        if bit_len > 0 {
            writer.write_bits(value, bit_len)?;
        }
        Self::from_bytes(writer.to_vec(), bit_len)
    }

    pub(crate) fn read_from(reader: &mut BitReader<'_>, bit_len: usize) -> Result<Self> {
        Self::from_bytes(reader.read_bytes_padded(bit_len)?, bit_len)
    }

    pub(crate) fn write_to(&self, writer: &mut BitWriter) -> Result<()> {
        self.write_range_to(writer, 0, self.bit_len)
    }

    /// Copies an MSB-first bit range into a writer without narrowing the value.
    pub(crate) fn write_range_to(
        &self,
        writer: &mut BitWriter,
        start: usize,
        bits: usize,
    ) -> Result<()> {
        if start > self.bit_len || bits > self.bit_len - start {
            return Err(SchcError::BitOutOfBounds {
                position: start,
                requested: bits,
                available: self.bit_len.saturating_sub(start),
            });
        }
        let mut reader = BitReader::new(self.bytes());
        reader.set_position(start)?;
        reader.copy_to(writer, bits)
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) const fn bit_len(&self) -> usize {
        self.bit_len
    }

    pub(crate) fn to_u64(&self) -> Result<u64> {
        if self.bit_len > 64 {
            return Err(SchcError::InvalidBitLength {
                operation: "field_value_to_u64",
                bits: self.bit_len,
            });
        }
        let mut reader = BitReader::new(&self.bytes);
        if self.bit_len == 0 {
            Ok(0)
        } else {
            reader.read_bits(self.bit_len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FieldKey, FieldStore, FieldValue};
    use crate::bit::{BitReader, BitWriter};
    use crate::rule::FieldRef;

    #[test]
    fn writes_non_byte_aligned_value() {
        let value = FieldValue::from_u64(0b101, 3).unwrap();
        let mut writer = BitWriter::new();

        value.write_to(&mut writer).unwrap();

        assert_eq!(writer.bit_len(), 3);
        assert_eq!(writer.to_vec(), vec![0b1010_0000]);
    }

    #[test]
    fn reads_non_byte_aligned_value() {
        let mut reader = BitReader::new(&[0b1011_0000]);

        let value = FieldValue::read_from(&mut reader, 5).unwrap();

        assert_eq!(value.bit_len(), 5);
        assert_eq!(value.to_u64().unwrap(), 0b10110);
    }

    #[test]
    fn preserves_payload_larger_than_u64() {
        let bytes = b"temperature=21.5".to_vec();

        let value = FieldValue::from_bytes(bytes.clone(), bytes.len() * 8).unwrap();

        assert_eq!(value.bytes(), bytes.as_slice());
        assert_eq!(value.bit_len(), bytes.len() * 8);
        assert!(value.to_u64().is_err());
    }

    #[test]
    fn rejects_non_zero_unused_bits() {
        assert!(FieldValue::from_bytes(vec![0b0001_0000], 3).is_err());
    }

    #[test]
    fn field_store_preserves_repeated_fields_by_entry_index() {
        let mut store = FieldStore::default();
        let first = FieldKey::new(FieldRef::CoapOption { number: 11 }, 1, 20);
        let second = FieldKey::new(FieldRef::CoapOption { number: 11 }, 2, 21);

        store.insert(
            first.clone(),
            FieldValue::from_bytes(b"sensors".to_vec(), 56).unwrap(),
        );
        store.insert(
            second.clone(),
            FieldValue::from_bytes(b"temp".to_vec(), 32).unwrap(),
        );

        assert_eq!(store.get(&first).unwrap().bytes(), b"sensors");
        assert_eq!(store.get(&second).unwrap().bytes(), b"temp");
        assert_eq!(
            store.by_field(&FieldRef::CoapOption { number: 11 }).count(),
            2
        );
    }
}
