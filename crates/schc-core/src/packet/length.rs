use crate::bit::{BitReader, BitWriter};
use crate::error::{Result, SchcError};
use crate::packet::field::FieldStore;
use crate::rule::{FieldLength, LengthUnit};

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub(crate) struct LengthResolver {
    token_length: Option<usize>,
}

impl LengthResolver {
    #[allow(dead_code)]
    pub(crate) fn set_token_length(&mut self, token_length: usize) {
        self.token_length = Some(token_length);
    }

    #[allow(dead_code)]
    pub(crate) fn resolve(&self, length: &FieldLength, fields: &FieldStore) -> Result<usize> {
        match length {
            FieldLength::FixedBits(bits) => Ok(*bits),
            FieldLength::TokenLength => self
                .token_length
                .map(|bytes| bytes * 8)
                .ok_or_else(|| SchcError::InvalidResidue("CoAP TKL is not available".to_owned())),
            FieldLength::FromPreviousField { entry_index, unit } => {
                let value = fields.by_entry_index(*entry_index).ok_or_else(|| {
                    SchcError::InvalidResidue(format!(
                        "field length references missing entry {entry_index}"
                    ))
                })?;
                let value = usize::try_from(value.to_u64()?).map_err(|_| {
                    SchcError::InvalidResidue("field length value does not fit usize".to_owned())
                })?;
                Ok(match unit {
                    LengthUnit::Bytes => value * 8,
                    LengthUnit::Bits => value,
                })
            }
            FieldLength::VariableBytes | FieldLength::VariableBits => {
                Err(SchcError::InvalidResidue(
                    "variable field length must be read from residue".to_owned(),
                ))
            }
            FieldLength::FunctionSid(sid) => Err(SchcError::InvalidResidue(format!(
                "unsupported field-length function SID {sid}"
            ))),
        }
    }
}

#[allow(dead_code)]
pub(crate) fn write_variable_length_prefix(writer: &mut BitWriter, value: usize) -> Result<()> {
    if value <= 14 {
        writer.write_bits(value as u64, 4)
    } else if value <= 254 {
        writer.write_bits(15, 4)?;
        writer.write_bits(value as u64, 8)
    } else if value <= 65_535 {
        writer.write_bits(15, 4)?;
        writer.write_bits(255, 8)?;
        writer.write_bits(value as u64, 16)
    } else {
        Err(SchcError::InvalidResidue(format!(
            "variable length {value} is too large"
        )))
    }
}

#[allow(dead_code)]
pub(crate) fn read_variable_length_prefix(reader: &mut BitReader<'_>) -> Result<usize> {
    let first = usize::try_from(reader.read_bits(4)?).expect("4 bits fit usize");
    if first < 15 {
        return Ok(first);
    }
    let second = usize::try_from(reader.read_bits(8)?).expect("8 bits fit usize");
    if second < 255 {
        return Ok(second);
    }
    usize::try_from(reader.read_bits(16)?)
        .map_err(|_| SchcError::InvalidResidue("variable length does not fit usize".to_owned()))
}

#[allow(dead_code)]
pub(crate) fn write_variable_length_bytes(output: &mut Vec<u8>, value: usize) -> Result<()> {
    let mut writer = BitWriter::new();
    write_variable_length_prefix(&mut writer, value)?;
    *output = writer.to_vec();
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn read_variable_length_bytes(reader: &mut BitReader<'_>) -> Result<usize> {
    read_variable_length_prefix(reader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::field::{FieldKey, FieldStore, FieldValue};
    use crate::rule::FieldRef;

    #[test]
    fn resolves_token_length_from_tkl_bytes() {
        let mut resolver = LengthResolver::default();
        resolver.set_token_length(2);

        assert_eq!(
            resolver
                .resolve(&FieldLength::TokenLength, &FieldStore::default())
                .unwrap(),
            16
        );
    }

    #[test]
    fn resolves_fixed_bit_lengths() {
        assert_eq!(
            LengthResolver::default()
                .resolve(&FieldLength::FixedBits(12), &FieldStore::default())
                .unwrap(),
            12
        );
    }

    #[test]
    fn resolves_previous_field_length_in_bytes() {
        let mut store = FieldStore::default();
        store.insert(
            FieldKey::new(FieldRef::Coap("fid-coap-option-length"), 1, 7),
            FieldValue::from_u64(4, 8).unwrap(),
        );

        let length = FieldLength::FromPreviousField {
            entry_index: 7,
            unit: LengthUnit::Bytes,
        };

        assert_eq!(
            LengthResolver::default().resolve(&length, &store).unwrap(),
            32
        );
    }

    #[test]
    fn resolves_previous_field_length_in_bits() {
        let mut store = FieldStore::default();
        store.insert(
            FieldKey::new(FieldRef::Coap("fid-coap-option-length"), 1, 7),
            FieldValue::from_u64(13, 8).unwrap(),
        );

        let length = FieldLength::FromPreviousField {
            entry_index: 7,
            unit: LengthUnit::Bits,
        };

        assert_eq!(
            LengthResolver::default().resolve(&length, &store).unwrap(),
            13
        );
    }

    #[test]
    fn rejects_variable_lengths_at_resolve_time() {
        assert!(LengthResolver::default()
            .resolve(&FieldLength::VariableBytes, &FieldStore::default())
            .is_err());
        assert!(LengthResolver::default()
            .resolve(&FieldLength::VariableBits, &FieldStore::default())
            .is_err());
    }

    #[test]
    fn rejects_unsupported_field_length_function_sids() {
        assert!(LengthResolver::default()
            .resolve(&FieldLength::FunctionSid(9999), &FieldStore::default())
            .is_err());
    }

    #[test]
    fn encodes_and_decodes_variable_byte_lengths() {
        let mut bytes = Vec::new();
        write_variable_length_bytes(&mut bytes, 13).unwrap();

        assert_eq!(bytes, vec![0xd0]);
        assert_eq!(
            read_variable_length_bytes(&mut crate::bit::BitReader::new(&bytes)).unwrap(),
            13
        );
    }
}
