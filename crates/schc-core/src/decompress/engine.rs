//! Rule-driven SCHC decompression engine.

use crate::bit::{BitReader, BitWriter};
use crate::error::{Result, SchcError};
use crate::packet::{
    field::{FieldKey, FieldStore, FieldValue, PacketScope},
    length::{read_variable_length_prefix, LengthResolver},
};
use crate::rule::{
    Cda, Direction, FieldLength, FieldRef, FieldRule, MatchingOperator, Position, Rule,
    RuleContext, TargetValue,
};

/// SCHC decompressor.
#[derive(Debug, Clone)]
pub struct Decompressor {
    context: RuleContext,
}

impl Decompressor {
    /// Builds a decompressor from a loaded rule context.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied context cannot be used to initialize
    /// decompression state.
    pub fn new(context: RuleContext) -> Result<Self> {
        Ok(Self { context })
    }

    /// Decompresses a SCHC datagram into an IPv6 packet.
    ///
    /// `Position::Core` reconstructs an uplink packet and `Position::Device`
    /// reconstructs a downlink packet.
    ///
    /// No-compression rules return the packet bytes that follow the rule ID,
    /// preserving bit order and zero-bit padding exactly.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::NoMatchingRule`] when the datagram rule ID does not
    /// match a loaded rule.
    /// Returns [`SchcError::UnsupportedRuleNature`] when the selected rule is a
    /// fragmentation rule.
    /// Returns [`SchcError::InvalidResidue`] when residue bits are malformed or
    /// cannot be reconstructed into a supported packet.
    pub fn decompress(&self, position: Position, compressed: &[u8]) -> Result<Vec<u8>> {
        let (rule, mut reader) = select_rule(self.context.rules().rules(), compressed)?;
        match rule.nature() {
            crate::RuleNature::Compression => {
                let direction = inverse_direction(position);
                let fields = decode_fields(rule, direction, &mut reader)?;
                validate_padding(&mut reader)?;
                crate::packet::builder::reconstruct_packet(direction, &fields)
            }
            crate::RuleNature::NoCompression => decode_no_compression_payload(&mut reader),
            crate::RuleNature::Fragmentation => Err(SchcError::UnsupportedRuleNature {
                nature: rule.nature().as_str(),
            }),
        }
    }

    /// Returns the rule context used by this decompressor.
    #[must_use]
    pub fn context(&self) -> &RuleContext {
        &self.context
    }
}

fn select_rule<'a>(rules: &'a [Rule], compressed: &'a [u8]) -> Result<(&'a Rule, BitReader<'a>)> {
    for rule in rules {
        let mut reader = BitReader::new(compressed);
        let rule_id = rule.id();
        if reader.remaining() < rule_id.bit_len() {
            continue;
        }
        if reader.read_bits(rule_id.bit_len())? == rule_id.value() {
            return Ok((rule, reader));
        }
    }

    Err(SchcError::NoMatchingRule)
}

fn inverse_direction(position: Position) -> Direction {
    match position {
        Position::Device => Direction::Down,
        Position::Core => Direction::Up,
    }
}

fn value_is_icmp_error(value: u64) -> bool {
    matches!(value, 1..=4)
}

fn decode_fields(
    rule: &Rule,
    direction: Direction,
    reader: &mut BitReader<'_>,
) -> Result<FieldStore> {
    let mut fields = FieldStore::default();
    let mut lengths = LengthResolver::default();
    let mut scope = PacketScope::Outer;
    for field in rule
        .fields()
        .iter()
        .filter(|field| field.direction.accepts(direction))
    {
        if matches!(field.field, FieldRef::SyntheticCoapMarker) {
            continue;
        }
        if matches!(field.action, Cda::Compute) {
            continue;
        }
        if scope == PacketScope::Outer
            && matches!(field.field, FieldRef::Ipv6("fid-ipv6-version"))
            && fields
                .first_by_field_scope(&FieldRef::Icmpv6("fid-icmpv6-type"), PacketScope::Outer)
                .is_some_and(|value| value.to_u64().ok().is_some_and(value_is_icmp_error))
            && fields.contains_field_scope(&FieldRef::Ipv6("fid-ipv6-version"), PacketScope::Outer)
        {
            scope = PacketScope::Embedded;
        }
        if scope == PacketScope::Outer
            && matches!(
                field.field,
                FieldRef::Udp(_) | FieldRef::Coap(_) | FieldRef::CoapOption { .. }
            )
            && fields
                .first_by_field_scope(&FieldRef::Ipv6("fid-ipv6-nextheader"), PacketScope::Outer)
                .is_some_and(|value| value.to_u64().ok() == Some(58))
            && fields
                .first_by_field_scope(&FieldRef::Icmpv6("fid-icmpv6-type"), PacketScope::Outer)
                .is_some_and(|value| value.to_u64().ok().is_some_and(value_is_icmp_error))
        {
            return Err(SchcError::InvalidResidue(
                "embedded transport field appears before embedded IPv6 scope".to_owned(),
            ));
        }
        let bit_len = decode_field_len(field, reader, &lengths, &fields)?;
        let value = decode_field_value(field, bit_len, reader)?;
        if matches!(field.field, FieldRef::Coap("fid-coap-tkl")) {
            lengths.set_token_length(usize::try_from(value.to_u64()?).map_err(|_| {
                SchcError::InvalidResidue("CoAP TKL does not fit usize".to_owned())
            })?);
        }
        fields.insert(
            FieldKey::with_scope(
                field.field.clone(),
                field.field_position,
                field.entry_index,
                scope,
            ),
            value,
        );
    }
    Ok(fields)
}

fn decode_field_len(
    field: &FieldRule,
    reader: &mut BitReader<'_>,
    lengths: &LengthResolver,
    fields: &FieldStore,
) -> Result<usize> {
    match (&field.length, field.action) {
        (FieldLength::VariableBytes | FieldLength::VariableBits, Cda::NotSent) => {
            not_sent_target_bit_len(field)
        }
        // Mapping-sent fields derive their length from the selected mapping
        // entry, not from a residue length prefix.
        (FieldLength::VariableBytes | FieldLength::VariableBits, Cda::MappingSent) => Ok(0),
        (FieldLength::VariableBytes, _) => Ok(read_variable_length_prefix(reader)? * 8),
        (FieldLength::VariableBits, _) => read_variable_length_prefix(reader),
        (length, _) => lengths.resolve(length, fields),
    }
}

fn not_sent_target_bit_len(field: &FieldRule) -> Result<usize> {
    match &field.target {
        TargetValue::Bytes(bytes) => Ok(bytes.len() * 8),
        _ => Err(SchcError::InvalidResidue(format!(
            "not-sent field {:?} requires a byte target",
            field.field
        ))),
    }
}

fn decode_field_value(
    field: &FieldRule,
    bit_len: usize,
    reader: &mut BitReader<'_>,
) -> Result<FieldValue> {
    match field.action {
        Cda::NotSent => target_as_value(&field.target, bit_len).and_then(|value| {
            value.ok_or_else(|| {
                SchcError::InvalidResidue(format!(
                    "not-sent field {:?} requires a byte target",
                    field.field
                ))
            })
        }),
        Cda::ValueSent => FieldValue::read_from(reader, bit_len),
        Cda::MappingSent => decode_mapping_sent(&field.target, bit_len, reader),
        Cda::Lsb => decode_lsb(field, bit_len, reader),
        Cda::Compute => unreachable!("compute fields are skipped before decoding"),
    }
}

fn decode_mapping_sent(
    target: &TargetValue,
    _bit_len: usize,
    reader: &mut BitReader<'_>,
) -> Result<FieldValue> {
    let TargetValue::Mapping(values) = target else {
        return Err(SchcError::InvalidResidue(
            "mapping-sent requires a mapping target".to_owned(),
        ));
    };
    let index_bits = mapping_index_bits(values.len());
    let index = if index_bits == 0 {
        0
    } else {
        usize::try_from(reader.read_bits(index_bits)?)
            .map_err(|_| SchcError::InvalidResidue("mapping index does not fit usize".to_owned()))?
    };
    let value = values.get(index).ok_or_else(|| {
        SchcError::InvalidResidue(format!("mapping index {index} is out of range"))
    })?;
    // The field length is determined by the selected mapping entry, so variable
    // length options can be reconstructed without a separate length prefix.
    let entry_bit_len = value.len() * 8;
    bytes_as_value(value, entry_bit_len)
}

fn decode_lsb(field: &FieldRule, bit_len: usize, reader: &mut BitReader<'_>) -> Result<FieldValue> {
    let MatchingOperator::Msb(msb_bits) = field.matching else {
        return Err(SchcError::InvalidResidue(
            "lsb requires an msb matching operator".to_owned(),
        ));
    };
    if msb_bits > bit_len {
        return Err(SchcError::InvalidBitLength {
            operation: "decompress_msb",
            bits: msb_bits,
        });
    }

    let Some(target) = target_as_value(&field.target, bit_len)? else {
        return Err(SchcError::InvalidResidue(
            "lsb requires a byte target".to_owned(),
        ));
    };
    let lsb_bits = bit_len - msb_bits;
    let mut writer = BitWriter::new();
    target.write_range_to(&mut writer, 0, msb_bits)?;
    reader.copy_to(&mut writer, lsb_bits)?;
    FieldValue::from_bytes(writer.to_vec(), bit_len)
}

fn target_as_value(target: &TargetValue, bit_len: usize) -> Result<Option<FieldValue>> {
    match target {
        TargetValue::Bytes(bytes) => bytes_as_value(bytes, bit_len).map(Some),
        _ => Ok(None),
    }
}

fn bytes_as_value(bytes: &[u8], bit_len: usize) -> Result<FieldValue> {
    let byte_len = bit_len.div_ceil(8);
    if bytes.len() > byte_len {
        return Err(SchcError::InvalidResidue(format!(
            "target value has {} bytes but field is {bit_len} bits",
            bytes.len()
        )));
    }

    if bit_len <= 64 {
        let mut value = 0_u64;
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
        return FieldValue::from_u64(value, bit_len);
    }

    let mut padded = vec![0; byte_len];
    padded[..bytes.len()].copy_from_slice(bytes);
    FieldValue::from_bytes(padded, bit_len)
}

fn mapping_index_bits(len: usize) -> usize {
    if len <= 1 {
        return 0;
    }

    let mut bit_len = 0;
    let mut max_index = len - 1;
    while max_index > 0 {
        bit_len += 1;
        max_index >>= 1;
    }
    bit_len
}

fn validate_padding(reader: &mut BitReader<'_>) -> Result<()> {
    if reader.remaining() >= 8 {
        return Err(SchcError::InvalidResidue(format!(
            "{} trailing residue bits remain",
            reader.remaining()
        )));
    }

    while reader.remaining() > 0 {
        if reader.read_bits(1)? != 0 {
            return Err(SchcError::InvalidResidue(
                "non-zero padding bit after structured residue".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Decodes a no-compression payload by reading every full byte that follows
/// the rule ID. The packet is byte-aligned, so the number of packet bits is
/// the largest multiple of eight that fits in the remaining bits; the leftover
/// bits are zero padding and are validated.
fn decode_no_compression_payload(reader: &mut BitReader<'_>) -> Result<Vec<u8>> {
    let remaining = reader.remaining();
    let packet_bits = (remaining / 8) * 8;
    let packet = reader.read_bytes_padded(packet_bits)?;
    validate_padding(reader)?;
    Ok(packet)
}

#[cfg(test)]
mod tests {
    use super::{decode_lsb, select_rule};
    use crate::bit::BitReader;
    use crate::packet::checksum::transport_checksum;
    use crate::rule::FieldRule;
    use crate::{
        Cda, DirectionSelector, FieldLength, FieldRef, MatchingOperator, Rule, RuleId, RuleSet,
        SidRegistry, TargetValue,
    };

    fn lsb_field(length: usize, msb_bits: usize, target: Vec<u8>) -> FieldRule {
        FieldRule {
            field: FieldRef::Ipv6("fid-ipv6-devprefix"),
            length: FieldLength::FixedBits(length),
            field_position: 1,
            direction: DirectionSelector::Bidirectional,
            target: TargetValue::Bytes(target),
            matching: MatchingOperator::Msb(msb_bits),
            action: Cda::Lsb,
            entry_index: 0,
        }
    }

    #[test]
    fn rule_selection_tries_loaded_rules_in_order() {
        let first = Rule::new(RuleId::new(0b10, 2), Vec::new());
        let second = Rule::new(RuleId::new(0b1010, 4), Vec::new());
        let rules = RuleSet::new(vec![first, second], SidRegistry::default());

        let (rule, reader) = select_rule(rules.rules(), &[0b1010_0000]).unwrap();

        assert_eq!(rule.id().value(), 0b10);
        assert_eq!(reader.position(), 2);
    }

    #[test]
    fn lsb_reconstructs_values_wider_than_u64() {
        let field = lsb_field(72, 64, vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0]);
        let mut reader = BitReader::new(&[0x99]);

        let value = decode_lsb(&field, 72, &mut reader).unwrap();

        assert_eq!(value.bytes(), &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x99]);
        assert_eq!(value.bit_len(), 72);
    }

    #[test]
    fn lsb_reconstructs_65_bit_suffix_without_narrowing() {
        let field = lsb_field(96, 31, vec![0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0]);
        let mut reader = BitReader::new(&[0x4d, 0x5e, 0x6f, 0x78, 0x08, 0x91, 0x19, 0xa2, 0]);

        let value = decode_lsb(&field, 96, &mut reader).unwrap();

        assert_eq!(
            value.bytes(),
            &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44]
        );
        assert_eq!(value.bit_len(), 96);
    }

    #[test]
    fn lsb_reconstructs_96_bit_suffix_without_narrowing() {
        let field = lsb_field(
            128,
            32,
            vec![0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        let mut reader = BitReader::new(&[
            0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        ]);

        let value = decode_lsb(&field, 128, &mut reader).unwrap();

        assert_eq!(
            value.bytes(),
            &[
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef
            ]
        );
        assert_eq!(value.bit_len(), 128);
    }

    #[test]
    fn lsb_reconstructs_suffix_across_non_byte_aligned_field_boundary() {
        let field = lsb_field(
            101,
            36,
            vec![0xa5, 0xc3, 0xf0, 0x96, 0x80, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        let mut reader = BitReader::new(&[0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x80]);

        let value = decode_lsb(&field, 101, &mut reader).unwrap();

        assert_eq!(
            value.bytes(),
            &[0xa5, 0xc3, 0xf0, 0x96, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x08]
        );
        assert_eq!(value.bit_len(), 101);
    }

    #[test]
    fn udp_checksum_matches_roundtrip_fixture() {
        let source = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let destination = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        let udp = [
            0x16, 0x33, 0x16, 0x33, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x01, 0x00, 0x2a,
        ];

        let checksum = transport_checksum(&source, &destination, 17, &udp);

        assert_eq!(checksum, 0x37d0);
    }

    #[test]
    fn target_value_rejects_bytes_longer_than_field() {
        assert!(super::bytes_as_value(&[0x00, 0x01], 8).is_err());
    }
}
