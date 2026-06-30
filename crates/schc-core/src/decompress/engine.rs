//! Rule-driven SCHC decompression engine.

use crate::bit::BitReader;
use crate::error::{Result, SchcError};
use crate::packet::field::FieldValue;
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
    /// `Position::App` follows the core-side behavior because the current core
    /// model has no separate application-side direction selector.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::NoMatchingRule`] when the datagram rule ID does not
    /// match a loaded rule.
    /// Returns [`SchcError::InvalidResidue`] when residue bits are malformed or
    /// cannot be reconstructed into a supported packet.
    pub fn decompress(&self, position: Position, compressed: &[u8]) -> Result<Vec<u8>> {
        let (rule, mut reader) = select_rule(self.context.rules().rules(), compressed)?;
        let direction = inverse_direction(position);
        let fields = decode_fields(rule, direction, &mut reader)?;
        validate_padding(&mut reader)?;
        reconstruct_packet(direction, &fields)
    }

    /// Returns the rule context used by this decompressor.
    #[must_use]
    pub fn context(&self) -> &RuleContext {
        &self.context
    }
}

#[derive(Debug, Default)]
struct DecodedFields {
    values: Vec<(FieldRef, FieldValue)>,
}

impl DecodedFields {
    fn push(&mut self, field: FieldRef, value: FieldValue) {
        self.values.push((field, value));
    }

    fn get(&self, field: &FieldRef) -> Option<&FieldValue> {
        self.values
            .iter()
            .find_map(|(candidate, value)| (candidate == field).then_some(value))
    }

    fn fixed_bits(&self, field: &FieldRef) -> Result<usize> {
        self.get(field)
            .map(|value| {
                usize::try_from(value.to_u64()?).map_err(|_| {
                    SchcError::InvalidResidue("field value does not fit usize".to_owned())
                })
            })
            .transpose()?
            .ok_or_else(|| missing_field(field))
    }

    fn fixed_u8(&self, field: &FieldRef) -> Result<u8> {
        let value = self.fixed_bits(field)?;
        u8::try_from(value)
            .map_err(|_| SchcError::InvalidResidue(format!("field {field:?} does not fit u8")))
    }

    fn fixed_u16(&self, field: &FieldRef) -> Result<u16> {
        let value = self.fixed_bits(field)?;
        u16::try_from(value)
            .map_err(|_| SchcError::InvalidResidue(format!("field {field:?} does not fit u16")))
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
        Position::Core | Position::App => Direction::Up,
    }
}

fn decode_fields(
    rule: &Rule,
    direction: Direction,
    reader: &mut BitReader<'_>,
) -> Result<DecodedFields> {
    let mut fields = DecodedFields::default();
    for field in rule
        .fields()
        .iter()
        .filter(|field| field.direction.accepts(direction))
    {
        if matches!(field.action, Cda::Compute) {
            continue;
        }
        let bit_len = fixed_field_len(&field.length)?;
        let value = decode_field_value(field, bit_len, reader)?;
        fields.push(field.field.clone(), value);
    }
    Ok(fields)
}

fn fixed_field_len(length: &FieldLength) -> Result<usize> {
    match length {
        FieldLength::FixedBits(bits) => Ok(*bits),
        FieldLength::VariableBytes
        | FieldLength::VariableBits
        | FieldLength::TokenLength
        | FieldLength::FromPreviousField { .. }
        | FieldLength::FunctionSid(_) => Err(SchcError::InvalidResidue(
            "decompression only supports fixed-length fields for this task".to_owned(),
        )),
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
    bit_len: usize,
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
    bytes_as_value(value, bit_len)
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
    let lsb = read_optional_bits(reader, lsb_bits)?;
    let value = if lsb_bits == 64 {
        lsb
    } else {
        let msb_value = (target.to_u64()? >> lsb_bits) << lsb_bits;
        msb_value | lsb
    };
    FieldValue::from_u64(value, bit_len)
}

fn read_optional_bits(reader: &mut BitReader<'_>, bit_len: usize) -> Result<u64> {
    if bit_len == 0 {
        Ok(0)
    } else {
        reader.read_bits(bit_len)
    }
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

fn reconstruct_packet(direction: Direction, fields: &DecodedFields) -> Result<Vec<u8>> {
    let coap = reconstruct_coap(fields)?;
    let udp = reconstruct_udp(direction, fields, &coap)?;
    reconstruct_ipv6(direction, fields, &udp)
}

fn reconstruct_coap(fields: &DecodedFields) -> Result<Vec<u8>> {
    let version = fields.fixed_u8(&FieldRef::Coap("fid-coap-version"))?;
    let message_type = fields.fixed_u8(&FieldRef::Coap("fid-coap-type"))?;
    let token_len = fields.fixed_u8(&FieldRef::Coap("fid-coap-tkl"))?;
    let code = fields.fixed_u8(&FieldRef::Coap("fid-coap-code"))?;
    let message_id = fields.fixed_u16(&FieldRef::Coap("fid-coap-mid"))?;

    if version > 3 || message_type > 3 || token_len > 8 {
        return Err(SchcError::InvalidResidue(
            "CoAP fixed header fields are out of range".to_owned(),
        ));
    }
    if token_len != 0 {
        return Err(SchcError::InvalidResidue(
            "CoAP token reconstruction is not supported by this fixture".to_owned(),
        ));
    }

    let mut output = Vec::with_capacity(4);
    output.push((version << 6) | (message_type << 4) | token_len);
    output.push(code);
    output.extend_from_slice(&message_id.to_be_bytes());
    Ok(output)
}

fn reconstruct_udp(direction: Direction, fields: &DecodedFields, coap: &[u8]) -> Result<Vec<u8>> {
    let dev_port = fields.fixed_u16(&FieldRef::Udp("fid-udp-dev-port"))?;
    let app_port = fields.fixed_u16(&FieldRef::Udp("fid-udp-app-port"))?;
    let (source_port, destination_port) = match direction {
        Direction::Up => (dev_port, app_port),
        Direction::Down => (app_port, dev_port),
    };
    let udp_length = u16::try_from(8 + coap.len()).map_err(|_| {
        SchcError::InvalidResidue("UDP payload is too large to encode length".to_owned())
    })?;

    let mut output = Vec::with_capacity(usize::from(udp_length));
    output.extend_from_slice(&source_port.to_be_bytes());
    output.extend_from_slice(&destination_port.to_be_bytes());
    output.extend_from_slice(&udp_length.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(coap);
    Ok(output)
}

fn reconstruct_ipv6(direction: Direction, fields: &DecodedFields, udp: &[u8]) -> Result<Vec<u8>> {
    let version = fields.fixed_u8(&FieldRef::Ipv6("fid-ipv6-version"))?;
    let traffic_class = fields.fixed_u8(&FieldRef::Ipv6("fid-ipv6-trafficclass"))?;
    let flow_label = fields.fixed_bits(&FieldRef::Ipv6("fid-ipv6-flowlabel"))?;
    let next_header = fields.fixed_u8(&FieldRef::Ipv6("fid-ipv6-nextheader"))?;
    let hop_limit = fields.fixed_u8(&FieldRef::Ipv6("fid-ipv6-hoplimit"))?;
    let payload_len = u16::try_from(udp.len()).map_err(|_| {
        SchcError::InvalidResidue("IPv6 payload is too large to encode length".to_owned())
    })?;
    let (source, destination) = endpoint_addresses(direction, fields)?;

    if version != 6 || flow_label > 0x000f_ffff {
        return Err(SchcError::InvalidResidue(
            "IPv6 fixed header fields are out of range".to_owned(),
        ));
    }

    let mut output = Vec::with_capacity(40 + udp.len());
    let traffic_flow = (u32::from(version) << 28)
        | (u32::from(traffic_class) << 20)
        | u32::try_from(flow_label).expect("flow label was range-checked");
    output.extend_from_slice(&traffic_flow.to_be_bytes());
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.push(next_header);
    output.push(hop_limit);
    output.extend_from_slice(&source);
    output.extend_from_slice(&destination);

    let mut udp_with_checksum = udp.to_vec();
    let computed_checksum =
        transport_checksum(&source, &destination, next_header, &udp_with_checksum);
    udp_with_checksum[6..8].copy_from_slice(&computed_checksum.to_be_bytes());
    output.extend_from_slice(&udp_with_checksum);
    Ok(output)
}

fn endpoint_addresses(
    direction: Direction,
    fields: &DecodedFields,
) -> Result<([u8; 16], [u8; 16])> {
    let device = endpoint_address(
        fields,
        &FieldRef::Ipv6("fid-ipv6-devprefix"),
        &FieldRef::Ipv6("fid-ipv6-deviid"),
    )?;
    let application = endpoint_address(
        fields,
        &FieldRef::Ipv6("fid-ipv6-appprefix"),
        &FieldRef::Ipv6("fid-ipv6-appiid"),
    )?;

    Ok(match direction {
        Direction::Up => (device, application),
        Direction::Down => (application, device),
    })
}

fn endpoint_address(
    fields: &DecodedFields,
    prefix_field: &FieldRef,
    iid_field: &FieldRef,
) -> Result<[u8; 16]> {
    let prefix = fields
        .get(prefix_field)
        .ok_or_else(|| missing_field(prefix_field))?;
    let iid = fields
        .get(iid_field)
        .ok_or_else(|| missing_field(iid_field))?;
    let mut address = [0; 16];
    address[0..8].copy_from_slice(&field_u64(prefix)?.to_be_bytes());
    address[8..16].copy_from_slice(&field_u64(iid)?.to_be_bytes());
    Ok(address)
}

fn field_u64(field: &FieldValue) -> Result<u64> {
    if field.bit_len() != 64 {
        return Err(SchcError::InvalidResidue(format!(
            "address field is {} bits, expected 64",
            field.bit_len()
        )));
    }
    field.to_u64()
}

fn transport_checksum(
    source: &[u8; 16],
    destination: &[u8; 16],
    next_header: u8,
    segment: &[u8],
) -> u16 {
    let mut sum = Checksum::default();
    sum.add_bytes(source);
    sum.add_bytes(destination);
    sum.add_u32(u32::try_from(segment.len()).expect("segment length fits u32"));
    sum.add_bytes(&[0, 0, 0, next_header]);
    sum.add_bytes(segment);
    sum.finish()
}

#[derive(Debug, Default)]
struct Checksum {
    sum: u32,
    pending: Option<u8>,
}

impl Checksum {
    fn add_u32(&mut self, value: u32) {
        self.add_bytes(&value.to_be_bytes());
    }

    fn add_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if let Some(high) = self.pending.take() {
                self.add_word(u16::from_be_bytes([high, *byte]));
            } else {
                self.pending = Some(*byte);
            }
        }
    }

    fn finish(mut self) -> u16 {
        if let Some(high) = self.pending.take() {
            self.add_word(u16::from_be_bytes([high, 0]));
        }
        while self.sum > 0xffff {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        let checksum = !u16::try_from(self.sum).expect("folded checksum fits u16");
        if checksum == 0 {
            0xffff
        } else {
            checksum
        }
    }

    fn add_word(&mut self, word: u16) {
        self.sum += u32::from(word);
    }
}

fn missing_field(field: &FieldRef) -> SchcError {
    SchcError::InvalidResidue(format!("missing reconstructed field {field:?}"))
}

#[cfg(test)]
mod tests {
    use super::{select_rule, transport_checksum};
    use crate::{Rule, RuleId, RuleSet, SidRegistry};

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
