//! Tree-guided SCHC compressor.

use crate::bit::{BitReader, BitWriter};
use crate::error::{Result, SchcError};
use crate::packet::{
    field::{FieldKey, FieldStore, FieldValue},
    length::{write_variable_length_prefix, LengthResolver},
    Ipv6Packet, UdpDatagram,
};
use crate::rule::{
    Cda, Direction, FieldLength, FieldRef, MatchingOperator, Rule, RuleContext, RuleNature,
};
use crate::tree::{Branch, DecisionTree, ParseStep};
use crate::TargetValue;

/// Compressed SCHC datagram.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompressedDatagram {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl CompressedDatagram {
    /// Returns encoded bytes, padded with zero bits in the final byte.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the number of meaningful encoded bits.
    #[must_use]
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }
}

impl AsRef<[u8]> for CompressedDatagram {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl core::ops::Index<usize> for CompressedDatagram {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.bytes[index]
    }
}

/// SCHC compressor.
#[derive(Debug, Clone)]
pub struct Compressor {
    context: RuleContext,
    tree: DecisionTree,
}

impl Compressor {
    /// Builds a compressor from a loaded rule context.
    ///
    /// # Errors
    ///
    /// Returns an error when the decision tree cannot be built from the rule
    /// context.
    pub fn new(context: RuleContext) -> Result<Self> {
        let tree = DecisionTree::build(context.rules())?;
        Ok(Self { context, tree })
    }

    /// Compresses one packet.
    ///
    /// Rules whose nature is not [`RuleNature::Compression`] or
    /// [`RuleNature::NoCompression`] are not processed: reaching a
    /// fragmentation leaf returns a clear [`SchcError::UnsupportedRuleNature`]
    /// instead of silently compressing. A no-compression rule emits the rule ID
    /// followed by the original packet bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Packet`] when packet parsing fails and no
    /// empty-fields no-compression rule can wrap the original bytes.
    /// Returns [`SchcError::NoMatchingRule`] when no rule path matches.
    /// Returns [`SchcError::UnsupportedRuleNature`] when the only matching rule
    /// is a fragmentation rule.
    /// Returns [`SchcError::InvalidResidue`] when residue encoding cannot be
    /// represented.
    pub fn compress(&self, direction: Direction, packet: &[u8]) -> Result<CompressedDatagram> {
        if let Err(error) = Ipv6Packet::parse(packet) {
            if let Some(candidate) = self.empty_no_compression_candidate(packet)? {
                return Ok(candidate.datagram);
            }
            return Err(error);
        }

        let mut candidates = Vec::new();
        let mut nature_errors = Vec::new();
        let state = CompressionState::default();
        self.traverse(
            0,
            direction,
            packet,
            &state,
            &mut candidates,
            &mut nature_errors,
        )?;

        if let Some(candidate) = candidates
            .into_iter()
            .min_by_key(|candidate| (candidate.datagram.bit_len, candidate.rule_order))
        {
            return Ok(candidate.datagram);
        }

        if let Some(nature) = nature_errors.into_iter().next() {
            return Err(SchcError::UnsupportedRuleNature {
                nature: nature.as_str(),
            });
        }

        Err(SchcError::NoMatchingRule)
    }

    /// Returns the decision tree used by this compressor.
    #[must_use]
    pub fn tree(&self) -> &DecisionTree {
        &self.tree
    }

    /// Returns the rule context used to build this compressor.
    #[must_use]
    pub fn context(&self) -> &RuleContext {
        &self.context
    }

    fn empty_no_compression_candidate(&self, packet: &[u8]) -> Result<Option<Candidate>> {
        for (rule_order, rule) in self.context.rules().rules().iter().enumerate() {
            if rule.nature() == RuleNature::NoCompression && rule.fields().is_empty() {
                return no_compression_candidate(rule_order, rule.id(), packet).map(Some);
            }
        }
        Ok(None)
    }

    fn traverse(
        &self,
        node_index: usize,
        direction: Direction,
        packet: &[u8],
        state: &CompressionState,
        candidates: &mut Vec<Candidate>,
        nature_errors: &mut Vec<RuleNature>,
    ) -> Result<()> {
        let node = &self.tree.nodes()[node_index];
        if let (Some(rule_id), Some(rule_order)) = (node.rule_id, node.rule_order) {
            let nature = self
                .context
                .rules()
                .rules()
                .get(rule_order)
                .map_or(RuleNature::Compression, Rule::nature);
            match nature {
                RuleNature::Compression => {
                    // Verify the rule accounts for every byte of the original
                    // packet by reconstructing from the extracted fields. If the
                    // reconstruction does not match, the rule silently omits
                    // payload bytes and must not be accepted.
                    let reconstructed =
                        crate::packet::builder::reconstruct_packet(direction, &state.fields);
                    if let Ok(ref bytes) = reconstructed {
                        if bytes.as_slice() == packet {
                            let mut writer = BitWriter::new();
                            writer.write_bits(rule_id.value(), rule_id.bit_len())?;
                            append_bits(&mut writer, &state.residue)?;
                            candidates.push(Candidate {
                                rule_order,
                                datagram: CompressedDatagram {
                                    bytes: writer.to_vec(),
                                    bit_len: writer.bit_len(),
                                },
                            });
                        }
                    }
                }
                RuleNature::NoCompression => {
                    candidates.push(no_compression_candidate(rule_order, rule_id, packet)?);
                }
                RuleNature::Fragmentation => nature_errors.push(nature),
            }
        }

        for branch in node.branches.clone() {
            if !branch.direction.accepts(direction) {
                continue;
            }

            if matches!(branch.parse.field, FieldRef::SyntheticCoapMarker) {
                let next_state = state.clone();
                self.traverse(
                    branch.next,
                    direction,
                    packet,
                    &next_state,
                    candidates,
                    nature_errors,
                )?;
                continue;
            }

            let bit_len = match &branch.parse.length {
                FieldLength::VariableBytes | FieldLength::VariableBits => None,
                length => Some(state.lengths.resolve(length, &state.fields)?),
            };
            let field = extract_field(
                packet,
                direction,
                &branch.parse,
                bit_len,
                state.coap_option_index,
            )?;
            let Some(match_result) = matches_branch(&field, &branch)? else {
                continue;
            };

            let mut next_state = state.clone();
            write_residue(&mut next_state.residue, &field, &branch, &match_result)?;
            if let FieldRef::Coap("fid-coap-tkl") = branch.parse.field {
                let token_length = usize::try_from(field.to_u64()?).map_err(|_| {
                    SchcError::InvalidResidue("CoAP TKL does not fit usize".to_owned())
                })?;
                next_state.lengths.set_token_length(token_length);
            }
            next_state.fields.insert(
                FieldKey::new(
                    branch.parse.field.clone(),
                    branch.parse.field_position,
                    branch.parse.entry_index,
                ),
                field,
            );
            if matches!(branch.parse.field, FieldRef::CoapOption { .. }) {
                next_state.coap_option_index += 1;
            }
            self.traverse(
                branch.next,
                direction,
                packet,
                &next_state,
                candidates,
                nature_errors,
            )?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
struct CompressionState {
    residue: BitWriter,
    fields: FieldStore,
    lengths: LengthResolver,
    coap_option_index: usize,
}

impl Default for CompressionState {
    fn default() -> Self {
        Self {
            residue: BitWriter::new(),
            fields: FieldStore::default(),
            lengths: LengthResolver::default(),
            coap_option_index: 0,
        }
    }
}

#[derive(Debug)]
struct Candidate {
    rule_order: usize,
    datagram: CompressedDatagram,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct MatchResult {
    mapping_index: Option<usize>,
    msb_bits: Option<usize>,
}

fn matches_branch(field: &FieldValue, branch: &Branch) -> Result<Option<MatchResult>> {
    let result = match branch.matching {
        MatchingOperator::Equal => target_as_value(&branch.target, field.bit_len())?
            .filter(|target| target == field)
            .map(|_| MatchResult {
                mapping_index: None,
                msb_bits: None,
            }),
        MatchingOperator::Ignore => Some(MatchResult {
            mapping_index: None,
            msb_bits: None,
        }),
        MatchingOperator::Msb(bits) => {
            if bits > field.bit_len() {
                return Err(SchcError::InvalidBitLength {
                    operation: "msb",
                    bits,
                });
            }
            let Some(target) = target_as_value(&branch.target, field.bit_len())? else {
                return Ok(None);
            };
            prefix_bits_equal(field, &target, bits).then_some(MatchResult {
                mapping_index: None,
                msb_bits: Some(bits),
            })
        }
        MatchingOperator::MatchMapping => match &branch.target {
            TargetValue::Mapping(values) => {
                let mut match_result = None;
                for (index, value) in values.iter().enumerate() {
                    if bytes_as_value(value, field.bit_len())? == *field {
                        match_result = Some(MatchResult {
                            mapping_index: Some(index),
                            msb_bits: None,
                        });
                        break;
                    }
                }
                match_result
            }
            _ => None,
        },
    };

    Ok(result)
}

fn write_residue(
    writer: &mut BitWriter,
    field: &FieldValue,
    branch: &Branch,
    match_result: &MatchResult,
) -> Result<()> {
    match branch.action {
        Cda::NotSent | Cda::Compute => Ok(()),
        Cda::ValueSent => {
            match &branch.parse.length {
                FieldLength::VariableBytes => {
                    if field.bit_len() % 8 != 0 {
                        return Err(SchcError::InvalidResidue(
                            "variable byte field is not byte aligned".to_owned(),
                        ));
                    }
                    write_variable_length_prefix(writer, field.bytes().len())?;
                }
                FieldLength::VariableBits => {
                    write_variable_length_prefix(writer, field.bit_len())?;
                }
                _ => {}
            }
            if field.bit_len() == 0 {
                return Ok(());
            }
            field.write_to(writer)
        }
        Cda::MappingSent => {
            let Some(index) = match_result.mapping_index else {
                return Err(SchcError::InvalidResidue(
                    "mapping-sent requires a selected mapping entry".to_owned(),
                ));
            };
            let bit_len = mapping_index_bits(&branch.target)?;
            if bit_len == 0 {
                return Ok(());
            }
            writer.write_bits(index as u64, bit_len)
        }
        Cda::Lsb => {
            let Some(msb_bits) = match_result.msb_bits else {
                return Err(SchcError::InvalidResidue(
                    "lsb requires an msb matching operator".to_owned(),
                ));
            };
            let lsb_bits = field.bit_len() - msb_bits;
            if lsb_bits == 0 {
                return Ok(());
            }
            writer.write_bits(low_bits_u64(field, lsb_bits)?, lsb_bits)
        }
    }
}

fn mapping_index_bits(target: &TargetValue) -> Result<usize> {
    let TargetValue::Mapping(values) = target else {
        return Err(SchcError::InvalidResidue(
            "mapping-sent requires a mapping target".to_owned(),
        ));
    };
    if values.len() <= 1 {
        return Ok(0);
    }

    let mut bit_len = 0;
    let mut max_index = values.len() - 1;
    while max_index > 0 {
        bit_len += 1;
        max_index >>= 1;
    }
    Ok(bit_len)
}

fn append_bits(output: &mut BitWriter, input: &BitWriter) -> Result<()> {
    let bytes = input.to_vec();
    let mut reader = BitReader::new(&bytes);
    for _ in 0..input.bit_len() {
        output.write_bits(reader.read_bits(1)?, 1)?;
    }
    Ok(())
}

/// Builds a no-compression candidate by writing the rule ID followed by the
/// original packet bytes. The rule ID may be non-byte-aligned, so the packet
/// bits are written directly after it and the final byte is zero-padded.
fn no_compression_candidate(
    rule_order: usize,
    rule_id: crate::RuleId,
    packet: &[u8],
) -> Result<Candidate> {
    let mut writer = BitWriter::new();
    writer.write_bits(rule_id.value(), rule_id.bit_len())?;
    for byte in packet {
        writer.write_bits(u64::from(*byte), 8)?;
    }
    Ok(Candidate {
        rule_order,
        datagram: CompressedDatagram {
            bytes: writer.to_vec(),
            bit_len: writer.bit_len(),
        },
    })
}

fn target_as_value(target: &TargetValue, bit_len: usize) -> Result<Option<FieldValue>> {
    match target {
        TargetValue::Bytes(bytes) => bytes_as_value(bytes, bit_len).map(Some),
        _ => Ok(None),
    }
}

fn field_bit(value: &FieldValue, index: usize) -> bool {
    let byte = value.bytes()[index / 8];
    let shift = 7 - (index % 8);
    ((byte >> shift) & 1) == 1
}

fn prefix_bits_equal(left: &FieldValue, right: &FieldValue, bit_len: usize) -> bool {
    left.bit_len() == right.bit_len()
        && (0..bit_len).all(|index| field_bit(left, index) == field_bit(right, index))
}

fn low_bits_u64(value: &FieldValue, bit_len: usize) -> Result<u64> {
    if bit_len > 64 {
        return Err(SchcError::InvalidResidue(
            "lsb for suffixes wider than 64 bits is not supported".to_owned(),
        ));
    }
    if bit_len > value.bit_len() {
        return Err(SchcError::InvalidBitLength {
            operation: "lsb",
            bits: bit_len,
        });
    }

    let mut output = 0_u64;
    for index in (value.bit_len() - bit_len)..value.bit_len() {
        output = (output << 1) | u64::from(field_bit(value, index));
    }
    Ok(output)
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

fn extract_field(
    packet: &[u8],
    direction: Direction,
    parse: &ParseStep,
    bit_len: Option<usize>,
    coap_option_index: usize,
) -> Result<FieldValue> {
    if parse.field_position >= 2 && is_inner_embedded_field(&parse.field) {
        return extract_embedded_field(packet, direction, parse);
    }
    match &parse.field {
        FieldRef::Ipv6(name) => extract_ipv6_field(packet, direction, name),
        FieldRef::Udp(name) => {
            let ipv6 = Ipv6Packet::parse(packet)?;
            let udp = UdpDatagram::parse(ipv6.payload())?;
            extract_udp_field(&udp.to_vec(), direction, name)
        }
        FieldRef::Coap(name) => {
            let ipv6 = Ipv6Packet::parse(packet)?;
            let udp = UdpDatagram::parse(ipv6.payload())?;
            extract_coap_field(udp.payload(), name, bit_len)
        }
        FieldRef::CoapOption { number } => {
            let ipv6 = Ipv6Packet::parse(packet)?;
            let udp = UdpDatagram::parse(ipv6.payload())?;
            let coap = crate::packet::CoapMessage::parse(udp.payload())?;
            let option = coap
                .options()
                .iter()
                .skip(coap_option_index)
                .find(|candidate| u64::from(candidate.number()) == *number)
                .ok_or(SchcError::NoMatchingRule)?;
            FieldValue::from_bytes(option.value().to_vec(), option.value().len() * 8)
        }
        FieldRef::Icmpv6(name) => {
            let ipv6 = Ipv6Packet::parse(packet)?;
            let icmp = crate::packet::Icmpv6Message::parse(ipv6.payload())?;
            extract_icmpv6_field(&icmp.to_vec(), name)
        }
        FieldRef::SyntheticCoapMarker => Err(packet_error(
            "compression",
            "unsupported synthetic CoAP marker field",
        )),
        FieldRef::UnknownSid(sid) => Err(SchcError::UnknownSid { sid: *sid }),
    }
}

/// Returns true when `field` may belong to an ICMPv6-embedded inner packet.
fn is_inner_embedded_field(field: &FieldRef) -> bool {
    matches!(field, FieldRef::Ipv6(_) | FieldRef::Udp(_))
}

/// Reverses a packet direction.
fn reverse_direction(direction: Direction) -> Direction {
    match direction {
        Direction::Up => Direction::Down,
        Direction::Down => Direction::Up,
    }
}

/// Returns true when `message_type` is an `ICMPv6` error type that embeds a copy
/// of the invoking packet.
fn is_icmpv6_error_type(message_type: u8) -> bool {
    matches!(message_type, 1..=4)
}

/// Extracts a field from the packet embedded in an `ICMPv6` error message.
///
/// The embedded packet starts after the 8-byte `ICMPv6` error header
/// (type, code, checksum, 4 unused bytes) and is parsed with the direction
/// reversed relative to the outer packet.
fn extract_embedded_field(
    packet: &[u8],
    direction: Direction,
    parse: &ParseStep,
) -> Result<FieldValue> {
    let ipv6 = Ipv6Packet::parse(packet)?;
    if ipv6.next_header() != 58 {
        return Err(packet_error(
            "compression",
            "inner embedded field requires an ICMPv6 next header",
        ));
    }
    let icmp = crate::packet::Icmpv6Message::parse(ipv6.payload())?;
    if !is_icmpv6_error_type(icmp.message_type()) {
        return Err(packet_error(
            "compression",
            "inner embedded field requires an ICMPv6 error type",
        ));
    }
    if ipv6.payload().len() < 8 {
        return Err(packet_error(
            "ICMPv6",
            "error header is shorter than 8 bytes",
        ));
    }
    let embedded = &ipv6.payload()[8..];
    let inner_direction = reverse_direction(direction);
    match &parse.field {
        FieldRef::Ipv6(name) => extract_ipv6_field(embedded, inner_direction, name),
        FieldRef::Udp(name) => {
            let inner_ipv6 = Ipv6Packet::parse(embedded)?;
            let udp = UdpDatagram::parse(inner_ipv6.payload())?;
            extract_udp_field(&udp.to_vec(), inner_direction, name)
        }
        _ => Err(packet_error(
            "compression",
            "unsupported inner embedded field",
        )),
    }
}

fn extract_ipv6_field(packet: &[u8], direction: Direction, name: &str) -> Result<FieldValue> {
    let ipv6 = Ipv6Packet::parse(packet)?;
    let bytes = ipv6.to_vec();
    match name {
        "fid-ipv6-version" => FieldValue::from_u64(u64::from(bytes[0] >> 4), 4),
        "fid-ipv6-trafficclass" => {
            let value = (u64::from(bytes[0] & 0x0f) << 4) | u64::from(bytes[1] >> 4);
            FieldValue::from_u64(value, 8)
        }
        "fid-ipv6-flowlabel" => {
            let value = (u64::from(bytes[1] & 0x0f) << 16)
                | (u64::from(bytes[2]) << 8)
                | u64::from(bytes[3]);
            FieldValue::from_u64(value, 20)
        }
        "fid-ipv6-payload-length" => {
            let value = u64::from(u16::from_be_bytes([bytes[4], bytes[5]]));
            FieldValue::from_u64(value, 16)
        }
        "fid-ipv6-nextheader" => FieldValue::from_u64(u64::from(bytes[6]), 8),
        "fid-ipv6-hoplimit" => FieldValue::from_u64(u64::from(bytes[7]), 8),
        "fid-ipv6-devprefix" => {
            let address = role_address(&bytes, direction, Role::Device);
            FieldValue::from_u64(u64::from_be_bytes(address[0..8].try_into().unwrap()), 64)
        }
        "fid-ipv6-deviid" => {
            let address = role_address(&bytes, direction, Role::Device);
            FieldValue::from_u64(u64::from_be_bytes(address[8..16].try_into().unwrap()), 64)
        }
        "fid-ipv6-appprefix" => {
            let address = role_address(&bytes, direction, Role::Application);
            FieldValue::from_u64(u64::from_be_bytes(address[0..8].try_into().unwrap()), 64)
        }
        "fid-ipv6-appiid" => {
            let address = role_address(&bytes, direction, Role::Application);
            FieldValue::from_u64(u64::from_be_bytes(address[8..16].try_into().unwrap()), 64)
        }
        _ => Err(packet_error(
            "compression",
            format!("unsupported IPv6 field {name}"),
        )),
    }
}

fn extract_udp_field(udp: &[u8], direction: Direction, name: &str) -> Result<FieldValue> {
    match name {
        "fid-udp-dev-port" => {
            let offset = if direction == Direction::Up { 0 } else { 2 };
            FieldValue::from_u64(
                u64::from(u16::from_be_bytes([udp[offset], udp[offset + 1]])),
                16,
            )
        }
        "fid-udp-app-port" => {
            let offset = if direction == Direction::Up { 2 } else { 0 };
            FieldValue::from_u64(
                u64::from(u16::from_be_bytes([udp[offset], udp[offset + 1]])),
                16,
            )
        }
        "fid-udp-length" => {
            FieldValue::from_u64(u64::from(u16::from_be_bytes([udp[4], udp[5]])), 16)
        }
        "fid-udp-checksum" => {
            FieldValue::from_u64(u64::from(u16::from_be_bytes([udp[6], udp[7]])), 16)
        }
        "fid-udp-payload" => FieldValue::from_bytes(udp[8..].to_vec(), (udp.len() - 8) * 8),
        _ => Err(packet_error(
            "compression",
            format!("unsupported UDP field {name}"),
        )),
    }
}

fn extract_coap_field(coap: &[u8], name: &str, bit_len: Option<usize>) -> Result<FieldValue> {
    crate::packet::CoapMessage::parse(coap)?;
    match name {
        "fid-coap-version" => FieldValue::from_u64(u64::from(coap[0] >> 6), 2),
        "fid-coap-type" => FieldValue::from_u64(u64::from((coap[0] >> 4) & 0x03), 2),
        "fid-coap-tkl" => FieldValue::from_u64(u64::from(coap[0] & 0x0f), 4),
        "fid-coap-code" => FieldValue::from_u64(u64::from(coap[1]), 8),
        "fid-coap-mid" => {
            FieldValue::from_u64(u64::from(u16::from_be_bytes([coap[2], coap[3]])), 16)
        }
        "fid-coap-token" => {
            let bit_len = bit_len.ok_or_else(|| {
                SchcError::InvalidResidue("CoAP token length is not available".to_owned())
            })?;
            if bit_len % 8 != 0 {
                return Err(packet_error("CoAP", "token length is not byte aligned"));
            }
            let token_len = bit_len / 8;
            if token_len != usize::from(coap[0] & 0x0f) {
                return Err(packet_error("CoAP", "token length does not match TKL"));
            }
            if token_len > 8 {
                return Err(packet_error("CoAP", "token length exceeds 8 bytes"));
            }
            bytes_as_value(&coap[4..4 + token_len], token_len * 8)
        }
        "fid-coap-payload" => {
            let parsed = crate::packet::CoapMessage::parse(coap)?;
            FieldValue::from_bytes(parsed.payload().to_vec(), parsed.payload().len() * 8)
        }
        _ => Err(packet_error(
            "compression",
            format!("unsupported CoAP field {name}"),
        )),
    }
}

fn extract_icmpv6_field(icmp: &[u8], name: &str) -> Result<FieldValue> {
    crate::packet::Icmpv6Message::parse(icmp)?;
    match name {
        "fid-icmpv6-type" => FieldValue::from_u64(u64::from(icmp[0]), 8),
        "fid-icmpv6-code" => FieldValue::from_u64(u64::from(icmp[1]), 8),
        "fid-icmpv6-checksum" => {
            FieldValue::from_u64(u64::from(u16::from_be_bytes([icmp[2], icmp[3]])), 16)
        }
        "fid-icmpv6-payload" => FieldValue::from_bytes(icmp[4..].to_vec(), (icmp.len() - 4) * 8),
        _ => Err(packet_error(
            "compression",
            format!("unsupported ICMPv6 field {name}"),
        )),
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Role {
    Device,
    Application,
}

fn role_address(bytes: &[u8], direction: Direction, role: Role) -> &[u8] {
    let source = &bytes[8..24];
    let destination = &bytes[24..40];
    match (direction, role) {
        (Direction::Up, Role::Device) | (Direction::Down, Role::Application) => source,
        (Direction::Up, Role::Application) | (Direction::Down, Role::Device) => destination,
    }
}

fn packet_error(protocol: &'static str, reason: impl Into<String>) -> SchcError {
    SchcError::Packet {
        protocol,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        extract_coap_field, matches_branch, write_residue, Branch, Cda, FieldRef, FieldValue,
        MatchingOperator, ParseStep, TargetValue,
    };
    use crate::bit::BitWriter;
    use crate::{DirectionSelector, FieldLength};

    fn branch(matching: MatchingOperator, target: TargetValue, action: Cda) -> Branch {
        Branch {
            parse: ParseStep {
                field: FieldRef::Ipv6("fid-ipv6-hoplimit"),
                length: FieldLength::FixedBits(8),
                field_position: 1,
                entry_index: 0,
            },
            direction: DirectionSelector::Bidirectional,
            target,
            matching,
            action,
            next: 0,
        }
    }

    #[test]
    fn equal_accepts_identical_bytes() {
        let field = FieldValue::from_u64(0x40, 8).unwrap();
        let branch = branch(
            MatchingOperator::Equal,
            TargetValue::Bytes(vec![0x40]),
            Cda::NotSent,
        );

        assert!(matches_branch(&field, &branch).unwrap().is_some());
    }

    #[test]
    fn equal_rejects_target_bytes_longer_than_field() {
        let field = FieldValue::from_u64(0x01, 8).unwrap();
        let branch = branch(
            MatchingOperator::Equal,
            TargetValue::Bytes(vec![0x00, 0x01]),
            Cda::NotSent,
        );

        assert!(matches_branch(&field, &branch).is_err());
    }

    #[test]
    fn ignore_accepts_any_bytes() {
        let field = FieldValue::from_u64(0xaa, 8).unwrap();
        let branch = branch(MatchingOperator::Ignore, TargetValue::None, Cda::NotSent);

        assert!(matches_branch(&field, &branch).unwrap().is_some());
    }

    #[test]
    fn msb_accepts_matching_high_bits() {
        let field = FieldValue::from_u64(0b1010_1111, 8).unwrap();
        let branch = branch(
            MatchingOperator::Msb(4),
            TargetValue::Bytes(vec![0b1010_0000]),
            Cda::Lsb,
        );

        assert!(matches_branch(&field, &branch).unwrap().is_some());
    }

    #[test]
    fn match_mapping_accepts_table_members() {
        let field = FieldValue::from_u64(0x02, 8).unwrap();
        let branch = branch(
            MatchingOperator::MatchMapping,
            TargetValue::Mapping(vec![vec![0x01], vec![0x02]]),
            Cda::MappingSent,
        );

        let result = matches_branch(&field, &branch).unwrap().unwrap();

        assert_eq!(result.mapping_index, Some(1));
    }

    #[test]
    fn mapping_sent_writes_selected_index() {
        let field = FieldValue::from_u64(0x02, 8).unwrap();
        let branch = branch(
            MatchingOperator::MatchMapping,
            TargetValue::Mapping(vec![vec![0x01], vec![0x02]]),
            Cda::MappingSent,
        );
        let result = matches_branch(&field, &branch).unwrap().unwrap();
        let mut writer = BitWriter::new();

        write_residue(&mut writer, &field, &branch, &result).unwrap();

        assert_eq!(writer.bit_len(), 1);
        assert_eq!(writer.to_vec(), vec![0b1000_0000]);
    }

    #[test]
    fn value_sent_can_carry_more_than_u64_bits() {
        let value = FieldValue::from_bytes(b"temperature=21.5".to_vec(), 128).unwrap();
        let mut writer = BitWriter::new();

        value.write_to(&mut writer).unwrap();

        assert_eq!(writer.bit_len(), 128);
        assert_eq!(writer.to_vec(), b"temperature=21.5");
    }

    #[test]
    fn coap_token_rejects_resolved_length_that_is_shorter_than_packet_tkl() {
        let coap = [0x42, 0x01, 0x12, 0x34, 0xaa, 0xbb];

        let error = extract_coap_field(&coap, "fid-coap-token", Some(8)).unwrap_err();

        assert!(matches!(error, crate::SchcError::Packet { .. }));
    }

    #[test]
    fn lsb_writes_only_low_bits_after_msb_match() {
        let field = FieldValue::from_u64(0b1010_1111, 8).unwrap();
        let branch = branch(
            MatchingOperator::Msb(4),
            TargetValue::Bytes(vec![0b1010_0000]),
            Cda::Lsb,
        );
        let result = matches_branch(&field, &branch).unwrap().unwrap();
        let mut writer = BitWriter::new();

        write_residue(&mut writer, &field, &branch, &result).unwrap();

        assert_eq!(writer.bit_len(), 4);
        assert_eq!(writer.to_vec(), vec![0b1111_0000]);
    }

    #[test]
    fn lsb_writes_low_bits_for_values_wider_than_u64() {
        let field =
            FieldValue::from_bytes(vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0x99], 72).unwrap();
        let branch = branch(
            MatchingOperator::Msb(64),
            TargetValue::Bytes(vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0]),
            Cda::Lsb,
        );
        let result = matches_branch(&field, &branch).unwrap().unwrap();
        let mut writer = BitWriter::new();

        write_residue(&mut writer, &field, &branch, &result).unwrap();

        assert_eq!(writer.bit_len(), 8);
        assert_eq!(writer.to_vec(), vec![0x99]);
    }
}
