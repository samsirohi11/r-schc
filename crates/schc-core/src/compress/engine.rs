//! Tree-guided SCHC compressor.

use crate::bit::{BitReader, BitWriter};
use crate::error::{Result, SchcError};
use crate::packet::{
    field::{FieldKey, FieldStore, FieldValue, PacketScope},
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
        let mut branch_errors = Vec::new();
        let state = CompressionState::default();
        let mut traversal = TraversalContext {
            direction,
            packet,
            candidates: &mut candidates,
            nature_errors: &mut nature_errors,
            branch_errors: &mut branch_errors,
        };
        self.traverse(0, &state, &mut traversal)?;

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
        if let Some(error) = branch_errors.into_iter().next() {
            return Err(error);
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
        state: &CompressionState,
        traversal: &mut TraversalContext<'_>,
    ) -> Result<()> {
        let direction = traversal.direction;
        let packet = traversal.packet;
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
                    let reconstructed =
                        crate::packet::builder::reconstruct_packet(direction, &state.fields);
                    let suffix = if reconstructed
                        .as_ref()
                        .is_ok_and(|bytes| bytes.as_slice() == packet)
                    {
                        Some(Vec::new())
                    } else {
                        carry_through_suffix(packet, state)?
                    };
                    if let Some(suffix) = suffix {
                        let mut writer = BitWriter::new();
                        writer.write_bits(rule_id.value(), rule_id.bit_len())?;
                        append_bits(&mut writer, &state.residue)?;
                        for byte in suffix {
                            writer.write_bits(u64::from(byte), 8)?;
                        }
                        traversal.candidates.push(Candidate {
                            rule_order,
                            datagram: CompressedDatagram {
                                bytes: writer.to_vec(),
                                bit_len: writer.bit_len(),
                            },
                        });
                    }
                }
                RuleNature::NoCompression => {
                    traversal
                        .candidates
                        .push(no_compression_candidate(rule_order, rule_id, packet)?);
                }
                RuleNature::Fragmentation => traversal.nature_errors.push(nature),
            }
        }

        for branch in node.branches.clone() {
            // A direction-mismatched entry is not a failed rule. It is absent
            // from the active traversal, so advance to the next entry in the
            // same candidate rule without consuming packet state.
            if !branch.direction.accepts(direction) {
                if let Err(error) = self.traverse(branch.next, state, traversal) {
                    record_branch_error(traversal.branch_errors, error);
                }
                continue;
            }

            if let Err(error) = self.traverse_branch(&branch, state, traversal) {
                record_branch_error(traversal.branch_errors, error);
            }
        }

        Ok(())
    }

    fn traverse_branch(
        &self,
        branch: &Branch,
        state: &CompressionState,
        traversal: &mut TraversalContext<'_>,
    ) -> Result<()> {
        let direction = traversal.direction;
        let packet = traversal.packet;
        if matches!(branch.parse.field, FieldRef::SyntheticCoapMarker) {
            let next_state = state.clone();
            return self.traverse(branch.next, &next_state, traversal);
        }

        let scope = scope_for_field(state, &branch.parse.field)?;
        if !field_position_applies(
            branch.parse.field_position,
            scope,
            &branch.parse.field,
            state,
        ) {
            return Ok(());
        }
        let bit_len = resolve_field_bit_len(&branch.parse.length, state)?;
        let coap_present = state
            .fields
            .contains_field_scope(&FieldRef::Coap("fid-coap-version"), scope);
        let (field, mut match_result) = if matches!(branch.parse.field, FieldRef::CoapOption { .. })
            && branch.parse.field_position == 0
        {
            let Some((field, match_result)) =
                extract_matching_coap_option(packet, &branch.parse, bit_len, scope, branch)?
            else {
                return Ok(());
            };
            (field, match_result)
        } else {
            let field = extract_field(
                packet,
                direction,
                &branch.parse,
                bit_len,
                scope,
                coap_present,
                state,
            )?;
            if bit_len.is_some_and(|expected| field.bit_len() != expected) {
                return Ok(());
            }
            let Some(match_result) = matches_branch(&field, branch)? else {
                return Ok(());
            };
            (field, match_result)
        };
        if matches!(branch.parse.field, FieldRef::CoapOption { .. })
            && match_result.coap_option_ordinal.is_none()
        {
            match_result.coap_option_ordinal =
                Some(extract_coap_option_ordinal(packet, &branch.parse, scope)?);
        }

        let mut next_state = state.clone();
        write_residue(&mut next_state.residue, &field, branch, &match_result)?;
        if let FieldRef::Coap("fid-coap-tkl") = branch.parse.field {
            let token_length = usize::try_from(field.to_u64()?)
                .map_err(|_| SchcError::InvalidResidue("CoAP TKL does not fit usize".to_owned()))?;
            next_state.lengths.set_token_length(token_length);
        }
        next_state.scope = scope;
        next_state.fields.insert(
            FieldKey::with_scope(
                branch.parse.field.clone(),
                branch.parse.field_position,
                branch.parse.entry_index,
                scope,
            ),
            field,
        );
        if let Some(ordinal) = match_result.coap_option_ordinal {
            next_state.coap_option_ordinals.push(ordinal);
        }
        self.traverse(branch.next, &next_state, traversal)
    }
}

fn carry_through_suffix(packet: &[u8], state: &CompressionState) -> Result<Option<Vec<u8>>> {
    let has_explicit_payload = state.fields.iter().any(|(key, _)| {
        matches!(
            key.field(),
            FieldRef::Payload
                | FieldRef::Udp("fid-udp-payload")
                | FieldRef::Coap("fid-coap-payload")
                | FieldRef::Icmpv6("fid-icmpv6-payload")
        )
    });
    if has_explicit_payload {
        return Ok(None);
    }

    let ipv6 = Ipv6Packet::parse(packet)?;
    let mut offset = 40;
    if ipv6.next_header() == 17
        && state
            .fields
            .by_field(&FieldRef::Udp("fid-udp-dev-port"))
            .next()
            .is_some()
    {
        offset += 8;
        if state
            .fields
            .iter()
            .any(|(key, _)| matches!(key.field(), FieldRef::Coap(_) | FieldRef::CoapOption { .. }))
        {
            let udp = UdpDatagram::parse(ipv6.payload())?;
            let coap = crate::packet::CoapMessage::parse(udp.payload())?;
            let Some(option_boundary) = coap_option_boundary(state) else {
                return Ok(None);
            };
            let options = coap
                .options()
                .iter()
                .take(option_boundary)
                .cloned()
                .collect();
            let prefix = crate::packet::CoapMessage::from_parts(
                coap.version(),
                (udp.payload()[0] >> 4) & 0x03,
                coap.code(),
                coap.message_id(),
                coap.token().to_vec(),
                options,
                Vec::new(),
            )?;
            offset += prefix.to_vec().len();
        }
    } else if ipv6.next_header() == 58
        && state
            .fields
            .by_field(&FieldRef::Icmpv6("fid-icmpv6-type"))
            .next()
            .is_some()
    {
        let icmp = crate::packet::Icmpv6Message::parse(ipv6.payload())?;
        offset += icmp.payload_offset();
    }
    if offset > packet.len() {
        return Err(SchcError::Packet {
            protocol: "compression",
            reason: "unread packet suffix starts beyond packet length".to_owned(),
        });
    }
    Ok(Some(packet[offset..].to_vec()))
}

fn coap_option_boundary(state: &CompressionState) -> Option<usize> {
    let boundary = state
        .coap_option_ordinals
        .last()
        .map_or(0, |ordinal| ordinal + 1);
    state
        .coap_option_ordinals
        .iter()
        .copied()
        .enumerate()
        .all(|(expected, actual)| expected == actual)
        .then_some(boundary)
}

fn record_branch_error(errors: &mut Vec<SchcError>, error: SchcError) {
    if !matches!(error, SchcError::NoMatchingRule) {
        errors.push(error);
    }
}

fn field_position_applies(
    position: usize,
    scope: PacketScope,
    field: &FieldRef,
    state: &CompressionState,
) -> bool {
    if position == 0 {
        return true;
    }
    if matches!(field, FieldRef::CoapOption { .. }) {
        return true;
    }
    match scope {
        PacketScope::Outer => position == 1,
        PacketScope::Embedded => {
            position == 2
                && state
                    .fields
                    .contains_field_scope(&FieldRef::Ipv6("fid-ipv6-version"), PacketScope::Outer)
        }
    }
}

fn resolve_field_bit_len(length: &FieldLength, state: &CompressionState) -> Result<Option<usize>> {
    match length {
        FieldLength::VariableBytes | FieldLength::VariableBits => Ok(None),
        length => state.lengths.resolve(length, &state.fields).map(Some),
    }
}

struct TraversalContext<'a> {
    direction: Direction,
    packet: &'a [u8],
    candidates: &'a mut Vec<Candidate>,
    nature_errors: &'a mut Vec<RuleNature>,
    branch_errors: &'a mut Vec<SchcError>,
}

#[derive(Debug, Clone)]
struct CompressionState {
    residue: BitWriter,
    fields: FieldStore,
    lengths: LengthResolver,
    coap_option_ordinals: Vec<usize>,
    scope: PacketScope,
}

impl Default for CompressionState {
    fn default() -> Self {
        Self {
            residue: BitWriter::new(),
            fields: FieldStore::default(),
            lengths: LengthResolver::default(),
            coap_option_ordinals: Vec::new(),
            scope: PacketScope::Outer,
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
    coap_option_ordinal: Option<usize>,
}

fn matches_branch(field: &FieldValue, branch: &Branch) -> Result<Option<MatchResult>> {
    let result = match branch.matching {
        MatchingOperator::Equal => target_as_value(&branch.target, field.bit_len())?
            .filter(|target| target == field)
            .map(|_| MatchResult {
                mapping_index: None,
                msb_bits: None,
                coap_option_ordinal: None,
            }),
        MatchingOperator::Ignore => Some(MatchResult {
            mapping_index: None,
            msb_bits: None,
            coap_option_ordinal: None,
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
                coap_option_ordinal: None,
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
                            coap_option_ordinal: None,
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
        Cda::NotSent | Cda::Compute | Cda::DeviceIid | Cda::AppIid => Ok(()),
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
            match branch.parse.length {
                FieldLength::VariableBytes => {
                    if field.bit_len() % 8 != 0 {
                        return Err(SchcError::InvalidResidue(
                            "variable byte field is not byte aligned".to_owned(),
                        ));
                    }
                    write_variable_length_prefix(writer, field.bit_len() / 8)?;
                }
                FieldLength::VariableBits => write_variable_length_prefix(writer, field.bit_len())?,
                _ => {}
            }
            let lsb_bits = field.bit_len() - msb_bits;
            field.write_range_to(writer, msb_bits, lsb_bits)
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
    reader.copy_to(output, input.bit_len())
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

fn extract_matching_coap_option(
    packet: &[u8],
    parse: &ParseStep,
    bit_len: Option<usize>,
    scope: PacketScope,
    branch: &Branch,
) -> Result<Option<(FieldValue, MatchResult)>> {
    if scope == PacketScope::Embedded {
        return Err(packet_error(
            "compression",
            "CoAP option is outside supported embedded scope",
        ));
    }
    let FieldRef::CoapOption { number } = &parse.field else {
        return Ok(None);
    };
    let ipv6 = Ipv6Packet::parse(packet)?;
    let udp = UdpDatagram::parse(ipv6.payload())?;
    let coap = crate::packet::CoapMessage::parse(udp.payload())?;
    for (ordinal, option) in coap.options().iter().enumerate() {
        if u64::from(option.number()) != *number {
            continue;
        }
        let field = FieldValue::from_bytes(option.value().to_vec(), option.value().len() * 8)?;
        if bit_len.is_some_and(|expected| field.bit_len() != expected) {
            continue;
        }
        if let Some(mut match_result) = matches_branch(&field, branch)? {
            match_result.coap_option_ordinal = Some(ordinal);
            return Ok(Some((field, match_result)));
        }
    }
    Ok(None)
}

fn select_coap_option(
    coap: &crate::packet::CoapMessage,
    number: u64,
    occurrence: usize,
) -> Result<(usize, &crate::packet::CoapOption)> {
    // Option occurrences are normally relative to the requested absolute
    // option number. Keep the absolute wire-position fallback for existing
    // rules that use a non-repeated option with a global field position.
    coap.options()
        .iter()
        .enumerate()
        .filter(|(_, candidate)| u64::from(candidate.number()) == number)
        .nth(occurrence)
        .or_else(|| {
            coap.options()
                .iter()
                .enumerate()
                .nth(occurrence)
                .filter(|(_, candidate)| u64::from(candidate.number()) == number)
        })
        .ok_or(SchcError::NoMatchingRule)
}

fn extract_coap_option_ordinal(
    packet: &[u8],
    parse: &ParseStep,
    scope: PacketScope,
) -> Result<usize> {
    if scope == PacketScope::Embedded {
        return Err(packet_error(
            "compression",
            "CoAP option is outside supported embedded scope",
        ));
    }
    let FieldRef::CoapOption { number } = &parse.field else {
        return Err(SchcError::NoMatchingRule);
    };
    let occurrence = parse
        .field_position
        .checked_sub(1)
        .ok_or(SchcError::NoMatchingRule)?;
    let ipv6 = Ipv6Packet::parse(packet)?;
    let udp = UdpDatagram::parse(ipv6.payload())?;
    let coap = crate::packet::CoapMessage::parse(udp.payload())?;
    select_coap_option(&coap, *number, occurrence).map(|(ordinal, _)| ordinal)
}

fn extract_field(
    packet: &[u8],
    direction: Direction,
    parse: &ParseStep,
    bit_len: Option<usize>,
    scope: PacketScope,
    coap_present: bool,
    state: &CompressionState,
) -> Result<FieldValue> {
    let source = crate::packet::traversal::packet_for_scope(packet, scope)?;
    let source_direction = if scope == PacketScope::Embedded {
        reverse_direction(direction)
    } else {
        direction
    };
    match &parse.field {
        FieldRef::Ipv6(name) => extract_ipv6_field(&source, source_direction, name),
        FieldRef::Udp(name) => {
            let ipv6 = Ipv6Packet::parse(&source)?;
            let udp = UdpDatagram::parse(ipv6.payload())?;
            extract_udp_field(&udp.to_vec(), source_direction, name)
        }
        FieldRef::Coap(name) => {
            if scope == PacketScope::Embedded {
                return Err(packet_error(
                    "compression",
                    "CoAP field is outside supported embedded scope",
                ));
            }
            let ipv6 = Ipv6Packet::parse(&source)?;
            let udp = UdpDatagram::parse(ipv6.payload())?;
            extract_coap_field(udp.payload(), name, bit_len)
        }
        FieldRef::CoapOption { number } => {
            if scope == PacketScope::Embedded {
                return Err(packet_error(
                    "compression",
                    "CoAP option is outside supported embedded scope",
                ));
            }
            let ipv6 = Ipv6Packet::parse(&source)?;
            let udp = UdpDatagram::parse(ipv6.payload())?;
            let coap = crate::packet::CoapMessage::parse(udp.payload())?;
            let Some(occurrence) = parse.field_position.checked_sub(1) else {
                return Err(SchcError::NoMatchingRule);
            };
            let (_, option) = select_coap_option(&coap, *number, occurrence)?;
            FieldValue::from_bytes(option.value().to_vec(), option.value().len() * 8)
        }
        FieldRef::Icmpv6(name) => {
            if scope == PacketScope::Embedded {
                return Err(packet_error(
                    "compression",
                    "ICMPv6 field is outside supported embedded scope",
                ));
            }
            let ipv6 = Ipv6Packet::parse(&source)?;
            let icmp = crate::packet::Icmpv6Message::parse(ipv6.payload())?;
            let structured = state.fields.iter().any(|(key, _)| {
                key.scope() == scope
                    && matches!(
                        key.field(),
                        FieldRef::Icmpv6(
                            "fid-icmpv6-identifier"
                                | "fid-icmpv6-sequence"
                                | "fid-icmpv6-mtu"
                                | "fid-icmpv6-pointer"
                        )
                    )
            });
            extract_icmpv6_field(&icmp.to_vec(), name, structured)
        }
        FieldRef::Unused => {
            if scope == PacketScope::Embedded {
                return Err(packet_error(
                    "compression",
                    "fid-unused is only valid in an outer ICMPv6 error",
                ));
            }
            if bit_len != Some(32) {
                return Err(SchcError::InvalidResidue(
                    "fid-unused requires a 32-bit length for ICMPv6 error processing".to_owned(),
                ));
            }
            extract_unused_field(&source)
        }
        FieldRef::Payload => extract_generic_payload(&source, source_direction, coap_present),
        FieldRef::SyntheticCoapMarker => Err(packet_error(
            "compression",
            "unsupported synthetic CoAP marker field",
        )),
        FieldRef::UnknownSid(sid) => Err(SchcError::UnknownSid { sid: *sid }),
    }
}

fn reverse_direction(direction: Direction) -> Direction {
    match direction {
        Direction::Up => Direction::Down,
        Direction::Down => Direction::Up,
    }
}

fn scope_for_field(state: &CompressionState, field: &FieldRef) -> Result<PacketScope> {
    if state.scope == PacketScope::Embedded {
        return Ok(PacketScope::Embedded);
    }
    let is_error = state
        .fields
        .first_by_field_scope(&FieldRef::Icmpv6("fid-icmpv6-type"), PacketScope::Outer)
        .is_some_and(|value| value.to_u64().ok().is_some_and(value_is_icmp_error));
    if is_error {
        if matches!(field, FieldRef::Ipv6("fid-ipv6-version"))
            && state
                .fields
                .contains_field_scope(&FieldRef::Ipv6("fid-ipv6-version"), PacketScope::Outer)
        {
            return Ok(PacketScope::Embedded);
        }
        if matches!(
            field,
            FieldRef::Udp(_) | FieldRef::Coap(_) | FieldRef::CoapOption { .. }
        ) && state
            .fields
            .first_by_field_scope(&FieldRef::Ipv6("fid-ipv6-nextheader"), PacketScope::Outer)
            .is_some_and(|value| value.to_u64().ok() == Some(58))
        {
            return Err(packet_error(
                "compression",
                "embedded transport field appears before embedded IPv6 scope",
            ));
        }
    }
    Ok(PacketScope::Outer)
}

fn value_is_icmp_error(value: u64) -> bool {
    matches!(value, 1..=4)
}

fn extract_unused_field(packet: &[u8]) -> Result<FieldValue> {
    let source = crate::packet::traversal::packet_for_scope(packet, PacketScope::Outer)?;
    let ipv6 = Ipv6Packet::parse(&source)?;
    if ipv6.next_header() != 58 {
        return Err(packet_error(
            "ICMPv6",
            "fid-unused requires an ICMPv6 next header",
        ));
    }
    let icmp = crate::packet::Icmpv6Message::parse(ipv6.payload())?;
    if !crate::packet::traversal::has_icmpv6_unused_field(icmp.message_type()) {
        return Err(packet_error(
            "ICMPv6",
            format!(
                "fid-unused is not defined for ICMPv6 error type {}",
                icmp.message_type()
            ),
        ));
    }
    let raw = icmp.to_vec();
    if raw.len() < 8 {
        return Err(packet_error(
            "ICMPv6",
            "error header is shorter than 8 bytes",
        ));
    }
    FieldValue::from_bytes(raw[4..8].to_vec(), 32)
}

fn extract_generic_payload(
    packet: &[u8],
    direction: Direction,
    coap_present: bool,
) -> Result<FieldValue> {
    let source = crate::packet::traversal::packet_for_scope(packet, PacketScope::Outer)?;
    let ipv6 = Ipv6Packet::parse(&source)?;
    match ipv6.next_header() {
        17 => {
            let udp = UdpDatagram::parse(ipv6.payload())?;
            if coap_present {
                let coap = crate::packet::CoapMessage::parse(udp.payload())?;
                FieldValue::from_bytes(coap.payload().to_vec(), coap.payload().len() * 8)
            } else {
                FieldValue::from_bytes(udp.payload().to_vec(), udp.payload().len() * 8)
            }
        }
        58 => {
            let icmp = crate::packet::Icmpv6Message::parse(ipv6.payload())?;
            let payload = icmp.payload();
            FieldValue::from_bytes(payload.to_vec(), payload.len() * 8)
        }
        value => Err(packet_error(
            "compression",
            format!("unsupported generic payload next header {value} for {direction:?} direction"),
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

fn extract_icmpv6_field(icmp: &[u8], name: &str, structured: bool) -> Result<FieldValue> {
    let message = crate::packet::Icmpv6Message::parse(icmp)?;
    match name {
        "fid-icmpv6-type" => FieldValue::from_u64(u64::from(icmp[0]), 8),
        "fid-icmpv6-code" => FieldValue::from_u64(u64::from(icmp[1]), 8),
        "fid-icmpv6-checksum" => {
            FieldValue::from_u64(u64::from(u16::from_be_bytes([icmp[2], icmp[3]])), 16)
        }
        "fid-icmpv6-identifier" => {
            if !message.is_echo() || icmp.len() < 8 {
                return Err(packet_error(
                    "ICMPv6",
                    "identifier is only defined for echo messages",
                ));
            }
            FieldValue::from_u64(u64::from(u16::from_be_bytes([icmp[4], icmp[5]])), 16)
        }
        "fid-icmpv6-sequence" => {
            if !message.is_echo() || icmp.len() < 8 {
                return Err(packet_error(
                    "ICMPv6",
                    "sequence is only defined for echo messages",
                ));
            }
            FieldValue::from_u64(u64::from(u16::from_be_bytes([icmp[6], icmp[7]])), 16)
        }
        "fid-icmpv6-mtu" | "fid-icmpv6-pointer" => {
            if icmp.len() < 8 {
                return Err(packet_error("ICMPv6", "type-specific field is truncated"));
            }
            let expected = if name.ends_with("mtu") { 2 } else { 4 };
            if message.message_type() != expected {
                return Err(packet_error(
                    "ICMPv6",
                    "type-specific field does not match message type",
                ));
            }
            FieldValue::from_bytes(icmp[4..8].to_vec(), 32)
        }
        "fid-icmpv6-payload" => {
            let offset = if structured {
                message.payload_offset()
            } else {
                4
            };
            FieldValue::from_bytes(icmp[offset..].to_vec(), (icmp.len() - offset) * 8)
        }
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
        branch_with_length(8, matching, target, action)
    }

    fn branch_with_length(
        length: usize,
        matching: MatchingOperator,
        target: TargetValue,
        action: Cda,
    ) -> Branch {
        Branch {
            parse: ParseStep {
                field: FieldRef::Ipv6("fid-ipv6-hoplimit"),
                length: FieldLength::FixedBits(length),
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

    #[test]
    fn lsb_writes_65_bit_suffix_without_narrowing() {
        let field = FieldValue::from_bytes(
            vec![
                0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44,
            ],
            96,
        )
        .unwrap();
        let branch = branch_with_length(
            96,
            MatchingOperator::Msb(31),
            TargetValue::Bytes(vec![0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0, 0, 0, 0, 0]),
            Cda::Lsb,
        );
        let result = matches_branch(&field, &branch).unwrap().unwrap();
        let mut writer = BitWriter::new();

        write_residue(&mut writer, &field, &branch, &result).unwrap();

        assert_eq!(writer.bit_len(), 65);
        assert_eq!(
            writer.to_vec(),
            vec![0x4d, 0x5e, 0x6f, 0x78, 0x08, 0x91, 0x19, 0xa2, 0x00]
        );
    }

    #[test]
    fn lsb_writes_96_bit_suffix_without_narrowing() {
        let field = FieldValue::from_bytes(
            vec![
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef,
            ],
            128,
        )
        .unwrap();
        let branch = branch_with_length(
            128,
            MatchingOperator::Msb(32),
            TargetValue::Bytes(vec![
                0x01, 0x23, 0x45, 0x67, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            Cda::Lsb,
        );
        let result = matches_branch(&field, &branch).unwrap().unwrap();
        let mut writer = BitWriter::new();

        write_residue(&mut writer, &field, &branch, &result).unwrap();

        assert_eq!(writer.bit_len(), 96);
        assert_eq!(
            writer.to_vec(),
            vec![0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]
        );
    }

    #[test]
    fn lsb_writes_suffix_across_non_byte_aligned_field_boundary() {
        let field = FieldValue::from_bytes(
            vec![
                0xa5, 0xc3, 0xf0, 0x96, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x08,
            ],
            101,
        )
        .unwrap();
        let branch = branch_with_length(
            101,
            MatchingOperator::Msb(36),
            TargetValue::Bytes(vec![0xa5, 0xc3, 0xf0, 0x96, 0x80, 0, 0, 0, 0, 0, 0, 0, 0]),
            Cda::Lsb,
        );
        let result = matches_branch(&field, &branch).unwrap().unwrap();
        let mut writer = BitWriter::new();

        write_residue(&mut writer, &field, &branch, &result).unwrap();

        assert_eq!(writer.bit_len(), 65);
        assert_eq!(
            writer.to_vec(),
            vec![0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x80]
        );
    }
}
