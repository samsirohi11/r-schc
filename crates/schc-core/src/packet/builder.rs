//! Packet reconstruction from decoded field stores.

use crate::error::{Result, SchcError};
use crate::packet::checksum::transport_checksum;
use crate::packet::field::{FieldKey, FieldStore, FieldValue, PacketScope};
use crate::packet::{CoapMessage, CoapOption, Icmpv6Message, Ipv6Packet, UdpDatagram};
use crate::rule::{Direction, FieldRef};

/// Reconstructs a full IPv6 packet from decoded fields.
///
/// Dispatches to UDP or `ICMPv6` reconstruction based on the IPv6 next-header
/// field. Outer and embedded fields are separated by packet scope.
///
/// # Errors
///
/// Returns [`SchcError::InvalidResidue`] when required fields are missing,
/// out of range, or the next-header value is unsupported.
pub(crate) fn reconstruct_packet(direction: Direction, fields: &FieldStore) -> Result<Vec<u8>> {
    let packet = reconstruct_packet_at(direction, fields, PacketScope::Outer)?;
    crate::packet::validate_packet_lengths(&packet)?;
    Ok(packet)
}

/// Reconstructs a packet and appends the unread wire suffix carried by a
/// header-only compression rule.
pub(crate) fn reconstruct_packet_with_suffix(
    direction: Direction,
    fields: &FieldStore,
    suffix: &[u8],
) -> Result<Vec<u8>> {
    let inject_icmp_payload = header_only_icmp_error(fields)?;
    if inject_icmp_payload {
        validate_embedded_ipv6_suffix(suffix)?;
    }
    let mut packet = if inject_icmp_payload {
        let mut fields_with_payload = fields.clone();
        fields_with_payload.insert(
            FieldKey::with_scope(FieldRef::Payload, 1, 0, PacketScope::Outer),
            FieldValue::from_bytes(suffix.to_vec(), suffix.len() * 8)?,
        );
        reconstruct_packet_at(direction, &fields_with_payload, PacketScope::Outer)?
    } else {
        reconstruct_packet_at(direction, fields, PacketScope::Outer)?
    };
    if !inject_icmp_payload {
        packet.extend_from_slice(suffix);
    }
    if packet.len() < 40 {
        return Err(SchcError::InvalidResidue(
            "carried packet suffix follows an incomplete IPv6 header".to_owned(),
        ));
    }

    let next_header = packet[6];
    if fields
        .first_by_field_scope(
            &FieldRef::Ipv6("fid-ipv6-payload-length"),
            PacketScope::Outer,
        )
        .is_none()
    {
        let payload_len = u16::try_from(packet.len() - 40).map_err(|_| {
            SchcError::InvalidResidue("carried IPv6 payload is too large".to_owned())
        })?;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    let source: [u8; 16] = packet[8..24].try_into().expect("IPv6 source is 16 bytes");
    let destination: [u8; 16] = packet[24..40]
        .try_into()
        .expect("IPv6 destination is 16 bytes");
    match next_header {
        17 => {
            if packet.len() < 48 {
                return Err(SchcError::InvalidResidue(
                    "carried UDP packet is shorter than its header".to_owned(),
                ));
            }
            if fields
                .first_by_field_scope(&FieldRef::Udp("fid-udp-length"), PacketScope::Outer)
                .is_none()
            {
                let length = u16::try_from(packet.len() - 40).map_err(|_| {
                    SchcError::InvalidResidue("carried UDP payload is too large".to_owned())
                })?;
                packet[44..46].copy_from_slice(&length.to_be_bytes());
            }
            if fields
                .first_by_field_scope(&FieldRef::Udp("fid-udp-checksum"), PacketScope::Outer)
                .is_none()
            {
                packet[46..48].copy_from_slice(&[0, 0]);
                let checksum = transport_checksum(&source, &destination, 17, &packet[40..]);
                packet[46..48].copy_from_slice(&checksum.to_be_bytes());
            }
            if fields
                .first_by_field_scope(&FieldRef::Coap("fid-coap-version"), PacketScope::Outer)
                .is_some()
            {
                CoapMessage::parse(&packet[48..])?;
            }
        }
        58 => {
            if packet.len() < 44 {
                return Err(SchcError::InvalidResidue(
                    "carried ICMPv6 packet is shorter than its header".to_owned(),
                ));
            }
            if fields
                .first_by_field_scope(&FieldRef::Icmpv6("fid-icmpv6-checksum"), PacketScope::Outer)
                .is_none()
            {
                packet[42..44].copy_from_slice(&[0, 0]);
                let checksum = transport_checksum(&source, &destination, 58, &packet[40..]);
                packet[42..44].copy_from_slice(&checksum.to_be_bytes());
            }
            Icmpv6Message::parse(&packet[40..])?;
        }
        _ => {}
    }
    crate::packet::validate_packet_lengths(&packet)?;
    Ok(packet)
}

fn validate_embedded_ipv6_suffix(suffix: &[u8]) -> Result<()> {
    let embedded = Ipv6Packet::parse(suffix)?;
    if embedded.next_header() == 17 {
        UdpDatagram::parse(embedded.payload())?;
    }
    Ok(())
}

fn header_only_icmp_error(fields: &FieldStore) -> Result<bool> {
    let next_header = fields
        .first_by_field_scope(&FieldRef::Ipv6("fid-ipv6-nextheader"), PacketScope::Outer)
        .map(FieldValue::to_u64)
        .transpose()?;
    let message_type = fields
        .first_by_field_scope(&FieldRef::Icmpv6("fid-icmpv6-type"), PacketScope::Outer)
        .map(FieldValue::to_u64)
        .transpose()?;
    let has_payload = fields.iter().any(|(key, _)| {
        matches!(
            key.field(),
            FieldRef::Payload | FieldRef::Icmpv6("fid-icmpv6-payload")
        )
    });
    Ok(next_header == Some(58)
        && message_type.is_some_and(|value| matches!(value, 1..=4))
        && !has_payload)
}

/// Reverses a packet direction.
fn reverse_direction(direction: Direction) -> Direction {
    match direction {
        Direction::Up => Direction::Down,
        Direction::Down => Direction::Up,
    }
}

/// Reconstructs an IPv6 packet using fields stored in `scope`.
///
/// Scope is tracked independently of field position so repeated field
/// positions retain their SCHC meaning while nested packet traversal remains
/// explicit.
fn reconstruct_packet_at(
    direction: Direction,
    fields: &FieldStore,
    scope: PacketScope,
) -> Result<Vec<u8>> {
    let next_header = first_u8_at(fields, &FieldRef::Ipv6("fid-ipv6-nextheader"), scope)?;
    match next_header {
        17 => {
            let (upper, compute_checksum) = reconstruct_udp(direction, fields, scope)?;
            reconstruct_ipv6_with_upper(direction, fields, scope, 17, upper, compute_checksum)
        }
        58 => {
            let (upper, compute_checksum) = reconstruct_icmpv6(direction, fields, scope)?;
            reconstruct_ipv6_with_upper(direction, fields, scope, 58, upper, compute_checksum)
        }
        value => Err(SchcError::InvalidResidue(format!(
            "unsupported IPv6 next header {value}"
        ))),
    }
}

fn reconstruct_udp(
    direction: Direction,
    fields: &FieldStore,
    scope: PacketScope,
) -> Result<(Vec<u8>, bool)> {
    let coap = if scope == PacketScope::Outer
        && fields
            .first_by_field_scope(&FieldRef::Coap("fid-coap-version"), scope)
            .is_some()
    {
        reconstruct_coap(fields, scope)?
    } else {
        Vec::new()
    };

    let dev_port = first_u16_at(fields, &FieldRef::Udp("fid-udp-dev-port"), scope)?;
    let app_port = first_u16_at(fields, &FieldRef::Udp("fid-udp-app-port"), scope)?;
    let (source_port, destination_port) = match direction {
        Direction::Up => (dev_port, app_port),
        Direction::Down => (app_port, dev_port),
    };
    let udp_payload = fields.first_by_field_scope(&FieldRef::Udp("fid-udp-payload"), scope);
    let payload = if coap.is_empty() {
        shared_payload(fields, scope, &FieldRef::Udp("fid-udp-payload"))?
    } else {
        if let Some(udp_payload) = udp_payload {
            if udp_payload.bytes() != coap.as_slice() {
                return Err(SchcError::InvalidResidue(
                    "UDP and CoAP payload values differ".to_owned(),
                ));
            }
        }
        coap.clone()
    };

    // Honor a sent length value; otherwise compute from the payload.
    let udp_length = match fields.first_by_field_scope(&FieldRef::Udp("fid-udp-length"), scope) {
        Some(value) => u16::try_from(value.to_u64()?).map_err(|_| {
            SchcError::InvalidResidue("sent UDP length does not fit u16".to_owned())
        })?,
        None => u16::try_from(8 + payload.len()).map_err(|_| {
            SchcError::InvalidResidue("UDP payload is too large to encode length".to_owned())
        })?,
    };

    // Honor a sent checksum; otherwise leave it zero and compute it later.
    let (checksum, compute_checksum) =
        match fields.first_by_field_scope(&FieldRef::Udp("fid-udp-checksum"), scope) {
            Some(value) => (
                u16::try_from(value.to_u64()?).map_err(|_| {
                    SchcError::InvalidResidue("sent UDP checksum does not fit u16".to_owned())
                })?,
                false,
            ),
            None => (0, true),
        };

    let mut output = Vec::with_capacity(usize::from(udp_length));
    output.extend_from_slice(&source_port.to_be_bytes());
    output.extend_from_slice(&destination_port.to_be_bytes());
    output.extend_from_slice(&udp_length.to_be_bytes());
    output.extend_from_slice(&checksum.to_be_bytes());
    output.extend_from_slice(&payload);
    Ok((output, compute_checksum))
}

fn reconstruct_coap(fields: &FieldStore, scope: PacketScope) -> Result<Vec<u8>> {
    let version = first_u8_at(fields, &FieldRef::Coap("fid-coap-version"), scope)?;
    let message_type = first_u8_at(fields, &FieldRef::Coap("fid-coap-type"), scope)?;
    let token_len = first_u8_at(fields, &FieldRef::Coap("fid-coap-tkl"), scope)?;
    let code = first_u8_at(fields, &FieldRef::Coap("fid-coap-code"), scope)?;
    let message_id = first_u16_at(fields, &FieldRef::Coap("fid-coap-mid"), scope)?;

    if version > 3 || message_type > 3 || token_len > 8 {
        return Err(SchcError::InvalidResidue(
            "CoAP fixed header fields are out of range".to_owned(),
        ));
    }

    let token = fields
        .first_by_field_scope(&FieldRef::Coap("fid-coap-token"), scope)
        .map(|value| {
            if value.bit_len() != usize::from(token_len) * 8 {
                return Err(SchcError::InvalidResidue(
                    "CoAP token length does not match TKL".to_owned(),
                ));
            }
            Ok(value.bytes().to_vec())
        })
        .transpose()?;
    let token = match (token_len, token) {
        (0, None) => Vec::new(),
        (0, Some(value)) if value.is_empty() => value,
        (0, Some(_)) => {
            return Err(SchcError::InvalidResidue(
                "CoAP token present with zero TKL".to_owned(),
            ));
        }
        (_, Some(value)) => value,
        (_, None) => {
            return Err(SchcError::InvalidResidue(
                "missing reconstructed CoAP token".to_owned(),
            ));
        }
    };

    let mut options = Vec::new();
    for (key, value) in fields.iter() {
        if key.scope() == scope {
            if let FieldRef::CoapOption { number } = key.field() {
                let number = u32::try_from(*number).map_err(|_| {
                    SchcError::InvalidResidue(format!(
                        "CoAP option number {number} does not fit u32"
                    ))
                })?;
                options.push(CoapOption::new(number, value.bytes().to_vec())?);
            }
        }
    }

    let payload = shared_payload(fields, scope, &FieldRef::Coap("fid-coap-payload"))?;

    let message = CoapMessage::from_parts(
        version,
        message_type,
        code,
        message_id,
        token,
        options,
        payload,
    )?;
    Ok(message.to_vec())
}

fn reconstruct_icmpv6(
    direction: Direction,
    fields: &FieldStore,
    scope: PacketScope,
) -> Result<(Vec<u8>, bool)> {
    let message_type = first_u8_at(fields, &FieldRef::Icmpv6("fid-icmpv6-type"), scope)?;
    let code = first_u8_at(fields, &FieldRef::Icmpv6("fid-icmpv6-code"), scope)?;
    let (checksum, compute_checksum) =
        match fields.first_by_field_scope(&FieldRef::Icmpv6("fid-icmpv6-checksum"), scope) {
            Some(value) => (
                u16::try_from(value.to_u64()?).map_err(|_| {
                    SchcError::InvalidResidue("sent ICMPv6 checksum does not fit u16".to_owned())
                })?,
                false,
            ),
            None => (0, true),
        };

    if crate::packet::traversal::is_icmpv6_error_type(message_type) {
        let type_word = if crate::packet::traversal::has_icmpv6_unused_field(message_type) {
            fields
                .first_by_field_scope(&FieldRef::Unused, scope)
                .ok_or_else(|| {
                    SchcError::InvalidResidue(
                        "missing fid-unused for ICMPv6 error reconstruction".to_owned(),
                    )
                })?
        } else if let Some(field) = fields.first_by_field_scope(
            &FieldRef::Icmpv6(if message_type == 2 {
                "fid-icmpv6-mtu"
            } else {
                "fid-icmpv6-pointer"
            }),
            scope,
        ) {
            field
        } else {
            return Err(SchcError::InvalidResidue(
                "missing ICMPv6 type-specific 32-bit field".to_owned(),
            ));
        };
        if type_word.bit_len() != 32 || type_word.bytes().len() != 4 {
            return Err(SchcError::InvalidResidue(
                "ICMPv6 type-specific field must be exactly 32 bits".to_owned(),
            ));
        }
        let mut bytes = vec![message_type, code];
        bytes.extend_from_slice(&checksum.to_be_bytes());
        bytes.extend_from_slice(type_word.bytes());

        if fields
            .first_by_field_scope(&FieldRef::Ipv6("fid-ipv6-version"), PacketScope::Embedded)
            .is_some()
        {
            let inner =
                reconstruct_packet_at(reverse_direction(direction), fields, PacketScope::Embedded)?;
            if let Some(outer_payload) = fields.first_by_field_scope(&FieldRef::Payload, scope) {
                if outer_payload.bytes() != inner.as_slice() {
                    return Err(SchcError::InvalidResidue(
                        "outer and embedded generic payload values differ".to_owned(),
                    ));
                }
            }
            bytes.extend_from_slice(&inner);
        } else if fields
            .first_by_field_scope(&FieldRef::Payload, scope)
            .is_some()
        {
            bytes.extend_from_slice(&shared_payload(fields, scope, &FieldRef::Payload)?);
        } else {
            return Err(SchcError::InvalidResidue(
                "missing embedded packet for ICMPv6 error reconstruction".to_owned(),
            ));
        }
        Ok((bytes, compute_checksum))
    } else {
        let payload = shared_payload(fields, scope, &FieldRef::Icmpv6("fid-icmpv6-payload"))?;
        let mut bytes = vec![message_type, code];
        bytes.extend_from_slice(&checksum.to_be_bytes());
        if matches!(message_type, 128 | 129)
            && fields
                .first_by_field_scope(&FieldRef::Icmpv6("fid-icmpv6-identifier"), scope)
                .is_some()
        {
            let identifier =
                first_u16_at(fields, &FieldRef::Icmpv6("fid-icmpv6-identifier"), scope)?;
            let sequence = first_u16_at(fields, &FieldRef::Icmpv6("fid-icmpv6-sequence"), scope)?;
            bytes.extend_from_slice(&identifier.to_be_bytes());
            bytes.extend_from_slice(&sequence.to_be_bytes());
        }
        bytes.extend_from_slice(&payload);
        Ok((bytes, compute_checksum))
    }
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_ipv6_with_upper(
    direction: Direction,
    fields: &FieldStore,
    scope: PacketScope,
    next_header: u8,
    mut upper: Vec<u8>,
    compute_checksum: bool,
) -> Result<Vec<u8>> {
    let version = first_u8_at(fields, &FieldRef::Ipv6("fid-ipv6-version"), scope)?;
    let traffic_class = first_u8_at(fields, &FieldRef::Ipv6("fid-ipv6-trafficclass"), scope)?;
    let flow_label = first_usize_at(fields, &FieldRef::Ipv6("fid-ipv6-flowlabel"), scope)?;
    let hop_limit = first_u8_at(fields, &FieldRef::Ipv6("fid-ipv6-hoplimit"), scope)?;

    // Honor a sent payload length; otherwise compute from the upper segment.
    let payload_len =
        match fields.first_by_field_scope(&FieldRef::Ipv6("fid-ipv6-payload-length"), scope) {
            Some(value) => u16::try_from(value.to_u64()?).map_err(|_| {
                SchcError::InvalidResidue("sent IPv6 payload length does not fit u16".to_owned())
            })?,
            None => u16::try_from(upper.len()).map_err(|_| {
                SchcError::InvalidResidue("IPv6 payload is too large to encode length".to_owned())
            })?,
        };
    let (source, destination) = endpoint_addresses(direction, fields, scope)?;

    if version != 6 || flow_label > 0x000f_ffff {
        return Err(SchcError::InvalidResidue(
            "IPv6 fixed header fields are out of range".to_owned(),
        ));
    }

    // Compute and patch the transport-layer checksum only when the rule did not
    // send a value for it (i.e. the CDA was compute).
    if compute_checksum {
        let transport_sum = transport_checksum(&source, &destination, next_header, &upper);
        let checksum_range = checksum_range(next_header, &upper)?;
        upper[checksum_range].copy_from_slice(&transport_sum.to_be_bytes());
    }

    let mut output = Vec::with_capacity(40 + upper.len());
    let traffic_flow = (u32::from(version) << 28)
        | (u32::from(traffic_class) << 20)
        | u32::try_from(flow_label).expect("flow label was range-checked");
    output.extend_from_slice(&traffic_flow.to_be_bytes());
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.push(next_header);
    output.push(hop_limit);
    output.extend_from_slice(&source);
    output.extend_from_slice(&destination);
    output.extend_from_slice(&upper);
    Ok(output)
}

fn checksum_range(next_header: u8, upper: &[u8]) -> Result<std::ops::Range<usize>> {
    match next_header {
        17 if upper.len() >= 8 => Ok(6..8),
        58 if upper.len() >= 4 => Ok(2..4),
        _ => Err(SchcError::InvalidResidue(format!(
            "upper segment too short for next header {next_header} checksum"
        ))),
    }
}

fn endpoint_addresses(
    direction: Direction,
    fields: &FieldStore,
    scope: PacketScope,
) -> Result<([u8; 16], [u8; 16])> {
    let device = endpoint_address(
        fields,
        scope,
        &FieldRef::Ipv6("fid-ipv6-devprefix"),
        &FieldRef::Ipv6("fid-ipv6-deviid"),
    )?;
    let application = endpoint_address(
        fields,
        scope,
        &FieldRef::Ipv6("fid-ipv6-appprefix"),
        &FieldRef::Ipv6("fid-ipv6-appiid"),
    )?;

    Ok(match direction {
        Direction::Up => (device, application),
        Direction::Down => (application, device),
    })
}

fn endpoint_address(
    fields: &FieldStore,
    scope: PacketScope,
    prefix_field: &FieldRef,
    iid_field: &FieldRef,
) -> Result<[u8; 16]> {
    let prefix = first_value_at(fields, prefix_field, scope)?;
    let iid = first_value_at(fields, iid_field, scope)?;
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

fn shared_payload(
    fields: &FieldStore,
    scope: PacketScope,
    protocol_field: &FieldRef,
) -> Result<Vec<u8>> {
    let protocol = fields.first_by_field_scope(protocol_field, scope);
    let generic = fields.first_by_field_scope(&FieldRef::Payload, scope);
    match (protocol, generic) {
        (Some(protocol), Some(generic)) if protocol.bytes() != generic.bytes() => {
            Err(SchcError::InvalidResidue(
                "generic and protocol-specific payload values differ".to_owned(),
            ))
        }
        (Some(value), _) | (None, Some(value)) => Ok(value.bytes().to_vec()),
        (None, None) => Ok(Vec::new()),
    }
}

fn first_u8_at(fields: &FieldStore, field: &FieldRef, scope: PacketScope) -> Result<u8> {
    let value = first_value_at(fields, field, scope)?;
    u8::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit u8".to_owned()))
}

fn first_u16_at(fields: &FieldStore, field: &FieldRef, scope: PacketScope) -> Result<u16> {
    let value = first_value_at(fields, field, scope)?;
    u16::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit u16".to_owned()))
}

fn first_usize_at(fields: &FieldStore, field: &FieldRef, scope: PacketScope) -> Result<usize> {
    let value = first_value_at(fields, field, scope)?;
    usize::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit usize".to_owned()))
}

fn first_value_at<'a>(
    fields: &'a FieldStore,
    field: &FieldRef,
    scope: PacketScope,
) -> Result<&'a FieldValue> {
    fields.first_by_field_scope(field, scope).ok_or_else(|| {
        SchcError::InvalidResidue(format!(
            "missing reconstructed field {field:?} in {scope:?} scope"
        ))
    })
}
