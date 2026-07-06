//! Packet reconstruction from decoded field stores.

use crate::error::{Result, SchcError};
use crate::packet::checksum::transport_checksum;
use crate::packet::field::{FieldStore, FieldValue};
use crate::packet::{CoapMessage, CoapOption};
use crate::rule::{Direction, FieldRef};

/// Reconstructs a full IPv6 packet from decoded fields.
///
/// Dispatches to UDP or `ICMPv6` reconstruction based on the IPv6 next-header
/// field. Outer packet fields are read at field position 1.
///
/// # Errors
///
/// Returns [`SchcError::InvalidResidue`] when required fields are missing,
/// out of range, or the next-header value is unsupported.
pub(crate) fn reconstruct_packet(direction: Direction, fields: &FieldStore) -> Result<Vec<u8>> {
    reconstruct_packet_at(direction, fields, 1)
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

/// Reconstructs an IPv6 packet using fields stored at `position`.
///
/// `position` selects between the outer packet (1) and an ICMPv6-embedded inner
/// packet (2). The inner packet is reconstructed with the direction reversed by
/// the caller.
fn reconstruct_packet_at(
    direction: Direction,
    fields: &FieldStore,
    position: usize,
) -> Result<Vec<u8>> {
    let next_header = first_u8_at(fields, &FieldRef::Ipv6("fid-ipv6-nextheader"), position)?;
    match next_header {
        17 => {
            let (upper, compute_checksum) = reconstruct_udp(direction, fields, position)?;
            reconstruct_ipv6_with_upper(direction, fields, position, 17, upper, compute_checksum)
        }
        58 => {
            let (upper, compute_checksum) = reconstruct_icmpv6(direction, fields, position)?;
            reconstruct_ipv6_with_upper(direction, fields, position, 58, upper, compute_checksum)
        }
        value => Err(SchcError::InvalidResidue(format!(
            "unsupported IPv6 next header {value}"
        ))),
    }
}

fn reconstruct_udp(
    direction: Direction,
    fields: &FieldStore,
    position: usize,
) -> Result<(Vec<u8>, bool)> {
    let coap = if position == 1
        && fields
            .first_by_field_position(&FieldRef::Coap("fid-coap-version"), 1)
            .is_some()
    {
        reconstruct_coap(fields)?
    } else {
        Vec::new()
    };

    let dev_port = first_u16_at(fields, &FieldRef::Udp("fid-udp-dev-port"), position)?;
    let app_port = first_u16_at(fields, &FieldRef::Udp("fid-udp-app-port"), position)?;
    let (source_port, destination_port) = match direction {
        Direction::Up => (dev_port, app_port),
        Direction::Down => (app_port, dev_port),
    };
    let payload = fields
        .first_by_field_position(&FieldRef::Udp("fid-udp-payload"), position)
        .map_or_else(|| coap.clone(), |value| value.bytes().to_vec());

    // Honor a sent length value; otherwise compute from the payload.
    let udp_length =
        match fields.first_by_field_position(&FieldRef::Udp("fid-udp-length"), position) {
            Some(value) => u16::try_from(value.to_u64()?).map_err(|_| {
                SchcError::InvalidResidue("sent UDP length does not fit u16".to_owned())
            })?,
            None => u16::try_from(8 + payload.len()).map_err(|_| {
                SchcError::InvalidResidue("UDP payload is too large to encode length".to_owned())
            })?,
        };

    // Honor a sent checksum; otherwise leave it zero and compute it later.
    let (checksum, compute_checksum) =
        match fields.first_by_field_position(&FieldRef::Udp("fid-udp-checksum"), position) {
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

fn reconstruct_coap(fields: &FieldStore) -> Result<Vec<u8>> {
    let version = first_u8_at(fields, &FieldRef::Coap("fid-coap-version"), 1)?;
    let message_type = first_u8_at(fields, &FieldRef::Coap("fid-coap-type"), 1)?;
    let token_len = first_u8_at(fields, &FieldRef::Coap("fid-coap-tkl"), 1)?;
    let code = first_u8_at(fields, &FieldRef::Coap("fid-coap-code"), 1)?;
    let message_id = first_u16_at(fields, &FieldRef::Coap("fid-coap-mid"), 1)?;

    if version > 3 || message_type > 3 || token_len > 8 {
        return Err(SchcError::InvalidResidue(
            "CoAP fixed header fields are out of range".to_owned(),
        ));
    }

    let token = fields
        .first_by_field_position(&FieldRef::Coap("fid-coap-token"), 1)
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
        if let FieldRef::CoapOption { number } = key.field() {
            options.push(CoapOption::new(u32::from(*number), value.bytes().to_vec())?);
        }
    }

    let payload = fields
        .first_by_field_position(&FieldRef::Coap("fid-coap-payload"), 1)
        .map(|value| value.bytes().to_vec())
        .unwrap_or_default();

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
    position: usize,
) -> Result<(Vec<u8>, bool)> {
    let message_type = first_u8_at(fields, &FieldRef::Icmpv6("fid-icmpv6-type"), position)?;
    let code = first_u8_at(fields, &FieldRef::Icmpv6("fid-icmpv6-code"), position)?;
    let (checksum, compute_checksum) =
        match fields.first_by_field_position(&FieldRef::Icmpv6("fid-icmpv6-checksum"), position) {
            Some(value) => (
                u16::try_from(value.to_u64()?).map_err(|_| {
                    SchcError::InvalidResidue("sent ICMPv6 checksum does not fit u16".to_owned())
                })?,
                false,
            ),
            None => (0, true),
        };

    if is_icmpv6_error_type(message_type) {
        // ICMPv6 error header: type, code, checksum, 4 unused bytes.
        let mut bytes = vec![message_type, code];
        bytes.extend_from_slice(&checksum.to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);

        // Known error types embed the invoking packet, reconstructed with the
        // direction reversed. The inner packet fields
        // live at the next field position.
        if fields
            .first_by_field_position(&FieldRef::Ipv6("fid-ipv6-version"), position + 1)
            .is_some()
        {
            let inner = reconstruct_packet_at(reverse_direction(direction), fields, position + 1)?;
            bytes.extend_from_slice(&inner);
        }
        Ok((bytes, compute_checksum))
    } else {
        // Echo and other simple ICMPv6 messages keep an opaque payload.
        let payload = fields
            .first_by_field_position(&FieldRef::Icmpv6("fid-icmpv6-payload"), position)
            .map(|value| value.bytes().to_vec())
            .unwrap_or_default();
        let mut bytes = vec![message_type, code];
        bytes.extend_from_slice(&checksum.to_be_bytes());
        bytes.extend_from_slice(&payload);
        Ok((bytes, compute_checksum))
    }
}

#[allow(clippy::too_many_arguments)]
fn reconstruct_ipv6_with_upper(
    direction: Direction,
    fields: &FieldStore,
    position: usize,
    next_header: u8,
    mut upper: Vec<u8>,
    compute_checksum: bool,
) -> Result<Vec<u8>> {
    let version = first_u8_at(fields, &FieldRef::Ipv6("fid-ipv6-version"), position)?;
    let traffic_class = first_u8_at(fields, &FieldRef::Ipv6("fid-ipv6-trafficclass"), position)?;
    let flow_label = first_usize_at(fields, &FieldRef::Ipv6("fid-ipv6-flowlabel"), position)?;
    let hop_limit = first_u8_at(fields, &FieldRef::Ipv6("fid-ipv6-hoplimit"), position)?;

    // Honor a sent payload length; otherwise compute from the upper segment.
    let payload_len = match fields
        .first_by_field_position(&FieldRef::Ipv6("fid-ipv6-payload-length"), position)
    {
        Some(value) => u16::try_from(value.to_u64()?).map_err(|_| {
            SchcError::InvalidResidue("sent IPv6 payload length does not fit u16".to_owned())
        })?,
        None => u16::try_from(upper.len()).map_err(|_| {
            SchcError::InvalidResidue("IPv6 payload is too large to encode length".to_owned())
        })?,
    };
    let (source, destination) = endpoint_addresses(direction, fields, position)?;

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
    position: usize,
) -> Result<([u8; 16], [u8; 16])> {
    let device = endpoint_address(
        fields,
        position,
        &FieldRef::Ipv6("fid-ipv6-devprefix"),
        &FieldRef::Ipv6("fid-ipv6-deviid"),
    )?;
    let application = endpoint_address(
        fields,
        position,
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
    position: usize,
    prefix_field: &FieldRef,
    iid_field: &FieldRef,
) -> Result<[u8; 16]> {
    let prefix = first_value_at(fields, prefix_field, position)?;
    let iid = first_value_at(fields, iid_field, position)?;
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

fn first_u8_at(fields: &FieldStore, field: &FieldRef, position: usize) -> Result<u8> {
    let value = first_value_at(fields, field, position)?;
    u8::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit u8".to_owned()))
}

fn first_u16_at(fields: &FieldStore, field: &FieldRef, position: usize) -> Result<u16> {
    let value = first_value_at(fields, field, position)?;
    u16::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit u16".to_owned()))
}

fn first_usize_at(fields: &FieldStore, field: &FieldRef, position: usize) -> Result<usize> {
    let value = first_value_at(fields, field, position)?;
    usize::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit usize".to_owned()))
}

fn first_value_at<'a>(
    fields: &'a FieldStore,
    field: &FieldRef,
    position: usize,
) -> Result<&'a FieldValue> {
    fields
        .first_by_field_position(field, position)
        .ok_or_else(|| {
            SchcError::InvalidResidue(format!(
                "missing reconstructed field {field:?} at position {position}"
            ))
        })
}
