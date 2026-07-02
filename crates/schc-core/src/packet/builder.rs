//! Packet reconstruction from decoded field stores.

use crate::error::{Result, SchcError};
use crate::packet::checksum::transport_checksum;
use crate::packet::field::{FieldStore, FieldValue};
use crate::packet::{CoapMessage, CoapOption, Icmpv6Message};
use crate::rule::{Direction, FieldRef};

/// Reconstructs a full IPv6 packet from decoded fields.
///
/// Dispatches to UDP or `ICMPv6` reconstruction based on the IPv6 next-header
/// field.
///
/// # Errors
///
/// Returns [`SchcError::InvalidResidue`] when required fields are missing,
/// out of range, or the next-header value is unsupported.
pub(crate) fn reconstruct_packet(direction: Direction, fields: &FieldStore) -> Result<Vec<u8>> {
    let next_header = first_u8(fields, &FieldRef::Ipv6("fid-ipv6-nextheader"))?;
    match next_header {
        17 => {
            reconstruct_ipv6_with_upper(direction, fields, 17, reconstruct_udp(direction, fields)?)
        }
        58 => reconstruct_ipv6_with_upper(
            direction,
            fields,
            58,
            reconstruct_icmpv6(direction, fields)?,
        ),
        value => Err(SchcError::InvalidResidue(format!(
            "unsupported IPv6 next header {value}"
        ))),
    }
}

fn reconstruct_udp(direction: Direction, fields: &FieldStore) -> Result<Vec<u8>> {
    let coap = if fields
        .first_by_field(&FieldRef::Coap("fid-coap-version"))
        .is_some()
    {
        reconstruct_coap(fields)?
    } else {
        Vec::new()
    };

    let dev_port = first_u16(fields, &FieldRef::Udp("fid-udp-dev-port"))?;
    let app_port = first_u16(fields, &FieldRef::Udp("fid-udp-app-port"))?;
    let (source_port, destination_port) = match direction {
        Direction::Up => (dev_port, app_port),
        Direction::Down => (app_port, dev_port),
    };
    let payload = fields
        .first_by_field(&FieldRef::Udp("fid-udp-payload"))
        .map_or_else(|| coap.clone(), |value| value.bytes().to_vec());
    let udp_length = u16::try_from(8 + payload.len()).map_err(|_| {
        SchcError::InvalidResidue("UDP payload is too large to encode length".to_owned())
    })?;

    let mut output = Vec::with_capacity(usize::from(udp_length));
    output.extend_from_slice(&source_port.to_be_bytes());
    output.extend_from_slice(&destination_port.to_be_bytes());
    output.extend_from_slice(&udp_length.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&payload);
    Ok(output)
}

fn reconstruct_coap(fields: &FieldStore) -> Result<Vec<u8>> {
    let version = first_u8(fields, &FieldRef::Coap("fid-coap-version"))?;
    let message_type = first_u8(fields, &FieldRef::Coap("fid-coap-type"))?;
    let token_len = first_u8(fields, &FieldRef::Coap("fid-coap-tkl"))?;
    let code = first_u8(fields, &FieldRef::Coap("fid-coap-code"))?;
    let message_id = first_u16(fields, &FieldRef::Coap("fid-coap-mid"))?;

    if version > 3 || message_type > 3 || token_len > 8 {
        return Err(SchcError::InvalidResidue(
            "CoAP fixed header fields are out of range".to_owned(),
        ));
    }

    let token = fields
        .first_by_field(&FieldRef::Coap("fid-coap-token"))
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
        .first_by_field(&FieldRef::Coap("fid-coap-payload"))
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

fn reconstruct_icmpv6(direction: Direction, fields: &FieldStore) -> Result<Vec<u8>> {
    let _ = direction;
    let message_type = first_u8(fields, &FieldRef::Icmpv6("fid-icmpv6-type"))?;
    let code = first_u8(fields, &FieldRef::Icmpv6("fid-icmpv6-code"))?;
    let payload = fields
        .first_by_field(&FieldRef::Icmpv6("fid-icmpv6-payload"))
        .map(|value| value.bytes().to_vec())
        .unwrap_or_default();

    // Checksum is computed later by reconstruct_ipv6_with_upper; build with zero.
    let icmp = Icmpv6Message::from_parts(message_type, code, 0, payload)?;
    Ok(icmp.to_vec())
}

fn reconstruct_ipv6_with_upper(
    direction: Direction,
    fields: &FieldStore,
    next_header: u8,
    mut upper: Vec<u8>,
) -> Result<Vec<u8>> {
    let version = first_u8(fields, &FieldRef::Ipv6("fid-ipv6-version"))?;
    let traffic_class = first_u8(fields, &FieldRef::Ipv6("fid-ipv6-trafficclass"))?;
    let flow_label = first_usize(fields, &FieldRef::Ipv6("fid-ipv6-flowlabel"))?;
    let hop_limit = first_u8(fields, &FieldRef::Ipv6("fid-ipv6-hoplimit"))?;
    let payload_len = u16::try_from(upper.len()).map_err(|_| {
        SchcError::InvalidResidue("IPv6 payload is too large to encode length".to_owned())
    })?;
    let (source, destination) = endpoint_addresses(direction, fields)?;

    if version != 6 || flow_label > 0x000f_ffff {
        return Err(SchcError::InvalidResidue(
            "IPv6 fixed header fields are out of range".to_owned(),
        ));
    }

    // Compute and patch the transport-layer checksum.
    let computed_checksum = transport_checksum(&source, &destination, next_header, &upper);
    let checksum_range = checksum_range(next_header, &upper)?;
    upper[checksum_range].copy_from_slice(&computed_checksum.to_be_bytes());

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

fn endpoint_addresses(direction: Direction, fields: &FieldStore) -> Result<([u8; 16], [u8; 16])> {
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
    fields: &FieldStore,
    prefix_field: &FieldRef,
    iid_field: &FieldRef,
) -> Result<[u8; 16]> {
    let prefix = first_value(fields, prefix_field)?;
    let iid = first_value(fields, iid_field)?;
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

fn first_u8(fields: &FieldStore, field: &FieldRef) -> Result<u8> {
    let value = first_value(fields, field)?;
    u8::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit u8".to_owned()))
}

fn first_u16(fields: &FieldStore, field: &FieldRef) -> Result<u16> {
    let value = first_value(fields, field)?;
    u16::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit u16".to_owned()))
}

fn first_usize(fields: &FieldStore, field: &FieldRef) -> Result<usize> {
    let value = first_value(fields, field)?;
    usize::try_from(value.to_u64()?)
        .map_err(|_| SchcError::InvalidResidue("field does not fit usize".to_owned()))
}

fn first_value<'a>(fields: &'a FieldStore, field: &FieldRef) -> Result<&'a FieldValue> {
    fields
        .first_by_field(field)
        .ok_or_else(|| SchcError::InvalidResidue(format!("missing reconstructed field {field:?}")))
}
