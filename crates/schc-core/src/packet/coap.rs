use crate::error::{Result, SchcError};

const PAYLOAD_MARKER: u8 = 0xff;

/// Parsed CoAP option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapOption {
    number: u32,
    value: Vec<u8>,
}

impl CoapOption {
    /// Creates a CoAP option from an absolute option number and value.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Packet`] when the option value length exceeds the
    /// encodable CoAP range.
    pub fn new(number: u32, value: Vec<u8>) -> Result<Self> {
        let length = u32::try_from(value.len())
            .map_err(|_| packet_error("CoAP", "option length does not fit u32"))?;
        if length > 65_804 {
            return Err(packet_error(
                "CoAP",
                "option length exceeds encodable range",
            ));
        }
        Ok(Self { number, value })
    }

    /// Returns the cumulative CoAP option number.
    #[must_use]
    pub fn number(&self) -> u32 {
        self.number
    }

    /// Returns the raw CoAP option value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Parsed CoAP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoapMessage {
    version: u8,
    message_type: u8,
    code: u8,
    message_id: u16,
    token: Vec<u8>,
    options: Vec<CoapOption>,
    payload: Vec<u8>,
}

impl CoapMessage {
    /// Parses a CoAP message from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Packet`] when the message is truncated, uses an
    /// invalid token length, uses a reserved option delta or length nibble, or
    /// contains a payload marker without payload bytes.
    pub fn parse(input: &[u8]) -> Result<Self> {
        if input.len() < 4 {
            return Err(packet_error("CoAP", "message shorter than 4-byte header"));
        }

        let first = input[0];
        let version = first >> 6;
        let message_type = (first >> 4) & 0x03;
        let token_len = usize::from(first & 0x0f);
        if token_len > 8 {
            return Err(packet_error("CoAP", "token length exceeds 8 bytes"));
        }

        let token_end = 4usize
            .checked_add(token_len)
            .ok_or_else(|| packet_error("CoAP", "token length overflows message length"))?;
        if token_end > input.len() {
            return Err(packet_error("CoAP", "token length exceeds available bytes"));
        }

        let code = input[1];
        let message_id = u16::from_be_bytes([input[2], input[3]]);
        let token = input[4..token_end].to_vec();
        let mut offset = token_end;
        let mut option_number = 0u32;
        let mut options = Vec::new();
        let mut payload = Vec::new();

        while offset < input.len() {
            if input[offset] == PAYLOAD_MARKER {
                offset += 1;
                if offset == input.len() {
                    return Err(packet_error("CoAP", "payload marker without payload"));
                }
                payload.extend_from_slice(&input[offset..]);
                break;
            }

            let option_header = input[offset];
            offset += 1;
            let delta_nibble = option_header >> 4;
            let length_nibble = option_header & 0x0f;
            let delta = read_extended("option delta", delta_nibble, input, &mut offset)?;
            let length = read_extended("option length", length_nibble, input, &mut offset)?;
            let value_len = usize::try_from(length)
                .map_err(|_| packet_error("CoAP", "option length does not fit usize"))?;
            let value_end = offset
                .checked_add(value_len)
                .ok_or_else(|| packet_error("CoAP", "option length overflows message length"))?;
            if value_end > input.len() {
                return Err(packet_error(
                    "CoAP",
                    "option length exceeds available bytes",
                ));
            }

            option_number = option_number
                .checked_add(delta)
                .ok_or_else(|| packet_error("CoAP", "option number overflows u32"))?;
            options.push(CoapOption {
                number: option_number,
                value: input[offset..value_end].to_vec(),
            });
            offset = value_end;
        }

        Ok(Self {
            version,
            message_type,
            code,
            message_id,
            token,
            options,
            payload,
        })
    }

    /// Returns the CoAP version.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Returns the CoAP code.
    #[must_use]
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Returns the CoAP message ID.
    #[must_use]
    pub fn message_id(&self) -> u16 {
        self.message_id
    }

    /// Returns the CoAP token bytes.
    #[must_use]
    pub fn token(&self) -> &[u8] {
        &self.token
    }

    /// Returns the parsed CoAP options.
    #[must_use]
    pub fn options(&self) -> &[CoapOption] {
        &self.options
    }

    /// Returns the CoAP payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Builds a CoAP message from header fields, token, options, and payload.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Packet`] when header fields are out of range, the
    /// token is longer than eight bytes, options are not in nondecreasing
    /// order, or an option delta exceeds the encodable range.
    pub fn from_parts(
        version: u8,
        message_type: u8,
        code: u8,
        message_id: u16,
        token: Vec<u8>,
        options: Vec<CoapOption>,
        payload: Vec<u8>,
    ) -> Result<Self> {
        if version > 3 {
            return Err(packet_error("CoAP", "version exceeds 3"));
        }
        if message_type > 3 {
            return Err(packet_error("CoAP", "message type exceeds 3"));
        }
        if token.len() > 8 {
            return Err(packet_error("CoAP", "token length exceeds 8 bytes"));
        }

        let mut previous_number = 0u32;
        for option in &options {
            if option.number < previous_number {
                return Err(packet_error(
                    "CoAP",
                    "options are not in nondecreasing order",
                ));
            }
            if option.number - previous_number > 65_804 {
                return Err(packet_error("CoAP", "option delta exceeds encodable range"));
            }
            previous_number = option.number;
        }

        Ok(Self {
            version,
            message_type,
            code,
            message_id,
            token,
            options,
            payload,
        })
    }

    /// Serializes this message to bytes using canonical option encoding.
    ///
    /// # Panics
    ///
    /// Panics only if internal parser invariants are violated after construction,
    /// such as a token longer than the CoAP maximum or options stored out of
    /// nondecreasing order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u8> {
        let mut output = Vec::new();
        let token_len = u8::try_from(self.token.len()).expect("parsed CoAP token length fits u8");
        output.push((self.version << 6) | (self.message_type << 4) | token_len);
        output.push(self.code);
        output.extend_from_slice(&self.message_id.to_be_bytes());
        output.extend_from_slice(&self.token);

        let mut previous_number = 0u32;
        for option in &self.options {
            let delta = option
                .number
                .checked_sub(previous_number)
                .expect("parsed CoAP options are in nondecreasing order");
            let length = u32::try_from(option.value.len()).expect("option length fits u32");
            let mut delta_extra = Vec::new();
            let mut length_extra = Vec::new();
            let delta_nibble = encode_extended(delta, &mut delta_extra);
            let length_nibble = encode_extended(length, &mut length_extra);
            output.push((delta_nibble << 4) | length_nibble);
            output.extend_from_slice(&delta_extra);
            output.extend_from_slice(&length_extra);
            output.extend_from_slice(&option.value);
            previous_number = option.number;
        }

        if !self.payload.is_empty() {
            output.push(PAYLOAD_MARKER);
            output.extend_from_slice(&self.payload);
        }

        output
    }
}

fn read_extended(field: &'static str, nibble: u8, input: &[u8], offset: &mut usize) -> Result<u32> {
    match nibble {
        0..=12 => Ok(u32::from(nibble)),
        13 => {
            let byte = *input
                .get(*offset)
                .ok_or_else(|| packet_error("CoAP", format!("{field} missing 8-bit extension")))?;
            *offset += 1;
            Ok(u32::from(byte) + 13)
        }
        14 => {
            let end = offset
                .checked_add(2)
                .ok_or_else(|| packet_error("CoAP", format!("{field} extension overflows")))?;
            if end > input.len() {
                return Err(packet_error(
                    "CoAP",
                    format!("{field} missing 16-bit extension"),
                ));
            }
            let value = u16::from_be_bytes([input[*offset], input[*offset + 1]]);
            *offset = end;
            Ok(u32::from(value) + 269)
        }
        15 => Err(packet_error(
            "CoAP",
            format!("{field} uses reserved nibble value 15"),
        )),
        _ => unreachable!("option nibble is four bits"),
    }
}

fn encode_extended(value: u32, extra: &mut Vec<u8>) -> u8 {
    match value {
        0..=12 => u8::try_from(value).expect("small option value fits u8"),
        13..=268 => {
            extra.push(u8::try_from(value - 13).expect("8-bit option extension fits u8"));
            13
        }
        269..=65_804 => {
            extra.extend_from_slice(
                &u16::try_from(value - 269)
                    .expect("16-bit option extension fits u16")
                    .to_be_bytes(),
            );
            14
        }
        _ => panic!("parsed CoAP option delta or length exceeds encodable range"),
    }
}

fn packet_error(protocol: &'static str, reason: impl Into<String>) -> SchcError {
    SchcError::Packet {
        protocol,
        reason: reason.into(),
    }
}
