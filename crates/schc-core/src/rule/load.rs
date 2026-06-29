//! JSON loading for typed SCHC rules.

use serde::Deserialize;

use crate::error::{Result, SchcError};
use crate::rule::model::{
    Cda, DirectionSelector, FieldLength, FieldRef, FieldRule, MatchingOperator, Rule, RuleId,
    RuleSet, TargetValue,
};
use crate::SidRegistry;

/// Loaded rule context used by SCHC processing.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleContext {
    rules: RuleSet,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    rules: Vec<JsonRule>,
}

#[derive(Debug, Deserialize)]
struct JsonRule {
    rule_id: u64,
    rule_id_length: usize,
    fields: Vec<JsonField>,
}

#[derive(Debug, Deserialize)]
struct JsonField {
    field: String,
    length_bits: usize,
    direction: String,
    target: serde_json::Value,
    mo: String,
    cda: String,
}

impl RuleContext {
    /// Loads a typed rule context from a JSON rule document.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Json`] when `data` is not valid JSON.
    /// Returns [`SchcError::InvalidRule`] or [`SchcError::InvalidRuleField`] when
    /// the decoded rule structure is invalid or references missing SID
    /// identifiers.
    pub fn from_json_str(data: &str, sid_registry: SidRegistry) -> Result<Self> {
        let file: RuleFile =
            serde_json::from_str(data).map_err(|error| SchcError::Json(error.to_string()))?;
        let mut rules = Vec::with_capacity(file.rules.len());

        for (rule_index, json_rule) in file.rules.into_iter().enumerate() {
            if json_rule.rule_id_length == 0 || json_rule.rule_id_length > 64 {
                return Err(SchcError::InvalidRule {
                    rule_index,
                    reason: format!("rule_id_length {} is invalid", json_rule.rule_id_length),
                });
            }
            if json_rule.rule_id_length < 64
                && json_rule.rule_id >= (1_u64 << json_rule.rule_id_length)
            {
                return Err(SchcError::InvalidRule {
                    rule_index,
                    reason: format!(
                        "rule_id {} does not fit in {} bits",
                        json_rule.rule_id, json_rule.rule_id_length
                    ),
                });
            }

            let mut fields = Vec::with_capacity(json_rule.fields.len());
            for (entry_index, json_field) in json_rule.fields.into_iter().enumerate() {
                fields.push(load_field(
                    &sid_registry,
                    rule_index,
                    entry_index,
                    json_field,
                )?);
            }

            rules.push(Rule::new(
                RuleId::new(json_rule.rule_id, json_rule.rule_id_length),
                fields,
            ));
        }

        Ok(Self {
            rules: RuleSet::new(rules, sid_registry),
        })
    }

    /// Returns the loaded rule set.
    #[must_use]
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }
}

fn load_field(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    json_field: JsonField,
) -> Result<FieldRule> {
    let field_sid = validate_field_identifier(
        sid_registry,
        rule_index,
        entry_index,
        "field",
        &json_field.field,
    )?;

    Ok(FieldRule {
        field: field_ref(&json_field.field, field_sid),
        length: FieldLength::FixedBits(json_field.length_bits),
        direction: direction_selector(
            sid_registry,
            rule_index,
            entry_index,
            &json_field.direction,
        )?,
        target: target_value(rule_index, entry_index, json_field.target)?,
        matching: matching_operator(sid_registry, rule_index, entry_index, &json_field.mo)?,
        action: cda(sid_registry, rule_index, entry_index, &json_field.cda)?,
        entry_index,
    })
}

fn direction_selector(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    value: &str,
) -> Result<DirectionSelector> {
    match value {
        "bi" => {
            validate_field_identifier(
                sid_registry,
                rule_index,
                entry_index,
                "direction",
                "di-bidirectional",
            )?;
            Ok(DirectionSelector::Bidirectional)
        }
        "up" => {
            validate_field_identifier(sid_registry, rule_index, entry_index, "direction", "di-up")?;
            Ok(DirectionSelector::Up)
        }
        "down" => {
            validate_field_identifier(
                sid_registry,
                rule_index,
                entry_index,
                "direction",
                "di-down",
            )?;
            Ok(DirectionSelector::Down)
        }
        _ => Err(invalid_field(
            rule_index,
            entry_index,
            format!("unknown direction {value}"),
        )),
    }
}

fn matching_operator(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    value: &str,
) -> Result<MatchingOperator> {
    match value {
        "equal" => {
            validate_field_identifier(sid_registry, rule_index, entry_index, "mo", "mo-equal")?;
            Ok(MatchingOperator::Equal)
        }
        "ignore" => {
            validate_field_identifier(sid_registry, rule_index, entry_index, "mo", "mo-ignore")?;
            Ok(MatchingOperator::Ignore)
        }
        "match-mapping" => {
            validate_field_identifier(
                sid_registry,
                rule_index,
                entry_index,
                "mo",
                "mo-match-mapping",
            )?;
            Ok(MatchingOperator::MatchMapping)
        }
        _ if value.starts_with("msb(") && value.ends_with(')') => {
            validate_field_identifier(sid_registry, rule_index, entry_index, "mo", "mo-msb")?;
            let bit_count = value[4..value.len() - 1].parse::<usize>().map_err(|_| {
                invalid_field(
                    rule_index,
                    entry_index,
                    format!("invalid msb argument in {value}"),
                )
            })?;
            Ok(MatchingOperator::Msb(bit_count))
        }
        _ => Err(invalid_field(
            rule_index,
            entry_index,
            format!("unknown matching operator {value}"),
        )),
    }
}

fn cda(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    value: &str,
) -> Result<Cda> {
    match value {
        "not-sent" => {
            validate_field_identifier(
                sid_registry,
                rule_index,
                entry_index,
                "cda",
                "cda-not-sent",
            )?;
            Ok(Cda::NotSent)
        }
        "value-sent" => {
            validate_field_identifier(
                sid_registry,
                rule_index,
                entry_index,
                "cda",
                "cda-value-sent",
            )?;
            Ok(Cda::ValueSent)
        }
        "mapping-sent" => {
            validate_field_identifier(
                sid_registry,
                rule_index,
                entry_index,
                "cda",
                "cda-mapping-sent",
            )?;
            Ok(Cda::MappingSent)
        }
        "lsb" => {
            validate_field_identifier(sid_registry, rule_index, entry_index, "cda", "cda-lsb")?;
            Ok(Cda::Lsb)
        }
        "compute" => {
            validate_field_identifier(sid_registry, rule_index, entry_index, "cda", "cda-compute")?;
            Ok(Cda::Compute)
        }
        _ => Err(invalid_field(
            rule_index,
            entry_index,
            format!("unknown cda {value}"),
        )),
    }
}

fn target_value(
    rule_index: usize,
    entry_index: usize,
    value: serde_json::Value,
) -> Result<TargetValue> {
    match value {
        serde_json::Value::Null => Ok(TargetValue::None),
        serde_json::Value::String(hex) => {
            decode_hex(rule_index, entry_index, &hex).map(TargetValue::Bytes)
        }
        serde_json::Value::Array(values) => {
            let mut mapping = Vec::with_capacity(values.len());
            for value in values {
                let serde_json::Value::String(hex) = value else {
                    return Err(invalid_field(
                        rule_index,
                        entry_index,
                        "target mapping entries must be hex strings".to_owned(),
                    ));
                };
                mapping.push(decode_hex(rule_index, entry_index, &hex)?);
            }
            Ok(TargetValue::Mapping(mapping))
        }
        _ => Err(invalid_field(
            rule_index,
            entry_index,
            "target must be null, a hex string, or an array of hex strings".to_owned(),
        )),
    }
}

fn decode_hex(rule_index: usize, entry_index: usize, value: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0 {
        return Err(invalid_field(
            rule_index,
            entry_index,
            format!("hex target {value} has an odd number of digits"),
        ));
    }

    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let high = hex_digit(value.as_bytes()[index]).ok_or_else(|| {
            invalid_field(
                rule_index,
                entry_index,
                format!("hex target {value} contains an invalid digit"),
            )
        })?;
        let low = hex_digit(value.as_bytes()[index + 1]).ok_or_else(|| {
            invalid_field(
                rule_index,
                entry_index,
                format!("hex target {value} contains an invalid digit"),
            )
        })?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn field_ref(identifier: &str, sid: u64) -> FieldRef {
    match identifier {
        "fid-ipv6-version" => FieldRef::Ipv6("fid-ipv6-version"),
        "fid-ipv6-trafficclass" => FieldRef::Ipv6("fid-ipv6-trafficclass"),
        "fid-ipv6-flowlabel" => FieldRef::Ipv6("fid-ipv6-flowlabel"),
        "fid-ipv6-payload-length" => FieldRef::Ipv6("fid-ipv6-payload-length"),
        "fid-ipv6-nextheader" => FieldRef::Ipv6("fid-ipv6-nextheader"),
        "fid-ipv6-hoplimit" => FieldRef::Ipv6("fid-ipv6-hoplimit"),
        "fid-ipv6-devprefix" => FieldRef::Ipv6("fid-ipv6-devprefix"),
        "fid-ipv6-deviid" => FieldRef::Ipv6("fid-ipv6-deviid"),
        "fid-ipv6-appprefix" => FieldRef::Ipv6("fid-ipv6-appprefix"),
        "fid-ipv6-appiid" => FieldRef::Ipv6("fid-ipv6-appiid"),
        "fid-udp-dev-port" => FieldRef::Udp("fid-udp-dev-port"),
        "fid-udp-app-port" => FieldRef::Udp("fid-udp-app-port"),
        "fid-udp-length" => FieldRef::Udp("fid-udp-length"),
        "fid-udp-checksum" => FieldRef::Udp("fid-udp-checksum"),
        "fid-coap-version" => FieldRef::Coap("fid-coap-version"),
        "fid-coap-type" => FieldRef::Coap("fid-coap-type"),
        "fid-coap-tkl" => FieldRef::Coap("fid-coap-tkl"),
        "fid-coap-code" => FieldRef::Coap("fid-coap-code"),
        "fid-coap-mid" => FieldRef::Coap("fid-coap-mid"),
        "fid-coap-token" => FieldRef::Coap("fid-coap-token"),
        "fid-icmpv6-type" => FieldRef::Icmpv6("fid-icmpv6-type"),
        "fid-icmpv6-code" => FieldRef::Icmpv6("fid-icmpv6-code"),
        "fid-icmpv6-checksum" => FieldRef::Icmpv6("fid-icmpv6-checksum"),
        "fid-icmpv6-payload" => FieldRef::Icmpv6("fid-icmpv6-payload"),
        _ => FieldRef::UnknownSid(sid),
    }
}

fn validate_field_identifier(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    kind: &str,
    identifier: &str,
) -> Result<u64> {
    sid_registry.sid(identifier).map_err(|_| {
        invalid_field(
            rule_index,
            entry_index,
            format!("{kind} identifier {identifier} is not present in SID registry"),
        )
    })
}

fn invalid_field(rule_index: usize, entry_index: usize, reason: String) -> SchcError {
    SchcError::InvalidRuleField {
        rule_index,
        entry_index,
        reason,
    }
}
