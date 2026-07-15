//! JSON and CBOR loading for typed SCHC rules.

use std::{collections::BTreeSet, io::Cursor, mem::size_of};

use ciborium::value::Value;
use serde::Deserialize;

use crate::error::{Result, SchcError};
use crate::rule::model::{
    Cda, DirectionSelector, FieldLength, FieldRef, FieldRule, LengthUnit, MatchingOperator, Rule,
    RuleId, RuleNature, RuleSet, TargetValue,
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
    #[serde(default)]
    nature: Option<String>,
    fields: Vec<JsonField>,
}

#[derive(Debug, Deserialize)]
struct JsonField {
    field: String,
    #[serde(default)]
    length_bits: Option<usize>,
    #[serde(default)]
    length: Option<JsonLength>,
    #[serde(default = "default_field_position")]
    field_position: usize,
    direction: String,
    target: serde_json::Value,
    mo: String,
    cda: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
enum JsonLength {
    Fixed {
        bits: usize,
    },
    TokenLength,
    FromPrevious {
        entry_index: usize,
        unit: JsonLengthUnit,
    },
    Variable {
        unit: JsonLengthUnit,
    },
    FunctionSid {
        sid: u64,
    },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum JsonLengthUnit {
    Bytes,
    Bits,
}

fn default_field_position() -> usize {
    1
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

            let nature = parse_nature(rule_index, json_rule.nature.as_deref())?;
            rules.push(Rule::new_with_nature(
                RuleId::new(json_rule.rule_id, json_rule.rule_id_length),
                fields,
                nature,
            ));
        }
        validate_rule_id_prefixes(&rules)?;

        Ok(Self {
            rules: RuleSet::new(rules, sid_registry),
        })
    }

    /// Loads a typed rule context from a CORECONF CBOR rule document.
    ///
    /// # Errors
    ///
    /// Returns [`SchcError::Cbor`] when `data` is not valid CBOR.
    /// Returns [`SchcError::InvalidRule`] or [`SchcError::InvalidRuleField`] when
    /// the decoded rule structure is invalid or references missing SID values.
    pub fn from_cbor_slice(data: &[u8], sid_registry: SidRegistry) -> Result<Self> {
        let root: Value = ciborium::de::from_reader(Cursor::new(data))
            .map_err(|error| SchcError::Cbor(error.to_string()))?;
        let envelope = required_map_value(&root, 2574)
            .map_err(|reason| SchcError::Cbor(format!("missing CORECONF root 2574: {reason}")))?;
        let rule_values = required_array(envelope, 23)
            .map_err(|reason| SchcError::Cbor(format!("invalid rule list key 23: {reason}")))?;
        let mut rules = Vec::with_capacity(rule_values.len());

        for (rule_index, rule_value) in rule_values.iter().enumerate() {
            let rule_id_length =
                required_usize(rule_value, 1).map_err(|reason| SchcError::InvalidRule {
                    rule_index,
                    reason: format!("invalid rule ID length key 1: {reason}"),
                })?;
            let rule_id = required_u64(rule_value, 2).map_err(|reason| SchcError::InvalidRule {
                rule_index,
                reason: format!("invalid rule ID value key 2: {reason}"),
            })?;
            validate_rule_id(rule_index, rule_id, rule_id_length)?;
            let nature = cbor_rule_nature(&sid_registry, rule_index, rule_value)?;

            let entry_values = match map_value(rule_value, 23) {
                Some(Value::Array(values)) => values.as_slice(),
                Some(_) => {
                    return Err(SchcError::InvalidRule {
                        rule_index,
                        reason: "invalid entry list key 23: value is not an array".to_owned(),
                    });
                }
                None if matches!(
                    nature,
                    RuleNature::NoCompression | RuleNature::Fragmentation
                ) =>
                {
                    &[]
                }
                None => {
                    return Err(SchcError::InvalidRule {
                        rule_index,
                        reason: "missing required entry list key 23 for compression rule"
                            .to_owned(),
                    });
                }
            };
            let mut fields = Vec::with_capacity(entry_values.len());
            for (entry_order, entry_value) in entry_values.iter().enumerate() {
                fields.push(load_cbor_field(
                    &sid_registry,
                    rule_index,
                    entry_order,
                    entry_value,
                )?);
            }
            normalize_cbor_fields(rule_index, &mut fields)?;

            rules.push(Rule::new_with_nature(
                RuleId::new(rule_id, rule_id_length),
                fields,
                nature,
            ));
        }
        validate_rule_id_prefixes(&rules)?;

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

/// Rejects rule sets where one rule ID is a bit-prefix of another, including
/// exact duplicates.
///
/// A compressed SCHC packet begins with a variable-length rule ID. If one ID
/// is a bit-prefix of another, decompression can select the wrong rule depending
/// on insertion order. The first detected collision is reported with both rule
/// ID values and bit lengths. The shorter ID is reported as `first`; for equal
/// lengths (exact duplicates) the earlier rule in load order is `first`.
fn validate_rule_id_prefixes(rules: &[Rule]) -> Result<()> {
    for (later_index, later) in rules.iter().enumerate() {
        for earlier in &rules[..later_index] {
            let earlier_id = earlier.id();
            let later_id = later.id();
            if let Some((first, second)) = rule_id_collision(earlier_id, later_id) {
                return Err(SchcError::AmbiguousRuleIdPrefix {
                    first_value: first.value(),
                    first_bits: first.bit_len(),
                    second_value: second.value(),
                    second_bits: second.bit_len(),
                });
            }
        }
    }
    Ok(())
}

/// Returns the colliding rule ID pair ordered as `(prefix, container)` when the
/// two IDs collide, or `None` when they are independent.
///
/// Equal-length IDs collide only when their values match (exact duplicates).
/// For differing lengths, the shorter ID collides when its value equals the top
/// `shorter.bit_len()` bits of the longer ID. The returned pair is ordered so
/// the shorter (prefix) ID is first; for exact duplicates the `earlier` argument
/// is first to keep reporting stable.
fn rule_id_collision(earlier: RuleId, later: RuleId) -> Option<(RuleId, RuleId)> {
    match earlier.bit_len().cmp(&later.bit_len()) {
        core::cmp::Ordering::Equal => {
            (earlier.value() == later.value()).then_some((earlier, later))
        }
        core::cmp::Ordering::Less => {
            let prefix = later.value() >> (later.bit_len() - earlier.bit_len());
            (prefix == earlier.value()).then_some((earlier, later))
        }
        core::cmp::Ordering::Greater => {
            let prefix = earlier.value() >> (earlier.bit_len() - later.bit_len());
            (prefix == later.value()).then_some((later, earlier))
        }
    }
}

fn validate_rule_id(rule_index: usize, rule_id: u64, rule_id_length: usize) -> Result<()> {
    if rule_id_length == 0 || rule_id_length > 64 {
        return Err(SchcError::InvalidRule {
            rule_index,
            reason: format!("rule_id_length {rule_id_length} is invalid"),
        });
    }
    if rule_id_length < 64 && rule_id >= (1_u64 << rule_id_length) {
        return Err(SchcError::InvalidRule {
            rule_index,
            reason: format!("rule_id {rule_id} does not fit in {rule_id_length} bits"),
        });
    }
    Ok(())
}

/// Parses an optional JSON nature identifier, defaulting to compression.
fn parse_nature(rule_index: usize, nature: Option<&str>) -> Result<RuleNature> {
    match nature {
        None => Ok(RuleNature::Compression),
        Some(value) => RuleNature::parse_identifier(value).ok_or_else(|| SchcError::InvalidRule {
            rule_index,
            reason: format!("unknown rule nature {value}"),
        }),
    }
}

/// Resolves the CBOR rule nature (key 3), defaulting to compression when absent.
///
/// A nature value of `0` is treated as the default (compression).
fn cbor_rule_nature(
    sid_registry: &SidRegistry,
    rule_index: usize,
    rule_value: &Value,
) -> Result<RuleNature> {
    let Some(nature_value) = map_value(rule_value, 3) else {
        return Ok(RuleNature::Compression);
    };
    let sid = value_to_u64(nature_value).map_err(|reason| SchcError::InvalidRule {
        rule_index,
        reason: format!("invalid rule nature key 3: {reason}"),
    })?;
    if sid == 0 {
        return Ok(RuleNature::Compression);
    }
    let identifier = sid_identifier(sid_registry, rule_index, 0, "nature", sid)?;
    match identifier.as_str() {
        "nature-compression" => Ok(RuleNature::Compression),
        "nature-no-compression" => Ok(RuleNature::NoCompression),
        "nature-fragmentation" => Ok(RuleNature::Fragmentation),
        other => Err(SchcError::InvalidRule {
            rule_index,
            reason: format!("unsupported rule nature SID {sid} identifier {other}"),
        }),
    }
}

/// Returns true when `field` is a field identity the core can compute.
fn is_compute_supported(field: &FieldRef) -> bool {
    matches!(
        field,
        FieldRef::Ipv6("fid-ipv6-payload-length")
            | FieldRef::Udp("fid-udp-length" | "fid-udp-checksum")
            | FieldRef::Icmpv6("fid-icmpv6-checksum")
    )
}

/// Validates that a field rule's CDA and matching operator are consistent.
///
/// - `mapping-sent` requires a `TargetValue::Mapping` target.
/// - `lsb` requires an `Msb(_)` matching operator.
/// - `compute` is only allowed for field identities the core can compute
///   (length or transport checksum fields).
/// - the CoAP payload marker sentinel must use `not-sent` with `ignore`.
fn validate_field_rule(rule_index: usize, field: &FieldRule) -> Result<()> {
    let is_marker = matches!(field.field, FieldRef::SyntheticCoapMarker);
    if matches!(
        field.matching,
        MatchingOperator::Equal | MatchingOperator::Msb(_)
    ) && !matches!(field.target, TargetValue::Bytes(_))
    {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "equal and msb matching require a byte target".to_owned(),
        ));
    }
    if field.matching == MatchingOperator::MatchMapping
        && !matches!(field.target, TargetValue::Mapping(ref values) if !values.is_empty())
    {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "match-mapping requires a non-empty mapping target".to_owned(),
        ));
    }
    if field.action == Cda::MappingSent
        && !matches!(field.target, TargetValue::Mapping(ref values) if !values.is_empty())
    {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "mapping-sent requires a non-empty mapping target".to_owned(),
        ));
    }
    if matches!(field.action, Cda::NotSent | Cda::Lsb)
        && !is_marker
        && !matches!(field.target, TargetValue::Bytes(_))
    {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "not-sent and lsb require a byte target".to_owned(),
        ));
    }
    if field.action == Cda::Lsb && !matches!(field.matching, MatchingOperator::Msb(_)) {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "lsb requires an msb matching operator".to_owned(),
        ));
    }
    if field.action == Cda::Compute && !is_compute_supported(&field.field) {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            format!(
                "compute is not supported for field {:?}; only length and checksum fields can be computed",
                field.field
            ),
        ));
    }
    if field.action == Cda::AppIid && !matches!(field.field, FieldRef::Ipv6("fid-ipv6-appiid")) {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "cda-appiid is only valid for fid-ipv6-appiid".to_owned(),
        ));
    }
    if field.action == Cda::DeviceIid && !matches!(field.field, FieldRef::Ipv6("fid-ipv6-deviid")) {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "cda-deviid is only valid for fid-ipv6-deviid".to_owned(),
        ));
    }
    if matches!(field.field, FieldRef::SyntheticCoapMarker)
        && (field.action != Cda::NotSent || field.matching != MatchingOperator::Ignore)
    {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "CoAP payload marker must use not-sent with ignore".to_owned(),
        ));
    }
    if !payload_length_is_supported(field) {
        return Err(invalid_field(
            rule_index,
            field.entry_index,
            "fid-payload length must be expressed in whole bytes".to_owned(),
        ));
    }
    Ok(())
}

fn payload_length_is_supported(field: &FieldRule) -> bool {
    !matches!(field.field, FieldRef::Payload)
        || matches!(&field.length, FieldLength::FixedBits(bits) if *bits % 8 == 0)
        || matches!(&field.length, FieldLength::VariableBytes)
        || (field.action == Cda::Lsb && matches!(&field.length, FieldLength::VariableBits))
        || matches!(
            &field.length,
            FieldLength::FromPreviousField {
                unit: LengthUnit::Bytes,
                ..
            }
        )
}

fn load_field(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    json_field: JsonField,
) -> Result<FieldRule> {
    let field = if let Some(number) = parse_coap_option_field(&json_field.field) {
        FieldRef::CoapOption { number }
    } else {
        let field_sid = validate_field_identifier(
            sid_registry,
            rule_index,
            entry_index,
            "field",
            &json_field.field,
        )?;
        resolve_supported_field_ref(
            rule_index,
            entry_index,
            &json_field.field,
            field_sid,
            field_ref(&json_field.field, field_sid),
        )?
    };

    let rule = FieldRule {
        field,
        length: json_field_length(rule_index, entry_index, &json_field)?,
        field_position: json_field.field_position,
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
    };
    validate_field_rule(rule_index, &rule)?;
    Ok(rule)
}

/// Parses a `coap-option(<number>)` JSON field identifier.
///
/// Returns the option number when `value` matches the universal option-by-number
/// form, which does not require a per-option SID registry entry.
fn parse_coap_option_field(value: &str) -> Option<u64> {
    let inner = value.strip_prefix("coap-option(")?.strip_suffix(')')?;
    let number = inner.parse::<u64>().ok()?;
    Some(number)
}

fn json_field_length(
    rule_index: usize,
    entry_index: usize,
    field: &JsonField,
) -> Result<FieldLength> {
    match (&field.length, field.length_bits) {
        (Some(JsonLength::Fixed { bits }), None) => Ok(FieldLength::FixedBits(*bits)),
        (Some(JsonLength::TokenLength), None) => Ok(FieldLength::TokenLength),
        (Some(JsonLength::FromPrevious { entry_index, unit }), None) => {
            Ok(FieldLength::FromPreviousField {
                entry_index: *entry_index,
                unit: json_length_unit(unit),
            })
        }
        (
            Some(JsonLength::Variable {
                unit: JsonLengthUnit::Bytes,
            }),
            None,
        ) => Ok(FieldLength::VariableBytes),
        (
            Some(JsonLength::Variable {
                unit: JsonLengthUnit::Bits,
            }),
            None,
        ) => Ok(FieldLength::VariableBits),
        (Some(JsonLength::FunctionSid { sid }), None) => Ok(FieldLength::FunctionSid(*sid)),
        (None, Some(bits)) => Ok(FieldLength::FixedBits(bits)),
        (Some(_), Some(_)) => Err(invalid_field(
            rule_index,
            entry_index,
            "field must use either length or length_bits, not both".to_owned(),
        )),
        (None, None) => Err(invalid_field(
            rule_index,
            entry_index,
            "field length is missing".to_owned(),
        )),
    }
}

fn json_length_unit(unit: &JsonLengthUnit) -> LengthUnit {
    match unit {
        JsonLengthUnit::Bytes => LengthUnit::Bytes,
        JsonLengthUnit::Bits => LengthUnit::Bits,
    }
}

fn load_cbor_field(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_order: usize,
    value: &Value,
) -> Result<FieldRule> {
    let has_field_id = map_value(value, 2).is_some();
    let has_space_id = map_value(value, 3).is_some();
    let has_universal_value = map_value(value, 4).is_some();

    match (has_field_id, has_space_id, has_universal_value) {
        (true, false, false) => {
            load_cbor_normal_field(sid_registry, rule_index, entry_order, value)
        }
        (false, true, true) => {
            load_cbor_universal_option_field(sid_registry, rule_index, entry_order, value)
        }
        _ => Err(invalid_field(
            rule_index,
            entry_order,
            "entry must contain either field-id key 2 or both space-id key 3 and universal-value key 4"
                .to_owned(),
        )),
    }
}

fn normalize_cbor_fields(rule_index: usize, fields: &mut [FieldRule]) -> Result<()> {
    let mut indexes = BTreeSet::new();
    for field in fields.iter() {
        if !indexes.insert(field.entry_index) {
            return Err(invalid_field(
                rule_index,
                field.entry_index,
                format!("duplicate field entry index {}", field.entry_index),
            ));
        }
    }
    fields.sort_by_key(|field| field.entry_index);
    Ok(())
}

fn load_cbor_normal_field(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_order: usize,
    value: &Value,
) -> Result<FieldRule> {
    load_cbor_coreconf_field(sid_registry, rule_index, entry_order, value)
}

/// Parses a CORECONF compression field entry using the IETF SCHC CORECONF CBOR key map.
///
/// Key map: 1 = entry-index, 2 = field-id, 5 = field-length,
/// 6 = field-length-value, 7 = direction-indicator, 8 = field-position,
/// 9 = target-value, 12 = matching-operator, 13 = matching-operator-value,
/// 16 = comp-decomp-action.
fn load_cbor_coreconf_field(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_order: usize,
    value: &Value,
) -> Result<FieldRule> {
    let entry_index = required_field_usize(value, 1, rule_index, entry_order)?;
    let field_sid = required_field_u64(value, 2, rule_index, entry_order)?;
    let field_identifier =
        sid_identifier(sid_registry, rule_index, entry_order, "field", field_sid)?;
    let field = resolve_supported_field_ref(
        rule_index,
        entry_order,
        &field_identifier,
        field_sid,
        field_ref(&field_identifier, field_sid),
    )?;
    let length = cbor_field_length(
        sid_registry,
        value,
        5,
        map_value(value, 6),
        rule_index,
        entry_order,
    )?;
    let direction = cbor_direction_selector(
        sid_registry,
        rule_index,
        entry_order,
        required_field_u64(value, 7, rule_index, entry_order)?,
    )?;
    let field_position = required_field_usize(value, 8, rule_index, entry_order)?;
    let matching = cbor_matching_operator(
        sid_registry,
        rule_index,
        entry_order,
        required_field_u64(value, 12, rule_index, entry_order)?,
        map_value(value, 13),
    )?;
    let action = cbor_cda(
        sid_registry,
        rule_index,
        entry_order,
        required_field_u64(value, 16, rule_index, entry_order)?,
    )?;
    let target = cbor_target_value(
        map_value(value, 9),
        matching,
        action,
        rule_index,
        entry_order,
    )?;

    let rule = FieldRule {
        field,
        length,
        field_position,
        direction,
        target,
        matching,
        action,
        entry_index,
    };
    validate_field_rule(rule_index, &rule)?;
    Ok(rule)
}

fn load_cbor_universal_option_field(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_order: usize,
    value: &Value,
) -> Result<FieldRule> {
    let entry_index = required_field_usize(value, 1, rule_index, entry_order)?;
    let space_sid = required_field_u64(value, 3, rule_index, entry_order)?;
    let space_identifier = sid_identifier(
        sid_registry,
        rule_index,
        entry_order,
        "universal field space",
        space_sid,
    )?;
    if space_identifier != "space-id-coap" {
        return Err(invalid_field(
            rule_index,
            entry_order,
            format!(
                "unsupported universal field space SID {space_sid} identifier {space_identifier}"
            ),
        ));
    }
    let option_number = required_field_u64(value, 4, rule_index, entry_order)?;
    let length = cbor_field_length(
        sid_registry,
        value,
        5,
        map_value(value, 6),
        rule_index,
        entry_order,
    )?;
    let direction = cbor_direction_selector(
        sid_registry,
        rule_index,
        entry_order,
        required_field_u64(value, 7, rule_index, entry_order)?,
    )?;
    let field_position = required_field_usize(value, 8, rule_index, entry_order)?;
    let matching = cbor_matching_operator(
        sid_registry,
        rule_index,
        entry_order,
        required_field_u64(value, 12, rule_index, entry_order)?,
        map_value(value, 13),
    )?;
    let action = cbor_cda(
        sid_registry,
        rule_index,
        entry_order,
        required_field_u64(value, 16, rule_index, entry_order)?,
    )?;
    let target = cbor_target_value(
        map_value(value, 9),
        matching,
        action,
        rule_index,
        entry_order,
    )?;

    let rule = FieldRule {
        field: FieldRef::CoapOption {
            number: option_number,
        },
        length,
        field_position,
        direction,
        target,
        matching,
        action,
        entry_index,
    };
    validate_field_rule(rule_index, &rule)?;
    Ok(rule)
}

fn cbor_field_length(
    sid_registry: &SidRegistry,
    value: &Value,
    key: i128,
    function_value: Option<&Value>,
    rule_index: usize,
    entry_index: usize,
) -> Result<FieldLength> {
    let value = required_field_value(value, key, rule_index, entry_index)?;
    match value {
        Value::Integer(integer) => {
            let bits = usize::try_from(*integer).map_err(|_| {
                invalid_field(
                    rule_index,
                    entry_index,
                    format!("field length key {key} is not a valid usize"),
                )
            })?;
            Ok(FieldLength::FixedBits(bits))
        }
        Value::Tag(45, boxed) => {
            let sid = value_to_u64(boxed).map_err(|reason| {
                invalid_field(
                    rule_index,
                    entry_index,
                    format!("unsupported field-length function tag 45: {reason}"),
                )
            })?;
            field_length_function(sid_registry, rule_index, entry_index, sid, function_value)
        }
        _ => Err(invalid_field(
            rule_index,
            entry_index,
            format!("field length key {key} must be an integer"),
        )),
    }
}

fn field_length_function(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    sid: u64,
    value: Option<&Value>,
) -> Result<FieldLength> {
    let Ok(identifier) = sid_registry.identifier(sid) else {
        return Ok(FieldLength::FunctionSid(sid));
    };
    match identifier {
        "fl-token-length" => Ok(FieldLength::TokenLength),
        "fl-variable" => Ok(FieldLength::VariableBytes),
        "fl-variable-bits" => Ok(FieldLength::VariableBits),
        "fl-length-bytes" => Ok(FieldLength::FromPreviousField {
            entry_index: field_length_parameter(value, rule_index, entry_index)?,
            unit: LengthUnit::Bytes,
        }),
        "fl-length-bits" => Ok(FieldLength::FromPreviousField {
            entry_index: field_length_parameter(value, rule_index, entry_index)?,
            unit: LengthUnit::Bits,
        }),
        _ => Ok(FieldLength::FunctionSid(sid)),
    }
}

fn field_length_parameter(
    value: Option<&Value>,
    rule_index: usize,
    entry_index: usize,
) -> Result<usize> {
    let value = value.ok_or_else(|| {
        invalid_field(
            rule_index,
            entry_index,
            "field-length function requires field-length-value".to_owned(),
        )
    })?;
    match value {
        Value::Integer(_) => value_to_usize(value).map_err(|reason| {
            invalid_field(
                rule_index,
                entry_index,
                format!("field-length-value must be a usize integer: {reason}"),
            )
        }),
        Value::Bytes(bytes) => bytes_to_usize(bytes).ok_or_else(|| {
            invalid_field(
                rule_index,
                entry_index,
                "field-length-value bytes do not fit usize".to_owned(),
            )
        }),
        _ => Err(invalid_field(
            rule_index,
            entry_index,
            "field-length-value must be an integer or byte string".to_owned(),
        )),
    }
}

fn cbor_direction_selector(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    sid: u64,
) -> Result<DirectionSelector> {
    match sid_identifier(sid_registry, rule_index, entry_index, "direction", sid)?.as_str() {
        "di-bidirectional" => Ok(DirectionSelector::Bidirectional),
        "di-up" => Ok(DirectionSelector::Up),
        "di-down" => Ok(DirectionSelector::Down),
        identifier => Err(invalid_field(
            rule_index,
            entry_index,
            format!("unknown direction SID {sid} identifier {identifier}"),
        )),
    }
}

fn cbor_matching_operator(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    sid: u64,
    value_list: Option<&Value>,
) -> Result<MatchingOperator> {
    match sid_identifier(sid_registry, rule_index, entry_index, "mo", sid)?.as_str() {
        "mo-equal" => Ok(MatchingOperator::Equal),
        "mo-ignore" => Ok(MatchingOperator::Ignore),
        "mo-match-mapping" => Ok(MatchingOperator::MatchMapping),
        "mo-msb" => {
            let Some(value_list) = value_list else {
                return Err(invalid_field(
                    rule_index,
                    entry_index,
                    "mo-msb requires a matching-operator value list".to_owned(),
                ));
            };
            let bits = cbor_target_entries(value_list, rule_index, entry_index)?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    invalid_field(
                        rule_index,
                        entry_index,
                        "mo-msb matching-operator value list is empty".to_owned(),
                    )
                })?;
            let bytes = value_to_bytes(bits.1, rule_index, entry_index)?;
            Ok(MatchingOperator::Msb(bytes_to_usize(&bytes).ok_or_else(
                || {
                    invalid_field(
                        rule_index,
                        entry_index,
                        "mo-msb value does not fit usize".to_owned(),
                    )
                },
            )?))
        }
        identifier => Err(invalid_field(
            rule_index,
            entry_index,
            format!("unsupported matching operator SID {sid} identifier {identifier}"),
        )),
    }
}

fn cbor_cda(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    sid: u64,
) -> Result<Cda> {
    match sid_identifier(sid_registry, rule_index, entry_index, "cda", sid)?.as_str() {
        "cda-not-sent" => Ok(Cda::NotSent),
        "cda-value-sent" => Ok(Cda::ValueSent),
        "cda-mapping-sent" => Ok(Cda::MappingSent),
        "cda-lsb" => Ok(Cda::Lsb),
        "cda-compute" => Ok(Cda::Compute),
        "cda-deviid" => Ok(Cda::DeviceIid),
        "cda-appiid" => Ok(Cda::AppIid),
        identifier => Err(invalid_field(
            rule_index,
            entry_index,
            format!("unsupported CDA SID {sid} identifier {identifier}"),
        )),
    }
}

fn cbor_target_value(
    value: Option<&Value>,
    matching: MatchingOperator,
    action: Cda,
    rule_index: usize,
    entry_index: usize,
) -> Result<TargetValue> {
    let Some(value) = value else {
        return Ok(TargetValue::None);
    };
    if matches!(value, Value::Null) {
        return Ok(TargetValue::None);
    }

    let entries = cbor_target_entries(value, rule_index, entry_index)?;
    let mut values = Vec::with_capacity(entries.len());
    for (_, value) in entries {
        values.push(value_to_bytes(value, rule_index, entry_index)?);
    }

    if values.is_empty() {
        return Ok(TargetValue::None);
    }
    if matches!(matching, MatchingOperator::MatchMapping) || action == Cda::MappingSent {
        return Ok(TargetValue::Mapping(values));
    }
    if values.len() == 1 {
        Ok(TargetValue::Bytes(values.remove(0)))
    } else {
        Ok(TargetValue::Mapping(values))
    }
}

fn cbor_target_entries(
    value: &Value,
    rule_index: usize,
    entry_index: usize,
) -> Result<Vec<(usize, &Value)>> {
    let Value::Array(entries) = value else {
        return Err(invalid_field(
            rule_index,
            entry_index,
            "target-value list must be an array".to_owned(),
        ));
    };
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let index = required_field_usize(entry, 1, rule_index, entry_index)?;
        if parsed.iter().any(|(previous, _)| *previous == index) {
            return Err(invalid_field(
                rule_index,
                entry_index,
                format!("duplicate target index {index}"),
            ));
        }
        let value = required_field_value(entry, 2, rule_index, entry_index)?;
        parsed.push((index, value));
    }
    parsed.sort_by_key(|(index, _)| *index);
    for (expected, (actual, _)) in parsed.iter().enumerate() {
        if *actual != expected {
            return Err(invalid_field(
                rule_index,
                entry_index,
                format!(
                    "value-list indexes must be consecutive from 0; expected {expected}, found {actual}"
                ),
            ));
        }
    }
    Ok(parsed)
}

fn value_to_bytes(value: &Value, rule_index: usize, entry_index: usize) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(bytes) => Ok(bytes.clone()),
        Value::Integer(integer) => integer_to_minimal_bytes(*integer).ok_or_else(|| {
            invalid_field(
                rule_index,
                entry_index,
                "negative target integers are not supported".to_owned(),
            )
        }),
        _ => Err(invalid_field(
            rule_index,
            entry_index,
            "target values must be byte strings or integers".to_owned(),
        )),
    }
}

fn integer_to_minimal_bytes(integer: ciborium::value::Integer) -> Option<Vec<u8>> {
    let value = u64::try_from(integer).ok()?;
    if value == 0 {
        return Some(vec![0]);
    }
    let bytes = value.to_be_bytes();
    let first_nonzero = bytes.iter().position(|byte| *byte != 0)?;
    Some(bytes[first_nonzero..].to_vec())
}

fn bytes_to_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.len() > size_of::<usize>() {
        return None;
    }
    let mut value = 0usize;
    for byte in bytes {
        value = (value << 8) | usize::from(*byte);
    }
    Some(value)
}

fn sid_identifier(
    sid_registry: &SidRegistry,
    rule_index: usize,
    entry_index: usize,
    kind: &str,
    sid: u64,
) -> Result<String> {
    sid_registry
        .identifier(sid)
        .map(str::to_owned)
        .map_err(|_| invalid_field(rule_index, entry_index, format!("unknown {kind} SID {sid}")))
}

fn required_field_value(
    value: &Value,
    key: i128,
    rule_index: usize,
    entry_index: usize,
) -> Result<&Value> {
    required_map_value(value, key).map_err(|reason| {
        invalid_field(
            rule_index,
            entry_index,
            format!("missing or invalid key {key}: {reason}"),
        )
    })
}

fn required_field_usize(
    value: &Value,
    key: i128,
    rule_index: usize,
    entry_index: usize,
) -> Result<usize> {
    value_to_usize(required_field_value(value, key, rule_index, entry_index)?).map_err(|reason| {
        invalid_field(
            rule_index,
            entry_index,
            format!("key {key} must be a usize integer: {reason}"),
        )
    })
}

fn required_field_u64(
    value: &Value,
    key: i128,
    rule_index: usize,
    entry_index: usize,
) -> Result<u64> {
    value_to_u64(required_field_value(value, key, rule_index, entry_index)?).map_err(|reason| {
        invalid_field(
            rule_index,
            entry_index,
            format!("key {key} must be a u64 integer: {reason}"),
        )
    })
}

fn required_array(value: &Value, key: i128) -> core::result::Result<&[Value], String> {
    let value = required_map_value(value, key)?;
    let Value::Array(values) = value else {
        return Err("value is not an array".to_owned());
    };
    Ok(values)
}

fn required_usize(value: &Value, key: i128) -> core::result::Result<usize, String> {
    value_to_usize(required_map_value(value, key)?)
}

fn required_u64(value: &Value, key: i128) -> core::result::Result<u64, String> {
    value_to_u64(required_map_value(value, key)?)
}

fn required_map_value(value: &Value, key: i128) -> core::result::Result<&Value, String> {
    map_value(value, key).ok_or_else(|| format!("missing map key {key}"))
}

fn map_value(value: &Value, key: i128) -> Option<&Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(candidate, value)| (integer_key(candidate) == Some(key)).then_some(value))
}

fn integer_key(value: &Value) -> Option<i128> {
    let Value::Integer(integer) = value else {
        return None;
    };
    Some(i128::from(*integer))
}

fn value_to_usize(value: &Value) -> core::result::Result<usize, String> {
    let Value::Integer(integer) = value else {
        return Err("value is not an integer".to_owned());
    };
    usize::try_from(*integer).map_err(|error| error.to_string())
}

fn value_to_u64(value: &Value) -> core::result::Result<u64, String> {
    let Value::Integer(integer) = value else {
        return Err("value is not an integer".to_owned());
    };
    u64::try_from(*integer).map_err(|error| error.to_string())
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
        "deviid" => {
            validate_field_identifier(sid_registry, rule_index, entry_index, "cda", "cda-deviid")?;
            Ok(Cda::DeviceIid)
        }
        "appiid" => {
            validate_field_identifier(sid_registry, rule_index, entry_index, "cda", "cda-appiid")?;
            Ok(Cda::AppIid)
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
        "fid-udp-payload" => FieldRef::Udp("fid-udp-payload"),
        "fid-coap-version" => FieldRef::Coap("fid-coap-version"),
        "fid-coap-type" => FieldRef::Coap("fid-coap-type"),
        "fid-coap-tkl" => FieldRef::Coap("fid-coap-tkl"),
        "fid-coap-code" => FieldRef::Coap("fid-coap-code"),
        "fid-coap-mid" => FieldRef::Coap("fid-coap-mid"),
        "fid-coap-token" => FieldRef::Coap("fid-coap-token"),
        "fid-coap-payload" => FieldRef::Coap("fid-coap-payload"),
        "fid-coap-payload-marker" => FieldRef::SyntheticCoapMarker,
        "fid-coap-option-uri-host" => FieldRef::CoapOption { number: 3 },
        "fid-coap-option-uri-path" => FieldRef::CoapOption { number: 11 },
        "fid-icmpv6-type" => FieldRef::Icmpv6("fid-icmpv6-type"),
        "fid-icmpv6-code" => FieldRef::Icmpv6("fid-icmpv6-code"),
        "fid-icmpv6-checksum" => FieldRef::Icmpv6("fid-icmpv6-checksum"),
        "fid-icmpv6-identifier" => FieldRef::Icmpv6("fid-icmpv6-identifier"),
        "fid-icmpv6-sequence" => FieldRef::Icmpv6("fid-icmpv6-sequence"),
        "fid-icmpv6-mtu" => FieldRef::Icmpv6("fid-icmpv6-mtu"),
        "fid-icmpv6-pointer" => FieldRef::Icmpv6("fid-icmpv6-pointer"),
        "fid-icmpv6-payload" => FieldRef::Icmpv6("fid-icmpv6-payload"),
        "fid-unused" => FieldRef::Unused,
        "fid-payload" => FieldRef::Payload,
        _ => FieldRef::UnknownSid(sid),
    }
}

/// Returns a loadable field reference, or an explicit error when `resolved` is
/// [`FieldRef::UnknownSid`].
///
/// A SID that the registry knows but the compression core does not map to a
/// built-in field family must not be silently accepted in a rule: the SID is
/// loadable as a name in the registry, but using it in a rule entry is
/// unsupported and must be reported with the field identifier, the SID, and
/// the rule/entry context so callers can diagnose the gap.
fn resolve_supported_field_ref(
    rule_index: usize,
    entry_index: usize,
    identifier: &str,
    field_sid: u64,
    resolved: FieldRef,
) -> Result<FieldRef> {
    if matches!(resolved, FieldRef::UnknownSid(_)) {
        return Err(invalid_field(
            rule_index,
            entry_index,
            format!(
                "unsupported field identifier {identifier} (SID {field_sid}) is not mapped to a \
                 compression-core field family"
            ),
        ));
    }
    Ok(resolved)
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
