//! Typed SCHC rule model.

use crate::error::Result;
use crate::SidRegistry;
use std::fmt::Debug;

/// Supplies values for runtime-dependent SCHC CDAs.
///
/// The core never derives device or application identifiers from networking
/// state. A runtime may provide those values through this interface when a
/// rule uses `cda-deviid` or `cda-appiid`.
pub trait ExternalValueProvider: Debug + Send + Sync {
    /// Returns the value for an external CDA at the requested width.
    ///
    /// # Errors
    ///
    /// Returns an error when the runtime cannot supply the requested value.
    fn value(&self, field: &FieldRef, direction: Direction, bit_len: usize) -> Result<Vec<u8>>;
}

/// Packet flow direction for a SCHC rule field.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Direction {
    /// Uplink direction.
    Up,
    /// Downlink direction.
    Down,
}

/// Runtime layer position for a SCHC rule field.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Position {
    /// Device-side position.
    Device,
    /// Core-network position.
    Core,
}

/// Direction selector attached to a field rule entry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DirectionSelector {
    /// The entry applies to uplink and downlink packets.
    Bidirectional,
    /// The entry applies only to uplink packets.
    Up,
    /// The entry applies only to downlink packets.
    Down,
}

impl DirectionSelector {
    /// Returns true when this selector applies to `direction`.
    #[must_use]
    pub fn accepts(self, direction: Direction) -> bool {
        matches!(
            (self, direction),
            (Self::Bidirectional, _) | (Self::Up, Direction::Up) | (Self::Down, Direction::Down)
        )
    }
}

/// Rule identifier and its encoded bit length.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RuleId {
    value: u64,
    bit_len: usize,
}

impl RuleId {
    /// Creates a rule identifier with an explicit encoded bit length.
    #[must_use]
    pub fn new(value: u64, bit_len: usize) -> Self {
        Self { value, bit_len }
    }

    /// Returns the numeric rule identifier value.
    #[must_use]
    pub fn value(self) -> u64 {
        self.value
    }

    /// Returns the number of bits used to encode the rule identifier.
    #[must_use]
    pub fn bit_len(self) -> usize {
        self.bit_len
    }
}

/// SCHC field identifier resolved from a SID field identity.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum FieldRef {
    /// IPv6 field identity.
    Ipv6(&'static str),
    /// UDP field identity.
    Udp(&'static str),
    /// CoAP field identity.
    Coap(&'static str),
    /// `ICMPv6` field identity.
    Icmpv6(&'static str),
    /// CoAP option field identity by option number.
    CoapOption {
        /// Universal CoAP option number.
        number: u64,
    },
    /// Generic protocol padding or unused data.
    Unused,
    /// Generic remaining payload data.
    Payload,
    /// Synthetic marker used for CoAP option processing.
    SyntheticCoapMarker,
    /// SID that exists but is not mapped to a built-in field family.
    UnknownSid(u64),
}

/// Length unit for field lengths derived from earlier fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LengthUnit {
    /// Length is measured in bytes.
    Bytes,
    /// Length is measured in bits.
    Bits,
}

/// Encoded field length rule.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FieldLength {
    /// A fixed number of bits.
    FixedBits(usize),
    /// A variable number of bytes.
    VariableBytes,
    /// A variable number of bits.
    VariableBits,
    /// Length is taken from the CoAP token length field.
    TokenLength,
    /// Length is derived from a previous field entry.
    FromPreviousField {
        /// Previous entry index to read from.
        entry_index: usize,
        /// Unit used by the previous field value.
        unit: LengthUnit,
    },
    /// CORECONF field-length function identified by SID.
    FunctionSid(u64),
}

/// Target value attached to a field rule entry.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TargetValue {
    /// No target value.
    None,
    /// A single target byte string.
    Bytes(Vec<u8>),
    /// A mapping of target byte strings.
    Mapping(Vec<Vec<u8>>),
}

/// Matching operator used by a field rule entry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum MatchingOperator {
    /// Match when the field equals the target value.
    Equal,
    /// Ignore the field value during matching.
    Ignore,
    /// Match the most significant `usize` bits.
    Msb(usize),
    /// Match against a target-value mapping.
    MatchMapping,
}

/// Compression and decompression action for a field rule entry.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Cda {
    /// The field value is not sent.
    NotSent,
    /// The field value is sent directly.
    ValueSent,
    /// A mapping index is sent.
    MappingSent,
    /// Least significant bits are sent.
    Lsb,
    /// The value is computed by the receiver.
    Compute,
    /// The device IID is supplied by the runtime.
    DeviceIid,
    /// The application IID is supplied by the runtime.
    AppIid,
}

/// Nature of a SCHC rule.
///
/// Matches the `nature-*` identities from the SCHC data model. Existing rules
/// default to [`RuleNature::Compression`]. Fragmentation is explicitly
/// unsupported by the core. No-compression rules wrap and unwrap the original
/// packet bytes with the selected rule ID and no compressed residue
/// transformation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RuleNature {
    /// Compression rule.
    Compression,
    /// No-compression rule.
    NoCompression,
    /// Fragmentation rule.
    Fragmentation,
}

impl RuleNature {
    /// Returns the stable lowercase identifier used by the JSON loader.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compression => "compression",
            Self::NoCompression => "no-compression",
            Self::Fragmentation => "fragmentation",
        }
    }

    /// Parses a lowercase nature identifier.
    ///
    /// # Errors
    ///
    /// Returns `None` when `value` is not a recognized nature identifier.
    #[must_use]
    pub fn parse_identifier(value: &str) -> Option<Self> {
        match value {
            "compression" => Some(Self::Compression),
            "no-compression" => Some(Self::NoCompression),
            "fragmentation" => Some(Self::Fragmentation),
            _ => None,
        }
    }
}

/// One field rule entry inside a SCHC rule.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FieldRule {
    /// Field identity for this entry.
    pub field: FieldRef,
    /// Field length rule.
    pub length: FieldLength,
    /// Field position for repeated field identifiers.
    pub field_position: usize,
    /// Direction selector for this entry.
    pub direction: DirectionSelector,
    /// Target value used by the matching operator.
    pub target: TargetValue,
    /// Matching operator for this entry.
    pub matching: MatchingOperator,
    /// Compression and decompression action for this entry.
    pub action: Cda,
    /// Entry index within the parent rule.
    pub entry_index: usize,
}

/// A typed SCHC rule.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Rule {
    id: RuleId,
    fields: Vec<FieldRule>,
    nature: RuleNature,
}

impl Rule {
    /// Creates a compression rule from an identifier and ordered field entries.
    #[must_use]
    pub fn new(id: RuleId, fields: Vec<FieldRule>) -> Self {
        Self {
            id,
            fields,
            nature: RuleNature::Compression,
        }
    }

    /// Creates a rule with an explicit nature.
    #[must_use]
    pub fn new_with_nature(id: RuleId, fields: Vec<FieldRule>, nature: RuleNature) -> Self {
        Self { id, fields, nature }
    }

    /// Returns this rule's identifier.
    #[must_use]
    pub fn id(&self) -> RuleId {
        self.id
    }

    /// Returns this rule's ordered field entries.
    #[must_use]
    pub fn fields(&self) -> &[FieldRule] {
        &self.fields
    }

    /// Returns this rule's nature.
    #[must_use]
    pub const fn nature(&self) -> RuleNature {
        self.nature
    }
}

/// A loaded set of SCHC rules and the SID registry used to validate them.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleSet {
    rules: Vec<Rule>,
    sid_registry: SidRegistry,
}

impl RuleSet {
    /// Creates a rule set from rules and their SID registry.
    #[must_use]
    pub fn new(rules: Vec<Rule>, sid_registry: SidRegistry) -> Self {
        Self {
            rules,
            sid_registry,
        }
    }

    /// Returns the loaded rules in file order.
    #[must_use]
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Returns the SID registry used to validate this rule set.
    #[must_use]
    pub fn sid_registry(&self) -> &SidRegistry {
        &self.sid_registry
    }
}
