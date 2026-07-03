//! Error types for SCHC core operations.

use thiserror::Error;

/// Result alias used by the core crate.
pub type Result<T> = core::result::Result<T, SchcError>;

/// Structured error type for rule loading, packet parsing, and SCHC processing.
#[derive(Debug, Error)]
pub enum SchcError {
    /// A bit cursor attempted to read or seek outside the available data.
    #[error("bit cursor out of bounds: requested {requested} bits at position {position}, available {available}")]
    BitOutOfBounds {
        /// Current bit position.
        position: usize,
        /// Requested bit count.
        requested: usize,
        /// Available remaining bit count.
        available: usize,
    },

    /// A bit length was invalid for the requested operation.
    #[error("invalid bit length {bits} for {operation}")]
    InvalidBitLength {
        /// Operation name.
        operation: &'static str,
        /// Invalid bit count.
        bits: usize,
    },

    /// JSON parsing failed.
    #[error("json parse error: {0}")]
    Json(String),

    /// CBOR parsing failed.
    #[error("cbor parse error: {0}")]
    Cbor(String),

    /// A SID could not be resolved.
    #[error("unknown SID {sid}")]
    UnknownSid {
        /// Unknown SID value.
        sid: u64,
    },

    /// A required SID identifier is missing.
    #[error("missing SID identifier {identifier}")]
    MissingSidIdentifier {
        /// Missing identifier.
        identifier: String,
    },

    /// A rule is structurally invalid.
    #[error("invalid rule {rule_index}: {reason}")]
    InvalidRule {
        /// Rule index in load order.
        rule_index: usize,
        /// Human-readable reason.
        reason: String,
    },

    /// A rule field is structurally invalid.
    #[error("invalid rule field rule={rule_index} entry={entry_index}: {reason}")]
    InvalidRuleField {
        /// Rule index in load order.
        rule_index: usize,
        /// Entry index inside the rule.
        entry_index: usize,
        /// Human-readable reason.
        reason: String,
    },

    /// Packet parsing failed.
    #[error("packet parse error at {protocol}: {reason}")]
    Packet {
        /// Protocol being parsed.
        protocol: &'static str,
        /// Human-readable reason.
        reason: String,
    },

    /// No SCHC rule matched the input.
    #[error("no matching rule")]
    NoMatchingRule,

    /// A rule nature is not supported by the requested operation.
    #[error("unsupported rule nature: {nature}")]
    UnsupportedRuleNature {
        /// Human-readable nature identifier.
        nature: &'static str,
    },

    /// A residue or mapping value is invalid.
    #[error("invalid residue: {0}")]
    InvalidResidue(String),
}
