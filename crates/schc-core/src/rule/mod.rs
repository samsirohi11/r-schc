//! SCHC rule model.

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
    /// Application-side position.
    App,
}

/// Public rule context placeholder reserved for rule processing implementation.
#[derive(Debug)]
pub struct RuleContext {
    _private: (),
}

/// Public rule set placeholder reserved for rule loading implementation.
#[derive(Debug)]
pub struct RuleSet {
    _private: (),
}
