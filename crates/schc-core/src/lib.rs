#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Core SCHC rule loading, compression, and decompression.

pub mod bit;
pub mod compress;
pub mod decompress;
pub mod error;
pub mod packet;
pub mod rule;
pub mod sid;
pub mod tree;

pub use compress::{CompressedDatagram, Compressor};
pub use decompress::{DecompressedDatagram, Decompressor};
pub use error::{Result, SchcError};
pub use rule::{
    Cda, Direction, DirectionSelector, ExternalValueProvider, FieldLength, FieldRef,
    MatchingOperator, Position, Rule, RuleContext, RuleId, RuleNature, RuleSet, TargetValue,
};
pub use sid::SidRegistry;
