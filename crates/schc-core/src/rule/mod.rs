//! SCHC rule model and loading support.

mod load;
mod model;

pub use load::RuleContext;
pub use model::{
    Cda, Direction, DirectionSelector, ExternalValueProvider, FieldLength, FieldRef, FieldRule,
    LengthUnit, MatchingOperator, Position, Rule, RuleId, RuleNature, RuleSet, TargetValue,
};
