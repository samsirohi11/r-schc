use crate::{Cda, DirectionSelector, FieldLength, FieldRef, MatchingOperator, RuleId, TargetValue};

/// Packet parsing step required before evaluating a branch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParseStep {
    /// Field identity to parse.
    pub field: FieldRef,
    /// Field length rule.
    pub length: FieldLength,
    /// Entry index inside the source rule.
    pub entry_index: usize,
}

/// Decision branch from one node to the next node.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Branch {
    /// Parsing step for the field tested by this branch.
    pub parse: ParseStep,
    /// Direction selector for this branch.
    pub direction: DirectionSelector,
    /// Target value used by this branch.
    pub target: TargetValue,
    /// Matching operator used by this branch.
    pub matching: MatchingOperator,
    /// Compression and decompression action associated with this branch.
    pub action: Cda,
    /// Index of the next node in the decision tree.
    pub next: usize,
}

/// Decision tree node.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Node {
    /// Matched rule identifier when this node is a leaf.
    pub rule_id: Option<RuleId>,
    /// Source rule order when this node is a leaf.
    pub rule_order: Option<usize>,
    /// Branches evaluated from this node.
    pub branches: Vec<Branch>,
}

/// Deterministic SCHC rule decision tree.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecisionTree {
    nodes: Vec<Node>,
}

impl DecisionTree {
    /// Creates a decision tree from prebuilt nodes.
    #[must_use]
    pub fn new(nodes: Vec<Node>) -> Self {
        Self { nodes }
    }

    /// Returns all nodes in this decision tree.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Returns the total branch count across all nodes.
    #[must_use]
    pub fn branch_count(&self) -> usize {
        self.nodes.iter().map(|node| node.branches.len()).sum()
    }
}
