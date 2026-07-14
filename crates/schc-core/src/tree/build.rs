use super::{Branch, DecisionTree, Node, ParseStep};
use crate::rule::{FieldRule, LengthUnit};
use crate::{
    Cda, DirectionSelector, FieldLength, FieldRef, MatchingOperator, Result, Rule, RuleSet,
    TargetValue,
};

impl DecisionTree {
    /// Builds a deterministic decision tree from a rule set.
    ///
    /// # Errors
    ///
    /// Returns an error if rule entries cannot be arranged into a valid tree.
    pub fn build(rule_set: &RuleSet) -> Result<Self> {
        let ordered_rules = rule_set.rules().iter().enumerate().collect::<Vec<_>>();
        let mut nodes = Vec::new();
        build_node(&ordered_rules, 0, &mut nodes)?;
        Ok(Self::new(nodes))
    }
}

#[derive(Debug)]
struct BranchGroup<'rule> {
    parse: ParseStep,
    field_position: usize,
    direction: DirectionSelector,
    target: TargetValue,
    matching: MatchingOperator,
    action: Cda,
    next_field: Option<FieldRef>,
    members: Vec<(usize, &'rule Rule)>,
    sort_key: Vec<u8>,
}

fn build_node(rules: &[(usize, &Rule)], depth: usize, nodes: &mut Vec<Node>) -> Result<usize> {
    let node_index = nodes.len();
    let leaf = rules
        .iter()
        .filter(|(_, rule)| rule.fields().len() == depth)
        .min_by_key(|(rule_order, _)| *rule_order);

    nodes.push(Node {
        rule_id: leaf.map(|(_, rule)| rule.id()),
        rule_order: leaf.map(|(rule_order, _)| *rule_order),
        branches: Vec::new(),
    });

    let mut groups = branch_groups(rules, depth)?;
    groups.sort_by(|left, right| left.sort_key.cmp(&right.sort_key));

    let mut branches = Vec::with_capacity(groups.len());
    for group in groups {
        let next = build_node(&group.members, depth + 1, nodes)?;
        branches.push(Branch {
            parse: group.parse,
            direction: group.direction,
            target: group.target,
            matching: group.matching,
            action: group.action,
            next,
        });
    }

    nodes[node_index].branches = branches;
    Ok(node_index)
}

fn branch_groups<'rule>(
    rules: &[(usize, &'rule Rule)],
    depth: usize,
) -> Result<Vec<BranchGroup<'rule>>> {
    let mut groups: Vec<BranchGroup<'rule>> = Vec::new();

    for &(rule_order, rule) in rules {
        if rule.fields().len() < depth {
            return Err(crate::SchcError::InvalidRule {
                rule_index: rule_order,
                reason: format!("rule is shorter than tree depth {depth}"),
            });
        }

        let Some(field_rule) = rule.fields().get(depth) else {
            continue;
        };
        let next_field = rule.fields().get(depth + 1).map(|next| next.field.clone());
        let sort_key = branch_sort_key(field_rule, next_field.as_ref());

        if let Some(group) = groups.iter_mut().find(|group| {
            group.parse.field == field_rule.field
                && group.parse.length == field_rule.length
                && group.field_position == field_rule.field_position
                && group.direction == field_rule.direction
                && group.target == field_rule.target
                && group.matching == field_rule.matching
                && group.action == field_rule.action
                && group.next_field == next_field
        }) {
            group.members.push((rule_order, rule));
            continue;
        }

        groups.push(BranchGroup {
            parse: ParseStep {
                field: field_rule.field.clone(),
                length: field_rule.length.clone(),
                field_position: field_rule.field_position,
                entry_index: field_rule.entry_index,
            },
            field_position: field_rule.field_position,
            direction: field_rule.direction,
            target: field_rule.target.clone(),
            matching: field_rule.matching,
            action: field_rule.action,
            next_field,
            members: vec![(rule_order, rule)],
            sort_key,
        });
    }

    Ok(groups)
}

fn branch_sort_key(field_rule: &FieldRule, next_field: Option<&FieldRef>) -> Vec<u8> {
    let mut key = Vec::new();
    push_field_ref(&mut key, &field_rule.field);
    key.extend_from_slice(&field_rule.field_position.to_be_bytes());
    push_field_length(&mut key, &field_rule.length);
    push_direction(&mut key, field_rule.direction);
    push_target(&mut key, &field_rule.target);
    push_matching(&mut key, field_rule.matching);
    push_cda(&mut key, field_rule.action);
    push_optional_field_ref(&mut key, next_field);
    key
}

fn push_field_ref(output: &mut Vec<u8>, field: &FieldRef) {
    match field {
        FieldRef::Ipv6(name) => push_tagged_str(output, 0, name),
        FieldRef::Udp(name) => push_tagged_str(output, 1, name),
        FieldRef::Coap(name) => push_tagged_str(output, 2, name),
        FieldRef::Icmpv6(name) => push_tagged_str(output, 3, name),
        FieldRef::CoapOption { number } => {
            output.push(4);
            output.extend_from_slice(&number.to_be_bytes());
        }
        FieldRef::Unused => output.push(5),
        FieldRef::Payload => output.push(6),
        FieldRef::SyntheticCoapMarker => output.push(7),
        FieldRef::UnknownSid(sid) => {
            output.push(8);
            output.extend_from_slice(&sid.to_be_bytes());
        }
    }
}

fn push_field_length(output: &mut Vec<u8>, length: &FieldLength) {
    match length {
        FieldLength::FixedBits(bits) => {
            output.push(0);
            output.extend_from_slice(&bits.to_be_bytes());
        }
        FieldLength::VariableBytes => output.push(1),
        FieldLength::VariableBits => output.push(2),
        FieldLength::TokenLength => output.push(3),
        FieldLength::FromPreviousField { entry_index, unit } => {
            output.push(4);
            output.extend_from_slice(&entry_index.to_be_bytes());
            output.push(match unit {
                LengthUnit::Bytes => 0,
                LengthUnit::Bits => 1,
            });
        }
        FieldLength::FunctionSid(sid) => {
            output.push(5);
            output.extend_from_slice(&sid.to_be_bytes());
        }
    }
}

fn push_direction(output: &mut Vec<u8>, direction: DirectionSelector) {
    output.push(match direction {
        DirectionSelector::Bidirectional => 0,
        DirectionSelector::Up => 1,
        DirectionSelector::Down => 2,
    });
}

fn push_target(output: &mut Vec<u8>, target: &TargetValue) {
    match target {
        TargetValue::None => output.push(0),
        TargetValue::Bytes(bytes) => {
            output.push(1);
            push_bytes(output, bytes);
        }
        TargetValue::Mapping(values) => {
            output.push(2);
            output.extend_from_slice(&values.len().to_be_bytes());
            for value in values {
                push_bytes(output, value);
            }
        }
    }
}

fn push_matching(output: &mut Vec<u8>, matching: MatchingOperator) {
    match matching {
        MatchingOperator::Equal => output.push(0),
        MatchingOperator::Ignore => output.push(1),
        MatchingOperator::Msb(bits) => {
            output.push(2);
            output.extend_from_slice(&bits.to_be_bytes());
        }
        MatchingOperator::MatchMapping => output.push(3),
    }
}

fn push_cda(output: &mut Vec<u8>, action: Cda) {
    output.push(match action {
        Cda::NotSent => 0,
        Cda::ValueSent => 1,
        Cda::MappingSent => 2,
        Cda::Lsb => 3,
        Cda::Compute => 4,
    });
}

fn push_optional_field_ref(output: &mut Vec<u8>, field: Option<&FieldRef>) {
    match field {
        Some(field) => {
            output.push(1);
            push_field_ref(output, field);
        }
        None => output.push(0),
    }
}

fn push_tagged_str(output: &mut Vec<u8>, tag: u8, value: &str) {
    output.push(tag);
    push_bytes(output, value.as_bytes());
}

fn push_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&bytes.len().to_be_bytes());
    output.extend_from_slice(bytes);
}
