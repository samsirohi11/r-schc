//! Packet reconstruction entry point.

use crate::error::Result;
use crate::packet::field::FieldStore;
use crate::rule::Direction;

pub(crate) fn reconstruct_packet(direction: Direction, fields: &FieldStore) -> Result<Vec<u8>> {
    crate::decompress::engine::reconstruct_packet_for_builder(direction, fields)
}
