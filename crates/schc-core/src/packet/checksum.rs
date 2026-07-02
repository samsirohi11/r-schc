//! IPv6 pseudo-header checksum helpers.

pub(crate) fn transport_checksum(
    source: &[u8; 16],
    destination: &[u8; 16],
    next_header: u8,
    segment: &[u8],
) -> u16 {
    let mut sum = Checksum::default();
    sum.add_bytes(source);
    sum.add_bytes(destination);
    sum.add_u32(u32::try_from(segment.len()).expect("segment length fits u32"));
    sum.add_bytes(&[0, 0, 0, next_header]);
    sum.add_bytes(segment);
    sum.finish()
}

#[derive(Debug, Default)]
struct Checksum {
    sum: u32,
    pending: Option<u8>,
}

impl Checksum {
    fn add_u32(&mut self, value: u32) {
        self.add_bytes(&value.to_be_bytes());
    }

    fn add_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if let Some(high) = self.pending.take() {
                self.add_word(u16::from_be_bytes([high, *byte]));
            } else {
                self.pending = Some(*byte);
            }
        }
    }

    fn finish(mut self) -> u16 {
        if let Some(high) = self.pending.take() {
            self.add_word(u16::from_be_bytes([high, 0]));
        }
        while self.sum > 0xffff {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        let checksum = !u16::try_from(self.sum).expect("folded checksum fits u16");
        if checksum == 0 {
            0xffff
        } else {
            checksum
        }
    }

    fn add_word(&mut self, word: u16) {
        self.sum += u32::from(word);
    }
}

#[cfg(test)]
mod tests {
    use super::transport_checksum;

    #[test]
    fn udp_checksum_matches_fixture() {
        let source = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let destination = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        let segment = [
            0x16, 0x33, 0x16, 0x33, 0x00, 0x0c, 0x00, 0x00, 0x40, 0x01, 0x00, 0x2a,
        ];

        assert_eq!(
            transport_checksum(&source, &destination, 17, &segment),
            0x37d0
        );
    }

    #[test]
    fn icmpv6_checksum_matches_echo_fixture() {
        let source = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let destination = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        let segment = [
            0x80, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01, 0x70, 0x69, 0x6e, 0x67,
        ];

        assert_eq!(
            transport_checksum(&source, &destination, 58, &segment),
            0x333e
        );
    }
}
