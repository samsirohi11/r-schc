//! Bit-level cursor and buffer utilities.

mod reader;
mod writer;

pub use reader::BitReader;
pub use writer::BitWriter;

#[cfg(test)]
mod tests {
    use super::{BitReader, BitWriter};

    #[test]
    fn reader_reads_msb_first_across_byte_boundary() {
        let mut reader = BitReader::new(&[0b1011_0011, 0b0101_0101]);

        assert_eq!(reader.read_bits(4).unwrap(), 0b1011);
        assert_eq!(reader.read_bits(6).unwrap(), 0b00_1101);
        assert_eq!(reader.position(), 10);
    }

    #[test]
    fn writer_writes_msb_first_and_pads_last_byte() {
        let mut writer = BitWriter::new();

        writer.write_bits(0b101, 3).unwrap();
        writer.write_bits(0b10, 2).unwrap();

        assert_eq!(writer.bit_len(), 5);
        assert_eq!(writer.to_vec(), vec![0b1011_0000]);
    }

    #[test]
    fn reader_rejects_out_of_bounds_read() {
        let mut reader = BitReader::new(&[0xff]);

        assert!(reader.read_bits(9).is_err());
    }

    #[test]
    fn writer_rejects_value_that_does_not_fit() {
        let mut writer = BitWriter::new();

        assert!(writer.write_bits(0b1000, 3).is_err());
    }
}
