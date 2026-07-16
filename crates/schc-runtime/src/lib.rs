#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Small synchronous SCHC runtime bindings.

#[cfg(target_os = "linux")]
pub mod linux_tun;
pub mod packet;
pub mod udp;

use schc_core::{
    Compressor, Decompressor, Direction, ExternalValueProvider, FieldRef, Position, RuleContext,
    SchcError,
};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

const IID_BITS: usize = 64;

/// An opaque textual identifier assigned to an authenticated device.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId(String);

impl DeviceId {
    /// Creates a non-empty device identifier.
    ///
    /// Authentication and credential semantics remain outside the runtime.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceIdError::Empty`] for an empty value.
    pub fn new(value: impl Into<String>) -> Result<Self, DeviceIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(DeviceIdError::Empty);
        }
        Ok(Self(value))
    }

    /// Returns the textual identifier for runtime lookups.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Error returned when a device identifier is invalid.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum DeviceIdError {
    /// The identifier is empty.
    #[error("device identifier must not be empty")]
    Empty,
}

/// The semantic endpoint participating in an operation.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Endpoint {
    /// The core-network endpoint.
    Core,
    /// The device endpoint.
    Device,
}

/// Packet flow direction for an encode or decode operation.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum PacketFlow {
    /// Device-to-core uplink traffic.
    Uplink,
    /// Core-to-device downlink traffic.
    Downlink,
}

/// A compressed SCHC frame with exact meaningful bit length.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SchcFrame {
    bytes: Vec<u8>,
    bit_len: usize,
}

impl SchcFrame {
    /// Creates a frame with canonical byte storage and zero padding.
    ///
    /// # Errors
    ///
    /// Returns a [`FrameError`] when the bit length is zero, storage is not
    /// `ceil(bit_len / 8)`, or unused low padding bits are non-zero.
    pub fn new(bytes: Vec<u8>, bit_len: usize) -> Result<Self, FrameError> {
        if bit_len == 0 {
            return Err(FrameError::ZeroBitLength);
        }
        let expected_bytes = bit_len.div_ceil(8);
        if bytes.len() != expected_bytes {
            return Err(FrameError::NonCanonicalStorageLength {
                bit_len,
                expected_bytes,
                actual_bytes: bytes.len(),
            });
        }
        let padding_bits = (8 - (bit_len % 8)) % 8;
        if padding_bits != 0 {
            let mask = (1_u8 << padding_bits) - 1;
            let padding = bytes[bytes.len() - 1] & mask;
            if padding != 0 {
                return Err(FrameError::NonZeroPadding {
                    padding_bits,
                    value: padding,
                });
            }
        }
        Ok(Self { bytes, bit_len })
    }

    /// Returns the encoded bytes, including canonical zero padding if needed.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact number of meaningful encoded bits.
    #[must_use]
    pub const fn bit_len(&self) -> usize {
        self.bit_len
    }
}

impl AsRef<[u8]> for SchcFrame {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

/// A compressed result with its selected SCHC `RuleID`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EncodedResult {
    frame: SchcFrame,
    rule_id: schc_core::RuleId,
}

impl EncodedResult {
    /// Returns the exact-bit SCHC frame.
    #[must_use]
    pub const fn frame(&self) -> &SchcFrame {
        &self.frame
    }

    /// Returns the `RuleID` selected during compression.
    #[must_use]
    pub const fn rule_id(&self) -> schc_core::RuleId {
        self.rule_id
    }

    /// Consumes the result and returns the exact-bit frame.
    #[must_use]
    pub fn into_frame(self) -> SchcFrame {
        self.frame
    }
}

/// A decompressed result with its matched SCHC `RuleID`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DecodedResult {
    packet: Vec<u8>,
    rule_id: schc_core::RuleId,
}

impl DecodedResult {
    /// Returns the reconstructed packet bytes.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Returns the `RuleID` matched during decompression.
    #[must_use]
    pub const fn rule_id(&self) -> schc_core::RuleId {
        self.rule_id
    }

    /// Consumes the result and returns the reconstructed packet bytes.
    #[must_use]
    pub fn into_packet(self) -> Vec<u8> {
        self.packet
    }
}

/// Error returned when compressed frame storage is not canonical.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum FrameError {
    /// A frame must contain at least one meaningful bit.
    #[error("compressed frame must contain at least one meaningful bit")]
    ZeroBitLength,
    /// The byte storage does not equal `ceil(bit_len / 8)`.
    #[error(
        "frame with {bit_len} meaningful bits requires {expected_bytes} bytes, got {actual_bytes}"
    )]
    NonCanonicalStorageLength {
        /// Meaningful bit count.
        bit_len: usize,
        /// Required canonical byte count.
        expected_bytes: usize,
        /// Supplied byte count.
        actual_bytes: usize,
    },
    /// Unused low bits in the final byte are non-zero.
    #[error("frame has {padding_bits} non-zero padding bits with value {value:#04x}")]
    NonZeroPadding {
        /// Number of unused low bits.
        padding_bits: usize,
        /// Value found in the unused bits.
        value: u8,
    },
}

/// Identifies an external IID value in a profile.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum IidKind {
    /// The Device IID value.
    Device,
    /// The Application IID value.
    Application,
}

/// Error returned when profile bytes do not have the required width.
#[derive(Debug, Clone, Eq, Error, PartialEq)]
pub enum ProfileError {
    /// An IID value was not exactly eight bytes.
    #[error("{iid:?} IID must be exactly 8 bytes, got {actual_bytes}")]
    WrongWidth {
        /// IID kind.
        iid: IidKind,
        /// Supplied byte length.
        actual_bytes: usize,
    },
}

/// Immutable external IID values used by one runtime device.
#[derive(Clone, Eq, PartialEq)]
pub struct DeviceProfile {
    device_iid: Option<[u8; 8]>,
    application_iid: Option<[u8; 8]>,
}

impl DeviceProfile {
    /// Creates a profile from optional exact eight-byte IID values.
    #[must_use]
    pub const fn new(device_iid: Option<[u8; 8]>, application_iid: Option<[u8; 8]>) -> Self {
        Self {
            device_iid,
            application_iid,
        }
    }

    /// Creates a profile from optional byte slices and validates their widths.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::WrongWidth`] when a supplied IID is not eight
    /// bytes long.
    pub fn from_bytes(
        device_iid: Option<&[u8]>,
        application_iid: Option<&[u8]>,
    ) -> Result<Self, ProfileError> {
        Ok(Self {
            device_iid: copy_iid(device_iid, IidKind::Device)?,
            application_iid: copy_iid(application_iid, IidKind::Application)?,
        })
    }

    /// Returns the optional Device IID without exposing mutable storage.
    #[must_use]
    pub const fn device_iid(&self) -> Option<&[u8; 8]> {
        self.device_iid.as_ref()
    }

    /// Returns the optional Application IID without exposing mutable storage.
    #[must_use]
    pub const fn application_iid(&self) -> Option<&[u8; 8]> {
        self.application_iid.as_ref()
    }
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl fmt::Debug for DeviceProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceProfile")
            .field("device_iid_present", &self.device_iid.is_some())
            .field("application_iid_present", &self.application_iid.is_some())
            .finish()
    }
}

fn copy_iid(value: Option<&[u8]>, iid: IidKind) -> Result<Option<[u8; 8]>, ProfileError> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.len() != 8 {
        return Err(ProfileError::WrongWidth {
            iid,
            actual_bytes: value.len(),
        });
    }
    let mut copied = [0_u8; 8];
    copied.copy_from_slice(value);
    Ok(Some(copied))
}

/// Errors returned by the synchronous runtime.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// The endpoint and flow do not form a supported operation path.
    #[error("invalid {operation:?} path for {endpoint:?} and {flow:?}")]
    InvalidPath {
        /// Operation that attempted the path.
        operation: Operation,
        /// Endpoint supplied by the caller.
        endpoint: Endpoint,
        /// Packet flow supplied by the caller.
        flow: PacketFlow,
    },
    /// The request identity does not match the one-device runtime.
    #[error("request device does not match this runtime")]
    WrongDevice,
    /// The core produced a compressed datagram with non-canonical frame storage.
    #[error("SCHC core produced an invalid compressed frame: {0}")]
    InvalidFrame(#[from] FrameError),
    /// Fragmentation is intentionally unsupported by P0.
    #[error("fragmentation is unsupported by schc-runtime")]
    UnsupportedFragmentation(#[source] SchcError),
    /// A non-fragmentation SCHC core operation failed.
    #[error("SCHC core operation failed: {0}")]
    Core(#[source] SchcError),
}

/// Identifies an encode or decode operation in a path error.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum Operation {
    /// Packet compression.
    Encode,
    /// SCHC decompression.
    Decode,
}

/// A one-device synchronous SCHC runtime.
#[derive(Debug)]
pub struct Runtime {
    device_id: DeviceId,
    compressor: Compressor,
    decompressor: Decompressor,
}

impl Runtime {
    /// Builds a one-device runtime from a loaded rule context and profile.
    ///
    /// # Errors
    ///
    /// Returns a wrapped core error when compressor or decompressor
    /// construction fails.
    pub fn new(
        device_id: DeviceId,
        rule_context: RuleContext,
        profile: DeviceProfile,
    ) -> Result<Self, RuntimeError> {
        let compressor = Compressor::new(rule_context.clone()).map_err(map_core_error)?;
        let provider = DeviceBoundProvider { profile };
        let decompressor =
            Decompressor::with_external_value_provider(rule_context, Arc::new(provider))
                .map_err(map_core_error)?;
        Ok(Self {
            device_id,
            compressor,
            decompressor,
        })
    }

    /// Returns the device identifier bound to this runtime.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Encodes one packet and reports the selected `RuleID`.
    ///
    /// # Errors
    ///
    /// Returns a typed runtime error for a wrong device, invalid endpoint path,
    /// unsupported fragmentation, non-canonical core output, or a core failure.
    pub fn encode_detailed(
        &self,
        device: &DeviceId,
        endpoint: Endpoint,
        flow: PacketFlow,
        packet: &[u8],
    ) -> Result<EncodedResult, RuntimeError> {
        self.ensure_device(device)?;
        let direction = encode_direction(endpoint, flow)?;
        let compressed = self
            .compressor
            .compress(direction, packet)
            .map_err(map_core_error)?;
        let rule_id = compressed.rule_id();
        let frame = SchcFrame::new(compressed.bytes().to_vec(), compressed.bit_len())?;
        Ok(EncodedResult { frame, rule_id })
    }

    /// Encodes one packet using explicit device, endpoint, and flow metadata.
    ///
    /// This compatibility wrapper returns only the exact-bit frame.
    ///
    /// # Errors
    ///
    /// Returns the errors described by [`Self::encode_detailed`].
    pub fn encode(
        &self,
        device: &DeviceId,
        endpoint: Endpoint,
        flow: PacketFlow,
        packet: &[u8],
    ) -> Result<SchcFrame, RuntimeError> {
        self.encode_detailed(device, endpoint, flow, packet)
            .map(EncodedResult::into_frame)
    }

    /// Decodes one exact-bit frame and reports the matched `RuleID`.
    ///
    /// # Errors
    ///
    /// Returns a typed runtime error for a wrong device, invalid endpoint path,
    /// unsupported fragmentation, or a core failure.
    pub fn decode_detailed(
        &self,
        device: &DeviceId,
        endpoint: Endpoint,
        flow: PacketFlow,
        frame: &SchcFrame,
    ) -> Result<DecodedResult, RuntimeError> {
        self.ensure_device(device)?;
        let position = decode_position(endpoint, flow)?;
        let decoded = self
            .decompressor
            .decompress_with_bit_len_detailed(position, frame.bytes(), frame.bit_len())
            .map_err(map_core_error)?;
        let rule_id = decoded.rule_id();
        Ok(DecodedResult {
            packet: decoded.into_packet(),
            rule_id,
        })
    }

    /// Decodes one exact-bit frame using explicit device, endpoint, and flow metadata.
    ///
    /// This compatibility wrapper returns only reconstructed packet bytes.
    ///
    /// # Errors
    ///
    /// Returns the errors described by [`Self::decode_detailed`].
    pub fn decode(
        &self,
        device: &DeviceId,
        endpoint: Endpoint,
        flow: PacketFlow,
        frame: &SchcFrame,
    ) -> Result<Vec<u8>, RuntimeError> {
        self.decode_detailed(device, endpoint, flow, frame)
            .map(DecodedResult::into_packet)
    }

    /// Decodes raw octet-padded SCHC Packet bytes and reports the matched `RuleID`.
    ///
    /// The input contains only the SCHC Packet and lower-layer zero padding.
    /// No meaningful bit length or runtime metadata is carried in the bytes.
    ///
    /// # Errors
    ///
    /// Returns the errors described by the core padded decompression operation.
    pub fn decode_padded_detailed(
        &self,
        device: &DeviceId,
        endpoint: Endpoint,
        flow: PacketFlow,
        bytes: &[u8],
    ) -> Result<DecodedResult, RuntimeError> {
        self.ensure_device(device)?;
        let position = decode_position(endpoint, flow)?;
        let decoded = self
            .decompressor
            .decompress_detailed(position, bytes)
            .map_err(map_core_error)?;
        let rule_id = decoded.rule_id();
        Ok(DecodedResult {
            packet: decoded.into_packet(),
            rule_id,
        })
    }

    /// Decodes raw octet-padded SCHC Packet bytes.
    ///
    /// This compatibility wrapper returns only reconstructed packet bytes.
    ///
    /// # Errors
    ///
    /// Returns the errors described by [`Self::decode_padded_detailed`].
    pub fn decode_padded(
        &self,
        device: &DeviceId,
        endpoint: Endpoint,
        flow: PacketFlow,
        bytes: &[u8],
    ) -> Result<Vec<u8>, RuntimeError> {
        self.decode_padded_detailed(device, endpoint, flow, bytes)
            .map(DecodedResult::into_packet)
    }

    fn ensure_device(&self, device: &DeviceId) -> Result<(), RuntimeError> {
        if device == &self.device_id {
            Ok(())
        } else {
            Err(RuntimeError::WrongDevice)
        }
    }
}

/// The role of a node participating in a point-to-point SCHC link.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum NodeRole {
    /// Compresses downlink packets and decompresses uplink packets.
    Core,
    /// Compresses uplink packets and decompresses downlink packets.
    Device,
}

impl NodeRole {
    /// Returns the only valid outbound endpoint and flow for this role.
    #[must_use]
    pub const fn outbound(self) -> (Endpoint, PacketFlow) {
        match self {
            Self::Core => (Endpoint::Core, PacketFlow::Downlink),
            Self::Device => (Endpoint::Device, PacketFlow::Uplink),
        }
    }

    /// Returns the only valid inbound endpoint and flow for this role.
    #[must_use]
    pub const fn inbound(self) -> (Endpoint, PacketFlow) {
        match self {
            Self::Core => (Endpoint::Core, PacketFlow::Uplink),
            Self::Device => (Endpoint::Device, PacketFlow::Downlink),
        }
    }
}

/// A point-to-point node facade around one SCHC runtime.
#[derive(Debug)]
pub struct Node {
    runtime: Runtime,
    role: NodeRole,
}

impl Node {
    /// Creates a node with a fixed role and one owned runtime.
    #[must_use]
    pub const fn new(runtime: Runtime, role: NodeRole) -> Self {
        Self { runtime, role }
    }

    /// Returns this node's configured role.
    #[must_use]
    pub const fn role(&self) -> NodeRole {
        self.role
    }

    /// Returns the local device identifier without serializing it.
    #[must_use]
    pub const fn device_id(&self) -> &DeviceId {
        self.runtime.device_id()
    }

    /// Returns the underlying runtime for read-only inspection.
    #[must_use]
    pub const fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    /// Compresses one outbound packet into a raw padded SCHC Packet.
    ///
    /// The returned frame bytes contain only the SCHC Packet and its canonical
    /// zero padding. No device identifier or bit-length metadata is added.
    ///
    /// # Errors
    ///
    /// Returns a runtime error when compression fails.
    pub fn outbound(&self, packet: &[u8]) -> Result<EncodedResult, RuntimeError> {
        let (endpoint, flow) = self.role.outbound();
        self.runtime
            .encode_detailed(self.device_id(), endpoint, flow, packet)
    }

    /// Decompresses one raw padded SCHC Packet received from the peer.
    ///
    /// # Errors
    ///
    /// Returns a runtime error when padded decompression fails.
    pub fn inbound(&self, bytes: &[u8]) -> Result<DecodedResult, RuntimeError> {
        let (endpoint, flow) = self.role.inbound();
        self.runtime
            .decode_padded_detailed(self.device_id(), endpoint, flow, bytes)
    }
}

fn encode_direction(endpoint: Endpoint, flow: PacketFlow) -> Result<Direction, RuntimeError> {
    match (endpoint, flow) {
        (Endpoint::Device, PacketFlow::Uplink) => Ok(Direction::Up),
        (Endpoint::Core, PacketFlow::Downlink) => Ok(Direction::Down),
        _ => Err(RuntimeError::InvalidPath {
            operation: Operation::Encode,
            endpoint,
            flow,
        }),
    }
}

fn decode_position(endpoint: Endpoint, flow: PacketFlow) -> Result<Position, RuntimeError> {
    match (endpoint, flow) {
        (Endpoint::Core, PacketFlow::Uplink) => Ok(Position::Core),
        (Endpoint::Device, PacketFlow::Downlink) => Ok(Position::Device),
        _ => Err(RuntimeError::InvalidPath {
            operation: Operation::Decode,
            endpoint,
            flow,
        }),
    }
}

#[derive(Debug)]
struct DeviceBoundProvider {
    profile: DeviceProfile,
}

impl ExternalValueProvider for DeviceBoundProvider {
    fn value(
        &self,
        field: &FieldRef,
        _direction: Direction,
        bit_len: usize,
    ) -> schc_core::Result<Vec<u8>> {
        let value = match field {
            FieldRef::Ipv6("fid-ipv6-deviid") => self.profile.device_iid,
            FieldRef::Ipv6("fid-ipv6-appiid") => self.profile.application_iid,
            _ => {
                return Err(SchcError::InvalidResidue(
                    "unsupported external IID field".to_owned(),
                ));
            }
        };
        let Some(value) = value else {
            return Err(SchcError::InvalidResidue(
                "external IID profile value is missing".to_owned(),
            ));
        };
        if bit_len != IID_BITS {
            return Err(SchcError::InvalidResidue(format!(
                "external IID profile requires {IID_BITS} bits, requested {bit_len}"
            )));
        }
        Ok(value.to_vec())
    }
}

fn map_core_error(error: SchcError) -> RuntimeError {
    match error {
        SchcError::UnsupportedRuleNature { nature } if nature == "fragmentation" => {
            RuntimeError::UnsupportedFragmentation(SchcError::UnsupportedRuleNature { nature })
        }
        error => RuntimeError::Core(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schc_core::{RuleContext, SidRegistry};

    fn fixture(name: &str) -> String {
        format!("{}/../../fixtures/core/{name}", env!("CARGO_MANIFEST_DIR"))
    }

    fn context() -> RuleContext {
        let sid = SidRegistry::load_path(fixture("ietf-schc@2026-05-07.sid")).unwrap();
        let sor = std::fs::read(fixture("core.sor")).unwrap();
        RuleContext::from_cbor_slice(&sor, sid).unwrap()
    }

    fn corpus_vector(name: &str) -> serde_json::Value {
        let corpus: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(fixture("vectors.json")).unwrap())
                .unwrap();
        corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == name)
            .unwrap()
            .clone()
    }

    fn frame_vector(name: &str) -> (Vec<u8>, usize) {
        let vector = corpus_vector(name);
        (
            hex::decode(vector["compressed_hex"].as_str().unwrap()).unwrap(),
            usize::try_from(vector["bit_len"].as_u64().unwrap()).unwrap(),
        )
    }

    #[test]
    fn device_id_only_rejects_empty_values() {
        assert_eq!(DeviceId::new("").unwrap_err(), DeviceIdError::Empty);
        assert_eq!(
            DeviceId::new("prototype-device").unwrap().as_str(),
            "prototype-device"
        );
    }

    #[test]
    fn frame_validates_shape_and_padding() {
        assert!(matches!(
            SchcFrame::new(vec![0x80], 0),
            Err(FrameError::ZeroBitLength)
        ));
        assert!(matches!(
            SchcFrame::new(vec![0x80], 9),
            Err(FrameError::NonCanonicalStorageLength { .. })
        ));
        assert!(matches!(
            SchcFrame::new(vec![0x81], 7),
            Err(FrameError::NonZeroPadding { .. })
        ));
        let frame = SchcFrame::new(vec![0x80], 1).unwrap();
        assert_eq!(frame.bytes(), &[0x80]);
        assert_eq!(frame.bit_len(), 1);
    }

    #[test]
    fn profile_validates_exact_iid_width_and_redacts_debug() {
        assert!(matches!(
            DeviceProfile::from_bytes(Some(&[1, 2][..]), None),
            Err(ProfileError::WrongWidth {
                iid: IidKind::Device,
                actual_bytes: 2
            })
        ));
        let profile = DeviceProfile::new(Some([0xAA; 8]), None);
        let debug = format!("{profile:?}");
        assert!(!debug.contains("aa"));
    }

    #[test]
    fn runtime_rejects_missing_profile_values_as_core_errors() {
        let device = DeviceId::new("prototype-device").unwrap();
        let runtime = Runtime::new(device.clone(), context(), DeviceProfile::default()).unwrap();
        let (bytes, bit_len) = frame_vector("udp-external-iid-reconstruction");
        let frame = SchcFrame::new(bytes, bit_len).unwrap();
        let error = runtime
            .decode(&device, Endpoint::Core, PacketFlow::Uplink, &frame)
            .unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Core(SchcError::InvalidResidue(_))
        ));
    }

    #[test]
    fn runtime_rejects_wrong_device_and_invalid_paths() {
        let device = DeviceId::new("prototype-device").unwrap();
        let other = DeviceId::new("other-device").unwrap();
        let runtime = Runtime::new(device.clone(), context(), DeviceProfile::default()).unwrap();
        assert!(matches!(
            runtime.encode(&other, Endpoint::Device, PacketFlow::Uplink, &[]),
            Err(RuntimeError::WrongDevice)
        ));
        assert!(matches!(
            runtime.encode(&device, Endpoint::Core, PacketFlow::Uplink, &[]),
            Err(RuntimeError::InvalidPath {
                operation: Operation::Encode,
                ..
            })
        ));
        let frame = SchcFrame::new(vec![0x18], 8).unwrap();
        assert!(matches!(
            runtime.decode(&device, Endpoint::Core, PacketFlow::Downlink, &frame),
            Err(RuntimeError::InvalidPath {
                operation: Operation::Decode,
                ..
            })
        ));
    }

    #[test]
    fn fragmentation_is_a_typed_runtime_error() {
        let context = RuleContext::from_json_str(
            r#"{"rules":[{"rule_id":1,"rule_id_length":1,"nature":"fragmentation","fields":[]}]}"#,
            SidRegistry::default(),
        )
        .unwrap();
        let device = DeviceId::new("prototype-device").unwrap();
        let runtime = Runtime::new(device.clone(), context, DeviceProfile::default()).unwrap();
        let packet = hex::decode(
            corpus_vector("udp-sent-checksum")["packet_hex"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let encode_error = runtime
            .encode(&device, Endpoint::Device, PacketFlow::Uplink, &packet)
            .unwrap_err();
        assert!(matches!(
            encode_error,
            RuntimeError::UnsupportedFragmentation(SchcError::UnsupportedRuleNature {
                nature: "fragmentation"
            })
        ));

        let frame = SchcFrame::new(vec![0x80], 1).unwrap();
        let decode_error = runtime
            .decode(&device, Endpoint::Core, PacketFlow::Uplink, &frame)
            .unwrap_err();
        assert!(matches!(
            decode_error,
            RuntimeError::UnsupportedFragmentation(SchcError::UnsupportedRuleNature {
                nature: "fragmentation"
            })
        ));
    }

    #[test]
    fn ordinary_core_errors_keep_their_typed_source() {
        let device = DeviceId::new("prototype-device").unwrap();
        let runtime = Runtime::new(device.clone(), context(), DeviceProfile::default()).unwrap();
        let frame = SchcFrame::new(vec![0xFF], 8).unwrap();
        let error = runtime
            .decode(&device, Endpoint::Core, PacketFlow::Uplink, &frame)
            .unwrap_err();
        assert!(matches!(
            error,
            RuntimeError::Core(SchcError::NoMatchingRule)
        ));
    }
}
