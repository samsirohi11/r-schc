use schc_core::{RuleContext, SidRegistry};
use schc_runtime::{
    DeviceId, DeviceIdError, DeviceProfile, Endpoint, FrameError, IidKind, Operation, PacketFlow,
    ProfileError, Runtime, RuntimeError, SchcFrame,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Corpus {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    packet_hex: String,
    compressed_hex: String,
    bit_len: usize,
    direction: String,
    receiver_position: String,
    #[serde(default)]
    provider: Option<ProviderValues>,
}

#[derive(Debug, Deserialize)]
struct ProviderValues {
    device_iid_hex: String,
    application_iid_hex: String,
}

fn fixture(name: &str) -> String {
    format!("{}/../../fixtures/core/{name}", env!("CARGO_MANIFEST_DIR"))
}

fn load_corpus() -> (RuleContext, Corpus) {
    let sid = SidRegistry::load_path(fixture("ietf-schc@2026-05-07.sid")).unwrap();
    let sor = std::fs::read(fixture("core.sor")).unwrap();
    let context = RuleContext::from_cbor_slice(&sor, sid).unwrap();
    let corpus: Corpus =
        serde_json::from_str(&std::fs::read_to_string(fixture("vectors.json")).unwrap()).unwrap();
    (context, corpus)
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap_or_else(|error| panic!("invalid corpus hex {value}: {error}"))
}

fn profile_from_corpus(corpus: &Corpus) -> DeviceProfile {
    let provider = corpus
        .vectors
        .iter()
        .find_map(|vector| vector.provider.as_ref())
        .expect("corpus must contain an external IID vector");
    let device_iid = decode_hex(&provider.device_iid_hex);
    let application_iid = decode_hex(&provider.application_iid_hex);
    DeviceProfile::from_bytes(Some(&device_iid), Some(&application_iid)).unwrap()
}

fn flow(value: &str) -> PacketFlow {
    match value {
        "up" => PacketFlow::Uplink,
        "down" => PacketFlow::Downlink,
        other => panic!("unknown corpus direction {other}"),
    }
}

fn endpoints(vector: &Vector, flow: PacketFlow) -> (Endpoint, Endpoint) {
    let encoder = match flow {
        PacketFlow::Uplink => Endpoint::Device,
        PacketFlow::Downlink => Endpoint::Core,
    };
    let decoder = match vector.receiver_position.as_str() {
        "core" => Endpoint::Core,
        "device" => Endpoint::Device,
        other => panic!("unknown corpus receiver position {other}"),
    };
    (encoder, decoder)
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn public_runtime_values_are_send_and_sync() {
    assert_send_sync::<Runtime>();
    assert_send_sync::<DeviceId>();
    assert_send_sync::<DeviceProfile>();
    assert_send_sync::<SchcFrame>();
    assert_send_sync::<Endpoint>();
    assert_send_sync::<PacketFlow>();
    assert_send_sync::<RuntimeError>();
    assert_send_sync::<FrameError>();
    assert_send_sync::<ProfileError>();
    assert_send_sync::<DeviceIdError>();
    assert_send_sync::<IidKind>();
    assert_send_sync::<Operation>();
}

#[test]
fn canonical_corpus_runs_through_runtime_encode_and_decode() {
    let (context, corpus) = load_corpus();
    let device = DeviceId::new("corpus-device").unwrap();
    let runtime = Runtime::new(device.clone(), context, profile_from_corpus(&corpus)).unwrap();
    let mut saw_uplink = false;
    let mut saw_downlink = false;
    let mut saw_non_byte_aligned = false;
    let mut saw_unread_suffix = false;
    let mut saw_no_compression = false;

    for vector in &corpus.vectors {
        let packet = decode_hex(&vector.packet_hex);
        let expected = SchcFrame::new(decode_hex(&vector.compressed_hex), vector.bit_len).unwrap();
        let packet_flow = flow(&vector.direction);
        let (encode_role, decode_role) = endpoints(vector, packet_flow);
        let encoded = runtime
            .encode(&device, encode_role, packet_flow, &packet)
            .unwrap_or_else(|error| panic!("{} encode failed: {error}", vector.name));
        assert_eq!(encoded, expected, "{} encoded frame changed", vector.name);
        let decoded = runtime
            .decode(&device, decode_role, packet_flow, &encoded)
            .unwrap_or_else(|error| panic!("{} decode failed: {error}", vector.name));
        assert_eq!(
            decoded, packet,
            "{} reconstructed packet changed",
            vector.name
        );

        saw_uplink |= packet_flow == PacketFlow::Uplink;
        saw_downlink |= packet_flow == PacketFlow::Downlink;
        saw_non_byte_aligned |= vector.bit_len % 8 != 0;
        saw_unread_suffix |= vector.name == "udp-header-only-unread-payload";
        saw_no_compression |= vector.name == "no-compression-fallback";
    }

    assert!(saw_uplink && saw_downlink);
    assert!(saw_non_byte_aligned);
    assert!(saw_unread_suffix);
    assert!(saw_no_compression);
    assert_eq!(corpus.vectors.len(), 10);
}
