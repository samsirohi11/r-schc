use schc_core::{
    Compressor, Decompressor, Direction, ExternalValueProvider, FieldRef, Position, RuleContext,
    SidRegistry,
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

#[derive(Debug, Deserialize)]
struct Corpus {
    provenance: Provenance,
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Provenance {
    schema_version: u32,
    canonical_sid: CanonicalSid,
    generator: String,
    contract: String,
}

#[derive(Debug, Deserialize)]
struct CanonicalSid {
    revision: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    rule_id: u64,
    packet_hex: String,
    compressed_hex: String,
    bit_len: usize,
    direction: String,
    receiver_position: String,
    #[serde(default)]
    provider: Option<ProviderValues>,
    coverage: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ProviderValues {
    device_iid_hex: String,
    application_iid_hex: String,
}

#[derive(Debug)]
struct StaticExternalValueProvider {
    device_iid: Vec<u8>,
    application_iid: Vec<u8>,
    calls: Arc<Mutex<Vec<ProviderCall>>>,
}

#[derive(Debug)]
struct ProviderCall {
    field: FieldRef,
    direction: Direction,
    bit_len: usize,
    value: Vec<u8>,
}

impl ExternalValueProvider for StaticExternalValueProvider {
    fn value(
        &self,
        field: &FieldRef,
        direction: Direction,
        bit_len: usize,
    ) -> schc_core::Result<Vec<u8>> {
        assert_eq!(bit_len, 64, "external IID width must be exactly 64 bits");
        let value = match field {
            FieldRef::Ipv6("fid-ipv6-deviid") => self.device_iid.clone(),
            FieldRef::Ipv6("fid-ipv6-appiid") => self.application_iid.clone(),
            other => panic!("unexpected external field {other:?}"),
        };
        assert_eq!(value.len(), 8, "external IID must contain exactly 8 bytes");
        self.calls.lock().unwrap().push(ProviderCall {
            field: field.clone(),
            direction,
            bit_len,
            value: value.clone(),
        });
        Ok(value)
    }
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

fn direction(value: &str) -> Direction {
    match value {
        "up" => Direction::Up,
        "down" => Direction::Down,
        other => panic!("unknown vector direction {other}"),
    }
}

fn receiver_position(value: &str) -> Position {
    match value {
        "core" => Position::Core,
        "device" => Position::Device,
        other => panic!("unknown receiver position {other}"),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap_or_else(|error| panic!("invalid hex {value}: {error}"))
}

fn assert_provider_calls(calls: &[ProviderCall], device_iid: &[u8], application_iid: &[u8]) {
    assert_eq!(calls.len(), 2, "external rule must request both IIDs");
    for call in calls {
        assert_eq!(call.direction, Direction::Up);
        assert_eq!(call.bit_len, 64);
        match call.field {
            FieldRef::Ipv6("fid-ipv6-deviid") => assert_eq!(call.value, device_iid),
            FieldRef::Ipv6("fid-ipv6-appiid") => assert_eq!(call.value, application_iid),
            ref other => panic!("unexpected provider call {other:?}"),
        }
    }
}

fn assert_vector_round_trip(context: &RuleContext, compressor: &Compressor, vector: &Vector) {
    assert!(
        !vector.coverage.is_empty(),
        "vector has no coverage metadata"
    );
    let packet = decode_hex(&vector.packet_hex);
    let expected = decode_hex(&vector.compressed_hex);
    assert!(vector.bit_len > 0);
    assert!(
        vector.bit_len <= expected.len() * 8,
        "vector {} bit length exceeds compressed bytes",
        vector.name
    );
    assert_eq!(
        expected[0],
        u8::try_from(vector.rule_id).unwrap(),
        "vector {} does not begin with its 8-bit rule ID",
        vector.name
    );

    let flow_direction = direction(&vector.direction);
    let compressed = compressor
        .compress(flow_direction, &packet)
        .unwrap_or_else(|error| panic!("{} compression failed: {error}", vector.name));
    assert_eq!(
        compressed.bytes(),
        expected,
        "{} compressed bytes changed",
        vector.name
    );
    assert_eq!(
        compressed.bit_len(),
        vector.bit_len,
        "{} meaningful bit length changed",
        vector.name
    );

    let position = receiver_position(&vector.receiver_position);
    let restored = if let Some(provider_values) = &vector.provider {
        let device_iid = decode_hex(&provider_values.device_iid_hex);
        let application_iid = decode_hex(&provider_values.application_iid_hex);
        assert_eq!(device_iid.len(), 8);
        assert_eq!(application_iid.len(), 8);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let provider = StaticExternalValueProvider {
            device_iid: device_iid.clone(),
            application_iid: application_iid.clone(),
            calls: Arc::clone(&calls),
        };
        let decompressor =
            Decompressor::with_external_value_provider(context.clone(), Arc::new(provider))
                .unwrap();
        let restored = decompressor
            .decompress_with_bit_len(position, &expected, vector.bit_len)
            .unwrap_or_else(|error| panic!("{} decompression failed: {error}", vector.name));
        assert_provider_calls(&calls.lock().unwrap(), &device_iid, &application_iid);
        restored
    } else {
        Decompressor::new(context.clone())
            .unwrap()
            .decompress_with_bit_len(position, &expected, vector.bit_len)
            .unwrap_or_else(|error| panic!("{} decompression failed: {error}", vector.name))
    };
    assert_eq!(restored, packet, "{} packet changed", vector.name);

    if vector.bit_len % 8 != 0 && vector.provider.is_none() {
        let padded = Decompressor::new(context.clone())
            .unwrap()
            .decompress(position, &expected)
            .unwrap_or_else(|error| panic!("{} padded decompression failed: {error}", vector.name));
        assert_eq!(padded, packet, "{} padded packet changed", vector.name);
    }
}

#[test]
fn canonical_core_corpus_round_trips_every_rule() {
    let (context, corpus) = load_corpus();
    assert_eq!(corpus.provenance.schema_version, 1);
    assert_eq!(
        corpus.provenance.canonical_sid.revision,
        "ietf-schc@2026-05-07"
    );
    assert_eq!(
        corpus.provenance.canonical_sid.sha256,
        "9053856d017170092aa066f47d559169df87b71c0b32e7b702542c2b37eb78ff"
    );
    assert_eq!(corpus.provenance.generator, "tools/regenerate_core_sor.py");
    assert_eq!(
        corpus.provenance.contract,
        "Expected vectors are committed regression and interoperability contracts."
    );

    let loaded_rule_ids: BTreeSet<u64> = context
        .rules()
        .rules()
        .iter()
        .map(|rule| rule.id().value())
        .collect();
    assert_eq!(loaded_rule_ids.len(), 10);

    let mut vector_names = BTreeSet::new();
    let mut vector_rule_ids = BTreeSet::new();
    assert_eq!(corpus.vectors.len(), loaded_rule_ids.len());
    assert_eq!(
        corpus
            .vectors
            .iter()
            .filter(|vector| vector.provider.is_some())
            .count(),
        1
    );

    let compressor = Compressor::new(context.clone()).unwrap();
    for vector in &corpus.vectors {
        assert!(
            vector_names.insert(vector.name.clone()),
            "duplicate vector name"
        );
        assert!(
            vector_rule_ids.insert(vector.rule_id),
            "duplicate vector rule ID {}",
            vector.rule_id
        );
        assert!(
            loaded_rule_ids.contains(&vector.rule_id),
            "vector {} references an unloaded rule",
            vector.name
        );
        if vector.provider.is_some() {
            assert_eq!(
                vector.rule_id, 0x18,
                "provider values belong only to the external-IID rule"
            );
        }
        assert_vector_round_trip(&context, &compressor, vector);
    }

    assert_eq!(vector_rule_ids, loaded_rule_ids);
}
