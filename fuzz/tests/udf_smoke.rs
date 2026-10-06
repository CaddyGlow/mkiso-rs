use libmkiso_fuzz::udf::{
    HEADER, IMAGE_LIMIT, RECIPE_LIMIT, read, read_once, roundtrip, seed_image, seed_recipes,
};

#[test]
fn complete_profiles_reach_payload_stream_and_writer_oracles() {
    for (name, recipe) in seed_recipes() {
        let stats = roundtrip(&recipe);
        assert!(stats.written, "{name}");
        assert!(stats.image_bytes <= IMAGE_LIMIT);
        assert!(
            stats.reader.opened && stats.reader.payload_bytes > 0,
            "{name}"
        );
        if recipe[0] >= 2 {
            assert_eq!(stats.reader.streams, 3, "{name}");
        }
    }
}

#[test]
fn checksum_repair_reaches_a_mutated_file_entry() {
    let mut recipe = vec![0; HEADER];
    recipe.extend_from_slice(b"payload");
    let mut bytes = seed_image(&recipe).unwrap();
    let offset = bytes
        .chunks_exact(2048)
        .position(|block| {
            block[0..2] == 261u16.to_le_bytes()
                && block[27] == 5
                && block[56..64] == 7u64.to_le_bytes()
        })
        .unwrap()
        * 2048;
    bytes[offset + 72 + 6] ^= 1; // Timestamp changes without altering payload geometry.
    let (raw, repaired) = read(&bytes);
    assert!(!raw.opened);
    assert!(repaired.opened && repaired.payload_bytes >= 7);
}

#[test]
fn malformed_inputs_and_explicit_limits_remain_bounded() {
    let mut recipe = vec![0; HEADER];
    recipe.extend_from_slice(b"payload");
    let bytes = seed_image(&recipe).unwrap();
    for length in [0, 16, 256 * 2048, bytes.len() / 2] {
        let _ = read(&bytes[..length]);
    }
    assert!(!read_once(&vec![0; IMAGE_LIMIT + 1]).opened);
    assert!(!roundtrip(&vec![0; RECIPE_LIMIT + 1]).written);
    for flag in [2, 16, 64, 128] {
        let mut bounded = recipe.clone();
        bounded[8] = flag;
        assert!(!roundtrip(&bounded).written);
    }
    let mut invalid = recipe;
    invalid[9] = 4;
    assert!(!roundtrip(&invalid).written);
}

#[test]
fn configuration_and_payload_mutations_use_the_same_replay_harness() {
    let (_, original) = seed_recipes()
        .into_iter()
        .find(|(name, _)| name == "indirect-icbs")
        .unwrap();
    for offset in 0..original.len() {
        for byte in [0, 1, 0xff] {
            let mut mutated = original.clone();
            mutated[offset] = byte;
            libmkiso_fuzz::run("udf_roundtrip", &mutated).unwrap();
        }
    }
}

#[test]
fn fragmented_metadata_mirror_recovery_and_aed_seeds_extract() {
    let seeds = libmkiso_fuzz::udf::metadata_seeds().unwrap();
    assert_eq!(seeds.len(), 3);
    for (name, bytes) in seeds {
        let stats = read_once(&bytes);
        assert!(stats.opened, "{name}");
        assert_eq!(stats.entries, 80, "{name}");
        assert_eq!(stats.payload_bytes, 80 * 31, "{name}");
        let _ = read(&bytes);
    }
}
