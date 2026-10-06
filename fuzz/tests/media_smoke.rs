use libmkiso::boot_media::manifest::{Manifest, MultibootManifest};

#[test]
fn manifest_seeds_reach_validation_and_serialization() {
    for (name, bytes) in libmkiso_fuzz::media::seeds() {
        let text = std::str::from_utf8(bytes).unwrap();
        if name == "single" {
            toml::from_str::<Manifest>(text)
                .unwrap()
                .validate()
                .unwrap();
        } else {
            toml::from_str::<MultibootManifest>(text)
                .unwrap()
                .validate()
                .unwrap();
        }
        libmkiso_fuzz::media::read(bytes);
        for offset in (0..bytes.len()).step_by(7) {
            let mut mutated = bytes.to_vec();
            mutated[offset] ^= 0xff;
            libmkiso_fuzz::media::read(&mutated);
        }
    }
    for input in [
        &[][..],
        &[255; 256][..],
        b"../invalid",
        b"2024-02-30T00:00:00Z",
    ] {
        libmkiso_fuzz::media::read(input);
    }
}
