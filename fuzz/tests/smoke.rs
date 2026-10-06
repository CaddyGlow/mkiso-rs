use libmkiso_fuzz::{iso9660, roundtrip, udf};

#[test]
fn malformed_inputs_do_not_panic() {
    for input in [&[][..], &[0][..], &[0xff; 65536][..]] {
        iso9660(input);
        udf(input);
    }
    assert!(libmkiso_fuzz::run("unknown", &[]).is_err());
}

#[test]
fn writer_profiles_roundtrip_and_seed_parser_mutations() {
    for selector in 0..60u8 {
        let mut input = vec![selector];
        input.extend((0..4096).map(|i| (i % 251) as u8));
        roundtrip(&input);
    }
    for input in [&[][..], &[0][..], &[19, 42][..]] {
        roundtrip(input);
    }
    for (target, image) in libmkiso_fuzz::images(&[0, 42]) {
        for cut in [0, 32768, image.len() / 2, image.len() - 1] {
            libmkiso_fuzz::run(target, &image[..cut]).unwrap();
        }
        // Exercise descriptor rejection after a valid seed has passed parsing.
        for offset in (16 * 2048..image.len()).step_by(2048) {
            let mut mutated = image.clone();
            mutated[offset] ^= 0xff;
            libmkiso_fuzz::run(target, &mutated).unwrap();
        }
    }
}
