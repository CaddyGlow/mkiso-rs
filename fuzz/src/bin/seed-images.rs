use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let root = PathBuf::from(env::args().nth(1).unwrap_or_else(|| "fuzz/corpus".into()));
    for target in [
        "bridge",
        "iso9660",
        "udf",
        "roundtrip",
        "iso_roundtrip",
        "udf_roundtrip",
        "media",
    ] {
        fs::create_dir_all(root.join(target))?;
    }
    for selector in 0..60u8 {
        let mut input = vec![selector];
        input.extend((0..4096).map(|i| (i % 251) as u8));
        for (target, image) in libmkiso_fuzz::images(&input) {
            fs::write(
                root.join(target).join(format!("profile-{selector:02}")),
                image,
            )?;
        }
        fs::write(
            root.join("roundtrip")
                .join(format!("profile-{selector:02}")),
            input,
        )?;
    }
    for (name, recipe) in libmkiso_fuzz::iso::seed_recipes() {
        let (image, _) = libmkiso_fuzz::iso::seed_image(&recipe).expect("valid ISO seed");
        fs::write(root.join("iso9660").join(&name), image)?;
        fs::write(root.join("iso_roundtrip").join(name), recipe)?;
    }
    for (name, recipe) in libmkiso_fuzz::udf::seed_recipes() {
        let image = libmkiso_fuzz::udf::seed_image(&recipe).expect("valid UDF seed");
        fs::write(root.join("udf").join(&name), image)?;
        fs::write(root.join("udf_roundtrip").join(name), recipe)?;
    }
    // Rejection/cancellation recipes are inputs too, without parser-image counterparts.
    let (_, iso_base) = libmkiso_fuzz::iso::seed_recipes().pop().unwrap();
    for flag in [1, 2, 4, 8, 16, 32, 64] {
        let mut recipe = iso_base.clone();
        recipe[14] = flag;
        let _ = libmkiso_fuzz::iso::roundtrip(&recipe);
        fs::write(
            root.join("iso_roundtrip").join(format!("reject-{flag}")),
            recipe,
        )?;
    }
    let (_, udf_base) = libmkiso_fuzz::udf::seed_recipes().pop().unwrap();
    for flag in [1, 2, 4, 8, 16, 32, 64, 128] {
        let mut recipe = udf_base.clone();
        recipe[8] = flag;
        let _ = libmkiso_fuzz::udf::roundtrip(&recipe);
        fs::write(
            root.join("udf_roundtrip").join(format!("reject-{flag}")),
            recipe,
        )?;
    }
    for (name, bytes) in libmkiso_fuzz::media::seeds() {
        fs::write(root.join("media").join(name), bytes)?;
    }
    for (name, bytes) in libmkiso_fuzz::udf::metadata_seeds()? {
        fs::write(root.join("udf").join(name), bytes)?;
    }
    Ok(())
}
