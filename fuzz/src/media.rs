//! Pure manifest/schema coverage. Never follow manifest paths or provision devices.
use libmkiso::boot_media::manifest::{Manifest, MultibootManifest};

pub const MAX_INPUT: usize = 64 << 10;

pub fn read(data: &[u8]) {
    if data.len() > MAX_INPUT {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("manifest.toml");
    std::fs::write(&file, data).unwrap();
    let single = libmkiso::boot_media::manifest::read_manifest(&file);
    let multi = libmkiso::boot_media::manifest::read_multiboot(&file);
    if let Ok(text) = std::str::from_utf8(data) {
        let direct: Result<Manifest, _> = toml::from_str(text);
        assert_eq!(
            single.is_ok(),
            direct.as_ref().is_ok_and(|m| m.validate().is_ok())
        );
        let direct_multi: Result<MultibootManifest, _> = toml::from_str(text);
        assert_eq!(
            multi.is_ok(),
            direct_multi.as_ref().is_ok_and(|m| m.validate().is_ok())
        );
        let _ = libmkiso::boot_media::manifest::source_relative(std::path::Path::new(text));
        let _ = libmkiso::boot_media::manifest::validate_timestamp(text);
    }
    if let Ok(manifest) = single {
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded: Manifest = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(encoded, serde_json::to_vec(&decoded).unwrap());
    }
    if let Ok(manifest) = multi {
        let encoded = serde_json::to_vec(&manifest).unwrap();
        let decoded: MultibootManifest = serde_json::from_slice(&encoded).unwrap();
        decoded.validate().unwrap();
        assert_eq!(encoded, serde_json::to_vec(&decoded).unwrap());
    }
}

pub fn seeds() -> Vec<(&'static str, &'static [u8])> {
    vec![
        (
            "single",
            br#"version = 1
[image]
source = "source"
output = "image.iso"
[filesystem]
type = "iso9660"
joliet = true
rock_ridge = true
[boot]
profile = "custom"
arch = "x86_64"
[[boot.entries]]
id = "bios"
firmware = "bios"
image = "bios.bin"
[windows]
boot_wim = "sources/boot.wim"
install_image = "sources/install.wim"
[reproducibility]
timestamp = "2024-02-29T12:00:00Z"
"#,
        ),
        (
            "multiboot",
            br#"version = 1
[menu]
title = "Fuzz menu"
default = "linux"
timeout_seconds = 15
[boot]
backend = "ventoy"
firmware = ["bios", "uefi"]
assets = "assets"
[[entries]]
id = "linux"
title = "Linux"
image = "linux.iso"
"#,
        ),
    ]
}
