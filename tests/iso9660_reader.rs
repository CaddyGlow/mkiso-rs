use libmkiso::iso9660::{IsoReader, Limits};
use std::io::Cursor;

fn both32(bytes: &mut [u8], value: u32) {
    bytes[..4].copy_from_slice(&value.to_le_bytes());
    bytes[4..8].copy_from_slice(&value.to_be_bytes());
}
fn both16(bytes: &mut [u8], value: u16) {
    bytes[..2].copy_from_slice(&value.to_le_bytes());
    bytes[2..4].copy_from_slice(&value.to_be_bytes());
}
fn record(name: &[u8], extent: u32, size: u32, directory: bool) -> Vec<u8> {
    let len = (33 + name.len() + 1) & !1;
    let mut bytes = vec![0; len];
    bytes[0] = len as u8;
    both32(&mut bytes[2..10], extent);
    both32(&mut bytes[10..18], size);
    bytes[18..25].copy_from_slice(&[126, 10, 5, 12, 0, 0, 0]);
    bytes[25] = if directory { 2 } else { 0 };
    both16(&mut bytes[28..32], 1);
    bytes[32] = name.len() as u8;
    bytes[33..33 + name.len()].copy_from_slice(name);
    bytes
}
fn fixture() -> Vec<u8> {
    let mut image = vec![0; 22 * 2048];
    let primary = &mut image[16 * 2048..17 * 2048];
    primary[0] = 1;
    primary[1..6].copy_from_slice(b"CD001");
    primary[6] = 1;
    both32(&mut primary[80..88], 22);
    both16(&mut primary[120..124], 1);
    both16(&mut primary[124..128], 1);
    both16(&mut primary[128..132], 2048);
    let root = record(&[0], 20, 2048, true);
    primary[156..156 + root.len()].copy_from_slice(&root);
    image[17 * 2048] = 255;
    image[17 * 2048 + 1..17 * 2048 + 6].copy_from_slice(b"CD001");
    image[17 * 2048 + 6] = 1;
    let mut offset = 20 * 2048;
    for bytes in [
        root,
        record(&[1], 20, 2048, true),
        record(b"HELLO.TXT;1", 21, 5, false),
    ] {
        image[offset..offset + bytes.len()].copy_from_slice(&bytes);
        offset += bytes.len();
    }
    image[21 * 2048..21 * 2048 + 5].copy_from_slice(b"hello");
    image
}

#[test]
fn iso_system_area_is_not_misidentified_as_empty_tar() {
    let mut archive = IsoReader::open(Cursor::new(fixture()), Limits::default()).unwrap();
    assert_eq!(archive.entries()[0].name, "HELLO.TXT");
    let mut payload = Vec::new();
    assert_eq!(archive.extract(0, &mut payload).unwrap(), 5);
    assert_eq!(payload, b"hello");
}

#[test]
fn malformed_root_cycle_is_rejected() {
    let mut bytes = fixture();
    let record = record(b"LOOP", 20, 2048, true);
    bytes[20 * 2048 + 68..20 * 2048 + 68 + record.len()].copy_from_slice(&record);
    assert!(IsoReader::open(Cursor::new(bytes), Limits::default()).is_err());
}

#[test]
fn independent_7z_reads_baseline_fixture_when_available() {
    if std::process::Command::new("7z").arg("i").output().is_err() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("baseline.iso");
    std::fs::write(&path, fixture()).unwrap();
    let output = std::process::Command::new("7z")
        .args(["e", "-so"])
        .arg(path)
        .arg("HELLO.TXT")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"hello");
}
