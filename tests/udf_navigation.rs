//! Independent byte-crafted ECMA-167 descriptors, without using the crate's writer.
use libmkiso::udf::{EntryKind, Limits, UdfReader};
const BLOCK: usize = 2048;
const PARTITION: usize = 320;
fn put16(b: &mut [u8], p: usize, n: u16) {
    b[p..p + 2].copy_from_slice(&n.to_le_bytes());
}
fn put32(b: &mut [u8], p: usize, n: u32) {
    b[p..p + 4].copy_from_slice(&n.to_le_bytes());
}
fn put64(b: &mut [u8], p: usize, n: u64) {
    b[p..p + 8].copy_from_slice(&n.to_le_bytes());
}
fn seal(b: &mut [u8], kind: u16, location: u32, length: usize, version: u16) {
    put16(b, 0, kind);
    put16(b, 2, version);
    put16(b, 10, (length - 16) as u16);
    put32(b, 12, location);
    let mut crc = 0u16;
    for byte in &b[16..length] {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    put16(b, 8, crc);
    b[4] = b[..16]
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .fold(0u8, |sum, (_, v)| sum.wrapping_add(*v));
}
fn fixture(revision: u16, extended: bool, embedded: bool) -> Vec<u8> {
    let mut image = vec![0u8; 326 * BLOCK];
    let version = if revision >= 0x200 { 3 } else { 2 };
    let anchor = &mut image[256 * BLOCK..257 * BLOCK];
    put32(anchor, 16, 4 * BLOCK as u32);
    put32(anchor, 20, 257);
    seal(anchor, 2, 256, 512, version);
    let pvd = &mut image[257 * BLOCK..258 * BLOCK];
    seal(pvd, 1, 257, 512, version);
    let pd = &mut image[258 * BLOCK..259 * BLOCK];
    put32(pd, 188, PARTITION as u32);
    put32(pd, 192, 6);
    seal(pd, 5, 258, 512, version);
    let lvd = &mut image[259 * BLOCK..260 * BLOCK];
    put32(lvd, 212, BLOCK as u32);
    put16(lvd, 240, revision);
    put32(lvd, 248, BLOCK as u32);
    put32(lvd, 264, 6);
    put32(lvd, 268, 1);
    lvd[440..442].copy_from_slice(&[1, 6]);
    put16(lvd, 442, 1);
    seal(lvd, 6, 259, 446, version);
    let end = &mut image[260 * BLOCK..261 * BLOCK];
    seal(end, 8, 260, 16, version);
    let fsd = &mut image[PARTITION * BLOCK..(PARTITION + 1) * BLOCK];
    put32(fsd, 400, BLOCK as u32);
    put32(fsd, 404, 1);
    seal(fsd, 256, 0, 512, version);
    let mut fid = [0u8; 44];
    fid[19] = 5;
    put32(&mut fid, 20, BLOCK as u32);
    put32(&mut fid, 24, 2);
    fid[38..43].copy_from_slice(b"\x08file");
    seal(&mut fid, 257, 1, 44, version);
    let root = &mut image[(PARTITION + 1) * BLOCK..(PARTITION + 2) * BLOCK];
    put16(root, 20, 4);
    root[27] = 4;
    put16(root, 34, 3);
    put64(root, 56, 44);
    put32(root, 172, 44);
    root[176..220].copy_from_slice(&fid);
    seal(root, 261, 1, 220, version);
    let file = &mut image[(PARTITION + 2) * BLOCK..(PARTITION + 3) * BLOCK];
    let header = if extended { 216 } else { 176 };
    put16(file, 20, 4);
    file[27] = 5;
    put16(file, 34, if embedded { 3 } else { 1 });
    put64(file, 56, 7);
    if extended {
        put64(file, 64, 7);
    }
    if embedded {
        put32(file, header - 4, 7);
        file[header..header + 7].copy_from_slice(b"payload");
    } else {
        put32(file, header - 4, 16);
        put32(file, header, BLOCK as u32);
        put32(file, header + 4, 4);
    }
    seal(
        file,
        if extended { 266 } else { 261 },
        2,
        header + if embedded { 7 } else { 16 },
        version,
    );
    image[(PARTITION + 4) * BLOCK..(PARTITION + 4) * BLOCK + 7].copy_from_slice(b"payload");
    image
}

#[test]
fn symbolic_pathname_is_decoded_without_following_target() {
    let mut image = fixture(0x201, false, true);
    let file = &mut image[(PARTITION + 2) * BLOCK..(PARTITION + 3) * BLOCK];
    let target = b"\x03\x00\x00\x00\x05\x05\x00\x00\x08file";
    file[27] = 12;
    put64(file, 56, target.len() as u64);
    put32(file, 172, target.len() as u32);
    file[176..176 + target.len()].copy_from_slice(target);
    seal(file, 261, 2, 176 + target.len(), 3);
    let reader = UdfReader::open(&image, Limits::default()).unwrap();
    assert_eq!(reader.entries()[0].kind, EntryKind::SymbolicLink);
    assert_eq!(reader.entries()[0].link_target.as_deref(), Some("../file"));
    assert_eq!(reader.read_entry(0, 100).unwrap(), target);
}
#[test]
fn indirect_icb_is_resolved_and_cycles_are_rejected() {
    let mut image = fixture(0x201, false, true);
    image.copy_within(
        (PARTITION + 2) * BLOCK..(PARTITION + 3) * BLOCK,
        (PARTITION + 3) * BLOCK,
    );
    seal(
        &mut image[(PARTITION + 3) * BLOCK..(PARTITION + 4) * BLOCK],
        261,
        3,
        183,
        3,
    );
    let indirect = &mut image[(PARTITION + 2) * BLOCK..(PARTITION + 3) * BLOCK];
    indirect.fill(0);
    put16(indirect, 20, 4);
    indirect[27] = 3;
    put32(indirect, 36, BLOCK as u32);
    put32(indirect, 40, 3);
    seal(indirect, 259, 2, 52, 3);
    let reader = UdfReader::open(&image, Limits::default()).unwrap();
    assert_eq!(reader.read_entry(0, 7).unwrap(), b"payload");
    assert_eq!(reader.entries()[0].icb.block, 3);
    let indirect = &mut image[(PARTITION + 2) * BLOCK..(PARTITION + 3) * BLOCK];
    put32(indirect, 40, 2);
    seal(indirect, 259, 2, 52, 3);
    assert!(UdfReader::open(&image, Limits::default()).is_err());
}
#[test]
fn chained_file_sets_select_highest_number_and_detect_cycles() {
    let mut image = fixture(0x201, false, true);
    image.copy_within(
        PARTITION * BLOCK..(PARTITION + 1) * BLOCK,
        (PARTITION + 3) * BLOCK,
    );
    let next = &mut image[(PARTITION + 3) * BLOCK..(PARTITION + 4) * BLOCK];
    put32(next, 40, 1);
    seal(next, 256, 3, 512, 3);
    let first = &mut image[PARTITION * BLOCK..(PARTITION + 1) * BLOCK];
    put32(first, 448, BLOCK as u32);
    put32(first, 452, 3);
    seal(first, 256, 0, 512, 3);
    assert_eq!(
        UdfReader::open(&image, Limits::default())
            .unwrap()
            .read_entry(0, 7)
            .unwrap(),
        b"payload"
    );
    let next = &mut image[(PARTITION + 3) * BLOCK..(PARTITION + 4) * BLOCK];
    put32(next, 448, BLOCK as u32);
    seal(next, 256, 3, 512, 3);
    assert!(UdfReader::open(&image, Limits::default()).is_err());
}
#[test]
fn hard_link_names_share_resolved_identity() {
    let mut image = fixture(0x201, false, true);
    let root = &mut image[(PARTITION + 1) * BLOCK..(PARTITION + 2) * BLOCK];
    root.copy_within(176..220, 220);
    root[259..263].copy_from_slice(b"link");
    seal(&mut root[220..264], 257, 1, 44, 3);
    put64(root, 56, 88);
    put32(root, 172, 88);
    seal(root, 261, 1, 264, 3);
    let reader = UdfReader::open(&image, Limits::default()).unwrap();
    assert_eq!(reader.entries().len(), 2);
    assert_eq!(reader.entries()[0].icb, reader.entries()[1].icb);
    assert_eq!(reader.read_entry(1, 7).unwrap(), b"payload");
}
#[test]
fn strategy_4096_terminal_entry_selects_direct_data() {
    let mut image = fixture(0x201, false, true);
    let root = &mut image[(PARTITION + 1) * BLOCK..(PARTITION + 2) * BLOCK];
    put32(root, 196, 4096);
    seal(&mut root[176..220], 257, 1, 44, 3);
    seal(root, 261, 1, 220, 3);
    let file = &mut image[(PARTITION + 2) * BLOCK..(PARTITION + 3) * BLOCK];
    put16(file, 20, 4096);
    seal(file, 261, 2, 183, 3);
    let terminal = &mut image[(PARTITION + 3) * BLOCK..(PARTITION + 4) * BLOCK];
    terminal[27] = 11;
    seal(terminal, 260, 3, 36, 3);
    assert_eq!(
        UdfReader::open(&image, Limits::default())
            .unwrap()
            .read_entry(0, 7)
            .unwrap(),
        b"payload"
    );
}
