//! Bounded UDF parsing and structured native-authoring fuzz oracles.
//! Adapted from the MIT archive-rs harness; see ../LICENSE.archive-rs.
use libmkiso::{
    AllocationMode, BootImage, BootOptions, IcbStrategy, UdfFileExtent, UdfImage, UdfOptions,
    UdfPartition, UdfRevision,
    udf::{EntryKind, Limits, UdfReader},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write};

/// Complete optical images fit this cap, unlike the legacy prefix-only target.
pub const IMAGE_LIMIT: usize = 4 << 20;
/// Structured writer input cap, including its 16-byte configuration header.
pub const RECIPE_LIMIT: usize = 64 << 10;
/// Writer configuration header length.
pub const HEADER: usize = 16;
const BLOCK: usize = 2048;

/// Successfully exercised reader paths, useful for deterministic harness tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReadStats {
    pub opened: bool,
    pub entries: usize,
    pub streams: usize,
    pub payload_bytes: u64,
}
/// Outcome of a bounded structured writer input.
#[derive(Debug, Default)]
pub struct RoundtripStats {
    pub written: bool,
    pub image_bytes: usize,
    pub reader: ReadStats,
}

fn limits() -> Limits {
    Limits {
        max_entries: 512,
        max_metadata_bytes: 2 << 20,
        max_entry_bytes: 1 << 20,
        max_total_bytes: 2 << 20,
        max_input_bytes: IMAGE_LIMIT as u64,
        max_nesting_depth: 16,
    }
}
#[derive(Default)]
struct DigestSink {
    bytes: u64,
    digest: Sha256,
}
impl Write for DigestSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes += bytes.len() as u64;
        assert!(self.bytes <= limits().max_entry_bytes);
        self.digest.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct FailingSink;
impl Write for FailingSink {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("fuzz output failure"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Parse and extract raw bytes, comparing streaming and allocating reader APIs.
/// Accepted metadata can still contain unreadable payloads; extraction errors are normal.
pub fn read_once(data: &[u8]) -> ReadStats {
    if data.len() > IMAGE_LIMIT {
        return ReadStats::default();
    }
    let Ok(reader) = UdfReader::open(data, limits()) else {
        return ReadStats::default();
    };
    let mut stats = ReadStats {
        opened: true,
        entries: reader.entries().len(),
        ..Default::default()
    };
    for (index, entry) in reader.entries().iter().enumerate() {
        stats.streams += usize::from(entry.stream.is_some());
        let mut output = DigestSink::default();
        let extracted = reader.extract(index, &mut output);
        if let Ok(count) = &extracted {
            assert_eq!(*count, entry.size);
            assert_eq!(output.bytes, entry.size);
            stats.payload_bytes += entry.size;
        }
        if entry.size <= 16384 {
            let buffered = reader.read_entry(index, 16384);
            assert_eq!(buffered.is_ok(), extracted.is_ok());
            if let Ok(buffered) = buffered {
                assert_eq!(Sha256::digest(&buffered), output.digest.finalize());
            }
        }
        if entry.size > 0 {
            assert!(reader.read_entry(index, entry.size - 1).is_err());
            assert!(reader.extract(index, &mut FailingSink).is_err());
        }
    }
    assert!(stats.payload_bytes <= limits().max_total_bytes);
    assert!(reader.extract(usize::MAX, &mut std::io::sink()).is_err());
    stats
}

fn crc(bytes: &[u8]) -> u16 {
    let mut value = 0u16;
    for &byte in bytes {
        value ^= u16::from(byte) << 8;
        for _ in 0..8 {
            value = if value & 0x8000 != 0 {
                (value << 1) ^ 0x1021
            } else {
                value << 1
            };
        }
    }
    value
}
fn repair_at(bytes: &mut [u8], offset: usize) -> Option<usize> {
    let tag = bytes.get(offset..offset.checked_add(16)?)?;
    let protected = usize::from(u16::from_le_bytes([tag[10], tag[11]]));
    let length = 16 + protected;
    if length > BLOCK || !matches!(u16::from_le_bytes([tag[2], tag[3]]), 2 | 3) {
        return None;
    }
    let descriptor = bytes.get_mut(offset..offset.checked_add(length)?)?;
    let value = crc(&descriptor[16..]);
    descriptor[8..10].copy_from_slice(&value.to_le_bytes());
    descriptor[4] = descriptor[..16]
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte));
    Some(length)
}

/// Repair only descriptor CRCs/checksums in a bounded copy; leave structural fields intact.
/// The unmodified input is always parsed first, so integrity rejection remains covered.
pub fn repair_tags(bytes: &mut [u8]) {
    if bytes.len() > IMAGE_LIMIT {
        return;
    }
    let mut repaired = 0;
    for offset in (0..bytes.len().saturating_sub(15)).step_by(BLOCK) {
        let id = u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        if matches!(id, 0..=9 | 256..=266) {
            repaired += usize::from(repair_at(bytes, offset).is_some());
        }
        if id == 257 {
            let end = offset.saturating_add(BLOCK).min(bytes.len());
            let mut fid = offset;
            while fid + 16 <= bytes.len() && fid < end && repaired < 512 {
                if bytes[fid..fid + 2] != 257u16.to_le_bytes() {
                    break;
                }
                let Some(length) = repair_at(bytes, fid) else {
                    break;
                };
                if length < 38 {
                    break;
                }
                repaired += 1;
                fid += length;
            }
        }
        if repaired >= 512 {
            break;
        }
    }
}

/// Exercise raw integrity checks and a checksum-repaired view to reach deeper descriptors.
pub fn read(data: &[u8]) -> (ReadStats, ReadStats) {
    let original = read_once(data);
    if data.len() > IMAGE_LIMIT {
        return (original, ReadStats::default());
    }
    let mut repaired = data.to_vec();
    repair_tags(&mut repaired);
    let checked = if repaired != data {
        read_once(&repaired)
    } else {
        ReadStats::default()
    };
    (original, checked)
}

struct Recipe {
    image: UdfImage,
    options: UdfOptions,
    files: BTreeMap<String, Vec<u8>>,
    main: String,
    stream: Vec<u8>,
    flags: u8,
    deterministic: bool,
    existing: bool,
    cancel_at: Option<usize>,
    expected_valid: bool,
}
fn recipe(data: &[u8]) -> Option<Recipe> {
    if !(HEADER..=RECIPE_LIMIT).contains(&data.len()) {
        return None;
    }
    let revision = [
        UdfRevision::V102,
        UdfRevision::V150,
        UdfRevision::V200,
        UdfRevision::V201,
        UdfRevision::V250,
        UdfRevision::V260,
    ][usize::from(data[0] % 6)];
    let partition = match data[1] % 7 {
        0 => UdfPartition::Physical,
        1 => UdfPartition::PhysicalSplit,
        2 => UdfPartition::Virtual,
        3 => UdfPartition::Sparable { packet_blocks: 32 },
        4 => UdfPartition::Metadata { mirror: false },
        5 => UdfPartition::Metadata { mirror: true },
        _ => UdfPartition::MetadataSparable {
            mirror: true,
            packet_blocks: 32,
        },
    };
    let allocation = [
        AllocationMode::Short,
        AllocationMode::Long,
        AllocationMode::Extended,
        AllocationMode::Embedded,
    ][usize::from(data[2] % 4)];
    let strategy = [
        IcbStrategy::Direct,
        IcbStrategy::Indirect,
        IcbStrategy::Strategy4096,
    ][usize::from(data[4] % 3)];
    let fragmented = data[6] & 1 != 0;
    let chains = 1 + u16::from(data[7] % 4);
    let mut options = UdfOptions {
        revision,
        partition,
        allocation,
        icb_strategy: strategy,
        file_set_descriptors: chains,
        max_entries: 256,
        max_metadata_bytes: 2 << 20,
        max_entry_bytes: 1 << 20,
        max_total_bytes: 2 << 20,
        max_image_bytes: IMAGE_LIMIT as u64,
        max_nesting_depth: 16,
        metadata_extent_blocks: if fragmented { 32 } else { 0 },
        ..Default::default()
    };
    if data[5] != 0 {
        options.extent_blocks = 1 + u32::from(data[5] % 8);
    }
    if data[8] & 1 != 0 {
        options.max_entries = 4;
    }
    if data[8] & 2 != 0 {
        options.max_metadata_bytes = 256;
    }
    if data[8] & 4 != 0 {
        options.max_entry_bytes = 511;
    }
    if data[8] & 8 != 0 {
        options.max_total_bytes = 1023;
    }
    if data[8] & 16 != 0 {
        options.max_image_bytes = 1 << 20;
    }
    if data[8] & 32 != 0 {
        options.max_nesting_depth = 1;
    }
    let existing = data[8] & 64 != 0;
    let cancel_at = (data[8] & 128 != 0).then_some(1 + usize::from(data[11] % 16));
    let main = match data[9] % 8 {
        0 => "payload",
        1 => "dir/日本語.bin",
        2 => "dir/nested/file",
        3 => "/absolute",
        4 => "dir//file",
        5 => "dir\\file",
        6 => "../file",
        _ => "a/./file",
    }
    .to_owned();
    let flags = data[3];
    let mut files = BTreeMap::new();
    let mut image = UdfImage::new();
    let payload = &data[HEADER..];
    let expected = if flags & 16 != 0 {
        let mut pieces = Vec::new();
        let mut expected = Vec::new();
        for index in 0..1 + usize::from(data[14] % 128) {
            let byte = payload
                .get(index % payload.len().max(1))
                .copied()
                .unwrap_or(index as u8);
            let block = vec![byte; BLOCK];
            expected.extend_from_slice(&block);
            expected.resize(expected.len() + BLOCK, 0);
            pieces.push(UdfFileExtent::Data(block));
            pieces.push(if data[15] & 1 == 0 {
                UdfFileExtent::Hole(BLOCK as u64)
            } else {
                UdfFileExtent::AllocatedHole(BLOCK as u64)
            });
        }
        let tail = payload[..payload.len().min(BLOCK)].to_vec();
        expected.extend_from_slice(&tail);
        pieces.push(UdfFileExtent::Data(tail));
        image.add_sparse_file(&main, pieces).ok()?;
        expected
    } else {
        image.add_bytes(&main, payload.to_vec()).ok()?;
        payload.to_vec()
    };
    files.insert(main.clone(), expected.clone());
    image.add_bytes("empty", Vec::new()).ok()?;
    files.insert("empty".into(), Vec::new());
    let small = payload[..payload.len().min(32)].to_vec();
    image.add_bytes("small", small.clone()).ok()?;
    files.insert("small".into(), small);
    let stream = payload[..payload.len().min(1024)].to_vec();
    if flags & 1 != 0 {
        image.add_named_stream(&main, "note", stream.clone()).ok()?;
    }
    if flags & 2 != 0 {
        image
            .add_system_stream("application", stream.clone())
            .ok()?;
    }
    if flags & 4 != 0 {
        image.add_symlink("link", format!("../{main}")).ok()?;
    }
    if flags & 8 != 0 {
        image.add_hard_link("alias", &main).ok()?;
        files.insert("alias".into(), expected);
    }
    if flags & 32 != 0 {
        image
            .set_preallocated_blocks(&main, u32::from(data[10] % 9))
            .ok()?;
    }
    if flags & 64 != 0 {
        image.add_root_stream("root-note", stream.clone()).ok()?;
    }
    if flags & 128 != 0 {
        for (name, size, byte) in [("boot/bios.bin", 4096, 0x31), ("boot/efi.bin", 8192, 0x72)] {
            let bytes = vec![byte; size];
            image.add_bytes(name, bytes.clone()).ok()?;
            files.insert(name.into(), bytes);
        }
        options.boot = BootOptions {
            bios: Some(BootImage::bios("boot/bios.bin")),
            efi: Some(BootImage::efi("boot/efi.bin")),
        };
    }
    if data[15] & 2 != 0 {
        options.sparing_packets = vec![0];
    }
    let metadata = matches!(
        partition,
        UdfPartition::Metadata { .. } | UdfPartition::MetadataSparable { .. }
    );
    let physical = matches!(
        partition,
        UdfPartition::Physical | UdfPartition::PhysicalSplit
    );
    let sparable = matches!(
        partition,
        UdfPartition::Sparable { .. } | UdfPartition::MetadataSparable { .. }
    );
    let qualified = matches!(allocation, AllocationMode::Long | AllocationMode::Embedded);
    let expected_valid = data[8] == 0
        && (flags & (1 | 2 | 64) == 0 || revision.number() >= 0x200)
        && (strategy != IcbStrategy::Strategy4096 || physical)
        && (chains == 1 || physical)
        && (!fragmented || metadata)
        && (data[15] & 2 == 0 || sparable)
        && match partition {
            UdfPartition::Physical => true,
            UdfPartition::PhysicalSplit => allocation != AllocationMode::Short,
            UdfPartition::Virtual => (0x150..=0x201).contains(&revision.number()) && qualified,
            UdfPartition::Sparable { .. } => (0x150..=0x201).contains(&revision.number()),
            _ => revision.number() >= 0x250 && qualified,
        };
    Some(Recipe {
        image,
        options,
        files,
        main,
        stream,
        flags,
        deterministic: data[12] & 1 != 0,
        existing,
        cancel_at,
        expected_valid,
    })
}

fn write_recipe(recipe: &Recipe) -> Option<Vec<u8>> {
    let directory = tempfile::tempdir().expect("UDF fuzz temporary directory");
    let output = directory.path().join("image.udf");
    if recipe.existing {
        std::fs::write(&output, b"preserve").unwrap();
    }
    let mut calls = 0;
    let result = recipe
        .image
        .write_with_cancel(&output, &recipe.options, || {
            calls += 1;
            if recipe.cancel_at == Some(calls) {
                Err(std::io::Error::other("fuzz cancellation").into())
            } else {
                Ok(())
            }
        });
    let hash = match result {
        Ok(hash) => hash,
        Err(error) => {
            assert!(
                !recipe.expected_valid,
                "valid UDF recipe rejected: {error:#}"
            );
            if recipe.existing {
                assert_eq!(std::fs::read(&output).unwrap(), b"preserve");
            } else {
                assert!(!output.exists());
            }
            assert_eq!(
                std::fs::read_dir(directory.path()).unwrap().count(),
                usize::from(recipe.existing)
            );
            return None;
        }
    };
    assert!(!recipe.existing);
    let bytes = std::fs::read(&output).unwrap();
    assert!(bytes.len() <= IMAGE_LIMIT);
    assert_eq!(hash, format!("{:x}", Sha256::digest(&bytes)));
    assert!(recipe.image.write(&output, &recipe.options).is_err());
    assert_eq!(std::fs::read(&output).unwrap(), bytes);
    if recipe.deterministic {
        let second = directory.path().join("second.udf");
        assert_eq!(recipe.image.write(&second, &recipe.options).unwrap(), hash);
        assert_eq!(std::fs::read(second).unwrap(), bytes);
    }
    Some(bytes)
}

fn check_recipe(recipe: &Recipe, bytes: &[u8]) -> ReadStats {
    let reader =
        UdfReader::open(bytes, limits()).expect("authored UDF must parse within writer budgets");
    let mut files = 0;
    let mut streams = 0;
    let mut links = 0;
    let main = reader
        .entries()
        .iter()
        .find(|entry| entry.name == recipe.main && entry.stream.is_none())
        .expect("main file");
    for (index, entry) in reader.entries().iter().enumerate() {
        if let Some(stream) = &entry.stream {
            streams += 1;
            assert_eq!(reader.read_entry(index, 1024).unwrap(), recipe.stream);
            match stream.name.as_str() {
                "note" => {
                    assert_eq!(recipe.flags & 1, 1);
                    assert!(!stream.system);
                    assert_eq!(
                        reader.entries()[stream.owner.expect("named stream owner")].icb,
                        main.icb
                    );
                }
                "application" => {
                    assert_eq!(recipe.flags & 2, 2);
                    assert!(stream.system);
                    assert!(stream.owner.is_none());
                }
                "root-note" => {
                    assert_eq!(recipe.flags & 64, 64);
                    assert!(!stream.system);
                    assert!(stream.owner.is_none());
                }
                _ => panic!("unexpected authored stream"),
            }
        } else if entry.kind == EntryKind::SymbolicLink {
            links += 1;
            assert_eq!(entry.name, "link");
            assert_eq!(
                entry.link_target.as_deref(),
                Some(format!("../{}", recipe.main).as_str())
            );
        } else if entry.kind == EntryKind::File {
            files += 1;
            assert_eq!(
                &reader.read_entry(index, limits().max_entry_bytes).unwrap(),
                recipe
                    .files
                    .get(&entry.name)
                    .expect("unexpected authored file")
            );
            if entry.name == "alias" {
                assert_eq!(entry.icb, main.icb);
            }
        }
    }
    assert_eq!(files, recipe.files.len());
    assert_eq!(links, usize::from(recipe.flags & 4 != 0));
    assert_eq!(
        streams,
        [1, 2, 64]
            .iter()
            .filter(|bit| recipe.flags & **bit != 0)
            .count()
    );
    if !recipe.options.boot.is_empty() {
        let descriptor = &bytes[17 * BLOCK..18 * BLOCK];
        let catalog = u32::from_le_bytes(descriptor[71..75].try_into().unwrap()) as usize * BLOCK;
        for (offset, name) in [(40, "boot/bios.bin"), (104, "boot/efi.bin")] {
            let block = u32::from_le_bytes(
                bytes[catalog + offset..catalog + offset + 4]
                    .try_into()
                    .unwrap(),
            ) as usize
                * BLOCK;
            let payload = &recipe.files[name];
            assert_eq!(bytes.get(block..block + payload.len()).unwrap(), payload);
        }
    }
    read_once(bytes)
}

/// Author a bounded structured tree, then compare every payload, stream and link.
/// Invalid names/profile combinations and explicit budgets/cancellation may reject normally.
pub fn roundtrip(data: &[u8]) -> RoundtripStats {
    let Some(recipe) = recipe(data) else {
        return RoundtripStats::default();
    };
    let Some(bytes) = write_recipe(&recipe) else {
        return RoundtripStats::default();
    };
    RoundtripStats {
        written: true,
        image_bytes: bytes.len(),
        reader: check_recipe(&recipe, &bytes),
    }
}

/// Generate a complete valid corpus image using the same recipe and identity oracle.
pub fn seed_image(data: &[u8]) -> Option<Vec<u8>> {
    let recipe = recipe(data)?;
    let bytes = write_recipe(&recipe)?;
    let _ = check_recipe(&recipe, &bytes);
    Some(bytes)
}

/// Valid configurations spanning every revision, partition and allocation encoding.
pub fn seed_recipes() -> Vec<(String, Vec<u8>)> {
    let mut result = Vec::new();
    for revision in 0..6u8 {
        let mut profiles = vec![(0, 0), (0, 1), (0, 2), (0, 3), (1, 1), (1, 2), (1, 3)];
        if (1..=3).contains(&revision) {
            profiles.extend([(2, 1), (2, 3), (3, 0), (3, 1), (3, 2), (3, 3)]);
        }
        if revision >= 4 {
            profiles.extend([(4, 1), (4, 3), (5, 1), (5, 3), (6, 1), (6, 3)]);
        }
        for (partition, allocation) in profiles {
            let mut recipe = vec![0; HEADER];
            recipe[0] = revision;
            recipe[1] = partition;
            recipe[2] = allocation;
            recipe[3] = if revision >= 2 { 0x7f } else { 0x3c };
            recipe[5] = 1;
            recipe[6] = u8::from(partition >= 4);
            recipe[9] = 1;
            recipe[10] = 3;
            recipe[14] = 127;
            recipe.extend_from_slice(b"UDF fuzz payload");
            result.push((
                format!("revision-{revision}-partition-{partition}-allocation-{allocation}"),
                recipe,
            ));
        }
    }
    for (name, revision, partition, allocation, strategy, flags, chains, spare) in [
        ("indirect-icbs", 3, 0, 1, 1, 0x7f, 0, 0),
        ("worm-file-sets", 3, 0, 1, 2, 0x7f, 3, 0),
        ("boot-embedded", 5, 5, 3, 0, 0xff, 0, 0),
        ("sparing-remaps", 3, 3, 1, 0, 0x7f, 0, 2),
        ("metadata-sparing-remaps", 5, 6, 1, 1, 0x7f, 0, 2),
        ("allocated-sparse-extended", 3, 0, 2, 0, 0x7f, 0, 1),
    ] {
        let mut recipe = vec![0; HEADER];
        recipe[0] = revision;
        recipe[1] = partition;
        recipe[2] = allocation;
        recipe[3] = flags;
        recipe[4] = strategy;
        recipe[5] = 1;
        recipe[6] = u8::from(partition >= 4);
        recipe[7] = chains;
        recipe[9] = 1;
        recipe[10] = 3;
        recipe[12] = 1;
        recipe[14] = 100;
        recipe[15] = spare;
        recipe.extend_from_slice(b"rich UDF fuzz seed");
        result.push((name.into(), recipe));
    }
    result
}

/// Complete fragmented metadata, damaged-primary mirror recovery and metadata AED seeds.
/// Adapted from windows-uup's MIT seed_udf generator (LICENSE.archive-rs).
pub type MetadataSeeds = Vec<(&'static str, Vec<u8>)>;

pub fn metadata_seeds() -> Result<MetadataSeeds, Box<dyn std::error::Error>> {
    let mut result = Vec::new();
    // Enough metadata blocks to span fragments, while staying below reader entry budgets.
    let directory = tempfile::tempdir()?;
    let image_path = directory.path().join("metadata.udf");
    let mut tree = UdfImage::new();
    for index in 0..80 {
        tree.add_bytes(format!("file-{index:03}"), vec![index as u8; 31])?;
    }
    tree.write(
        &image_path,
        &UdfOptions {
            revision: UdfRevision::V260,
            partition: UdfPartition::Metadata { mirror: true },
            allocation: AllocationMode::Long,
            metadata_extent_blocks: 32,
            max_image_bytes: IMAGE_LIMIT as u64,
            ..Default::default()
        },
    )?;
    let bytes = std::fs::read(image_path)?;
    assert!(read_once(&bytes).opened);
    result.push(("metadata-fragments.udf", bytes.clone()));
    let mut damaged = bytes.clone();
    damaged[(320 + 32) * 2048 + 112] ^= 1;
    assert!(read_once(&damaged).opened);
    result.push(("metadata-mirror-recovery.udf", damaged));
    let mut chained = bytes;
    let fe = 320 * 2048;
    let length = u32::from_le_bytes(chained[fe + 172..fe + 176].try_into()?) as usize;
    let allocations = chained[fe + 176..fe + 176 + length].to_vec();
    let aed_block = 64u32; // Reserved gap following the first metadata fragment.
    let aed = (320 + aed_block as usize) * 2048;
    chained[aed..aed + 2048].fill(0);
    chained[aed..aed + 2].copy_from_slice(&258u16.to_le_bytes());
    chained[aed + 2..aed + 4].copy_from_slice(&3u16.to_le_bytes());
    chained[aed + 6..aed + 8].copy_from_slice(&1u16.to_le_bytes());
    chained[aed + 10..aed + 12].copy_from_slice(&((8 + length) as u16).to_le_bytes());
    chained[aed + 12..aed + 16].copy_from_slice(&aed_block.to_le_bytes());
    chained[aed + 20..aed + 24].copy_from_slice(&(length as u32).to_le_bytes());
    chained[aed + 24..aed + 24 + length].copy_from_slice(&allocations);
    chained[fe + 176..fe + 2048].fill(0);
    chained[fe + 172..fe + 176].copy_from_slice(&8u32.to_le_bytes());
    chained[fe + 176..fe + 180].copy_from_slice(&0xc0000800u32.to_le_bytes());
    chained[fe + 180..fe + 184].copy_from_slice(&aed_block.to_le_bytes());
    chained[fe + 10..fe + 12].copy_from_slice(&168u16.to_le_bytes());
    repair_tags(&mut chained);
    assert!(read_once(&chained).opened);
    result.push(("metadata-allocation-chain.udf", chained));
    Ok(result)
}
