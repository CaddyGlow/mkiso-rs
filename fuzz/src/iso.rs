//! Structured ISO authoring, namespace identity and publication oracles.
use libmkiso::{
    AdvancedBootOptions, BootEmulation, BootEntry, FilenamePolicy, HybridLayout, HybridOptions,
    IsoLevel, IsoOptions, MbrBootPatch, UnixMetadataOptions,
    iso9660::{IsoReader, Namespace, ReadOptions},
};
use std::{collections::BTreeMap, fs, io::Cursor};

pub const HEADER: usize = 16;
pub const RECIPE_LIMIT: usize = (32 << 10) + HEADER;

#[derive(Debug, Default)]
pub struct Stats {
    pub written: bool,
    pub namespaces: usize,
    pub links: usize,
    pub multi_extent: bool,
    pub boot: bool,
    pub hybrid: bool,
}

/// First 16 bytes configure level, namespaces, boot layout, names, cancellation and budgets.
/// Invalid option combinations may reject; valid recipes must write and roundtrip.
pub fn seed_image(data: &[u8]) -> Option<(Vec<u8>, Stats)> {
    if !(HEADER..=RECIPE_LIMIT).contains(&data.len()) {
        return None;
    }
    let payload = &data[HEADER..];
    let level = [IsoLevel::Level1, IsoLevel::Level2, IsoLevel::Level3][usize::from(data[0] % 3)];
    let joliet = data[1] & 1 != 0;
    let rr = data[1] & 2 != 0;
    let rich_names = data[2] & 1 != 0;
    let boot = data[3] % 4;
    let hybrid = data[4] % 4;
    #[cfg(unix)]
    let links = data[5] & 1 != 0 && rr;
    let mut options = IsoOptions {
        level,
        joliet,
        rock_ridge: rr,
        joliet_level: 1 + data[6] % 3,
        joliet_max_name: 103,
        filename_policy: if rich_names {
            FilenamePolicy::Mangle
        } else {
            FilenamePolicy::Strict
        },
        extent_bytes: 2048 * (1 + u32::from(data[7] % 4)),
        unix_metadata: UnixMetadataOptions {
            uid: u32::from(data[8]),
            gid: u32::from(data[9]),
            file_mode: 0o600 | u32::from(data[10] & 0o77),
            directory_mode: 0o755,
            ..Default::default()
        },
        max_entries: 128,
        max_metadata_bytes: 1 << 20,
        max_image_bytes: super::MAX_INPUT as u64,
        ..Default::default()
    };
    // Vary representable volume metadata and leap-day timestamps.
    options.volume_metadata.publisher = format!("FUZZ-{}", data[8]);
    options.timestamp.year = if data[11] & 1 == 0 { 2000 } else { 2024 };
    options.timestamp.month = 2;
    options.timestamp.day = 29;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir_all(source.join("DIR")).unwrap();
    let mut files = BTreeMap::new();
    files.insert("DIR/PAYLOAD.BIN".to_owned(), payload.to_vec());
    files.insert("EMPTY.TXT".to_owned(), Vec::new());
    if rich_names {
        files.insert("Mixed Directory/日本語.txt".into(), b"Unicode".to_vec());
        files.insert("a".repeat(100), b"long name".to_vec());
        // These collide in the primary namespace before deterministic aliasing.
        files.insert("lower name.txt".into(), b"lower".to_vec());
        files.insert("lower-name.txt".into(), b"upper".to_vec());
    }
    for (name, bytes) in &files {
        let path = source.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    #[cfg(unix)]
    if links {
        std::os::unix::fs::symlink("DIR/PAYLOAD.BIN", source.join("LINK")).unwrap();
        let target = std::iter::repeat_n("x".repeat(200), 15)
            .collect::<Vec<_>>()
            .join("/");
        std::os::unix::fs::symlink(target, source.join("LONGLINK")).unwrap();
        fs::hard_link(source.join("DIR/PAYLOAD.BIN"), source.join("ALIAS.BIN")).unwrap();
        files.insert("ALIAS.BIN".into(), payload.to_vec());
    }
    let mut patched = false;
    let emulation = if boot == 3 || hybrid != 0 {
        [
            BootEmulation::None,
            BootEmulation::HardDisk,
            BootEmulation::Floppy1200,
            BootEmulation::Floppy1440,
            BootEmulation::Floppy2880,
        ][usize::from((data[3] / 4) % 5)]
    } else {
        BootEmulation::None
    };
    let bios_size = match emulation {
        BootEmulation::Floppy1200 => 1200 * 1024,
        BootEmulation::Floppy1440 => 1440 * 1024,
        BootEmulation::Floppy2880 => 2880 * 1024,
        _ => 4096,
    };
    if boot != 0 || hybrid != 0 {
        let mut bios_bytes = vec![0x31; bios_size];
        if emulation == BootEmulation::HardDisk {
            bios_bytes[446..510].fill(0);
            bios_bytes[450] = 0x83;
            bios_bytes[510..512].copy_from_slice(&[0x55, 0xaa]);
        }
        fs::write(source.join("BIOS.BIN"), &bios_bytes).unwrap();
        fs::write(source.join("EFI.IMG"), vec![0x72; 8192]).unwrap();
        files.insert("BIOS.BIN".into(), bios_bytes);
        files.insert("EFI.IMG".into(), vec![0x72; 8192]);
        if boot == 1 && hybrid == 0 {
            options.boot.bios = Some(libmkiso::BootImage::bios("BIOS.BIN"));
        } else if boot == 2 && hybrid == 0 {
            options.boot.efi = Some(libmkiso::BootImage::efi("EFI.IMG"));
        } else {
            let mut bios = BootEntry::bios("BIOS.BIN");
            patched = data[12] & 1 != 0;
            bios.emulation = emulation;
            if emulation == BootEmulation::HardDisk {
                bios.system_type = 0x83;
            }
            bios.boot_info_table = patched;
            bios.grub2_boot_info = patched;
            bios.image.load_segment = u16::from(data[8]) << 8;
            let mut efi = BootEntry::efi("EFI.IMG");
            efi.selection[0] = data[9];
            options.advanced_boot = AdvancedBootOptions {
                entries: vec![bios, efi],
                catalog_id: "libmkiso fuzz".into(),
            };
        }
        if hybrid != 0 {
            options.hybrid = Some(HybridOptions {
                mbr_boot_code: vec![0x90; 440],
                layout: [HybridLayout::Mbr, HybridLayout::Gpt, HybridLayout::MbrGpt]
                    [usize::from(hybrid - 1)],
                mbr_patch: [
                    MbrBootPatch::None,
                    MbrBootPatch::Syslinux,
                    MbrBootPatch::Grub2,
                ][usize::from(data[13] % 3)],
                efi_partition: Some("EFI.IMG".into()),
                ..Default::default()
            });
        }
    }
    let flags = data[14];
    if flags & 1 != 0 {
        options.max_entries = 1;
    }
    if flags & 2 != 0 {
        options.max_metadata_bytes = 1;
    }
    if flags & 4 != 0 {
        options.max_image_bytes = 2048;
    }
    if flags & 8 != 0 {
        options.timestamp.day = 30;
    }
    let existing = flags & 16 != 0;
    let cancel = flags & 32 != 0;
    let fail_progress = flags & 64 != 0;
    let output = dir.path().join("image.iso");
    if existing {
        fs::write(&output, b"preserve").unwrap();
    }
    let mut calls = 0;
    let mut previous = 0;
    let mut total = None;
    let mut cancelled = false;
    let mut progress_failed = false;
    let result = libmkiso::write_iso9660_with_options_and_progress(
        &source,
        &output,
        &options,
        || {
            calls += 1;
            if cancel && calls == 1 + usize::from(data[15] % 16) {
                cancelled = true;
                Err(libmkiso::iso9660::Error::Io(std::io::Error::other(
                    "fuzz cancellation",
                )))
            } else {
                Ok(())
            }
        },
        |done, size| {
            assert!(done >= previous && done <= size);
            assert!(total.is_none_or(|old| old == size));
            previous = done;
            total = Some(size);
            if fail_progress {
                progress_failed = true;
                Err(libmkiso::iso9660::Error::Io(std::io::Error::other(
                    "fuzz progress failure",
                )))
            } else {
                Ok(())
            }
        },
    );
    if let Err(error) = result {
        assert!(
            flags & 31 != 0 || cancelled || progress_failed,
            "valid ISO recipe rejected: {error}"
        );
        if existing {
            assert_eq!(fs::read(&output).unwrap(), b"preserve");
        } else {
            assert!(!output.exists());
        }
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1 + usize::from(existing)
        );
        return None;
    }
    assert!(!existing && !cancelled && !progress_failed);
    assert_eq!(Some(previous), total);
    let image = fs::read(&output).unwrap();
    assert!(image.len() <= super::MAX_INPUT);
    assert!(libmkiso::write_iso9660_with_options(&source, &output, &options).is_err());
    assert_eq!(fs::read(&output).unwrap(), image);
    if data[12] & 2 != 0 {
        let second = dir.path().join("second.iso");
        libmkiso::write_iso9660_with_options(&source, &second, &options).unwrap();
        assert_eq!(fs::read(second).unwrap(), image);
    }
    let mut stats = Stats {
        written: true,
        boot: boot != 0 || hybrid != 0,
        hybrid: hybrid != 0,
        ..Default::default()
    };
    for namespace in [Namespace::Primary, Namespace::Joliet, Namespace::RockRidge] {
        if namespace == Namespace::Joliet && !joliet || namespace == Namespace::RockRidge && !rr {
            continue;
        }
        let mut reader = IsoReader::open_with_options(
            Cursor::new(&image),
            ReadOptions {
                namespace,
                ..Default::default()
            },
        )
        .unwrap();
        stats.namespaces += 1;
        let mut actual = Vec::new();
        for index in 0..reader.entries().len() {
            let entry = reader.entries()[index].clone();
            if entry.directory {
                continue;
            }
            #[cfg(unix)]
            if links
                && namespace != Namespace::RockRidge
                && (entry.name == "LINK" || entry.name == "LONGLINK")
            {
                let mut bytes = Vec::new();
                reader.extract(index, &mut bytes).unwrap();
                assert!(bytes.is_empty());
                continue;
            }
            if let Some(target) = entry.link_target {
                stats.links += 1;
                assert!(
                    target == "DIR/PAYLOAD.BIN"
                        || target
                            == std::iter::repeat_n("x".repeat(200), 15)
                                .collect::<Vec<_>>()
                                .join("/")
                );
                continue;
            }
            let mut bytes = Vec::new();
            reader.extract(index, &mut bytes).unwrap();
            if patched && entry.name == "BIOS.BIN" {
                assert_eq!(bytes.len(), bios_size);
                assert_eq!(&bytes[..8], &files["BIOS.BIN"][..8]);
                assert_eq!(&bytes[64..2548], &files["BIOS.BIN"][64..2548]);
                assert_eq!(&bytes[2556..], &files["BIOS.BIN"][2556..]);
                continue;
            }
            if namespace == Namespace::Primary && rich_names {
                actual.push(bytes);
            } else {
                assert_eq!(
                    bytes,
                    *files.get(&entry.name).expect("unexpected authored file")
                );
                if namespace == Namespace::RockRidge {
                    let unix = entry.unix.as_ref().unwrap();
                    assert_eq!(unix.uid, options.unix_metadata.uid);
                    assert_eq!(unix.gid, options.unix_metadata.gid);
                }
            }
        }
        if namespace == Namespace::Primary && rich_names {
            let mut expected: Vec<_> = files
                .iter()
                .filter(|(name, _)| !patched || name.as_str() != "BIOS.BIN")
                .map(|(_, bytes)| bytes.clone())
                .collect();
            actual.sort();
            expected.sort();
            assert_eq!(actual, expected);
        }
    }
    let mut cursor = Cursor::new(&image);
    let index = libmkiso::iso9660::read_index(&mut cursor, Default::default()).unwrap();
    stats.multi_extent = index.extents.iter().any(|extents| extents.len() > 1);
    if level == IsoLevel::Level3 && payload.len() > options.extent_bytes as usize {
        assert!(stats.multi_extent);
    }
    if let Some(hybrid) = &options.hybrid {
        assert_eq!(&image[510..512], &[0x55, 0xaa]);
        if hybrid.layout != HybridLayout::Mbr {
            assert_eq!(&image[512..520], b"EFI PART");
            assert_eq!(&image[image.len() - 512..image.len() - 504], b"EFI PART");
        }
    }
    if stats.boot {
        let descriptor = image
            .chunks_exact(2048)
            .skip(16)
            .find(|sector| sector[0] == 0 && &sector[7..30] == b"EL TORITO SPECIFICATION")
            .unwrap();
        let offset = u32::from_le_bytes(descriptor[71..75].try_into().unwrap()) as usize * 2048;
        let catalog = &image[offset..offset + 2048];
        assert_eq!(&catalog[30..32], &[0x55, 0xaa]);
        assert_eq!(
            catalog[..32].chunks_exact(2).fold(0u16, |sum, word| sum
                .wrapping_add(u16::from_le_bytes(word.try_into().unwrap()))),
            0
        );
    }
    super::iso9660(&image);
    Some((image, stats))
}

pub fn roundtrip(data: &[u8]) -> Stats {
    seed_image(data).map(|(_, stats)| stats).unwrap_or_default()
}

pub fn seed_recipes() -> Vec<(String, Vec<u8>)> {
    let mut seeds = Vec::new();
    for level in 0..3 {
        for namespaces in 0..4 {
            for boot in 0..4 {
                let mut recipe = vec![0; HEADER];
                recipe[0] = level;
                recipe[1] = namespaces;
                recipe[2] = 1;
                recipe[3] = boot;
                recipe[5] = 1;
                recipe[6] = boot % 3;
                recipe[8] = 42;
                recipe[9] = 7;
                recipe[12] = 3;
                recipe.extend((0..10001).map(|i| (i % 251) as u8));
                seeds.push((
                    format!("level-{level}-namespaces-{namespaces}-boot-{boot}"),
                    recipe,
                ));
            }
        }
    }
    for layout in 1..4 {
        for patch in 0..3 {
            let mut recipe = vec![0; HEADER];
            recipe[0] = 2;
            recipe[1] = 3;
            recipe[2] = 1;
            recipe[4] = layout;
            recipe[5] = 1;
            recipe[12] = 3;
            recipe[13] = patch;
            recipe.extend_from_slice(b"hybrid payload");
            seeds.push((format!("hybrid-{layout}-patch-{patch}"), recipe));
        }
    }
    for emulation in 1..5 {
        let mut recipe = vec![0; HEADER];
        recipe[0] = 2;
        recipe[1] = 3;
        recipe[3] = 3 + emulation * 4;
        recipe[12] = 1;
        recipe.extend_from_slice(b"boot emulation seed");
        seeds.push((format!("emulation-{emulation}"), recipe));
    }
    let mut strict = vec![0; HEADER];
    strict.extend_from_slice(b"strict names");
    seeds.push(("strict-primary".into(), strict));
    seeds
}
