//! Bounded optical image fuzz harnesses, also callable without instrumentation.
pub mod iso;
pub mod media;
pub mod udf;

use libmkiso::{
    iso9660::{IsoReader, Namespace, ReadOptions},
    udf::UdfReader,
};
use std::io::{self, Cursor, Write};

pub const MAX_INPUT: usize = 8 << 20;
const MAX_PAYLOAD: usize = 32 << 10;
const MAX_METADATA: u64 = 1 << 20;

// Stop extraction even when malformed sparse allocations claim large output.
struct BoundedOutput {
    remaining: usize,
    written: u64,
}
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let count = bytes.len().min(self.remaining);
        if count == 0 {
            return Err(io::Error::other("fuzz output budget exhausted"));
        }
        self.remaining -= count;
        self.written += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Parse all namespace selections, then exercise extraction and invalid indices.
pub fn iso9660(data: &[u8]) {
    if data.len() > MAX_INPUT {
        return;
    }
    for namespace in [
        Namespace::Primary,
        Namespace::Joliet,
        Namespace::PreferJoliet,
        Namespace::RockRidge,
        Namespace::PreferRockRidge,
    ] {
        let options = ReadOptions {
            namespace,
            limits: libmkiso::iso9660::Limits {
                max_entries: 128,
                max_metadata_bytes: MAX_METADATA,
                max_nesting_depth: 16,
            },
        };
        if let Ok(mut reader) = IsoReader::open_with_options(Cursor::new(data), options) {
            let mut output = BoundedOutput {
                remaining: MAX_PAYLOAD,
                written: 0,
            };
            for index in 0..reader.entries().len() {
                let size = reader.entries()[index].size;
                let before = output.written;
                if let Ok(count) = reader.extract(index, &mut output) {
                    assert_eq!(count, size);
                    assert_eq!(count, output.written - before);
                }
            }
            assert!(reader.extract(reader.entries().len(), &mut output).is_err());
        }
    }
}

/// Exercise both raw and checksum-repaired UDF descriptors.
pub fn udf(data: &[u8]) {
    let _ = udf::read(data);
}

/// Generate valid images for both parser seeds and roundtrip checks.
/// The first byte selects options; the remaining bytes are file content.
pub fn images(data: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let selector = data.first().copied().unwrap_or(0);
    let payload = data.get(1..).unwrap_or_default();
    let payload = &payload[..payload.len().min(MAX_PAYLOAD)];
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    std::fs::create_dir_all(source.join("DIR")).unwrap();
    std::fs::write(source.join("DIR/PAYLOAD.BIN"), payload).unwrap();
    std::fs::write(source.join("EMPTY.TXT"), []).unwrap();
    let iso_path = temp.path().join("iso.img");
    let iso_options = libmkiso::IsoOptions {
        joliet: true,
        rock_ridge: true,
        extent_bytes: if selector & 1 == 0 { 2048 } else { 4096 },
        max_image_bytes: MAX_INPUT as u64,
        ..Default::default()
    };
    libmkiso::write_iso9660_with_options(&source, &iso_path, &iso_options).unwrap();
    let udf_path = temp.path().join("udf.img");
    let udf_options = libmkiso::UdfOptions {
        revision: libmkiso::UdfRevision::V260,
        partition: match selector % 5 {
            0 => libmkiso::UdfPartition::Physical,
            1 => libmkiso::UdfPartition::PhysicalSplit,
            2 => libmkiso::UdfPartition::Virtual,
            3 => libmkiso::UdfPartition::Sparable { packet_blocks: 32 },
            _ => libmkiso::UdfPartition::Metadata {
                mirror: selector & 8 != 0,
            },
        },
        allocation: match (selector / 5) % 4 {
            0 => libmkiso::AllocationMode::Short,
            1 => libmkiso::AllocationMode::Long,
            2 => libmkiso::AllocationMode::Extended,
            _ => libmkiso::AllocationMode::Embedded,
        },
        icb_strategy: match (selector / 20) % 3 {
            0 => libmkiso::IcbStrategy::Direct,
            1 => libmkiso::IcbStrategy::Indirect,
            _ => libmkiso::IcbStrategy::Strategy4096,
        },
        extent_blocks: 1,
        max_image_bytes: MAX_INPUT as u64,
        ..Default::default()
    };
    // Select only combinations accepted by the authored UDF profiles.
    let mut udf_options = udf_options;
    match udf_options.partition {
        libmkiso::UdfPartition::PhysicalSplit => {
            if udf_options.allocation == libmkiso::AllocationMode::Short {
                udf_options.allocation = libmkiso::AllocationMode::Long;
            }
        }
        libmkiso::UdfPartition::Virtual | libmkiso::UdfPartition::Metadata { .. } => {
            if udf_options.allocation != libmkiso::AllocationMode::Embedded {
                udf_options.allocation = libmkiso::AllocationMode::Long;
            }
            if udf_options.icb_strategy == libmkiso::IcbStrategy::Strategy4096 {
                udf_options.icb_strategy = libmkiso::IcbStrategy::Indirect;
            }
            if udf_options.partition == libmkiso::UdfPartition::Virtual {
                udf_options.revision = libmkiso::UdfRevision::V201;
            }
        }
        libmkiso::UdfPartition::Sparable { .. } => {
            udf_options.revision = libmkiso::UdfRevision::V201;
            if udf_options.icb_strategy == libmkiso::IcbStrategy::Strategy4096 {
                udf_options.icb_strategy = libmkiso::IcbStrategy::Indirect;
            }
        }
        _ => {}
    }
    libmkiso::write_udf_with_options(&source, &udf_path, &udf_options).unwrap();
    std::fs::create_dir_all(source.join("boot")).unwrap();
    std::fs::create_dir_all(source.join("efi/microsoft/boot")).unwrap();
    std::fs::write(source.join("boot/etfsboot.com"), vec![0x31; 4096]).unwrap();
    std::fs::write(
        source.join("efi/microsoft/boot/efisys.bin"),
        vec![0x72; 8192],
    )
    .unwrap();
    let bridge_path = temp.path().join("bridge.img");
    libmkiso::write_iso(&source, &bridge_path).unwrap();
    vec![
        ("bridge", std::fs::read(bridge_path).unwrap()),
        ("iso9660", std::fs::read(iso_path).unwrap()),
        ("udf", std::fs::read(udf_path).unwrap()),
    ]
}

/// Writer/reader consistency oracle; not an independent compatibility check.
pub fn roundtrip(data: &[u8]) {
    let payload = data.get(1..).unwrap_or_default();
    let payload = &payload[..payload.len().min(MAX_PAYLOAD)];
    for (format, image) in images(data) {
        assert!(image.len() <= MAX_INPUT);
        if format == "bridge" {
            iso9660(&image);
            let reader = IsoReader::open(Cursor::new(&image), Default::default()).unwrap();
            // The legacy bridge writer intentionally authors an empty ISO root.
            assert!(reader.entries().is_empty());
        }
        if format == "iso9660" {
            iso9660(&image);
            let mut reader = IsoReader::open(Cursor::new(&image), Default::default()).unwrap();
            let index = reader
                .entries()
                .iter()
                .position(|entry| entry.name == "DIR/PAYLOAD.BIN")
                .unwrap();
            let mut actual = Vec::new();
            reader.extract(index, &mut actual).unwrap();
            assert_eq!(actual, payload);
        }
        if format != "iso9660" {
            udf(&image);
            let reader = UdfReader::open(&image, Default::default()).unwrap();
            let index = reader
                .entries()
                .iter()
                .position(|entry| entry.name == "DIR/PAYLOAD.BIN")
                .unwrap();
            assert_eq!(
                reader.read_entry(index, MAX_PAYLOAD as u64).unwrap(),
                payload
            );
        }
    }
}

pub fn run(target: &str, data: &[u8]) -> Result<(), &'static str> {
    match target {
        "iso9660" => iso9660(data),
        "bridge" => {
            iso9660(data);
            udf(data);
        }
        "udf" => udf(data),
        "roundtrip" => roundtrip(data),
        "iso_roundtrip" => {
            let _ = iso::roundtrip(data);
        }
        "udf_roundtrip" => {
            let _ = udf::roundtrip(data);
        }
        "media" => media::read(data),
        _ => return Err("unknown fuzz target"),
    }
    Ok(())
}
