//! Read-only UDF 1.02–2.60 physical, virtual, sparable and metadata partition profiles.
//! Short/long/extended uncompressed allocations, embedded data and Extended File Entries are supported.
//! Sparse data and bounded allocation continuations are supported.
//! Named/system streams, symbolic links, hard-link identities and bounded indirect ICBs are indexed.
//! Descriptor layouts: ECMA-167, third edition, parts 3 and 4, and ECMA TR/112.
/// UDF reader failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Source or output I/O failed.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Invalid descriptor or extent.
    #[error("malformed UDF: {0}")]
    Malformed(String),
    /// Unsupported UDF profile.
    #[error("unsupported UDF: {0}")]
    Unsupported(String),
    /// Descriptor checksum failed.
    #[error("UDF integrity failure: {0}")]
    Integrity(String),
    /// Configured resource budget exceeded.
    #[error("UDF resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
}
/// UDF reader result.
pub type Result<T> = std::result::Result<T, Error>;
/// Budgets checked before metadata allocation and traversal.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum indexed entries, including pending traversal.
    pub max_entries: u64,
    /// Maximum cumulative directory and path bytes.
    pub max_metadata_bytes: u64,
    /// Maximum regular file size.
    pub max_entry_bytes: u64,
    /// Maximum sum of regular file sizes.
    pub max_total_bytes: u64,
    /// Maximum image size.
    pub max_input_bytes: u64,
    /// Maximum directory nesting depth.
    pub max_nesting_depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_metadata_bytes: 16 << 20,
            max_entry_bytes: 8 << 30,
            max_total_bytes: 32 << 30,
            max_input_bytes: 64 << 30,
            max_nesting_depth: 64,
        }
    }
}
/// Kind of an indexed UDF object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// Main file data.
    File,
    /// Main namespace directory.
    Directory,
    /// Symbolic link; extraction returns its encoded pathname.
    SymbolicLink,
    /// Stream associated with an indexed file or directory.
    NamedStream,
    /// Stream belonging to the file set system stream directory.
    SystemStream,
}
/// Structured stream association, separate from main namespace paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamInfo {
    /// Stable entry index of the owner; None identifies the file set or root.
    pub owner: Option<usize>,
    /// Name within the associated stream directory.
    pub name: String,
    /// Whether the stream belongs to the system stream directory.
    pub system: bool,
}
/// Resolved ICB identity, shared by hard-linked names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IcbIdentity {
    /// Logical partition map reference.
    pub partition: u16,
    /// Logical block of the prevailing file entry.
    pub block: u32,
}
/// Indexed UDF file, directory, link or stream.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Object kind.
    pub kind: EntryKind,
    /// Associated stream information, if this is a stream.
    pub stream: Option<StreamInfo>,
    /// Resolved identity used to recognize hard links.
    pub icb: IcbIdentity,
    /// Decoded symbolic link pathname, without following the target.
    pub link_target: Option<String>,
    /// Raw OSTA compressed Unicode identifier.
    pub raw_name: Vec<u8>,
    /// Decoded main namespace path, or name within the associated stream namespace.
    pub name: String,
    /// Whether this entry is a directory.
    pub directory: bool,
    /// Regular file size; zero for directories.
    pub size: u64,
    /// Stored extent size, including directory records.
    pub stored_size: u64,
}
use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::Write,
};

fn bad(message: &str) -> Error {
    Error::Malformed(format!("UDF: {message}"))
}
fn region(bytes: &[u8], start: u64, length: u64) -> Result<&[u8]> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| bad("range overflow"))?;
    bytes
        .get(
            usize::try_from(start).map_err(|_| bad("range conversion"))?
                ..usize::try_from(end).map_err(|_| bad("range conversion"))?,
        )
        .ok_or_else(|| bad("range outside input"))
}
fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let b = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| bad("truncated integer"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}
fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let b = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| bad("truncated integer"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    let b: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| bad("truncated integer"))?
        .try_into()
        .map_err(|_| bad("integer conversion"))?;
    Ok(u64::from_le_bytes(b))
}
fn crc(bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}
fn tag(bytes: &[u8], expected: u16, location: u32) -> Result<()> {
    if bytes.len() < 16
        || u16_at(bytes, 0)? != expected
        || !matches!(u16_at(bytes, 2)?, 2 | 3)
        || u32_at(bytes, 12)? != location
    {
        return Err(bad("invalid descriptor tag"));
    }
    let checksum = bytes[..16]
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 4)
        .fold(0u8, |sum, (_, byte)| sum.wrapping_add(*byte));
    let end = 16 + usize::from(u16_at(bytes, 10)?);
    let required = match expected {
        2 | 5 | 256 => 512,
        6 => 440usize
            .checked_add(u32_at(bytes, 264)? as usize)
            .ok_or_else(|| bad("partition table length overflow"))?,
        258 => 24,
        259 => 52,
        260 => 36,
        261 => 176usize
            .checked_add(u32_at(bytes, 168)? as usize)
            .and_then(|start| start.checked_add(u32_at(bytes, 172).ok()? as usize))
            .ok_or_else(|| bad("descriptor protected length overflow"))?,
        266 => 216usize
            .checked_add(u32_at(bytes, 208)? as usize)
            .and_then(|start| start.checked_add(u32_at(bytes, 212).ok()? as usize))
            .ok_or_else(|| bad("descriptor protected length overflow"))?,
        257 => bytes.len(),
        _ => 16,
    };
    if end < required {
        return Err(bad("descriptor checksum does not cover interpreted fields"));
    }
    if checksum != bytes[4]
        || crc(bytes
            .get(16..end)
            .ok_or_else(|| bad("descriptor CRC range"))?)
            != u16_at(bytes, 8)?
    {
        return Err(Error::Integrity("UDF descriptor checksum".into()));
    }
    Ok(())
}

fn recorded_icb_length(descriptor: &[u8], offset: usize) -> Result<u32> {
    let length = u32_at(descriptor, offset)?;
    if length >> 30 != 0 {
        return Err(Error::Unsupported(
            "UDF unrecorded or continuation ICB".into(),
        ));
    }
    if !(36..=4096).contains(&length) {
        return Err(bad("ICB extent length outside single-block profile"));
    }
    Ok(length)
}

fn identifier(bytes: &[u8]) -> Result<String> {
    let name = match bytes.split_first() {
        Some((&8, name)) => name.iter().map(|byte| char::from(*byte)).collect(),
        Some((&16, name)) if name.len().is_multiple_of(2) => {
            let units: Vec<_> = name
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units).map_err(|_| bad("invalid UTF16 identifier"))?
        }
        _ => return Err(Error::Unsupported("UDF identifier compression".into())),
    };
    Ok(name)
}

#[path = "udf_allocations.rs"]
mod allocations;
#[path = "udf_discovery.rs"]
mod discovery;
#[path = "udf_partition.rs"]
mod partition;
use allocations::Extent;

fn charge_metadata(budget: &mut u64, amount: u64, limits: Limits) -> Result<()> {
    *budget = budget
        .checked_add(amount)
        .ok_or(Error::ResourceLimit("metadata bytes"))?;
    if *budget > limits.max_metadata_bytes {
        return Err(Error::ResourceLimit("metadata bytes"));
    }
    Ok(())
}

fn copy_recorded(bytes: &[u8], extents: &[Extent], output: &mut [u8]) -> Result<()> {
    let mut cursor = 0usize;
    for extent in extents {
        let offset = extent
            .offset
            .ok_or_else(|| bad("unrecorded metadata extent"))?;
        let length = usize::try_from(extent.length).map_err(|_| bad("extent length conversion"))?;
        let end = cursor
            .checked_add(length)
            .ok_or_else(|| bad("resolved size overflow"))?;
        output
            .get_mut(cursor..end)
            .ok_or_else(|| bad("resolved metadata size mismatch"))?
            .copy_from_slice(region(bytes, offset, extent.length)?);
        cursor = end;
    }
    if cursor != output.len() {
        return Err(bad("resolved metadata size mismatch"));
    }
    Ok(())
}

struct TaggedBlock {
    bytes: [u8; 2048],
    extents: Vec<Extent>,
    mirror: bool,
}

fn tagged_block(
    bytes: &[u8],
    maps: &partition::VolumeMap,
    reference: u16,
    location: u32,
    expected: &[u16],
) -> Result<TaggedBlock> {
    let read = |extents: Vec<Extent>, mirror: bool| -> Result<TaggedBlock> {
        let mut descriptor = [0; 2048];
        copy_recorded(bytes, &extents, &mut descriptor)?;
        let kind = u16_at(&descriptor, 0)?;
        if !expected.contains(&kind) {
            return Err(bad("unexpected descriptor type"));
        }
        tag(&descriptor, kind, location)?;
        Ok(TaggedBlock {
            bytes: descriptor,
            extents,
            mirror,
        })
    };
    let primary = maps
        .resolve(reference, location, 2048)
        .and_then(|extents| read(extents, false));
    match primary {
        Ok(descriptor) => Ok(descriptor),
        Err(error) => {
            if let Some(extents) = maps.resolve_mirror(reference, location, 2048)? {
                read(extents, true)
            } else {
                Err(error)
            }
        }
    }
}

fn fid_location(extents: &[Extent], position: usize) -> Result<u32> {
    let mut remaining = position as u64;
    for extent in extents {
        if remaining < extent.length {
            return u32::try_from((extent.logical_byte + remaining) / 2048)
                .map_err(|_| bad("FID block overflow"));
        }
        remaining -= extent.length;
    }
    Err(bad("FID extent"))
}

fn validate_directory_tags(data: &[u8], extents: &[Extent]) -> Result<()> {
    let mut position = 0usize;
    while position < data.len() {
        let fid = &data[position..];
        if fid.len() < 38 {
            return Err(bad("truncated file identifier"));
        }
        let length = (38 + usize::from(u16_at(fid, 36)?) + usize::from(fid[19]) + 3) & !3;
        let fid = fid.get(..length).ok_or_else(|| bad("identifier range"))?;
        tag(fid, 257, fid_location(extents, position)?)?;
        position += length;
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "validated allocation context and budgets stay explicit"
)]
fn decode_allocations(
    bytes: &[u8],
    maps: &partition::VolumeMap,
    allocations: &[u8],
    allocation_type: u16,
    reference: u16,
    size: u64,
    budget: &mut u64,
    limits: Limits,
    prefer_mirror: bool,
) -> Result<Vec<Extent>> {
    allocations::decode(
        bytes,
        allocations,
        allocation_type,
        reference,
        size,
        budget,
        limits,
        |partition, block, length| {
            if prefer_mirror && let Some(extents) = maps.resolve_mirror(partition, block, length)? {
                return Ok(extents);
            }
            maps.resolve(partition, block, length)
        },
    )
}

struct Pending {
    path: String,
    raw_name: Vec<u8>,
    reference: u16,
    location: u32,
    depth: usize,
    icb_length: u32,
    stream: Option<StreamInfo>,
    stream_directory: bool,
}

fn decode_link(data: &[u8]) -> Result<String> {
    let mut components = Vec::new();
    let mut position = 0;
    let mut absolute = false;
    while position < data.len() {
        let component = data
            .get(position..position + 4)
            .ok_or_else(|| bad("truncated link component"))?;
        let length = usize::from(component[1]);
        let body = data
            .get(position + 4..position + 4 + length)
            .ok_or_else(|| bad("link component range"))?;
        match component[0] {
            1 | 2 if components.is_empty() && length == 0 => absolute = true,
            3 if length == 0 => components.push("..".to_owned()),
            4 if length == 0 => components.push(".".to_owned()),
            5 => {
                let name = identifier(body)?;
                if name.is_empty() || name.contains(['/', '\\', '\0']) {
                    return Err(bad("unsafe link component"));
                }
                components.push(name);
            }
            _ => return Err(Error::Unsupported("UDF link component type".into())),
        }
        position += 4 + length;
    }
    Ok(format!(
        "{}{}",
        if absolute { "/" } else { "" },
        components.join("/")
    ))
}

fn resolve_icb(
    bytes: &[u8],
    maps: &partition::VolumeMap,
    mut reference: u16,
    mut location: u32,
    mut length: u32,
    budget: &mut u64,
    limits: Limits,
) -> Result<(TaggedBlock, u16, u32, u32)> {
    let mut visited = HashSet::new();
    loop {
        if !visited.insert((reference, location)) {
            return Err(bad("indirect ICB cycle"));
        }
        charge_metadata(budget, 2048, limits)?;
        let descriptor = tagged_block(bytes, maps, reference, location, &[259, 261, 266])?;
        if 16 + u32::from(u16_at(&descriptor.bytes, 10)?) > length {
            return Err(bad("descriptor exceeds declared ICB extent"));
        }
        if u16_at(&descriptor.bytes, 0)? == 259 {
            if descriptor.bytes[27] != 3 {
                return Err(bad("indirect ICB file type"));
            }
            length = recorded_icb_length(&descriptor.bytes, 36)?;
            location = u32_at(&descriptor.bytes, 40)?;
            reference = u16_at(&descriptor.bytes, 44)?;
            continue;
        }
        match u16_at(&descriptor.bytes, 20)? {
            4 => return Ok((descriptor, reference, location, length)),
            4096 => {
                // Strategy 4096 places the indirect/terminal entry immediately
                // after the direct entry in the two-block ICB extent.
                if length < 4096 {
                    return Err(bad("strategy 4096 ICB extent too short"));
                }
                let next_location = location
                    .checked_add(1)
                    .ok_or_else(|| bad("ICB block overflow"))?;
                // An unrecorded second slot terminates an appendable ICB chain
                // (UDF strategy 4096), just like an explicit Terminal Entry.
                let mut slot = [0u8; 2048];
                let slot_extents = maps.resolve(reference, next_location, 2048)?;
                copy_recorded(bytes, &slot_extents, &mut slot)?;
                if slot.iter().all(|byte| *byte == 0) {
                    return Ok((descriptor, reference, location, length));
                }
                let next = tagged_block(bytes, maps, reference, next_location, &[259, 260])?;
                charge_metadata(budget, 2048, limits)?;
                if u16_at(&next.bytes, 0)? == 260 {
                    if next.bytes[27] != 11 {
                        return Err(bad("terminal ICB file type"));
                    }
                    return Ok((descriptor, reference, location, length));
                }
                if next.bytes[27] != 3 {
                    return Err(bad("indirect ICB file type"));
                }
                length = recorded_icb_length(&next.bytes, 36)?;
                location = u32_at(&next.bytes, 40)?;
                reference = u16_at(&next.bytes, 44)?;
            }
            _ => return Err(Error::Unsupported("UDF ICB strategy".into())),
        }
    }
}

/// Bounded UDF reader over caller-owned bytes.
pub struct UdfReader<'a> {
    bytes: &'a [u8],
    entries: Vec<Entry>,
    extents: Vec<Vec<Extent>>,
}

impl<'a> UdfReader<'a> {
    /// Parse UDF 1.02, 1.50, 2.00, 2.01, 2.50 or 2.60 with physical/metadata maps.
    /// Supports sparse files and bounded short/long allocation descriptor chains.
    /// Associated streams are indexed separately with structured ownership.
    /// Symbolic links are decoded without following targets; directory aliases
    /// are rejected. Chained file sets select the greatest set/descriptor number.
    pub fn open(bytes: &'a [u8], limits: Limits) -> Result<Self> {
        if bytes.len() as u64 > limits.max_input_bytes {
            return Err(Error::ResourceLimit("input bytes"));
        }
        let mut metadata_bytes = 0u64;
        let descriptors = discovery::discover(bytes, limits, &mut metadata_bytes)?;
        let logical = descriptors.logical;
        if u32_at(logical, 212)? != 2048
            || !matches!(
                u16_at(logical, 240)?,
                0x102 | 0x150 | 0x200 | 0x201 | 0x250 | 0x260
            )
        {
            return Err(Error::Unsupported(
                "UDF revision or logical block size".into(),
            ));
        }
        let maps = partition::VolumeMap::open(
            bytes,
            &descriptors.partitions,
            logical,
            limits,
            &mut metadata_bytes,
        )?;
        let file_set_reference = u16_at(logical, 256)?;
        let file_set_length = recorded_icb_length(logical, 248)?;
        if file_set_length < 512 {
            return Err(bad("file set extent too short"));
        }
        let file_set_location = u32_at(logical, 252)?;
        let mut set_ref = file_set_reference;
        let mut set_location = file_set_location;
        let mut seen_sets = HashSet::new();
        let mut selected = None;
        loop {
            if !seen_sets.insert((set_ref, set_location)) {
                return Err(bad("file set descriptor cycle"));
            }
            charge_metadata(&mut metadata_bytes, 2048, limits)?;
            let block = tagged_block(bytes, &maps, set_ref, set_location, &[256])?;
            let candidate = block.bytes;
            let key = (u32_at(&candidate, 40)?, u32_at(&candidate, 44)?);
            if selected
                .as_ref()
                .is_none_or(|(previous, _)| key > *previous)
            {
                selected = Some((key, candidate));
            }
            if u32_at(&candidate, 448)? == 0 {
                break;
            }
            if recorded_icb_length(&candidate, 448)? < 512 {
                return Err(bad("file set extent too short"));
            }
            set_location = u32_at(&candidate, 452)?;
            set_ref = u16_at(&candidate, 456)?;
        }
        let file_set = selected.ok_or_else(|| bad("missing file set"))?.1;
        let root_length = recorded_icb_length(&file_set, 400)?;
        let mut queue = VecDeque::from([Pending {
            path: String::new(),
            raw_name: Vec::new(),
            reference: u16_at(&file_set, 408)?,
            location: u32_at(&file_set, 404)?,
            depth: 0,
            icb_length: root_length,
            stream: None,
            stream_directory: false,
        }]);
        if u32_at(&file_set, 464)? != 0 {
            queue.push_back(Pending {
                path: String::new(),
                raw_name: Vec::new(),
                reference: u16_at(&file_set, 472)?,
                location: u32_at(&file_set, 468)?,
                depth: 0,
                icb_length: recorded_icb_length(&file_set, 464)?,
                stream: Some(StreamInfo {
                    owner: None,
                    name: String::new(),
                    system: true,
                }),
                stream_directory: true,
            });
        }
        let mut visited_directories = HashSet::new();
        let mut entries = Vec::new();
        let mut locations = Vec::new();
        let mut total_bytes = 0u64;
        let mut object_sizes = Vec::new();
        let mut stream_owners = HashMap::new();
        while let Some(pending) = queue.pop_front() {
            let Pending {
                path,
                raw_name,
                reference,
                location,
                depth,
                icb_length,
                stream,
                stream_directory,
            } = pending;
            if depth > limits.max_nesting_depth {
                return Err(Error::ResourceLimit("UDF nesting depth"));
            }
            let (descriptor, reference, location, icb_length) = resolve_icb(
                bytes,
                &maps,
                reference,
                location,
                icb_length,
                &mut metadata_bytes,
                limits,
            )?;
            let descriptor_block = descriptor;
            let descriptor = descriptor_block.bytes.as_slice();
            let kind = u16_at(descriptor, 0)?;
            if 16 + u32::from(u16_at(descriptor, 10)?) > icb_length {
                return Err(bad("file entry exceeds ICB extent"));
            }
            if kind == 266 {
                let information = u64_at(descriptor, 56)?;
                let object = u64_at(descriptor, 64)?;
                if object < information || (u32_at(descriptor, 152)? == 0 && object != information)
                {
                    return Err(bad("inconsistent extended file entry object size"));
                }
                // Object Size includes associated streams; charge each indexed
                // payload by its Information Length to avoid double counting.
            }
            let allocation_type = u16_at(descriptor, 34)? & 7;
            if !matches!(u16_at(descriptor, 20)?, 4 | 4096) || !matches!(allocation_type, 0..=3) {
                return Err(Error::Unsupported("UDF allocation descriptor type".into()));
            }
            let directory = matches!(descriptor[27], 4 | 13);
            if path.is_empty() && descriptor[27] != if stream_directory { 13 } else { 4 } {
                return Err(bad("root directory file type mismatch"));
            }
            if !matches!(descriptor[27], 4 | 5 | 12 | 13) {
                return Err(Error::Unsupported("UDF special file type".into()));
            }
            let size = u64_at(descriptor, 56)?;
            if size
                > if directory {
                    limits.max_metadata_bytes
                } else {
                    limits.max_entry_bytes
                }
            {
                return Err(Error::ResourceLimit("UDF entry bytes"));
            }
            let header: usize = if kind == 266 { 216 } else { 176 };
            let allocations_start = header
                .checked_add(u32_at(descriptor, header - 8)? as usize)
                .ok_or_else(|| bad("allocation overflow"))?;
            let allocations_end = allocations_start
                .checked_add(u32_at(descriptor, header - 4)? as usize)
                .ok_or_else(|| bad("allocation overflow"))?;
            let allocations = descriptor
                .get(allocations_start..allocations_end)
                .ok_or_else(|| bad("allocation range"))?;
            charge_metadata(&mut metadata_bytes, allocations.len() as u64, limits)?;
            let allocation_budget = metadata_bytes;
            let mut extents = if allocation_type == 3 {
                if allocations.len() as u64 != size {
                    return Err(bad("embedded allocation size mismatch"));
                }
                let resolved = descriptor_block.extents;
                // Preserve the chosen mirror mapping for embedded payloads.
                let mut skip = allocations_start as u64;
                let mut remain = size;
                let mut embedded = Vec::new();
                for extent in resolved {
                    if skip >= extent.length {
                        skip -= extent.length;
                        continue;
                    }
                    let length = (extent.length - skip).min(remain);
                    embedded.push(Extent {
                        offset: extent.offset.map(|offset| offset + skip),
                        length,
                        logical_byte: extent.logical_byte + skip,
                    });
                    remain -= length;
                    skip = 0;
                    if remain == 0 {
                        break;
                    }
                }
                if remain != 0 {
                    return Err(bad("embedded allocation mapping"));
                }
                embedded
            } else {
                let decoded = decode_allocations(
                    bytes,
                    &maps,
                    allocations,
                    allocation_type,
                    reference,
                    size,
                    &mut metadata_bytes,
                    limits,
                    descriptor_block.mirror,
                );
                match decoded {
                    Ok(extents) => extents,
                    Err(error @ (Error::Malformed(_) | Error::Integrity(_))) => {
                        metadata_bytes = allocation_budget;
                        decode_allocations(
                            bytes,
                            &maps,
                            allocations,
                            allocation_type,
                            reference,
                            size,
                            &mut metadata_bytes,
                            limits,
                            !descriptor_block.mirror,
                        )
                        .map_err(|mirror_error| {
                            if matches!(mirror_error, Error::ResourceLimit(_)) {
                                mirror_error
                            } else {
                                error
                            }
                        })?
                    }
                    Err(error) => return Err(error),
                }
            };
            let mut owner = None;
            if !path.is_empty() && !stream_directory {
                if entries.len() as u64 >= limits.max_entries {
                    return Err(Error::ResourceLimit("entries"));
                }
                total_bytes = total_bytes
                    .checked_add(if directory { 0 } else { size })
                    .ok_or(Error::ResourceLimit("total decoded bytes"))?;
                if total_bytes > limits.max_total_bytes {
                    return Err(Error::ResourceLimit("total decoded bytes"));
                }
                owner = Some(entries.len());
                let entry_kind = if stream.as_ref().is_some_and(|info| info.system) {
                    EntryKind::SystemStream
                } else if stream.is_some() {
                    EntryKind::NamedStream
                } else if directory {
                    EntryKind::Directory
                } else if descriptor[27] == 12 {
                    EntryKind::SymbolicLink
                } else {
                    EntryKind::File
                };
                let link_target = if descriptor[27] == 12 {
                    charge_metadata(&mut metadata_bytes, size, limits)?;
                    Some(decode_link(&allocations::read_recorded(
                        bytes, &extents, size,
                    )?)?)
                } else {
                    None
                };
                entries.push(Entry {
                    kind: entry_kind,
                    stream: stream.clone(),
                    icb: IcbIdentity {
                        partition: reference,
                        block: location,
                    },
                    link_target,
                    raw_name,
                    name: path.clone(),
                    directory,
                    size: if directory { 0 } else { size },
                    stored_size: size,
                });
                locations.push(extents.clone());
            }
            let identity = (reference, location);
            let (stream_owner, first_owner) = if stream.is_none() {
                if let Some(previous) = stream_owners.get(&identity) {
                    (*previous, false)
                } else {
                    stream_owners.insert(identity, owner);
                    (owner, true)
                }
            } else {
                (owner, true)
            };
            if kind == 266 && stream.is_none() {
                object_sizes.push((stream_owner, size, u64_at(descriptor, 64)?));
            }
            if kind == 266 && u32_at(descriptor, 152)? != 0 && first_owner {
                if stream.is_some() {
                    return Err(bad("stream contains nested stream directory"));
                }
                queue.push_back(Pending {
                    path: String::new(),
                    raw_name: Vec::new(),
                    reference: u16_at(descriptor, 160)?,
                    location: u32_at(descriptor, 156)?,
                    depth: depth + 1,
                    icb_length: recorded_icb_length(descriptor, 152)?,
                    stream: Some(StreamInfo {
                        owner: stream_owner,
                        name: String::new(),
                        system: false,
                    }),
                    stream_directory: true,
                });
            }
            if !directory {
                continue;
            }
            if !visited_directories.insert((reference, location)) {
                return Err(bad("directory cycle or alias"));
            }
            charge_metadata(&mut metadata_bytes, size, limits)?;
            let mut data = allocations::read_recorded(bytes, &extents, size)?;
            if let Err(error) = validate_directory_tags(&data, &extents) {
                if allocation_type == 3 {
                    return Err(error);
                }
                drop(data);
                // Retry the entire directory from the alternate metadata mapping;
                // no partially parsed children have been published to the queue.
                let mirror_extents = decode_allocations(
                    bytes,
                    &maps,
                    allocations,
                    allocation_type,
                    reference,
                    size,
                    &mut metadata_bytes,
                    limits,
                    !descriptor_block.mirror,
                )?;
                data = allocations::read_recorded(bytes, &mirror_extents, size)?;
                validate_directory_tags(&data, &mirror_extents)?;
                extents = mirror_extents;
            }
            let mut position = 0usize;
            let mut names = HashSet::new();
            while position < data.len() {
                let fid = &data[position..];
                if fid.len() < 38 {
                    return Err(bad("truncated file identifier"));
                }
                let implementation = usize::from(u16_at(fid, 36)?);
                let name_len = usize::from(fid[19]);
                let length = (38 + implementation + name_len + 3) & !3;
                let fid = fid.get(..length).ok_or_else(|| bad("identifier range"))?;
                tag(fid, 257, fid_location(&extents, position)?)?;
                if fid[18] & (4 | 8) == 0 {
                    let raw = fid[38 + implementation..38 + implementation + name_len].to_vec();
                    let leaf = identifier(&raw)?;
                    if leaf.is_empty()
                        || leaf.contains(['/', '\\', '\0'])
                        || leaf == "."
                        || leaf == ".."
                    {
                        return Err(bad("unsafe identifier"));
                    }
                    let child_path = if path.is_empty() {
                        leaf
                    } else {
                        format!("{path}/{leaf}")
                    };
                    if !names.insert(child_path.clone()) {
                        return Err(bad("duplicate directory identifier"));
                    }
                    charge_metadata(&mut metadata_bytes, child_path.len() as u64, limits)?;
                    if queue.len() as u64 + entries.len() as u64 >= limits.max_entries {
                        return Err(Error::ResourceLimit("entries"));
                    }
                    let child_stream = stream.as_ref().map(|info| StreamInfo {
                        owner: info.owner,
                        name: child_path.clone(),
                        system: info.system,
                    });
                    queue.push_back(Pending {
                        path: child_path,
                        raw_name: raw,
                        reference: u16_at(fid, 28)?,
                        location: u32_at(fid, 24)?,
                        depth: depth + 1,
                        icb_length: recorded_icb_length(fid, 20)?,
                        stream: child_stream,
                        stream_directory: false,
                    });
                }
                position += length;
            }
        }
        let mut stream_sizes = HashMap::<Option<usize>, u64>::new();
        for entry in &entries {
            if let Some(stream) = &entry.stream
                && !stream.system
            {
                let sum = stream_sizes.entry(stream.owner).or_default();
                *sum = sum
                    .checked_add(entry.stored_size)
                    .ok_or_else(|| bad("stream object size overflow"))?;
            }
        }
        for (owner, information, object) in object_sizes {
            let actual = information
                .checked_add(stream_sizes.get(&owner).copied().unwrap_or(0))
                .ok_or_else(|| bad("stream object size overflow"))?;
            if actual != object {
                return Err(bad("stream object size mismatch"));
            }
        }
        Ok(Self {
            bytes,
            entries,
            extents: locations,
        })
    }

    /// Metadata in breadth-first stored directory order.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
    /// Stream recorded extents and zero-fill sparse regions in bounded chunks.
    /// UDF descriptor checksums do not authenticate file payloads.
    pub fn extract(&self, index: usize, output: &mut impl Write) -> Result<u64> {
        let entry = self
            .entries
            .get(index)
            .ok_or_else(|| bad("unknown entry ID"))?;
        if !entry.directory {
            let zeros = [0u8; 64 * 1024];
            for extent in &self.extents[index] {
                if let Some(offset) = extent.offset {
                    output.write_all(region(self.bytes, offset, extent.length)?)?;
                } else {
                    let mut remaining = extent.length;
                    while remaining != 0 {
                        let length = remaining.min(zeros.len() as u64) as usize;
                        output.write_all(&zeros[..length])?;
                        remaining -= length as u64;
                    }
                }
            }
        }
        Ok(entry.size)
    }
    /// Return a payload with an explicit allocation maximum, including sparse bytes.
    pub fn read_entry(&self, index: usize, maximum: u64) -> Result<Vec<u8>> {
        if self
            .entries
            .get(index)
            .ok_or_else(|| bad("unknown entry ID"))?
            .size
            > maximum
        {
            return Err(Error::ResourceLimit("buffered entry bytes"));
        }
        let mut output = Vec::new();
        self.extract(index, &mut output)?;
        Ok(output)
    }
}
