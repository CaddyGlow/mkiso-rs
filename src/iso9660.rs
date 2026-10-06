//! Bounded ISO9660, Joliet and Rock Ridge reading, including level-3 file sections.
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};

/// ISO9660 reader error, independent of archive container adapters.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Source I/O failed.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    /// Descriptor or extent is malformed.
    #[error("malformed ISO9660 image: {0}")]
    Malformed(String),
    /// The image requires an unsupported profile.
    #[error("unsupported ISO9660 feature: {0}")]
    Unsupported(String),
    /// A configured parsing budget was exceeded.
    #[error("ISO9660 resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
}
/// Reader result.
pub type Result<T> = std::result::Result<T, Error>;

/// Metadata budgets applied before directory allocation and entry insertion.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum listed entries.
    pub max_entries: u64,
    /// Maximum directory and filename bytes.
    pub max_metadata_bytes: u64,
    /// Maximum directory nesting depth.
    pub max_nesting_depth: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_metadata_bytes: 16 << 20,
            max_nesting_depth: 64,
        }
    }
}
/// Filesystem namespace to read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Namespace {
    /// Read the primary ASCII ISO9660 namespace.
    #[default]
    Primary,
    /// Require a Joliet supplementary descriptor and decode UCS-2 names.
    Joliet,
    /// Prefer Joliet, falling back to the primary namespace.
    PreferJoliet,
    /// Require Rock Ridge in the primary filesystem.
    RockRidge,
    /// Prefer Rock Ridge, then Joliet, then the primary namespace.
    PreferRockRidge,
}
/// Descriptor selection and resource limits.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOptions {
    /// Namespace selection.
    pub namespace: Namespace,
    /// Metadata parsing budgets.
    pub limits: Limits,
}

/// A baseline ISO9660 directory entry.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Raw stored leaf identifier, including file version.
    pub raw_name: Vec<u8>,
    /// Full display path with file version suffix removed.
    pub name: String,
    /// Whether the record denotes a directory.
    pub directory: bool,
    /// File size; directories have zero payload size.
    pub size: u64,
    /// Rock Ridge POSIX metadata, when reading that namespace.
    pub unix: Option<crate::rock_ridge::UnixMetadata>,
    /// Symbolic-link target; never followed by extraction.
    pub link_target: Option<String>,
}
/// One recorded file section, in logical file order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// Absolute byte offset in the image.
    pub offset: u64,
    /// Number of payload bytes in this section.
    pub size: u64,
}
/// Indexed ISO9660 metadata and corresponding absolute payload offsets.
pub struct Index {
    /// Metadata in directory traversal order.
    pub entries: Vec<Entry>,
    /// First absolute extent offset per entry; use `extents` for all file sections.
    pub offsets: Vec<u64>,
    /// All file sections per entry, including noncontiguous level-3 extents.
    pub extents: Vec<Vec<Extent>>,
}

/// Seekable ISO9660 image with a validated selected-namespace index.
pub struct IsoReader<R> {
    reader: R,
    index: Index,
}

impl<R: Read + Seek> IsoReader<R> {
    /// Read primary filesystem descriptors and build a bounded index.
    pub fn open(reader: R, limits: Limits) -> Result<Self> {
        Self::open_with_options(
            reader,
            ReadOptions {
                limits,
                ..ReadOptions::default()
            },
        )
    }

    /// Read a selected namespace with bounded metadata traversal.
    pub fn open_with_options(mut reader: R, options: ReadOptions) -> Result<Self> {
        let index = read_index_with_options(&mut reader, options)?;
        Ok(Self { reader, index })
    }

    /// Listed files and directories in traversal order.
    pub fn entries(&self) -> &[Entry] {
        &self.index.entries
    }

    /// Borrow the full index, including all sections of multi-extent files.
    pub fn index(&self) -> &Index {
        &self.index
    }

    /// Return the underlying reader and validated index without reparsing the image.
    /// The reader's current seek position is unspecified.
    pub fn into_parts(self) -> (R, Index) {
        (self.reader, self.index)
    }

    /// Read one payload into memory with an explicit maximum allocation size.
    /// Directories return an empty buffer. Invalid indices and oversized files
    /// fail before reading payload data; truncated extents remain errors.
    pub fn read_entry(&mut self, index: usize, maximum: u64) -> Result<Vec<u8>> {
        let entry = self
            .index
            .entries
            .get(index)
            .ok_or_else(|| malformed("unknown entry index"))?;
        if entry.size > maximum || usize::try_from(entry.size).is_err() {
            return Err(Error::ResourceLimit("buffered entry bytes"));
        }
        let mut output = Vec::new();
        self.extract(index, &mut output)?;
        Ok(output)
    }

    /// Stream one regular file by index, checking that its full extent is readable.
    /// ISO9660 baseline does not provide payload checksums.
    pub fn extract(&mut self, index: usize, output: &mut impl Write) -> Result<u64> {
        let entry = self
            .index
            .entries
            .get(index)
            .ok_or_else(|| malformed("unknown entry index"))?;
        if entry.directory {
            return Ok(0);
        }
        let mut bytes = 0;
        for extent in &self.index.extents[index] {
            self.reader.seek(SeekFrom::Start(extent.offset))?;
            let copied = std::io::copy(&mut (&mut self.reader).take(extent.size), output)?;
            if copied != extent.size {
                return Err(malformed("truncated file extent"));
            }
            bytes += copied;
        }
        Ok(bytes)
    }
}

const SECTOR: u64 = 2048;

fn malformed(message: &str) -> Error {
    Error::Malformed(message.to_owned())
}

fn both_u32(bytes: &[u8]) -> Result<u32> {
    if bytes.len() < 8 {
        return Err(malformed("truncated ISO integer"));
    }
    let little = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let big = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if little != big {
        return Err(malformed("inconsistent ISO integer byte orders"));
    }
    Ok(little)
}

fn both_u16(bytes: &[u8]) -> Result<u16> {
    if bytes.len() < 4 {
        return Err(malformed("truncated ISO integer"));
    }
    let little = u16::from_le_bytes([bytes[0], bytes[1]]);
    let big = u16::from_be_bytes([bytes[2], bytes[3]]);
    if little != big {
        return Err(malformed("inconsistent ISO integer byte orders"));
    }
    Ok(little)
}

struct Record<'a> {
    extent: u64,
    size: u64,
    directory: bool,
    name: &'a [u8],
    more: bool,
}

fn record(bytes: &[u8], volume_bytes: u64) -> Result<Record<'_>> {
    if bytes.len() < 34 || usize::from(bytes[0]) != bytes.len() {
        return Err(malformed("invalid ISO directory record length"));
    }
    if bytes[1] != 0 || bytes[26] != 0 || bytes[27] != 0 {
        return Err(Error::Unsupported(
            "ISO extended attributes or interleaving".into(),
        ));
    }
    if both_u16(&bytes[28..32])? != 1 {
        return Err(Error::Unsupported("ISO multi-volume files".into()));
    }
    let extent = u64::from(both_u32(&bytes[2..10])?)
        .checked_mul(SECTOR)
        .ok_or_else(|| malformed("ISO extent overflow"))?;
    let size = u64::from(both_u32(&bytes[10..18])?);
    if extent
        .checked_add(size)
        .is_none_or(|end| end > volume_bytes)
    {
        return Err(malformed("ISO extent outside volume"));
    }
    let name_len = usize::from(bytes[32]);
    let name = bytes
        .get(33..33 + name_len)
        .ok_or_else(|| malformed("truncated ISO identifier"))?;
    if name.is_empty() {
        return Err(malformed("empty ISO identifier"));
    }
    Ok(Record {
        extent,
        size,
        directory: bytes[25] & 2 != 0,
        name,
        more: bytes[25] & 0x80 != 0,
    })
}

/// Read the primary ISO9660 filesystem view with bounded descriptor and directory traversal.
pub fn read_index<R: Read + Seek>(reader: &mut R, limits: Limits) -> Result<Index> {
    read_index_with_options(
        reader,
        ReadOptions {
            limits,
            ..ReadOptions::default()
        },
    )
}

/// Read a selected ISO9660 or Joliet namespace with bounded traversal.
pub fn read_index_with_options<R: Read + Seek>(
    reader: &mut R,
    options: ReadOptions,
) -> Result<Index> {
    let limits = options.limits;
    let input_size = reader.seek(SeekFrom::End(0))?;
    let mut primary = None;
    let mut joliet = None;
    let mut terminated = false;
    for sector in 16..80 {
        let mut descriptor = [0; 2048];
        reader.seek(SeekFrom::Start(sector * SECTOR))?;
        reader.read_exact(&mut descriptor)?;
        if &descriptor[1..6] != b"CD001" || descriptor[6] != 1 {
            return Err(malformed("invalid ISO volume descriptor"));
        }
        match descriptor[0] {
            1 if primary.is_none() => primary = Some(descriptor),
            255 => {
                terminated = true;
                break;
            }
            2 if matches!(&descriptor[88..91], b"%/@" | b"%/C" | b"%/E") => {
                joliet = Some(descriptor);
            }
            0 | 2 | 3 => {}
            _ => {
                return Err(malformed(
                    "unsupported ISO descriptor type or duplicate primary",
                ));
            }
        }
    }
    if !terminated {
        return Err(malformed("ISO descriptor set has no bounded terminator"));
    }
    let primary = primary.ok_or_else(|| malformed("missing ISO primary descriptor"))?;
    let mut rr_skip = None;
    let mut rr_metadata = 0;
    if matches!(
        options.namespace,
        Namespace::RockRidge | Namespace::PreferRockRidge
    ) {
        let declared = u64::from(both_u32(&primary[80..88])?) * SECTOR;
        if declared > input_size {
            return Err(malformed("truncated ISO volume"));
        }
        let root = record(&primary[156..190], declared)?;
        if !root.directory || root.size < SECTOR || root.more {
            return Err(malformed("invalid Rock Ridge root extent"));
        }
        let mut block = [0; 2048];
        reader.seek(SeekFrom::Start(root.extent))?;
        reader.read_exact(&mut block)?;
        let dot = block
            .get(..usize::from(block[0]))
            .ok_or_else(|| malformed("Rock Ridge root record"))?;
        let self_record = record(dot, declared)?;
        if self_record.name != [0]
            || !self_record.directory
            || self_record.extent != root.extent
            || self_record.size != root.size
        {
            return Err(malformed("inconsistent Rock Ridge root self record"));
        }
        let system = crate::rock_ridge::system_use(dot)?;
        if let Some(skip) = crate::rock_ridge::discover(system) {
            let attributes = crate::rock_ridge::parse(
                reader,
                system,
                declared,
                &mut rr_metadata,
                limits.max_metadata_bytes,
            )?;
            if attributes.rrip {
                rr_skip = Some(skip);
            }
        }
        if options.namespace == Namespace::RockRidge && rr_skip.is_none() {
            return Err(Error::Unsupported("missing Rock Ridge extension".into()));
        }
    }
    let use_rr = rr_skip.is_some();
    let use_joliet = !use_rr
        && options.namespace != Namespace::Primary
        && options.namespace != Namespace::RockRidge
        && joliet.is_some();
    let primary = match options.namespace {
        Namespace::Primary | Namespace::RockRidge => primary,
        Namespace::PreferRockRidge if use_rr => primary,
        Namespace::PreferRockRidge => joliet.unwrap_or(primary),
        Namespace::PreferJoliet => joliet.unwrap_or(primary),
        Namespace::Joliet => {
            joliet.ok_or_else(|| Error::Unsupported("missing Joliet descriptor".into()))?
        }
    };
    if both_u16(&primary[128..132])? != 2048 {
        return Err(Error::Unsupported(
            "ISO logical blocks other than 2048 bytes".into(),
        ));
    }
    if both_u16(&primary[120..124])? != 1 || both_u16(&primary[124..128])? != 1 {
        return Err(Error::Unsupported("ISO volume sets".into()));
    }
    let volume_bytes = u64::from(both_u32(&primary[80..88])?)
        .checked_mul(SECTOR)
        .ok_or_else(|| malformed("ISO volume size overflow"))?;
    if volume_bytes > input_size {
        return Err(malformed("truncated ISO volume"));
    }
    let root_len = usize::from(primary[156]);
    let root = record(
        primary
            .get(156..156 + root_len)
            .ok_or_else(|| malformed("truncated ISO root"))?,
        volume_bytes,
    )?;
    if !root.directory || root.name != [0] {
        return Err(malformed("invalid ISO root"));
    }
    let mut queue = VecDeque::from([(String::new(), root.extent, root.size, 0usize)]);
    let mut visited = HashSet::new();
    let mut entries = Vec::new();
    let mut offsets = Vec::new();
    let mut extents: Vec<Vec<Extent>> = Vec::new();
    let mut metadata_bytes = 0u64;
    let mut directory_bytes = rr_metadata;
    while let Some((parent, extent, size, depth)) = queue.pop_front() {
        if depth > limits.max_nesting_depth {
            return Err(Error::ResourceLimit("ISO directory depth"));
        }
        if !visited.insert(extent) {
            return Err(malformed("cyclic or aliased ISO directory"));
        }
        directory_bytes = directory_bytes
            .checked_add(size)
            .ok_or(Error::ResourceLimit("ISO directory bytes"))?;
        if directory_bytes > limits.max_metadata_bytes {
            return Err(Error::ResourceLimit("ISO directory bytes"));
        }
        let mut consumed = 0u64;
        let mut pending: Option<usize> = None;
        let mut names = HashSet::new();
        while consumed < size {
            let mut sector = [0; 2048];
            let amount = (size - consumed).min(SECTOR) as usize;
            reader.seek(SeekFrom::Start(extent + consumed))?;
            reader.read_exact(&mut sector[..amount])?;
            let mut position = 0;
            while position < amount && sector[position] != 0 {
                let len = usize::from(sector[position]);
                let end = position
                    .checked_add(len)
                    .ok_or_else(|| malformed("ISO record overflow"))?;
                let stored = sector
                    .get(position..end)
                    .filter(|_| end <= amount)
                    .ok_or_else(|| malformed("ISO record crosses sector"))?;
                let child = record(stored, volume_bytes)?;
                position = end;
                if child.name == [0] || child.name == [1] {
                    if pending.is_some() || child.more {
                        return Err(malformed("interrupted ISO multi-extent file"));
                    }
                    continue;
                }
                if child.more
                    && (child.directory || child.size == 0 || !child.size.is_multiple_of(SECTOR))
                {
                    return Err(malformed("invalid nonfinal ISO file section"));
                }
                let attributes = if use_rr {
                    let system = crate::rock_ridge::system_use(stored)?;
                    let system = system
                        .get(rr_skip.unwrap_or(0)..)
                        .ok_or_else(|| malformed("Rock Ridge system-use skip"))?;
                    crate::rock_ridge::parse(
                        reader,
                        system,
                        volume_bytes,
                        &mut directory_bytes,
                        limits.max_metadata_bytes,
                    )?
                } else {
                    crate::rock_ridge::Attributes::default()
                };
                let mut leaf = if use_joliet {
                    if !child.name.len().is_multiple_of(2) || child.name.len() > 206 {
                        return Err(malformed("invalid Joliet identifier length"));
                    }
                    let mut decoded = String::new();
                    for pair in child.name.chunks_exact(2) {
                        let unit = u16::from_be_bytes([pair[0], pair[1]]);
                        let ch = char::from_u32(u32::from(unit))
                            .ok_or_else(|| malformed("Joliet surrogate code point"))?;
                        decoded.push(ch);
                    }
                    decoded
                } else {
                    String::from_utf8_lossy(child.name).into_owned()
                };
                if leaf.is_empty() || leaf.chars().any(|c| matches!(c, '\0' | '/' | '\\')) {
                    return Err(malformed("invalid ISO filename"));
                }
                if attributes.name.is_none()
                    && !child.directory
                    && let Some((base, version)) = leaf.rsplit_once(';')
                    && !version.is_empty()
                    && version.bytes().all(|b| b.is_ascii_digit())
                {
                    leaf = base.trim_end_matches('.').to_owned();
                }
                if let Some(name) = attributes.name {
                    leaf = name;
                }
                if matches!(leaf.as_str(), "." | "..") {
                    return Err(malformed("invalid ISO leaf path"));
                }
                let name = if parent.is_empty() {
                    leaf
                } else {
                    format!("{parent}/{leaf}")
                };
                if let Some(index) = pending {
                    let previous: &mut Entry = &mut entries[index];
                    if previous.raw_name != child.name
                        || previous.name != name
                        || child.directory
                        || previous.unix != attributes.metadata
                        || previous.link_target != attributes.link
                    {
                        return Err(malformed("mismatched ISO multi-extent continuation"));
                    }
                    previous.size = previous
                        .size
                        .checked_add(child.size)
                        .ok_or_else(|| malformed("ISO file size overflow"))?;
                    if extents[index].len() as u64 >= limits.max_entries {
                        return Err(Error::ResourceLimit("ISO file sections"));
                    }
                    directory_bytes = directory_bytes
                        .checked_add(16)
                        .ok_or(Error::ResourceLimit("ISO file sections"))?;
                    if directory_bytes > limits.max_metadata_bytes {
                        return Err(Error::ResourceLimit("ISO file sections"));
                    }
                    extents[index].push(Extent {
                        offset: child.extent,
                        size: child.size,
                    });
                    pending = child.more.then_some(index);
                    continue;
                }
                if !names.insert(name.clone()) {
                    return Err(malformed("duplicate ISO display name"));
                }
                metadata_bytes = metadata_bytes
                    .checked_add(name.len() as u64)
                    .ok_or(Error::ResourceLimit("metadata bytes"))?;
                if metadata_bytes > limits.max_metadata_bytes {
                    return Err(Error::ResourceLimit("metadata bytes"));
                }
                if entries.len() as u64 >= limits.max_entries {
                    return Err(Error::ResourceLimit("entries"));
                }
                if child.directory {
                    queue.push_back((name.clone(), child.extent, child.size, depth + 1));
                }
                entries.push(Entry {
                    raw_name: child.name.to_vec(),
                    name,
                    directory: child.directory,
                    size: if child.directory { 0 } else { child.size },
                    unix: attributes.metadata,
                    link_target: attributes.link,
                });
                offsets.push(child.extent);
                extents.push(if child.directory {
                    Vec::new()
                } else {
                    vec![Extent {
                        offset: child.extent,
                        size: child.size,
                    }]
                });
                pending = child.more.then_some(entries.len() - 1);
            }
            if sector[position..amount].iter().any(|byte| *byte != 0) {
                return Err(malformed("nonzero ISO directory padding"));
            }
            consumed += amount as u64;
        }
        if pending.is_some() {
            return Err(malformed("unfinished ISO multi-extent file"));
        }
    }
    Ok(Index {
        entries,
        offsets,
        extents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconsistent_endian_numbers_are_rejected() {
        assert!(both_u32(&[1, 0, 0, 0, 0, 0, 0, 2]).is_err());
    }

    #[test]
    fn extent_outside_volume_is_rejected() {
        let mut bytes = [0; 34];
        bytes[0] = 34;
        bytes[2..6].copy_from_slice(&2u32.to_le_bytes());
        bytes[6..10].copy_from_slice(&2u32.to_be_bytes());
        bytes[28..30].copy_from_slice(&1u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&1u16.to_be_bytes());
        bytes[32] = 1;
        assert!(record(&bytes, 2048).is_err());
    }
}
