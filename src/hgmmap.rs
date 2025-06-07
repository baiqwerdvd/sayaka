use memmap2::Mmap;
use pyo3::{PyErr, PyResult, pyclass, pymethods};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fs::File;
use std::io::{self, BufWriter, Write};

#[derive(Debug)]
pub enum HgMmapError {
    InvalidHeader,
    InvalidVersion,
    InvalidRootCategory,
    MemoryMapError(io::Error),
    Utf16ConversionError(std::string::FromUtf16Error),
    NotInitialized,
    IndexOutOfRange,
}

impl Display for HgMmapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HgMmapError::InvalidHeader => write!(f, "Invalid header"),
            HgMmapError::InvalidVersion => write!(f, "Invalid version"),
            HgMmapError::InvalidRootCategory => write!(f, "Invalid root category"),
            HgMmapError::MemoryMapError(err) => write!(f, "Memory map error: {}", err),
            HgMmapError::Utf16ConversionError(err) => write!(f, "UTF-16 conversion error: {}", err),
            HgMmapError::NotInitialized => write!(f, "Not initialized"),
            HgMmapError::IndexOutOfRange => write!(f, "Index out of range"),
        }
    }
}

impl From<HgMmapError> for PyErr {
    fn from(err: HgMmapError) -> PyErr {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(err.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum RootCategory {
    Main = 0,
    Initial = 1,
    ENum = 2,
}

impl TryFrom<u32> for RootCategory {
    type Error = HgMmapError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(RootCategory::Main),
            1 => Ok(RootCategory::Initial),
            2 => Ok(RootCategory::ENum),
            _ => Err(HgMmapError::InvalidRootCategory),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidProxy {
    pub val0: u32,
    pub val1: u32,
    pub val2: u32,
    pub val3: u32,
}

impl GuidProxy {
    pub fn new(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 16 {
            return Err("GUID must be 16 bytes");
        }

        let val0 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let val1 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let val2 = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let val3 = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

        Ok(GuidProxy {
            val0,
            val1,
            val2,
            val3,
        })
    }

    pub fn to_string(&self) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:04x}{:08x}",
            self.val0,
            self.val1 >> 16,
            self.val1 & 0xFFFF,
            self.val2 >> 16,
            self.val2 & 0xFFFF,
            self.val3
        )
    }
}

#[derive(Debug)]
pub struct RefString {
    pub length: u32,
}

impl RefString {
    pub fn new(memory_map: &Mmap, offset: usize) -> Self {
        let length_bytes = &memory_map[offset..offset + 4];
        let length = u32::from_le_bytes([
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ]);

        RefString { length }
    }

    pub fn to_string(
        &self,
        memory_map: &Mmap,
        value_offset: usize,
    ) -> Result<String, std::string::FromUtf16Error> {
        // let char_count = (self.length / 2) as usize;
        let string_data = &memory_map[value_offset + 4..value_offset + 4 + self.length as usize];

        // Convert UTF-16LE to String
        let utf16_data: Vec<u16> = string_data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();

        String::from_utf16(&utf16_data)
    }
}

#[derive(Debug)]
pub struct RefArray {
    pub length: u32,
    pub offset: usize,
}

impl RefArray {
    pub fn new(memory_map: &Mmap, value_offset: usize) -> Self {
        let length_bytes = &memory_map[value_offset..value_offset + 4];
        let length = u32::from_le_bytes([
            length_bytes[0],
            length_bytes[1],
            length_bytes[2],
            length_bytes[3],
        ]);

        RefArray {
            length,
            offset: value_offset + 4,
        }
    }

    pub fn at<'a>(
        &self,
        memory_map: &'a Mmap,
        index: usize,
        item_size: usize,
    ) -> Result<&'a [u8], HgMmapError> {
        if index >= self.length as usize {
            return Err(HgMmapError::IndexOutOfRange);
        }

        let index_offset = item_size * index;
        let start = self.offset + index_offset;
        let end = start + item_size;

        Ok(&memory_map[start..end])
    }

    pub fn to_list_int(&self, memory_map: &Mmap, value_offset: Option<usize>) -> Vec<u32> {
        let mut result = Vec::new();
        let offset = value_offset.map(|v| v + 4).unwrap_or(self.offset);

        for i in 0..self.length as usize {
            let start = offset + i * 4;
            let int_bytes = &memory_map[start..start + 4];
            let value =
                u32::from_le_bytes([int_bytes[0], int_bytes[1], int_bytes[2], int_bytes[3]]);
            result.push(value);
        }

        result
    }
}

#[derive(Debug)]
pub struct RefValue {
    pub offset: u32,
}

impl RefValue {
    pub fn new(offset: u32) -> Self {
        RefValue { offset }
    }

    pub fn get_value<'a>(
        &self,
        memory_map: &'a Mmap,
        data_offset: usize,
        size: usize,
    ) -> (&'a [u8], usize) {
        let value_offset = data_offset + self.offset as usize;
        let value_data = &memory_map[value_offset..value_offset + size];
        (value_data, value_offset)
    }
}

#[derive(Debug)]
pub struct RefHashSlot {
    pub offset: u32,
    pub buckets_size: u32,
}

impl RefHashSlot {
    pub fn from_bytes(data: &[u8]) -> Self {
        let offset = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let buckets_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        RefHashSlot {
            offset,
            buckets_size,
        }
    }
}

#[derive(Debug)]
pub struct RefMultiHashTable {
    pub capacity: u32,
    pub offset: usize,
    pub slot_offset: usize,
}

impl RefMultiHashTable {
    pub fn new(memory_map: &Mmap, position: usize) -> Self {
        let capacity_bytes = &memory_map[position..position + 4];
        let capacity = u32::from_le_bytes([
            capacity_bytes[0],
            capacity_bytes[1],
            capacity_bytes[2],
            capacity_bytes[3],
        ]);

        RefMultiHashTable {
            capacity,
            offset: position,
            slot_offset: position + 4,
        }
    }

    pub fn get_enumerator(&self) -> RefEnumerator {
        RefEnumerator::new(self)
    }
}

#[derive(Debug)]
pub struct RefEnumerator<'a> {
    offset: usize,
    slot_offset: usize,
    current_index: i32,
    slot_index: usize,
    capacity: u32,
    memory_map: &'a Mmap,
}

impl<'a> RefEnumerator<'a> {
    pub fn new(table: &'a RefMultiHashTable) -> RefEnumerator<'a> {
        RefEnumerator {
            offset: table.offset,
            slot_offset: table.slot_offset,
            current_index: -1,
            slot_index: 0,
            capacity: table.capacity,
            memory_map: unsafe { std::mem::transmute::<*const Mmap, &'a Mmap>(std::ptr::null()) }, // This will be set properly
        }
    }

    pub fn with_memory_map(mut self, memory_map: &'a Mmap) -> Self {
        self.memory_map = memory_map;
        self
    }

    pub fn get_current(&self, item_size: usize) -> Result<&[u8], HgMmapError> {
        let slot_start = self.slot_offset + 8 * self.slot_index;
        let slot_data = &self.memory_map[slot_start..slot_start + 8];
        let slot = RefHashSlot::from_bytes(slot_data);

        if self.current_index as u32 >= slot.buckets_size {
            return Err(HgMmapError::IndexOutOfRange);
        }

        let value_offset =
            self.offset + slot.offset as usize + item_size * self.current_index as usize;
        Ok(&self.memory_map[value_offset..value_offset + item_size])
    }

    pub fn move_next(&mut self) -> bool {
        self.current_index += 1;

        if self.slot_index >= self.capacity as usize {
            return false;
        }

        loop {
            let slot_start = self.slot_offset + 8 * self.slot_index;
            let slot_data = &self.memory_map[slot_start..slot_start + 8];
            let slot = RefHashSlot::from_bytes(slot_data);

            if (self.current_index as u32) < slot.buckets_size {
                break;
            }

            self.slot_index += 1;
            self.current_index = 0;

            if self.slot_index >= self.capacity as usize {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle_index: u32,
    pub name: String,
    pub hash_name_string: String,
    pub dependencies: Vec<u32>,
    pub direct_reverse_dependencies: Vec<u32>,
    pub direct_dependencies: Vec<u32>,
    pub bundle_flags: u32,
    pub hash_name: u64,
    pub hash_version: u64,
    pub category: RootCategory,
}

impl Bundle {
    pub fn from_bytes(
        data: &[u8],
    ) -> Result<(Self, RefValue, RefValue, RefValue, RefValue, RefValue), HgMmapError> {
        let bundle_index = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let name_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let hash_name_string_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let dependencies_offset = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let direct_reverse_dependencies_offset =
            u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
        let direct_dependencies_offset =
            u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
        let bundle_flags = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        let hash_name = u64::from_le_bytes([
            data[28], data[29], data[30], data[31], data[32], data[33], data[34], data[35],
        ]);

        let hash_version = u64::from_le_bytes([
            data[36], data[37], data[38], data[39], data[40], data[41], data[42], data[43],
        ]);

        let category_value = u32::from_le_bytes([data[44], data[45], data[46], data[47]]);
        let category = RootCategory::try_from(category_value)?;

        let bundle = Bundle {
            bundle_index,
            name: String::new(),
            hash_name_string: String::new(),
            dependencies: Vec::new(),
            direct_reverse_dependencies: Vec::new(),
            direct_dependencies: Vec::new(),
            bundle_flags,
            hash_name,
            hash_version,
            category,
        };

        Ok((
            bundle,
            RefValue::new(name_offset),
            RefValue::new(hash_name_string_offset),
            RefValue::new(dependencies_offset),
            RefValue::new(direct_reverse_dependencies_offset),
            RefValue::new(direct_dependencies_offset),
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AssetInfo {
    pub path_hash_head: u64,
    pub path: String,
    pub guid: GuidProxy,
    pub sub_asset_name_hash: u32,
    pub file_id: u64,
    pub bundle_index: u32,
}

impl AssetInfo {
    pub fn from_bytes(data: &[u8]) -> (Self, RefValue) {
        let path_hash_head = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        let path_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let guid_data = &data[12..28];
        let guid = GuidProxy::new(guid_data).unwrap();

        let sub_asset_name_hash = u32::from_le_bytes([data[28], data[29], data[30], data[31]]);

        let file_id = u64::from_le_bytes([
            data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39],
        ]);

        let bundle_index = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);

        let asset_info = AssetInfo {
            path_hash_head,
            path: String::new(),
            guid,
            sub_asset_name_hash,
            file_id,
            bundle_index,
        };

        (asset_info, RefValue::new(path_offset))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestData {
    pub bundles: Vec<Bundle>,
    pub asset_infos: Vec<AssetInfo>,
}

#[pyclass]
pub struct ManifestDataBinary {
    bundles: Option<RefArray>,
    asset_info_dictionary: Option<RefMultiHashTable>,
    hash: String,
    perforce_cl: String,
    memory_map: Option<Mmap>,
    _file: Option<File>,
    offset: usize,
    asset_info_offset: usize,
    bundle_offset: usize,
    data_offset: usize,
}

#[pymethods]
impl ManifestDataBinary {
    #[new]
    pub fn new() -> Self {
        ManifestDataBinary {
            bundles: None,
            asset_info_dictionary: None,
            hash: String::new(),
            perforce_cl: String::new(),
            memory_map: None,
            _file: None,
            offset: 0,
            asset_info_offset: 0,
            bundle_offset: 0,
            data_offset: 0,
        }
    }

    pub fn init_binary(&mut self, file_path: &str) -> PyResult<bool> {
        let file = File::open(file_path)?;
        let mmap = unsafe { Mmap::map(&file)? };

        let mut position = 0;
        self.offset = position;

        // Read header 1
        let head1 = u32::from_le_bytes([
            mmap[position],
            mmap[position + 1],
            mmap[position + 2],
            mmap[position + 3],
        ]);
        if head1 != ManifestDataBinary::HEAD1 {
            return Ok(false);
        }
        position += 4;

        // Read version hash length
        let version_hash_length = u32::from_le_bytes([
            mmap[position],
            mmap[position + 1],
            mmap[position + 2],
            mmap[position + 3],
        ]) as usize;
        position += 4;

        // Skip version hash data
        position += version_hash_length * 2;

        // Read header 2
        let head2 = u32::from_le_bytes([
            mmap[position],
            mmap[position + 1],
            mmap[position + 2],
            mmap[position + 3],
        ]);
        if head2 != ManifestDataBinary::HEAD2 {
            return Ok(false);
        }
        position += 4;

        // Read hash
        let hash_length = u32::from_le_bytes([
            mmap[position],
            mmap[position + 1],
            mmap[position + 2],
            mmap[position + 3],
        ]) as usize;
        position += 4;

        let hash_data = &mmap[position..position + hash_length * 2];
        let utf16_hash: Vec<u16> = hash_data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        self.hash = String::from_utf16(&utf16_hash).unwrap_or_default();
        position += hash_length * 2;

        // Read Perforce CL
        let perforce_cl_length = u32::from_le_bytes([
            mmap[position],
            mmap[position + 1],
            mmap[position + 2],
            mmap[position + 3],
        ]) as usize;
        position += 4;

        let perforce_cl_data = &mmap[position..position + perforce_cl_length * 2];
        let utf16_perforce: Vec<u16> = perforce_cl_data
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        self.perforce_cl = String::from_utf16(&utf16_perforce).unwrap_or_default();
        position += perforce_cl_length * 2;

        // Read asset info dictionary
        let asset_info_dictionary_size = u32::from_le_bytes([
            mmap[position],
            mmap[position + 1],
            mmap[position + 2],
            mmap[position + 3],
        ]) as usize;
        position += 4;

        self.asset_info_offset = position;
        self.asset_info_dictionary = Some(RefMultiHashTable::new(&mmap, self.asset_info_offset));
        position += asset_info_dictionary_size;

        // Read Bundle array
        let bundles_size = u32::from_le_bytes([
            mmap[position],
            mmap[position + 1],
            mmap[position + 2],
            mmap[position + 3],
        ]) as usize;
        position += 4;

        self.bundle_offset = position;
        self.bundles = Some(RefArray::new(&mmap, self.bundle_offset));
        position += bundles_size;

        // Read data size
        let _data_size = u32::from_le_bytes([
            mmap[position],
            mmap[position + 1],
            mmap[position + 2],
            mmap[position + 3],
        ]) as usize;
        position += 4;

        self.data_offset = position;

        self.memory_map = Some(mmap);
        self._file = Some(file);

        Ok(true)
    }

    pub fn save_to_json_file(&self, output_path: &str) -> PyResult<bool> {
        let manifest_data = self.to_manifest_data()?;
        let file = File::create(output_path)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &manifest_data).map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Failed to serialize JSON: {}", e),
            )
        })?;
        writer.flush()?;
        Ok(true)
    }
}

impl ManifestDataBinary {
    const HEAD1: u32 = 4279369489;
    const HEAD2: u32 = 4059231220;
    const _VERSION: &'static str = "1.0.1";

    pub fn to_manifest_data(&self) -> PyResult<ManifestData> {
        let mmap = self
            .memory_map
            .as_ref()
            .ok_or(HgMmapError::NotInitialized)?;
        let bundles_ref = self.bundles.as_ref().ok_or(HgMmapError::NotInitialized)?;
        let asset_info_dict = self
            .asset_info_dictionary
            .as_ref()
            .ok_or(HgMmapError::NotInitialized)?;

        // Process Bundle data
        let mut result_bundles = Vec::new();
        for i in 0..bundles_ref.length as usize {
            let bundle_data = bundles_ref.at(mmap, i, 48)?;
            let (
                mut bundle,
                name_ref,
                hash_name_ref,
                deps_ref,
                direct_reverse_deps_ref,
                direct_deps_ref,
            ) = Bundle::from_bytes(bundle_data)?;

            // Get string values
            let (_, name_offset) = name_ref.get_value(mmap, self.data_offset, 4);
            let name_str_ref = RefString::new(mmap, name_offset);
            bundle.name = name_str_ref
                .to_string(mmap, name_offset)
                .unwrap_or_default();

            let (_, hash_name_offset) = hash_name_ref.get_value(mmap, self.data_offset, 4);
            let hash_name_str_ref = RefString::new(mmap, hash_name_offset);
            bundle.hash_name_string = hash_name_str_ref
                .to_string(mmap, hash_name_offset)
                .unwrap_or_default();

            // Get dependency arrays
            let (_, deps_offset) = deps_ref.get_value(mmap, self.data_offset, 4);
            let deps_array = RefArray::new(mmap, deps_offset);
            bundle.dependencies = deps_array.to_list_int(mmap, Some(deps_offset));

            let (_, direct_reverse_deps_offset) =
                direct_reverse_deps_ref.get_value(mmap, self.data_offset, 4);
            let direct_reverse_deps_array = RefArray::new(mmap, direct_reverse_deps_offset);
            bundle.direct_reverse_dependencies =
                direct_reverse_deps_array.to_list_int(mmap, Some(direct_reverse_deps_offset));

            let (_, direct_deps_offset) = direct_deps_ref.get_value(mmap, self.data_offset, 4);
            let direct_deps_array = RefArray::new(mmap, direct_deps_offset);
            bundle.direct_dependencies =
                direct_deps_array.to_list_int(mmap, Some(direct_deps_offset));

            result_bundles.push(bundle);
        }

        // Process AssetInfo data
        let mut result_assets = Vec::new();
        let mut enumerator = asset_info_dict.get_enumerator().with_memory_map(mmap);

        while enumerator.move_next() {
            let asset_data = enumerator.get_current(48)?;
            let (mut asset_info, path_ref) = AssetInfo::from_bytes(asset_data);

            // Get path string
            let (_, path_offset) = path_ref.get_value(mmap, self.data_offset, 4);
            let path_str_ref = RefString::new(mmap, path_offset);
            asset_info.path = path_str_ref
                .to_string(mmap, path_offset)
                .unwrap_or_default();

            result_assets.push(asset_info);
        }

        Ok(ManifestData {
            bundles: result_bundles,
            asset_infos: result_assets,
        })
    }

    pub fn to_json(&self) -> PyResult<String> {
        let manifest_data = self.to_manifest_data()?;
        Ok(serde_json::to_string(&manifest_data).map_err(|e| {
            PyErr::new::<pyo3::exceptions::PyValueError, _>(format!(
                "Failed to serialize JSON: {}",
                e
            ))
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() -> Result<(), Box<dyn std::error::Error>> {
        let mut manifest = ManifestDataBinary::new();

        let file_path = "manifest.hgmmap";

        match manifest.init_binary(file_path) {
            Ok(true) => {
                println!("Successfully loaded manifest binary");
                println!("Hash: {}", manifest.hash);

                manifest.save_to_json_file("manifest.hgmmap.json")?;
                println!("Manifest data saved to manifest.hgmmap.json");
            }
            Ok(false) => {
                println!("Failed to load manifest binary");
            }
            Err(e) => {
                println!("Error loading manifest binary: {}", e);
            }
        }

        Ok(())
    }
}
