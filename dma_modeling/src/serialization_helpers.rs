use anyhow::{Context, Result};

use std::{
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use fxhash::{FxHashMap, FxHashSet};
use serde::{
    ser::{SerializeMap, SerializeSeq},
    Serialize, Serializer,
};

use serde_yaml;

/// Serialize integer as a hexadecimal string.
pub fn hex_u64<S>(num: &u64, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let hex_string: String = format!("+0x{:x}", num);
        serializer.serialize_str(&hex_string)
    } else {
        serializer.serialize_u64(*num)
    }
}

/// Serialize integer as a hexadecimal string.
pub fn hex_u32<S>(num: &u32, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let hex_string: String = format!("+0x{:x}", num);
        serializer.serialize_str(&hex_string)
    } else {
        serializer.serialize_u32(*num)
    }
}

/// Serialize integer as a hexadecimal string.
pub fn hex_key<S, V>(
    map: &FxHashMap<u32, V>,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: Serializer,
    V: Serialize,
{
    let is_yaml = serializer.is_human_readable();
    let mut s = serializer.serialize_map(Some(map.len())).unwrap();
    for (k, v) in map {
        if is_yaml {
            s.serialize_entry(format!("+0x{:x}", k).as_str(), &v)?;
        } else {
            s.serialize_entry(&k, &v)?;
        }
    }
    s.end()
}

/// Serialize integer as a hexadecimal string.
pub fn hex_vals<S>(container: &Vec<u32>, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let is_yaml = serializer.is_human_readable();
    let mut s = serializer.serialize_seq(Some(container.len())).unwrap();
    for v in container {
        if is_yaml {
            s.serialize_element(format!("+0x{:x}", v).as_str())?;
        } else {
            s.serialize_element(v)?;
        }
    }
    s.end()
}

/// Serialize integer as a hexadecimal string.
pub fn hex_set_vals<S>(
    container: &FxHashSet<u32>,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let is_yaml = serializer.is_human_readable();

    let mut s = serializer.serialize_seq(Some(container.len())).unwrap();
    for v in container {
        if is_yaml {
            s.serialize_element(format!("+0x{:x}", v).as_str())?;
        } else {
            s.serialize_element(v)?;
        }
    }
    s.end()
}

pub fn bufwriter(path: &Path) -> Result<BufWriter<File>> {
    File::create(path)
        .with_context(|| format!("Failed to create file {path:?}"))
        .map(BufWriter::new)
}

pub fn save_yaml<S: Serialize>(obj: &S, path: &PathBuf) -> Result<()> {
    let config_str = serde_yaml::to_string(&obj).context("Failed to serialize object")?;
    let mut writer = bufwriter(&path).context("Failed to create output file")?;

    write!(writer, "{}", config_str.as_str())?;
    Ok(())
}

pub fn save_bin<S: Serialize>(obj: &S, path: &PathBuf) -> Result<()> {
    let mut writer = bufwriter(&path).context("Failed to create output file")?;

    bincode::serialize_into(&mut writer, &obj)?;
    Ok(())
}

pub fn is_none<T>(opt: &Option<T>) -> bool {
    opt.is_none()
}

pub fn is_empty_map<K, V>(opt: &FxHashMap<K, V>) -> bool {
    opt.is_empty()
}

pub fn is_empty_vec<V>(opt: &Vec<V>) -> bool {
    opt.is_empty()
}

pub fn is_zero<V: Into<isize> + Copy>(opt: &V) -> bool {
    let v: isize = (*opt).into();
    v == 0
}

pub fn is_false(opt: &bool) -> bool {
    !opt
}

pub fn zero() -> isize {
    0
}
