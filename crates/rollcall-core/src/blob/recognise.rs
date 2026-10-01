//! Built-in recognisers: well-known vendor binaries identified by file name alone.
//!
//! These are heuristics. A blob manifest's own values always win; a recogniser only fills a
//! name, version or supplier the manifest leaves out, with `filename` evidence at a lower
//! confidence. Licences are never inferred.
//!
//! A recogniser also knows the blob's CycloneDX type (a SoftDevice is `firmware`, a vendor
//! library `library`); for files no recogniser knows, [`type_from_extension`] guesses it.

use crate::model::ImageType;

/// What a recogniser knows about a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recognised {
    /// The component name, e.g. `s140_nrf52_softdevice`.
    pub name: String,
    /// The version, when the file name carries one.
    pub version: Option<String>,
    /// The vendor.
    pub supplier: &'static str,
    /// The CycloneDX component type.
    pub image_type: ImageType,
}

const NORDIC: &str = "Nordic Semiconductor ASA";
const ESPRESSIF: &str = "Espressif Systems";
const SILICON_LABS: &str = "Silicon Labs";

/// How a vendor library's file name is matched.
enum Pattern {
    /// The whole file name.
    Exact(&'static str),
    /// A prefix of the file name, which must also end in `.a`.
    Prefix(&'static str),
}

/// Vendor HAL / radio libraries shipped as binaries.
const LIBRARIES: &[(Pattern, &str)] = &[
    (Pattern::Exact("libphy.a"), ESPRESSIF),
    (Pattern::Exact("libnet80211.a"), ESPRESSIF),
    (Pattern::Exact("libpp.a"), ESPRESSIF),
    (Pattern::Exact("libcoexist.a"), ESPRESSIF),
    (Pattern::Prefix("libbt"), ESPRESSIF),
    (Pattern::Prefix("libnrf_802154"), NORDIC),
    (Pattern::Prefix("libnrf_cc310"), NORDIC),
    (Pattern::Prefix("librail_"), SILICON_LABS),
];

/// Whether `s` is one or more ASCII digits.
fn is_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// A Nordic SoftDevice: `s<nnn>_nrf5<n>_<major>.<minor>.<patch>_softdevice.hex`, e.g.
/// `s140_nrf52_7.3.0_softdevice.hex` → `s140_nrf52_softdevice` version `7.3.0`.
fn softdevice(file_name: &str) -> Option<Recognised> {
    let stem = file_name.strip_suffix("_softdevice.hex")?;
    let mut parts = stem.split('_');
    let (variant, family, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let variant_ok = variant.strip_prefix('s').is_some_and(is_digits);
    let family_ok = family.strip_prefix("nrf5").is_some_and(is_digits);
    let numbers: Vec<&str> = version.split('.').collect();
    let version_ok = numbers.len() == 3 && numbers.iter().all(|n| is_digits(n));
    (variant_ok && family_ok && version_ok).then(|| Recognised {
        name: format!("{variant}_{family}_softdevice"),
        version: Some(version.to_owned()),
        supplier: NORDIC,
        image_type: ImageType::Firmware,
    })
}

/// A vendor library from [`LIBRARIES`], named after its file without `.a`.
fn library(file_name: &str) -> Option<Recognised> {
    let stem = file_name.strip_suffix(".a").filter(|s| !s.is_empty())?;
    LIBRARIES.iter().find_map(|(pattern, supplier)| {
        let matched = match pattern {
            Pattern::Exact(name) => file_name == *name,
            Pattern::Prefix(prefix) => stem.starts_with(prefix),
        };
        matched.then(|| Recognised {
            name: stem.to_owned(),
            version: None,
            supplier,
            image_type: ImageType::Library,
        })
    })
}

/// Recognises a well-known vendor binary by its file name (not a path).
pub fn recognise(file_name: &str) -> Option<Recognised> {
    softdevice(file_name).or_else(|| library(file_name))
}

/// The CycloneDX type a file name's extension suggests, compared case-insensitively:
/// `.a`, `.lib` and `.o` are `library`; `.hex`, `.bin` and `.elf` are `firmware`; anything
/// else (including no extension) is `None`.
pub fn type_from_extension(file_name: &str) -> Option<ImageType> {
    let (stem, extension) = file_name.rsplit_once('.')?;
    if stem.is_empty() {
        return None;
    }
    match extension.to_ascii_lowercase().as_str() {
        "a" | "lib" | "o" => Some(ImageType::Library),
        "hex" | "bin" | "elf" => Some(ImageType::Firmware),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softdevice_file_names_are_recognised() {
        let r = recognise("s140_nrf52_7.3.0_softdevice.hex").unwrap();
        assert_eq!(r.name, "s140_nrf52_softdevice");
        assert_eq!(r.version.as_deref(), Some("7.3.0"));
        assert_eq!(r.supplier, NORDIC);
        let r = recognise("s132_nrf52_7.2.0_softdevice.hex").unwrap();
        assert_eq!(r.name, "s132_nrf52_softdevice");
        for name in [
            "s140_nrf52_7.3_softdevice.hex",
            "x140_nrf52_7.3.0_softdevice.hex",
            "s140_nrf52_7.3.0_extra_softdevice.hex",
            "s140_nrf52_7.3.0_softdevice.bin",
            "_softdevice.hex",
            "s_nrf5_.._softdevice.hex",
        ] {
            assert_eq!(recognise(name), None, "{name}");
        }
    }

    #[test]
    fn vendor_libraries_are_recognised() {
        for (file, name, supplier) in [
            ("libphy.a", "libphy", ESPRESSIF),
            ("libbtdm_app.a", "libbtdm_app", ESPRESSIF),
            ("libnrf_802154_sl.a", "libnrf_802154_sl", NORDIC),
            ("libnrf_cc310_0.9.13.a", "libnrf_cc310_0.9.13", NORDIC),
            ("librail_efr32xg21.a", "librail_efr32xg21", SILICON_LABS),
        ] {
            let r = recognise(file).unwrap();
            assert_eq!((r.name.as_str(), r.supplier), (name, supplier), "{file}");
            assert_eq!(r.version, None);
        }
        for file in ["libphy.so", "libphyx.a", ".a", "libc.a", "libbt"] {
            assert_eq!(recognise(file), None, "{file}");
        }
    }

    #[test]
    fn recognisers_supply_image_type() {
        let r = recognise("s140_nrf52_7.3.0_softdevice.hex").unwrap();
        assert_eq!(r.image_type, ImageType::Firmware);
        for file in ["libphy.a", "libbtdm_app.a", "librail_efr32xg21.a"] {
            assert_eq!(recognise(file).unwrap().image_type, ImageType::Library);
        }
    }

    #[test]
    fn extension_maps_to_image_type() {
        for file in ["x.a", "x.lib", "x.o", "X.A", "x.LIB", "dir.v1.O"] {
            assert_eq!(
                type_from_extension(file),
                Some(ImageType::Library),
                "{file}"
            );
        }
        for file in [
            "x.hex",
            "x.bin",
            "x.elf",
            "X.HEX",
            "x.Bin",
            "zephyr.signed.ELF",
        ] {
            assert_eq!(
                type_from_extension(file),
                Some(ImageType::Firmware),
                "{file}"
            );
        }
        for file in [
            "",
            "x",
            "x.",
            ".a",
            ".hex",
            "x.so",
            "x.a.gz",
            "x.bin~",
            "caf\u{e9}.\u{c9}LF",
        ] {
            assert_eq!(type_from_extension(file), None, "{file:?}");
        }
    }
}
