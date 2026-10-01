//! Sysbuild: find the image build directories of a sysbuild top-level build, ingest each and
//! merge them into one product.

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use super::{Ingest, IngestOptions, Warning, ZephyrError, build_info, read_text};
use crate::merge::{self, ProductSpec};

/// One image of a sysbuild build, from the top-level `build_info.yml`'s `cmake.images[]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SysbuildImage {
    /// The image name, which is also its build subdirectory.
    pub name: String,
    /// The sysbuild image type as written, e.g. `MAIN` or `BOOTLOADER`.
    pub kind: Option<String>,
    /// The image build directory: the top-level directory joined with `name`.
    pub dir: PathBuf,
}

impl SysbuildImage {
    /// Whether this is the application image (`type: MAIN`).
    pub fn is_main(&self) -> bool {
        self.kind.as_deref() == Some("MAIN")
    }
}

/// Whether `name` can be used as a single build subdirectory name: exactly one normal path
/// component, with no separator, drive or stream colon, or control character.
fn is_plain_dir_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(_)), None)
    ) && !name.contains(['/', '\\', ':'])
        && !name.chars().any(char::is_control)
}

/// Reads the images of the sysbuild top-level build directory `top_dir` from its
/// `build_info.yml`, sorted by name. `domains.yaml` is not used.
pub fn discover(top_dir: &Path) -> Result<Vec<SysbuildImage>, ZephyrError> {
    let path = top_dir.join("build_info.yml");
    let info = build_info::parse(&read_text(&path)?).map_err(|source| ZephyrError::BuildInfo {
        path: path.clone(),
        source,
    })?;
    if !info.is_sysbuild() {
        return Err(ZephyrError::NotASysbuild { path });
    }
    let listed = info
        .cmake
        .as_ref()
        .and_then(|c| c.images.as_ref())
        .map(Vec::as_slice)
        .unwrap_or_default();
    if listed.is_empty() {
        return Err(ZephyrError::NoImages { path });
    }
    let mut images = Vec::with_capacity(listed.len());
    for image in listed {
        if !is_plain_dir_name(&image.name) {
            return Err(ZephyrError::InvalidImageName {
                path,
                name: image.name.clone(),
            });
        }
        images.push(SysbuildImage {
            name: image.name.clone(),
            kind: image.kind.clone(),
            dir: top_dir.join(&image.name),
        });
    }
    images.sort();
    let repeated = images.windows(2).find_map(|pair| match pair {
        [a, b] if a.name == b.name => Some(a.name.clone()),
        _ => None,
    });
    if let Some(name) = repeated {
        return Err(ZephyrError::DuplicateImageName { path, name });
    }
    if !images.iter().any(SysbuildImage::is_main) {
        return Err(ZephyrError::NoMainImage { path });
    }
    Ok(images)
}

/// Ingests every image of the sysbuild top-level build directory `options.build_dir` and
/// merges them under one product named after the `MAIN` image's application.
///
/// The result is exactly what `rollcall merge --product <app>` gives for the images'
/// separately ingested products. Warnings come image by image (sorted by image name), each
/// location prefixed with `<image>: `.
///
/// Two images that ingest to the same image identity (kind, name and version, e.g. two
/// MCUboot builds that both become `bootloader:mcuboot`) are an error naming both image
/// directories, never silently merged into one node.
pub fn ingest_sysbuild(options: &IngestOptions) -> Result<Ingest, ZephyrError> {
    let top = &options.build_dir;
    let images = discover(top)?;
    let mut products = Vec::with_capacity(images.len());
    let mut warnings = Vec::new();
    let mut main_name = None;
    // Each ingested image's identity and the image build directory it came from.
    let mut seen: BTreeMap<(crate::model::ImageKind, String, Option<String>), PathBuf> =
        BTreeMap::new();
    for image in &images {
        let image_options = IngestOptions {
            build_dir: image.dir.clone(),
            west_list: options.west_list.clone(),
            include_sdk: options.include_sdk,
            sysbuild: false,
        };
        let ingest = super::ingest(&image_options)?;
        for ingested in &ingest.product.images {
            let (kind, name, version) = ingested.key();
            let key = (kind, name.to_owned(), version.map(str::to_owned));
            if let Some(first) = seen.get(&key) {
                let identity = match version {
                    Some(version) => format!("{}:{name}@{version}", kind.as_str()),
                    None => format!("{}:{name}", kind.as_str()),
                };
                return Err(ZephyrError::DuplicateImage {
                    path: top.join("build_info.yml"),
                    image: identity,
                    first: first.clone(),
                    second: image.dir.clone(),
                });
            }
            seen.insert(key, image.dir.clone());
        }
        if image.is_main() && main_name.is_none() {
            main_name = Some(ingest.product.name.clone());
        }
        warnings.extend(
            ingest
                .warnings
                .into_iter()
                .map(|w| Warning::new(format!("{}: {}", image.name, w.location), w.message)),
        );
        products.push(ingest.product);
    }
    let path = top.join("build_info.yml");
    let Some(name) = main_name else {
        return Err(ZephyrError::NoMainImage { path });
    };
    let spec = ProductSpec::new(&name, None).map_err(|e| ZephyrError::Merge {
        path: top.clone(),
        source: Box::new(merge::Error::Spec(e)),
    })?;
    let product = merge::merge(products, Some(&spec)).map_err(|source| ZephyrError::Merge {
        path: top.clone(),
        source: Box::new(source),
    })?;
    Ok(Ingest { product, warnings })
}
