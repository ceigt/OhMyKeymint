//! Root-private staging of issued Keyboxes. Creation and listing never import keys.
use anyhow::{anyhow, bail, Context, Result};
use kmr_common::runtime::fs::atomic_replace_preserving_metadata;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::UNIX_EPOCH,
};
use zeroize::Zeroizing;

const ROOT: &str = crate::root_path!("data/rkp-artifacts");
const MAX_ARTIFACTS: usize = 16;

#[derive(Serialize)]
pub struct Summary {
    pub id: String,
    pub created_at: u64,
    pub chain_subjects: Vec<String>,
    pub can_delete: bool,
    pub valid: bool,
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("RKP result operations require root");
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.uid() != 0 || meta.mode() & 0o077 != 0 {
        bail!("RKP result directory must be root-owned and private");
    }
    Ok(file)
}

/// Storage readiness/capacity check performed BEFORE the signing request.
pub fn prepare() -> Result<()> {
    require_root()?;
    match fs::DirBuilder::new().mode(0o700).create(ROOT) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error).context("create RKP results directory"),
    }
    let _root = private_directory(Path::new(ROOT))?;
    // A crash after reserving or deleting a result may leave an empty directory.
    for entry in fs::read_dir(ROOT)? {
        let entry = entry?;
        validate_id(&entry.file_name().to_string_lossy())?;
        let directory = entry.path();
        let _directory = private_directory(&directory)?;
        if fs::read_dir(&directory)?.next().is_none() {
            fs::remove_dir(&directory)?;
        }
    }
    if ids(Path::new(ROOT))?.len() >= MAX_ARTIFACTS {
        bail!("RKP result limit reached; remove unneeded staged results before issuing again");
    }
    Ok(())
}

pub fn validate_id(id: &str) -> Result<()> {
    if id.len() != 32
        || !id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        bail!("invalid RKP result ID");
    }
    Ok(())
}

fn ids(root: &Path) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for entry in fs::read_dir(root)? {
        let name = entry?
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("invalid RKP result entry"))?;
        validate_id(&name)?;
        if ids.len() >= MAX_ARTIFACTS {
            bail!("too many RKP results");
        }
        ids.push(name);
    }
    ids.sort();
    Ok(ids)
}

pub fn store_issued_keybox(xml: &[u8]) -> Result<String> {
    require_root()?;
    crate::local_rkp::validate_issued_xml(xml)?;
    prepare()?;
    let mut raw = [0; 16];
    SystemRandom::new()
        .fill(&mut raw)
        .map_err(|_| anyhow!("cannot allocate RKP result ID"))?;
    let id = hex::encode(raw);
    let directory = Path::new(ROOT).join(&id);
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .context("reserve RKP result directory")?;
    let result = (|| -> Result<()> {
        let _directory = private_directory(&directory)?;
        atomic_replace_preserving_metadata(&directory.join("keybox.xml"), xml, 0o600, 0, 0)?;
        File::open(ROOT)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        // Only this newly reserved, exact ID directory is removed on failed staging.
        let _ = fs::remove_dir_all(&directory);
        return Err(error).context("save private RKP result");
    }
    Ok(id)
}

fn open_result(id: &str) -> Result<(File, PathBuf)> {
    validate_id(id)?;
    let _root = private_directory(Path::new(ROOT))?;
    let directory = Path::new(ROOT).join(id);
    let _dir = private_directory(&directory)?;
    Ok((open_private_file(&directory.join("keybox.xml"))?, directory))
}

fn open_private_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != 0
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
        || meta.len() > crate::keybox::MAX_KEYBOX_XML_BYTES as u64
    {
        bail!("RKP result file has unsafe type, owner, permissions or size");
    }
    Ok(file)
}

fn read_result(file: File) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(crate::keybox::MAX_KEYBOX_XML_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > crate::keybox::MAX_KEYBOX_XML_BYTES {
        bail!("RKP result exceeds size limit");
    }
    Ok(bytes)
}

fn valid_summary(directory: &Path, id: &str) -> Result<Summary> {
    let _directory = private_directory(directory)?;
    let file = open_private_file(&directory.join("keybox.xml"))?;
    let created_at = file
        .metadata()?
        .modified()?
        .duration_since(UNIX_EPOCH)?
        .as_secs();
    let xml = read_result(file)?;
    let parsed = crate::keybox::KeyBox::from_xml_str(
        std::str::from_utf8(&xml).context("invalid RKP result encoding")?,
    )
    .map_err(|_| anyhow!("RKP result is not a valid Keybox"))?;
    let inspector = parsed.inspector();
    let chain = inspector.ec.context("RKP result has no EC chain")?;
    let chain_subjects: Vec<_> = chain
        .certificates
        .into_iter()
        .map(|cert| cert.subject)
        .collect();
    if chain_subjects.is_empty()
        || chain_subjects.len() > 8
        || chain_subjects
            .iter()
            .any(|subject| subject.len() > 512 || subject.chars().any(char::is_control))
    {
        bail!("RKP result metadata is out of bounds");
    }
    Ok(Summary {
        id: id.into(),
        created_at,
        chain_subjects,
        can_delete: false,
        valid: true,
    })
}

// Only known, private regular files can be removed. A crash in the atomic
// writer may leave its random temporary file; never follow links or recurse.
fn removable_files(directory: &Path) -> Result<Vec<(PathBuf, String)>> {
    let _directory = private_directory(directory)?;
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().context("Invalid result filename")?;
        if name != "keybox.xml"
            && !name
                .strip_prefix(".omk-tmp-")
                .is_some_and(|suffix| validate_id(suffix).is_ok())
        {
            bail!("Unknown file in staged result; refusing deletion");
        }
        if files.len() >= 2 {
            bail!("Unexpected files in staged result; refusing deletion");
        }
        let bytes = read_result(open_private_file(&entry.path())?)?;
        files.push((entry.path(), crate::rkp_renewal::sha256(&bytes)));
    }
    Ok(files)
}

fn protected_files(
    directory: &Path,
    id: &str,
    can_delete: &impl Fn(&str, &str) -> Result<bool>,
) -> Result<Vec<(PathBuf, String)>> {
    let files = removable_files(directory)?;
    // Check ID/transaction protection even for an empty interrupted reservation.
    if !can_delete(id, "")? {
        bail!("This result is protected by an unfinished renewal operation");
    }
    for (_, hash) in &files {
        if !can_delete(id, hash)? {
            bail!("This result is active or protected by an unfinished renewal operation");
        }
    }
    Ok(files)
}

fn summary(root: &Path, id: &str, can_delete: &impl Fn(&str, &str) -> Result<bool>) -> Summary {
    let directory = root.join(id);
    let mut summary = valid_summary(&directory, id).unwrap_or_else(|_| Summary {
        id: id.into(),
        created_at: 0,
        chain_subjects: Vec::new(),
        can_delete: false,
        valid: false,
    });
    summary.can_delete = protected_files(&directory, id, can_delete).is_ok();
    summary
}

fn list_at(root: &Path, can_delete: &impl Fn(&str, &str) -> Result<bool>) -> Result<Vec<Summary>> {
    let _root = private_directory(root)?;
    let mut entries: Vec<_> = ids(root)?
        .iter()
        .map(|id| summary(root, id, can_delete))
        .collect();
    entries.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(entries)
}

pub fn summary_json(id: &str) -> Result<String> {
    require_root()?;
    validate_id(id)?;
    let _root = private_directory(Path::new(ROOT))?;
    serde_json::to_string(&summary(
        Path::new(ROOT),
        id,
        &crate::rkp_renewal::artifact_can_delete,
    ))
    .context("encode public RKP result metadata")
}

pub fn list_json() -> Result<String> {
    require_root()?;
    #[derive(Serialize)]
    struct List {
        artifacts: Vec<Summary>,
    }
    // Listing an empty state is read-only; do not create storage just by opening UI.
    let artifacts = if !Path::new(ROOT).try_exists()? {
        Vec::new()
    } else {
        list_at(Path::new(ROOT), &crate::rkp_renewal::artifact_can_delete)?
    };
    serde_json::to_string(&List { artifacts }).context("encode RKP result list")
}

pub fn import(id: &str) -> Result<()> {
    require_root()?;
    let _operation = crate::rkp_renewal::operation_lock()?;
    crate::rkp_renewal::require_no_transaction()?;
    let (file, _) = open_result(id)?;
    let xml = read_result(file)?;
    // Recheck dates/signatures/trust AND private-key matching when importing, not
    // just when issuing. Expired results can be listed, but cannot be installed.
    crate::local_rkp::validate_issued_xml(&xml)?;
    crate::keybox::install_keybox_xml(&xml).context("import issued RKP Keybox")
}

pub(crate) fn read_private(id: &str) -> Result<Zeroizing<Vec<u8>>> {
    let (file, _) = open_result(id)?;
    read_result(file)
}
pub fn delete(id: &str) -> Result<()> {
    require_root()?;
    validate_id(id)?;
    let _operation = crate::rkp_renewal::operation_lock()?;
    let _keybox = crate::rkp_renewal::keybox_lock()?;
    delete_at(
        Path::new(ROOT),
        id,
        &crate::rkp_renewal::artifact_can_delete,
    )?;
    crate::rkp_renewal::forget_artifact(id)
}

fn delete_at(
    root: &Path,
    id: &str,
    can_delete: &impl Fn(&str, &str) -> Result<bool>,
) -> Result<()> {
    validate_id(id)?;
    let root_handle = private_directory(root)?;
    let directory = root.join(id);
    let files = protected_files(&directory, id, can_delete)?;
    for (path, _) in files {
        fs::remove_file(path)?;
    }
    fs::remove_dir(directory)?;
    root_handle.sync_all()?;
    Ok(())
}

pub(crate) fn remove_owned(id: &str, expected: &str) -> Result<()> {
    validate_id(id)?;
    let (file, directory) = match open_result(id) {
        Ok(result) => result,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            let _root = private_directory(Path::new(ROOT))?;
            let directory = Path::new(ROOT).join(id);
            if directory.try_exists()? {
                let _directory = private_directory(&directory)?;
                fs::remove_dir(&directory)?;
                File::open(ROOT)?.sync_all()?;
            }
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    if crate::rkp_renewal::sha256(&read_result(file)?) != expected {
        bail!("owned RKP artifact changed; refusing cleanup");
    }
    fs::remove_file(directory.join("keybox.xml"))?;
    fs::remove_dir(directory)?;
    File::open(ROOT)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
    fn staged(root: &Path, id: &str, filename: &str, bytes: &[u8]) -> PathBuf {
        let directory = root.join(id);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let file = directory.join(filename);
        fs::write(&file, bytes).unwrap();
        fs::set_permissions(file, fs::Permissions::from_mode(0o600)).unwrap();
        directory
    }
    #[test]
    fn partial_results_do_not_hide_valid_results_and_can_be_removed() {
        let root = fixture();
        let valid = "a".repeat(32);
        let partial = "b".repeat(32);
        let interrupted = "c".repeat(32);
        staged(
            root.path(),
            &valid,
            "keybox.xml",
            include_bytes!("../template/keybox.xml"),
        );
        staged(
            root.path(),
            &partial,
            "keybox.xml",
            b"<AndroidAttestation><Keybox",
        );
        staged(
            root.path(),
            &interrupted,
            &format!(".omk-tmp-{}", "d".repeat(32)),
            b"unfinished",
        );
        let entries = list_at(root.path(), &|_, _| Ok(true)).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().find(|e| e.id == valid).unwrap().valid);
        for id in [&partial, &interrupted] {
            let entry = entries.iter().find(|e| &e.id == id).unwrap();
            assert!(!entry.valid && entry.can_delete && entry.chain_subjects.is_empty());
            delete_at(root.path(), id, &|_, _| Ok(true)).unwrap();
            assert!(!root.path().join(id).exists());
        }
        assert_eq!(list_at(root.path(), &|_, _| Ok(true)).unwrap().len(), 1);
    }
    #[test]
    fn damaged_result_deletion_still_checks_ids_hashes_and_private_files() {
        let root = fixture();
        let id = "a".repeat(32);
        let directory = staged(root.path(), &id, "keybox.xml", b"partial");
        let hash = crate::rkp_renewal::sha256(b"partial");
        assert!(delete_at(root.path(), &id, &|_, h| Ok(h != hash)).is_err());
        assert!(delete_at(root.path(), &id, &|candidate, _| Ok(candidate != id)).is_err());
        assert!(delete_at(root.path(), &id, &|_, _| bail!(
            "Protection state unavailable"
        ))
        .is_err());
        assert!(directory.join("keybox.xml").exists());
        fs::remove_file(directory.join("keybox.xml")).unwrap();
        let victim = root.path().join("outside");
        fs::write(&victim, b"untouched").unwrap();
        symlink(&victim, directory.join("keybox.xml")).unwrap();
        assert!(!summary(root.path(), &id, &|_, _| Ok(true)).can_delete);
        assert!(delete_at(root.path(), &id, &|_, _| Ok(true)).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        fs::remove_file(directory.join("keybox.xml")).unwrap();
        fs::write(directory.join("unknown"), b"retain").unwrap();
        assert!(delete_at(root.path(), &id, &|_, _| Ok(true)).is_err());
        assert!(directory.join("unknown").exists());
    }
    #[test]
    fn atomic_publication_leaves_only_a_complete_private_result() {
        let root = fixture();
        let file = root.path().join("keybox.xml");
        atomic_replace_preserving_metadata(&file, b"complete", 0o600, 0, 0).unwrap();
        assert_eq!(
            &**read_result(open_private_file(&file).unwrap()).unwrap(),
            b"complete"
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }

    #[test]
    fn private_directories_reject_links_files_and_broad_permissions() {
        let parent = tempfile::tempdir().unwrap();
        let private = parent.path().join("private");
        fs::DirBuilder::new().mode(0o700).create(&private).unwrap();
        let link = parent.path().join("link");
        symlink(&private, &link).unwrap();
        assert!(private_directory(&link).is_err());
        let file = parent.path().join("regular");
        fs::write(&file, b"not a directory").unwrap();
        assert!(private_directory(&file).is_err());
        fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(private_directory(&private).is_err());
        // TempDir deletes these public test-only artifacts even on unwind.
    }

    #[test]
    fn reads_of_result_xml_are_bounded() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&vec![0; crate::keybox::MAX_KEYBOX_XML_BYTES + 1])
            .unwrap();
        use std::io::Seek;
        file.rewind().unwrap();
        assert!(read_result(file).is_err());
    }

    #[test]
    fn result_ids_cannot_escape_storage() {
        assert!(validate_id("0123456789abcdef0123456789abcdef").is_ok());
        for id in [
            "",
            "../test",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdef/",
            "a.xml",
        ] {
            assert!(validate_id(id).is_err());
        }
    }
    #[test]
    fn metadata_contains_no_xml_keys_or_paths() {
        let value = serde_json::to_value(Summary {
            id: "a".repeat(32),
            created_at: 1,
            chain_subjects: vec!["CN=test".into()],
            can_delete: true,
            valid: true,
        })
        .unwrap();
        assert_eq!(value.as_object().unwrap().len(), 5);
        for key in ["keybox_xml", "private_key", "path"] {
            assert!(value.get(key).is_none());
        }
    }
}
