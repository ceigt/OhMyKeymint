//! Opt-in, root-only RKP renewal. Local checks never contact a server.
use crate::{
    keybox,
    local_rkp::{self, Protocol},
    local_rkp_artifacts as artifacts,
};
use anyhow::{anyhow, bail, Context, Result};
use kmr_common::{
    consts::{KEYSTORE_GID, KEYSTORE_UID},
    runtime::fs::atomic_replace_preserving_metadata,
};
use ring::{
    digest,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const ROOT: &str = crate::root_path!("data/rkp-renewal");
const RECEIPT: &str = crate::root_path!("data/keybox-loaded.json");
const DAY: u64 = 86400;
const INTERVAL: u64 = 6 * 3600;
const MIN_CLOCK: u64 = 1735689600;
const MAX_JSON: usize = 32768;
const READ_RETRY_DELAYS: [u64; 3] = [900, 3600, 10800];
const PREPARATION_RETRY_DELAYS: [u64; 5] = [300, 900, 3600, 10800, INTERVAL];

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Consent {
    protocol: String,
    token: String,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct State {
    last_check: u64,
    last_success: u64,
    next_check: u64,
    attempts: Vec<u64>,
    blocked: Option<String>,
    pending: Option<Pending>,
    issuing_source: Option<String>,
    issuing_config: String,
    transaction: Option<Transaction>,
    owned: Vec<Owned>,
    read_retries: usize,
    preparation_retries: usize,
    last_error: Option<Failure>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    code: String,
    stage: String,
    at: u64,
    retry_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
enum RenewalFailure {
    #[error("Renewal configuration changed")]
    ConfigurationChanged,
    #[error("The staged certificate is invalid or changed")]
    CandidateInvalid,
    #[error("The active Keybox changed")]
    ActiveChanged,
    #[error("OMK did not confirm loading the Keybox")]
    LoadUnconfirmed,
    #[error("Automatic rollback is not confirmed")]
    RollbackUnconfirmed,
}
impl RenewalFailure {
    fn details(self) -> (&'static str, &'static str) {
        match self {
            Self::ConfigurationChanged => ("configuration_changed", "validation"),
            Self::CandidateInvalid => ("candidate_invalid", "validation"),
            Self::ActiveChanged => ("active_changed", "replacement"),
            Self::LoadUnconfirmed => ("load_unconfirmed", "confirmation"),
            Self::RollbackUnconfirmed => ("rollback_unconfirmed", "recovery"),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    config: String,
    id: String,
    source_hash: String,
    target_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Transaction {
    source_hash: String,
    target_hash: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owned {
    id: String,
    hash: String,
    expiry: i64,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Issuance {
    stage: String,
    protocol: String,
    last_successful_protocol: Option<String>,
    artifact_id: Option<String>,
    at: u64,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    pid: u32,
    start: String,
    boot: String,
    sequence: u64,
    sha256: String,
    identity: String,
    config: String,
    fallback: bool,
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, bytes))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
#[cfg(test)]
thread_local! { static TEST_ROOT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) }; }
fn root_dir() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_ROOT.with(|root| root.borrow().clone()) {
        return path;
    }
    PathBuf::from(ROOT)
}
fn path(name: &str) -> PathBuf {
    root_dir().join(name)
}
fn root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("RKP renewal requires root");
    }
    match fs::DirBuilder::new().mode(0o700).create(root_dir()) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root_dir())?;
    let m = dir.metadata()?;
    if m.uid() != 0 || m.mode() & 0o077 != 0 {
        bail!("Renewal directory is not root-private");
    }
    Ok(())
}
fn read_bounded(path: &Path, owner: u32, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != owner
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > limit as u64
    {
        bail!("Unsafe private RKP file");
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("RKP file exceeds size limit");
    }
    Ok(bytes)
}
fn load<T: serde::de::DeserializeOwned + Default>(name: &str) -> Result<T> {
    if !path(name).try_exists()? {
        return Ok(T::default());
    }
    Ok(serde_json::from_slice(&read_bounded(
        &path(name),
        0,
        MAX_JSON,
    )?)?)
}
fn save<T: Serialize>(name: &str, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_JSON {
        bail!("RKP state exceeds limit");
    }
    write_private(name, &bytes)
}
fn write_private(name: &str, bytes: &[u8]) -> Result<()> {
    let target = path(name);
    if target.try_exists()? {
        let _ = read_bounded(&target, 0, keybox::MAX_KEYBOX_XML_BYTES)?;
    }
    atomic_replace_preserving_metadata(&target, bytes, 0o600, 0, 0)?;
    Ok(())
}
fn remove(name: &str) -> Result<()> {
    match fs::remove_file(path(name)) {
        Ok(()) => File::open(root_dir())?.sync_all()?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
pub(crate) fn operation_lock() -> Result<File> {
    root()?;
    lock(&path("operation.lock"), 0, true)
}
fn lock(path: &Path, owner: u32, nonblocking: bool) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || ![0, owner].contains(&m.uid()) || m.mode() & 0o077 != 0 || m.nlink() != 1 {
        bail!("Unsafe RKP lock file");
    }
    if m.uid() != owner && unsafe { libc::fchown(file.as_raw_fd(), owner, owner) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let flags = libc::LOCK_EX | if nonblocking { libc::LOCK_NB } else { 0 };
    if unsafe { libc::flock(file.as_raw_fd(), flags) } != 0 {
        bail!("Another OMK operation is in progress");
    }
    Ok(file)
}
pub(crate) fn keybox_lock() -> Result<File> {
    lock(
        Path::new(crate::root_path!("data/keybox-operation.lock")),
        KEYSTORE_UID,
        false,
    )
}
pub(crate) fn read_keybox() -> Result<Zeroizing<Vec<u8>>> {
    read_bounded(
        Path::new(keybox::KEYBOX_PATH),
        KEYSTORE_UID,
        keybox::MAX_KEYBOX_XML_BYTES,
    )
}
pub(crate) fn require_no_transaction() -> Result<()> {
    let state: State = load("state.json")?;
    if state.transaction.is_some() || state.pending.is_some() || state.issuing_source.is_some() {
        bail!("Recover or discard the pending renewal operation first");
    }
    if load::<Issuance>("issuance.json")?.stage == "submitted" {
        bail!("Previous RKP submission is uncertain; acknowledge it in renewal settings before issuing again");
    }
    Ok(())
}
pub(crate) fn artifact_can_delete(id: &str, hash: &str) -> Result<bool> {
    let state: State = load("state.json")?;
    let trace: Issuance = load("issuance.json")?;
    let active = sha256(&read_keybox()?);
    let loaded = receipt().ok().map(|receipt| receipt.sha256);
    Ok(loaded.as_deref() != Some(hash) && artifact_is_removable(&state, &trace, id, hash, &active))
}
fn artifact_is_removable(
    state: &State,
    trace: &Issuance,
    id: &str,
    hash: &str,
    active: &str,
) -> bool {
    hash != active
        && state.transaction.is_none()
        && state.issuing_source.is_none()
        && trace.stage != "submitted"
        && state
            .pending
            .as_ref()
            .is_none_or(|p| p.id != id && p.target_hash != hash && p.source_hash != hash)
}
pub(crate) fn forget_artifact(id: &str) -> Result<()> {
    let mut state: State = load("state.json")?;
    state.owned.retain(|item| item.id != id);
    save("state.json", &state)
}
pub(crate) fn begin_manual_issuance(protocol: Protocol) -> Result<()> {
    let mut trace: Issuance = load("issuance.json")?;
    trace.stage = "preparing".into();
    trace.protocol = protocol.as_str().into();
    trace.artifact_id = None;
    trace.at = now()?;
    save("issuance.json", &trace)
}
pub(crate) fn before_submission(protocol: Protocol, token: Option<&str>) -> Result<()> {
    if let Some(token) = token {
        let c = consent()?.context("Renewal was disabled before submission")?;
        if c.token != token {
            bail!("Renewal settings changed before submission");
        }
        same_consent(&c)?;
        let state: State = load("state.json")?;
        if state.issuing_source.as_deref() != Some(sha256(&read_keybox()?).as_str())
            || state.issuing_config != config_hash()?
        {
            bail!("Keybox, PIF or patch configuration changed before submission");
        }
    }
    journal_submission(protocol, token.is_some())
}
fn journal_submission(protocol: Protocol, automatic: bool) -> Result<()> {
    if automatic {
        reserve_submission(now()?)?;
    }
    let mut trace: Issuance = load("issuance.json")?;
    trace.stage = "submitted".into();
    trace.protocol = protocol.as_str().into();
    trace.at = now()?;
    save("issuance.json", &trace)
}

// Persist the budget before the submitted journal and before any signing POST.
// A crash between these writes may spend one slot, but can never permit an
// uncounted or blindly repeated signing request.
fn reserve_submission(time: u64) -> Result<()> {
    let mut state: State = load("state.json")?;
    due(time, &state, i64::MAX)?;
    state.attempts.retain(|t| time.saturating_sub(*t) < DAY);
    if state.attempts.len() >= 2 {
        bail!("Automatic signing budget exhausted");
    }
    state.attempts.push(time);
    state.preparation_retries = 0;
    state.next_check = time.saturating_add(INTERVAL);
    save("state.json", &state)
}
pub(crate) fn record_success(protocol: Protocol, id: &str) -> Result<()> {
    let mut trace: Issuance = load("issuance.json")?;
    trace.stage = "completed".into();
    trace.protocol = protocol.as_str().into();
    trace.last_successful_protocol = Some(protocol.as_str().into());
    trace.artifact_id = Some(id.into());
    save("issuance.json", &trace)
}
fn consent() -> Result<Option<Consent>> {
    if !path("enabled.json").try_exists()? {
        return Ok(None);
    }
    let c: Consent = serde_json::from_slice(&read_bounded(&path("enabled.json"), 0, MAX_JSON)?)?;
    if Protocol::parse(&c.protocol)? == Protocol::Auto
        || c.token.len() != 32
        || !c.token.bytes().all(|b| b.is_ascii_hexdigit())
    {
        bail!("Invalid renewal consent");
    }
    Ok(Some(c))
}
fn same_consent(c: &Consent) -> Result<()> {
    if consent()?.is_none_or(|current| current.token != c.token) {
        bail!("Renewal was disabled or settings changed");
    }
    no_other_manager()
}
fn no_other_manager() -> Result<()> {
    let enabled = Path::new("/data/adb/duck-toolbox/var/renewal/enabled");
    match fs::read_to_string(enabled) {
        Ok(v) if v.trim() == "1" => {
            bail!("Disable Duck automatic renewal before using OMK renewal")
        }
        Ok(_) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => bail!("Cannot verify Duck renewal state"),
    }
    Ok(())
}
fn process_start(pid: u32) -> Result<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    Ok(stat
        .rsplit_once(')')
        .context("invalid process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .context("missing process start time")?
        .into())
}
pub(crate) fn config_hash() -> Result<String> {
    let mut bytes = Vec::new();
    for name in [
        crate::root_path!("config.toml"),
        crate::root_path!("injector.toml"),
        crate::root_path!("data/pif_fingerprint.json"),
        crate::root_path!("data/security_patch_defaults.toml"),
    ] {
        bytes.extend_from_slice(name.as_bytes());
        match fs::read(name) {
            Ok(value) => {
                bytes.push(1);
                bytes.extend_from_slice(sha256(&value).as_bytes());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => bytes.push(0),
            Err(e) => return Err(e.into()),
        }
    }
    for name in [
        "ro.build.fingerprint",
        "ro.build.version.security_patch",
        "ro.vendor.build.security_patch",
        "ro.bootimage.build.version.security_patch",
        "ro.product.name_for_attestation",
    ] {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(
            rsproperties::get::<String>(name)
                .unwrap_or_default()
                .as_bytes(),
        );
        bytes.push(0);
    }
    Ok(sha256(&bytes))
}
pub(crate) fn publish_loaded_receipt(identity: [u8; 32], loaded: bool) -> Result<()> {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let bytes = read_keybox()?;
    let parsed = keybox::KeyBox::from_xml_str(std::str::from_utf8(&bytes)?)?;
    if parsed.identity_digest() != identity {
        bail!("On-disk and loaded Keybox differ");
    }
    let pid = std::process::id();
    let receipt = Receipt {
        pid,
        start: process_start(pid)?,
        boot: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .into(),
        sequence: SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1,
        sha256: sha256(&bytes),
        identity: hex::encode(identity),
        config: config_hash()?,
        fallback: !loaded,
    };
    atomic_replace_preserving_metadata(
        Path::new(RECEIPT),
        &serde_json::to_vec(&receipt)?,
        0o600,
        KEYSTORE_UID,
        KEYSTORE_GID,
    )?;
    Ok(())
}
fn receipt() -> Result<Receipt> {
    let r: Receipt =
        serde_json::from_slice(&read_bounded(Path::new(RECEIPT), KEYSTORE_UID, MAX_JSON)?)?;
    if r.fallback
        || r.start != process_start(r.pid)?
        || r.boot != fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
    {
        bail!("OMK load receipt is stale or uses fallback keys");
    }
    let process = fs::metadata(format!("/proc/{}", r.pid))?;
    if process.uid() != KEYSTORE_UID {
        bail!("OMK process is not running as keystore");
    }
    Ok(r)
}
fn matches_fresh_receipt(current: &Receipt, before: &Receipt, hash: &str, config: &str) -> bool {
    current.pid == before.pid
        && current.start == before.start
        && current.boot == before.boot
        && current.sha256 == hash
        && current.config == config
        && current.sequence > before.sequence
        && !current.fallback
}
fn await_load(hash: &str, before: &Receipt, config: &str) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(45) {
        if sha256(&read_keybox()?) != hash || config_hash()? != config {
            bail!("Keybox changed while confirming load");
        }
        if let Ok(r) = receipt() {
            if r.pid != before.pid || r.start != before.start {
                bail!("OMK restarted or configuration changed during replacement");
            }
            if matches_fresh_receipt(&r, before, hash, config) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!("OMK did not confirm loading this Keybox within 45 seconds")
}
fn recover(state: &mut State) -> Result<()> {
    if let Err(error) = recover_transaction(state) {
        let error = error.context(RenewalFailure::RollbackUnconfirmed);
        pause_after_failure(state, &error)?;
        return Err(error);
    }
    Ok(())
}
fn recover_transaction(state: &mut State) -> Result<()> {
    let Some(t) = &state.transaction else {
        return Ok(());
    };
    let backup = read_bounded(&path("rollback.xml"), 0, keybox::MAX_KEYBOX_XML_BYTES)?;
    let current = sha256(&read_keybox()?);
    let source_hash = t.source_hash.clone();
    recover_with(state, &backup, &current, |restore| {
        if restore {
            let before = receipt().ok();
            let config = config_hash()?;
            keybox::replace_keybox_if_current(&current, &backup)?;
            let before =
                before.context("Original file restored; waiting for OMK to confirm loading it")?;
            await_load(&source_hash, &before, &config)?;
        } else if receipt()?.sha256 != source_hash {
            bail!("Restored Keybox load is not confirmed");
        }
        Ok(())
    })
}
fn recover_with(
    state: &mut State,
    backup: &[u8],
    current: &str,
    confirm: impl FnOnce(bool) -> Result<()>,
) -> Result<()> {
    let t = state
        .transaction
        .as_ref()
        .context("No recovery transaction")?;
    if sha256(backup) != t.source_hash {
        bail!("Rollback backup hash mismatch");
    }
    if current != t.source_hash && current != t.target_hash {
        bail!("A different Keybox was installed; refusing to overwrite it");
    }
    confirm(current == t.target_hash)?;
    state.transaction = None;
    state.blocked = Some("Replacement was rolled back; review before resuming".into());
    save("state.json", state)?;
    remove("rollback.xml")
}
fn apply(c: &Consent, state: &mut State) -> Result<()> {
    let pending = state.pending.clone().context("No pending certificate")?;
    if pending.config != config_hash()? {
        return Err(RenewalFailure::ConfigurationChanged.into());
    }
    let candidate =
        artifacts::read_private(&pending.id).context(RenewalFailure::CandidateInvalid)?;
    if sha256(&candidate) != pending.target_hash {
        return Err(RenewalFailure::CandidateInvalid.into());
    }
    let expiry = keybox::rkp_expiry(&candidate, false).context(RenewalFailure::CandidateInvalid)?;
    let source = read_keybox()?;
    if sha256(&source) != pending.source_hash {
        return Err(RenewalFailure::ActiveChanged.into());
    }
    if expiry <= keybox::rkp_expiry(&source, true)? || expiry <= now()? as i64 + DAY as i64 {
        return Err(RenewalFailure::CandidateInvalid.into());
    }
    let before = receipt().context(RenewalFailure::LoadUnconfirmed)?;
    if before.sha256 != pending.source_hash {
        return Err(RenewalFailure::LoadUnconfirmed.into());
    }
    keybox::require_live_rkp_status(&candidate).context(RenewalFailure::CandidateInvalid)?;
    if config_hash()? != pending.config {
        return Err(RenewalFailure::ConfigurationChanged.into());
    }
    same_consent(c).context(RenewalFailure::ConfigurationChanged)?;
    replace_with_confirmation(
        state,
        &source,
        &pending,
        || {
            same_consent(c).context(RenewalFailure::ConfigurationChanged)?;
            keybox::replace_keybox_if_current(&pending.source_hash, &candidate)
                .context(RenewalFailure::ActiveChanged)?;
            await_load(&pending.target_hash, &before, &pending.config)
                .context(RenewalFailure::LoadUnconfirmed)
        },
        recover,
    )?;
    cleanup(state)
}
fn replace_with_confirmation(
    state: &mut State,
    source: &[u8],
    pending: &Pending,
    replace: impl FnOnce() -> Result<()>,
    rollback: impl FnOnce(&mut State) -> Result<()>,
) -> Result<()> {
    write_private("rollback.xml", source)?;
    state.transaction = Some(Transaction {
        source_hash: pending.source_hash.clone(),
        target_hash: pending.target_hash.clone(),
    });
    save("state.json", state)?;
    if let Err(error) = replace() {
        // A diagnostic write failure must not prevent restoring the old key.
        // record_failure updates memory first; successful recovery persists it.
        let _ = record_local_failure(state, &error);
        if let Err(rollback_error) = rollback(state) {
            let rollback_error = rollback_error.context(RenewalFailure::RollbackUnconfirmed);
            record_local_failure(state, &rollback_error)?;
            return Err(rollback_error);
        }
        return Err(error);
    }
    state.transaction = None;
    state.pending = None;
    state.issuing_source = None;
    state.last_success = now()?;
    state.blocked = None;
    state.read_retries = 0;
    state.preparation_retries = 0;
    state.last_error = None;
    save("state.json", state)?;
    remove("rollback.xml")
}
fn cleanup(state: &mut State) -> Result<()> {
    let current = sha256(&read_keybox()?);
    let time = now()? as i64;
    let pending = state.pending.as_ref().map(|p| p.id.as_str());
    state.owned.retain(|item| {
        if item.expiry > time || item.hash == current || pending == Some(item.id.as_str()) {
            return true;
        }
        artifacts::remove_owned(&item.id, &item.hash).is_err()
    });
    save("state.json", state)
}
fn due(time: u64, state: &State, expiry: i64) -> Result<bool> {
    if time < MIN_CLOCK || time < state.last_check || state.attempts.iter().any(|t| *t > time) {
        bail!("Clock is invalid or moved backwards; renewal is paused");
    }
    if state.blocked.is_some() || time < state.next_check {
        return Ok(false);
    }
    Ok(expiry <= time as i64 + DAY as i64
        && state
            .attempts
            .iter()
            .filter(|t| time.saturating_sub(**t) < DAY)
            .count()
            < 2)
}
fn completed_artifact_id(trace: &Issuance) -> Result<Option<&str>> {
    match trace.stage.as_str() {
        "completed" => {
            let id = trace
                .artifact_id
                .as_deref()
                .context("Completed issuance has no artifact")?;
            artifacts::validate_id(id)?;
            Ok(Some(id))
        }
        "preparing" | "acknowledged" => Ok(None),
        _ => bail!("Previous automatic issuance has an uncertain submission state"),
    }
}
fn recover_completed_issuance(state: &mut State) -> Result<()> {
    let Some(source_hash) = state.issuing_source.clone() else {
        return Ok(());
    };
    let trace: Issuance = load("issuance.json")?;
    if let Some(id) = completed_artifact_id(&trace)? {
        let bytes = artifacts::read_private(id)?;
        let hash = sha256(&bytes);
        state.pending = Some(Pending {
            config: state.issuing_config.clone(),
            id: id.into(),
            source_hash,
            target_hash: hash.clone(),
        });
        if !state.owned.iter().any(|item| item.id == id) {
            state.owned.push(Owned {
                id: id.into(),
                hash,
                expiry: keybox::rkp_expiry(&bytes, true)?,
            });
        }
    }
    state.issuing_source = None;
    save("state.json", state)
}
fn record_failure(state: &mut State, code: &str, stage: &str, retry_at: Option<u64>) -> Result<()> {
    state.last_error = Some(Failure {
        code: code.into(),
        stage: stage.into(),
        at: now()?,
        retry_at,
    });
    save("state.json", state)
}
fn record_local_failure(state: &mut State, error: &anyhow::Error) -> Result<()> {
    let (code, stage) = error
        .downcast_ref::<RenewalFailure>()
        .map_or(("local_state", "recovery"), |error| error.details());
    record_failure(state, code, stage, None)
}

fn pause_after_failure(state: &mut State, error: &anyhow::Error) -> Result<()> {
    if state.blocked.is_none() {
        state.blocked = Some("Renewal paused; review local state before resuming".into());
    }
    // A transaction records its cause before rollback. Keep that timestamp and
    // cause after successful rollback, even though recovery already set blocked.
    if !state.last_error.as_ref().is_some_and(|failure| {
        error
            .downcast_ref::<RenewalFailure>()
            .is_some_and(|kind| failure.code == kind.details().0)
    }) {
        return record_local_failure(state, error);
    }
    save("state.json", state)
}

fn schedule_preparation_retry(state: &mut State, code: &str, time: u64) -> Result<()> {
    state.issuing_source = None;
    let index = state
        .preparation_retries
        .min(PREPARATION_RETRY_DELAYS.len() - 1);
    state.next_check = time.saturating_add(PREPARATION_RETRY_DELAYS[index]);
    state.preparation_retries = (index + 1).min(PREPARATION_RETRY_DELAYS.len() - 1);
    record_failure(state, code, "preparation", Some(state.next_check))
}
fn apply_pending(c: &Consent, state: &mut State) -> Result<()> {
    match apply(c, state) {
        Ok(()) => Ok(()),
        Err(error) if state.transaction.is_none() && error.is::<keybox::RkpStatusUnavailable>() => {
            schedule_validation_retry(state)
        }
        Err(error) => pause_after_failure(state, &error),
    }
}
fn schedule_validation_retry(state: &mut State) -> Result<()> {
    let delay = READ_RETRY_DELAYS.get(state.read_retries).copied();
    state.read_retries = state.read_retries.saturating_add(1);
    if let Some(delay) = delay {
        state.next_check = now()?.saturating_add(delay);
    } else {
        state.blocked = Some(
            "Revocation checks failed repeatedly; review network access before resuming".into(),
        );
    }
    record_failure(
        state,
        "revocation_network",
        "validation",
        delay.map(|_| state.next_check),
    )
}
fn tick() -> Result<()> {
    let mut state: State = load("state.json")?;
    if state.transaction.is_some() {
        return recover(&mut state);
    }
    recover_completed_issuance(&mut state)?;
    let Some(c) = consent()? else {
        return Ok(());
    };
    if state.blocked.is_some() {
        return Ok(());
    }
    let time = now()?;
    // Check the clock even on idle polls, before doing expensive key/chain validation.
    due(time, &state, i64::MAX)?;
    if time < state.next_check {
        return Ok(());
    }
    let source = read_keybox()?;
    let expiry = keybox::rkp_expiry(&source, true)?;
    let should_issue = due(time, &state, expiry)?;
    state.last_check = time;
    state.next_check = time + INTERVAL;
    save("state.json", &state)?;
    cleanup(&mut state)?;
    if state.pending.is_some() {
        return apply_pending(&c, &mut state);
    }
    if !should_issue {
        return Ok(());
    }
    same_consent(&c)?;
    let active = receipt()?;
    if active.sha256 != sha256(&source) {
        bail!("OMK has not loaded the current Keybox");
    }
    require_no_transaction()?;
    begin_manual_issuance(Protocol::parse(&c.protocol)?)?;
    state.issuing_source = Some(sha256(&source));
    state.issuing_config = config_hash()?;
    // A crash during preparation also gets a bounded retry without spending a
    // signing slot. before_submission persists the actual signing cooldown.
    state.next_check = time.saturating_add(
        PREPARATION_RETRY_DELAYS[state
            .preparation_retries
            .min(PREPARATION_RETRY_DELAYS.len() - 1)],
    );
    save("state.json", &state)?;
    let id = match local_rkp::issue_locked(Protocol::parse(&c.protocol)?, Some(&c.token)) {
        Ok(id) => id,
        Err(e) => {
            // before_submission may have persisted a signing attempt. Never
            // overwrite that journal with the pre-network in-memory snapshot.
            state = load("state.json")?;
            if load::<Issuance>("issuance.json")?.stage == "submitted" {
                state.blocked =
                    Some("Submission outcome is uncertain; inspect before resuming".into());
                save("state.json", &state)?;
                record_failure(&mut state, "submission_uncertain", "submission", None)?;
                return Ok(());
            }
            // The journal is fsynced before POST; preparing means no certificate
            // request was submitted. Retry only after the persisted cooldown.
            let code = e
                .downcast_ref::<local_rkp::IssueFailure>()
                .map_or("pre_submission", |error| error.code());
            schedule_preparation_retry(&mut state, code, now()?)?;
            return Ok(());
        }
    };
    state = load("state.json")?;
    let bytes = artifacts::read_private(&id)?;
    let target_hash = sha256(&bytes);
    state.issuing_source = None;
    state.owned.push(Owned {
        id: id.clone(),
        hash: target_hash.clone(),
        expiry: keybox::rkp_expiry(&bytes, false)?,
    });
    state.pending = Some(Pending {
        config: state.issuing_config.clone(),
        id,
        source_hash: sha256(&source),
        target_hash,
    });
    save("state.json", &state)?;
    apply_pending(&c, &mut state)
}
fn module_active() -> bool {
    let module = Path::new("/data/adb/modules/oh_my_keymint");
    module.is_dir() && !module.join("disable").exists() && !module.join("remove").exists()
}
pub fn start_worker() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("Renewal worker requires root");
    }
    if !module_active() || !Path::new(ROOT).try_exists()? {
        return Ok(());
    }
    root()?;
    let state: State = load("state.json")?;
    if consent()?.is_none() && state.transaction.is_none() {
        return Ok(());
    }
    if worker_running()? {
        return Ok(());
    }
    Command::new(std::env::current_exe()?)
        .arg("--rkp-renewal-worker")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}
fn worker_running() -> Result<bool> {
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path("worker.lock"))
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let m = file.metadata()?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.nlink() != 1 {
        bail!("Unsafe worker lock file");
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(false);
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        Ok(true)
    } else {
        Err(error.into())
    }
}
pub fn worker() -> Result<()> {
    root()?;
    let _singleton = lock(&path("worker.lock"), 0, true)?;
    loop {
        if !module_active() {
            return Ok(());
        }
        if rsproperties::get::<String>("sys.boot_completed").is_ok_and(|value| value == "1") {
            if let Ok(_lock) = operation_lock() {
                if let Err(error) = tick() {
                    let mut state: State = load("state.json")?;
                    // Safe local errors only: never store network response bodies or CSR data.
                    pause_after_failure(&mut state, &error)?;
                }
            }
        }
        if consent()?.is_none() && load::<State>("state.json")?.transaction.is_none() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(300));
    }
}
#[derive(Serialize)]
struct Status {
    enabled: bool,
    worker_running: bool,
    protocol: Option<String>,
    last_successful_protocol: Option<String>,
    expires_at: Option<i64>,
    last_check: u64,
    last_success: u64,
    next_check: u64,
    blocked: Option<String>,
    pending: bool,
    recovery_required: bool,
    issuance_stage: String,
    last_error: Option<Failure>,
}
fn status() -> Result<String> {
    let state: State = load("state.json")?;
    let trace: Issuance = load("issuance.json")?;
    let c = consent()?;
    serde_json::to_string(&Status {
        enabled: c.is_some(),
        worker_running: worker_running()?,
        protocol: c.map(|v| v.protocol),
        last_successful_protocol: trace.last_successful_protocol,
        expires_at: read_keybox()
            .and_then(|b| keybox::rkp_expiry(&b, true))
            .ok(),
        last_check: state.last_check,
        last_success: state.last_success,
        next_check: state.next_check,
        blocked: state.blocked,
        pending: state.pending.is_some(),
        recovery_required: state.transaction.is_some(),
        issuance_stage: trace.stage,
        last_error: state.last_error,
    })
    .map_err(Into::into)
}
pub fn command(args: Vec<String>) -> Result<String> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("Renewal settings require root");
    }
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["status"] => {
            if !Path::new(ROOT).try_exists()? {
                return status();
            }
            root()?;
        }
        ["disable"] => {
            root()?;
            remove("enabled.json")?;
            start_worker()?;
        }
        ["enable", "--confirm-renewal", selection] => {
            let _lock = operation_lock()?;
            let mut state: State = load("state.json")?;
            recover_completed_issuance(&mut state)?;
            if state.transaction.is_some()
                || load::<Issuance>("issuance.json")?.stage == "submitted"
            {
                bail!("Recover or acknowledge the unfinished operation before enabling renewal");
            }
            no_other_manager()?;
            let protocol = if *selection == "last-success" {
                load::<Issuance>("issuance.json")?
                    .last_successful_protocol
                    .context("No successful OMK protocol recorded; select V1, V2 or V1-native")?
            } else {
                selection.to_string()
            };
            if Protocol::parse(&protocol)? == Protocol::Auto {
                bail!("Select a concrete protocol or last-success");
            }
            let bytes = read_keybox()?;
            keybox::rkp_expiry(&bytes, true)?;
            let state: State = load("state.json")?;
            if state.blocked.is_some() {
                bail!("Acknowledge the paused state before enabling renewal");
            }
            let mut random = [0; 16];
            SystemRandom::new()
                .fill(&mut random)
                .map_err(|_| anyhow!("Cannot generate consent token"))?;
            save(
                "enabled.json",
                &Consent {
                    protocol,
                    token: hex::encode(random),
                },
            )?;
            start_worker()?;
        }
        ["resume", "--acknowledge-uncertain-result"] => {
            let _lock = operation_lock()?;
            let mut state: State = load("state.json")?;
            if state.transaction.is_some() {
                recover(&mut state)?;
            }
            let time = now()?;
            if time < MIN_CLOCK {
                bail!("Correct the clock before resuming");
            }
            if time < state.last_check || state.attempts.iter().any(|t| *t > time) {
                state.attempts = vec![time, time];
                state.next_check = time + DAY;
            }
            let mut trace: Issuance = load("issuance.json")?;
            if trace.stage == "submitted" {
                state.next_check = state.next_check.max(trace.at.min(time).saturating_add(DAY));
                // Persist the cooldown before acknowledging an uncertain request.
                save("state.json", &state)?;
                trace.stage = "acknowledged".into();
                save("issuance.json", &trace)?;
            }
            if state.issuing_source.is_some() {
                if trace.stage == "completed" {
                    recover_completed_issuance(&mut state)?;
                } else {
                    state.issuing_source = None;
                }
            }
            state.blocked = None;
            state.read_retries = 0;
            state.last_error = None;
            state.last_check = time;
            save("state.json", &state)?;
            start_worker()?;
        }
        ["discard", "--confirm-discard-pending"] => {
            let _lock = operation_lock()?;
            let mut state: State = load("state.json")?;
            if state.transaction.is_some() {
                bail!("Recover the transaction before discarding a pending result");
            }
            if state.issuing_source.is_some() {
                bail!("Acknowledge interrupted issuance before discarding");
            }
            state.pending = None;
            state.blocked = None;
            state.read_retries = 0;
            state.last_error = None;
            save("state.json", &state)?;
        }
        ["recover", "--confirm-rollback"] => {
            let _lock = operation_lock()?;
            let mut state: State = load("state.json")?;
            recover(&mut state)?;
        }
        _ => bail!("Invalid renewal command or missing confirmation"),
    }
    status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn fixture(run: impl FnOnce()) {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                TEST_ROOT.with(|root| *root.borrow_mut() = None);
            }
        }
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        TEST_ROOT.with(|root| *root.borrow_mut() = Some(temp.path().to_path_buf()));
        let _reset = Reset;
        root().unwrap();
        run();
    }
    fn pending_fixture() -> Pending {
        Pending {
            config: "snapshot".into(),
            id: "a".repeat(32),
            source_hash: sha256(b"old"),
            target_hash: sha256(b"new"),
        }
    }
    #[test]
    fn preparation_failures_retry_without_spending_the_signing_budget() {
        fixture(|| {
            let time = now().unwrap();
            let mut state = State::default();
            for delay in PREPARATION_RETRY_DELAYS
                .into_iter()
                .chain([INTERVAL, INTERVAL])
            {
                state.issuing_source = Some("source".into());
                schedule_preparation_retry(&mut state, "challenge_network", time).unwrap();
                state = load("state.json").unwrap();
                assert!(state.attempts.is_empty() && state.issuing_source.is_none());
                assert_eq!(state.next_check, time + delay);
                assert!(due(state.next_check, &state, (time + 18 * 3600) as i64).unwrap());
            }
            journal_submission(Protocol::V1, true).unwrap();
            let state: State = load("state.json").unwrap();
            assert_eq!(state.attempts.len(), 1);
            assert_eq!(state.preparation_retries, 0);
            assert_eq!(
                load::<Issuance>("issuance.json").unwrap().stage,
                "submitted"
            );
            // A restarted worker must retain both the charged budget and the
            // uncertain-submission fence; it cannot issue another request.
            assert!(require_no_transaction().is_err());
            assert!(completed_artifact_id(&load("issuance.json").unwrap()).is_err());
        });
    }
    #[test]
    fn signing_budget_is_durable_before_submission_and_survives_journal_failure() {
        fixture(|| {
            journal_submission(Protocol::V1, true).unwrap();
            journal_submission(Protocol::V1, true).unwrap();
            assert!(journal_submission(Protocol::V1, true).is_err());
            assert_eq!(load::<State>("state.json").unwrap().attempts.len(), 2);
            let time = now().unwrap() + DAY;
            reserve_submission(time).unwrap();
            assert_eq!(load::<State>("state.json").unwrap().attempts, vec![time]);
        });
        fixture(|| {
            fs::create_dir(path("issuance.json")).unwrap();
            assert!(journal_submission(Protocol::V1, true).is_err());
            assert_eq!(load::<State>("state.json").unwrap().attempts.len(), 1);
        });
    }
    #[test]
    fn rollback_failure_and_already_blocked_errors_keep_sanitized_diagnostics() {
        fixture(|| {
            let p = pending_fixture();
            let mut state = State {
                pending: Some(p.clone()),
                ..Default::default()
            };
            let error = replace_with_confirmation(
                &mut state,
                b"old",
                &p,
                || Err(anyhow!("private response body").context(RenewalFailure::LoadUnconfirmed)),
                |_| {
                    let saved: State = load("state.json")?;
                    assert_eq!(saved.last_error.unwrap().code, "load_unconfirmed");
                    bail!("private rollback detail")
                },
            )
            .unwrap_err();
            pause_after_failure(&mut state, &error).unwrap();
            let saved: State = load("state.json").unwrap();
            assert!(
                saved.transaction.is_some() && saved.pending.is_some() && saved.blocked.is_some()
            );
            let failure = saved.last_error.unwrap();
            assert_eq!(
                (failure.code.as_str(), failure.stage.as_str()),
                ("rollback_unconfirmed", "recovery")
            );
            assert!(failure.at > 0 && failure.retry_at.is_none());
            assert!(!fs::read_to_string(path("state.json"))
                .unwrap()
                .contains("private"));
            pause_after_failure(&mut state, &RenewalFailure::ConfigurationChanged.into()).unwrap();
            assert_eq!(
                load::<State>("state.json")
                    .unwrap()
                    .last_error
                    .unwrap()
                    .code,
                "configuration_changed"
            );
        });
    }
    #[test]
    fn replacement_journal_is_durable_before_swap_and_success_is_committed() {
        fixture(|| {
            let p = pending_fixture();
            let mut state = State {
                pending: Some(p.clone()),
                ..Default::default()
            };
            replace_with_confirmation(
                &mut state,
                b"old",
                &p,
                || {
                    let saved: State = load("state.json")?;
                    assert!(saved.transaction.is_some());
                    assert_eq!(&**read_bounded(&path("rollback.xml"), 0, 64)?, b"old");
                    Ok(())
                },
                |_| panic!("success must not roll back"),
            )
            .unwrap();
            let saved: State = load("state.json").unwrap();
            assert!(
                saved.pending.is_none() && saved.transaction.is_none() && saved.last_success > 0
            );
            assert!(!path("rollback.xml").exists());
        });
    }
    #[test]
    fn failed_confirmation_rolls_back_and_retains_pending_candidate() {
        fixture(|| {
            let p = pending_fixture();
            let mut state = State {
                pending: Some(p.clone()),
                ..Default::default()
            };
            let restored = std::cell::Cell::new(false);
            assert!(replace_with_confirmation(
                &mut state,
                b"old",
                &p,
                || Err(RenewalFailure::LoadUnconfirmed.into()),
                |state| {
                    assert_eq!(
                        load::<State>("state.json")?.last_error.unwrap().code,
                        "load_unconfirmed"
                    );
                    recover_with(state, b"old", &p.target_hash, |restore| {
                        assert!(restore);
                        restored.set(true);
                        Ok(())
                    })
                }
            )
            .is_err());
            let saved: State = load("state.json").unwrap();
            let failure = saved.last_error.as_ref().unwrap();
            assert_eq!(
                (failure.code.as_str(), failure.stage.as_str()),
                ("load_unconfirmed", "confirmation")
            );
            assert!(failure.at > 0);
            assert!(
                restored.get()
                    && saved.transaction.is_none()
                    && saved.pending.is_some()
                    && saved.blocked.is_some()
            );
        });
    }
    #[test]
    fn interrupted_replacement_recovers_both_pre_swap_and_post_swap_states() {
        for swapped in [false, true] {
            fixture(|| {
                let p = pending_fixture();
                write_private("rollback.xml", b"old").unwrap();
                let state = State {
                    pending: Some(p.clone()),
                    transaction: Some(Transaction {
                        source_hash: p.source_hash.clone(),
                        target_hash: p.target_hash.clone(),
                    }),
                    ..Default::default()
                };
                save("state.json", &state).unwrap();
                drop(state);
                let mut restarted: State = load("state.json").unwrap();
                recover_with(
                    &mut restarted,
                    b"old",
                    if swapped {
                        &p.target_hash
                    } else {
                        &p.source_hash
                    },
                    |restore| {
                        assert_eq!(restore, swapped);
                        Ok(())
                    },
                )
                .unwrap();
                let saved: State = load("state.json").unwrap();
                assert!(
                    saved.transaction.is_none()
                        && saved.pending.is_some()
                        && saved.blocked.is_some()
                );
            });
        }
    }
    #[test]
    fn recovery_never_overwrites_foreign_keys_or_discards_an_unconfirmed_backup() {
        fixture(|| {
            let p = pending_fixture();
            write_private("rollback.xml", b"old").unwrap();
            let mut state = State {
                transaction: Some(Transaction {
                    source_hash: p.source_hash.clone(),
                    target_hash: p.target_hash.clone(),
                }),
                ..Default::default()
            };
            save("state.json", &state).unwrap();
            assert!(
                recover_with(&mut state, b"corrupt", &p.target_hash, |_| panic!(
                    "corrupt backup"
                ))
                .is_err()
            );
            assert!(recover_with(&mut state, b"old", "foreign", |_| panic!(
                "foreign replacement"
            ))
            .is_err());
            assert!(recover_with(&mut state, b"old", &p.target_hash, |_| bail!(
                "restore not confirmed"
            ))
            .is_err());
            assert!(
                load::<State>("state.json").unwrap().transaction.is_some()
                    && path("rollback.xml").exists()
            );
        });
    }
    #[test]
    fn storage_failure_prevents_keybox_swap() {
        fixture(|| {
            let p = pending_fixture();
            let mut state = State::default();
            fs::create_dir(path("state.json")).unwrap();
            assert!(replace_with_confirmation(
                &mut state,
                b"old",
                &p,
                || panic!("journal was not committed"),
                |_| panic!("no swap occurred")
            )
            .is_err());
        });
    }
    #[test]
    fn read_only_retries_keep_candidate_and_do_not_spend_signing_budget() {
        fixture(|| {
            let mut state = State {
                pending: Some(pending_fixture()),
                attempts: vec![now().unwrap()],
                ..Default::default()
            };
            for delay in READ_RETRY_DELAYS {
                let before = now().unwrap();
                schedule_validation_retry(&mut state).unwrap();
                let saved: State = load("state.json").unwrap();
                assert!(saved.pending.is_some() && saved.blocked.is_none());
                assert!((before + delay..=now().unwrap() + delay).contains(&saved.next_check));
                assert_eq!(saved.attempts.len(), 1);
            }
            schedule_validation_retry(&mut state).unwrap();
            assert!(state.blocked.is_some());
            assert!(state.last_error.as_ref().unwrap().retry_at.is_none());
            assert_eq!(state.attempts.len(), 1);
        });
    }
    #[test]
    fn worker_status_checks_the_live_singleton_lock() {
        fixture(|| {
            assert!(!worker_running().unwrap());
            let worker = lock(&path("worker.lock"), 0, true).unwrap();
            assert!(worker_running().unwrap());
            drop(worker);
            assert!(!worker_running().unwrap());
        });
    }
    #[test]
    fn deletion_protects_active_pending_and_recovery_results() {
        let mut state = State::default();
        let mut trace = Issuance::default();
        assert!(!artifact_is_removable(
            &state, &trace, "id", "active", "active"
        ));
        assert!(artifact_is_removable(
            &state, &trace, "id", "other", "active"
        ));
        state.pending = Some(pending_fixture());
        let p = state.pending.as_ref().unwrap();
        assert!(!artifact_is_removable(
            &state, &trace, &p.id, "other", "active"
        ));
        assert!(!artifact_is_removable(
            &state,
            &trace,
            "id",
            &p.target_hash,
            "active"
        ));
        assert!(!artifact_is_removable(
            &state,
            &trace,
            "id",
            &p.source_hash,
            "active"
        ));
        state.pending = None;
        trace.stage = "submitted".into();
        assert!(!artifact_is_removable(
            &state, &trace, "id", "other", "active"
        ));
        trace.stage = "completed".into();
        state.transaction = Some(Transaction {
            source_hash: "old".into(),
            target_hash: "new".into(),
        });
        assert!(!artifact_is_removable(
            &state, &trace, "id", "other", "active"
        ));
        state.transaction = None;
        state.issuing_source = Some("old".into());
        assert!(!artifact_is_removable(
            &state, &trace, "id", "other", "active"
        ));
    }
    #[test]
    fn renewal_window_budget_and_clock() {
        let t = MIN_CLOCK + 10 * DAY;
        let mut s = State::default();
        assert!(!due(t, &s, (t + DAY + 1) as i64).unwrap());
        assert!(due(t, &s, (t + DAY) as i64).unwrap());
        assert!(due(t, &s, (t - DAY) as i64).unwrap());
        s.attempts = vec![t - 5, t - 1];
        assert!(!due(t, &s, t as i64).unwrap());
        assert!(due(t + DAY, &s, t as i64).unwrap());
        s.last_check = t + 1;
        assert!(due(t, &s, t as i64).is_err());
        assert!(due(1, &State::default(), 1).is_err());
    }
    #[test]
    fn disabled_and_cooldown_do_not_issue() {
        let t = MIN_CLOCK + DAY;
        let mut s = State {
            blocked: Some("review".into()),
            ..Default::default()
        };
        assert!(!due(t, &s, t as i64).unwrap());
        s.blocked = None;
        s.next_check = t + 1;
        assert!(!due(t, &s, t as i64).unwrap());
    }
    #[test]
    fn loaded_receipt_requires_this_process_candidate_and_configuration() {
        let before = Receipt {
            pid: 42,
            start: "100".into(),
            boot: "boot".into(),
            sequence: 1,
            sha256: "old".into(),
            identity: "old-id".into(),
            config: "old-config".into(),
            fallback: false,
        };
        let mut candidate = Receipt {
            sequence: 2,
            sha256: "new".into(),
            identity: "new-id".into(),
            config: "new-config".into(),
            ..before.clone()
        };
        assert!(matches_fresh_receipt(
            &candidate,
            &before,
            "new",
            "new-config"
        ));
        assert!(!matches_fresh_receipt(
            &before,
            &before,
            "old",
            "old-config"
        ));
        assert!(!matches_fresh_receipt(
            &candidate,
            &before,
            "old",
            "new-config"
        ));
        assert!(!matches_fresh_receipt(
            &candidate,
            &before,
            "new",
            "old-config"
        ));
        candidate.pid += 1;
        assert!(!matches_fresh_receipt(
            &candidate,
            &before,
            "new",
            "new-config"
        ));
        candidate.pid = before.pid;
        candidate.start = "101".into();
        assert!(!matches_fresh_receipt(
            &candidate,
            &before,
            "new",
            "new-config"
        ));
        candidate.start = before.start.clone();
        candidate.fallback = true;
        assert!(!matches_fresh_receipt(
            &candidate,
            &before,
            "new",
            "new-config"
        ));
    }
    #[test]
    fn private_reads_reject_links_permissions_and_oversize() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("private");
        fs::write(&file, b"data").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::metadata(&file).unwrap().uid();
        assert_eq!(&**read_bounded(&file, uid, 4).unwrap(), b"data");
        assert!(read_bounded(&file, uid, 3).is_err());
        assert!(read_bounded(&file, uid.wrapping_add(1), 4).is_err());
        let link = temp.path().join("link");
        symlink(&file, &link).unwrap();
        assert!(read_bounded(&link, uid, 4).is_err());
        fs::hard_link(&file, temp.path().join("hard")).unwrap();
        assert!(read_bounded(&file, uid, 4).is_err());
        fs::remove_file(temp.path().join("hard")).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_bounded(&file, uid, 4).is_err());
    }
    #[test]
    fn interrupted_issuance_never_blindly_retries_a_submitted_request() {
        let mut trace = Issuance {
            stage: "preparing".into(),
            ..Default::default()
        };
        assert_eq!(completed_artifact_id(&trace).unwrap(), None);
        trace.stage = "submitted".into();
        assert!(completed_artifact_id(&trace).is_err());
        trace.stage = "completed".into();
        assert!(completed_artifact_id(&trace).is_err());
        trace.artifact_id = Some("a".repeat(32));
        assert_eq!(
            completed_artifact_id(&trace).unwrap(),
            trace.artifact_id.as_deref()
        );
        trace.artifact_id = Some("../escape".into());
        assert!(completed_artifact_id(&trace).is_err());
        trace.stage = "acknowledged".into();
        assert_eq!(completed_artifact_id(&trace).unwrap(), None);
    }
    #[test]
    fn state_rejects_unknown_fields_and_corruption() {
        assert!(serde_json::from_str::<State>(r#"{"private_key":"secret"}"#).is_err());
        assert!(serde_json::from_str::<Consent>(r#"{"protocol":"v1"}"#).is_err());
        let s = State::default();
        let roundtrip: State = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
        assert!(roundtrip.transaction.is_none());
    }
}
