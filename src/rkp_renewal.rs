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
fn path(name: &str) -> PathBuf {
    Path::new(ROOT).join(name)
}
fn root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("RKP renewal requires root");
    }
    match fs::DirBuilder::new().mode(0o700).create(ROOT) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e.into()),
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(ROOT)?;
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
        Ok(()) => File::open(ROOT)?.sync_all()?,
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
    let mut trace: Issuance = load("issuance.json")?;
    trace.stage = "submitted".into();
    trace.protocol = protocol.as_str().into();
    trace.at = now()?;
    save("issuance.json", &trace)
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
fn config_hash() -> Result<String> {
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
    let Some(t) = &state.transaction else {
        return Ok(());
    };
    let backup = read_bounded(&path("rollback.xml"), 0, keybox::MAX_KEYBOX_XML_BYTES)?;
    if sha256(&backup) != t.source_hash {
        bail!("Rollback backup hash mismatch");
    }
    let current = sha256(&read_keybox()?);
    if current != t.source_hash && current != t.target_hash {
        bail!("A different Keybox was installed; refusing to overwrite it");
    }
    if current == t.target_hash {
        let before = receipt().ok();
        let config = config_hash()?;
        keybox::replace_keybox_if_current(&current, &backup)?;
        let before =
            before.context("Original file restored; waiting for OMK to confirm loading it")?;
        await_load(&t.source_hash, &before, &config)?;
    } else if receipt()?.sha256 != t.source_hash {
        bail!("Restored Keybox load is not confirmed");
    }
    state.transaction = None;
    state.blocked = Some("Replacement was rolled back; review before resuming".into());
    save("state.json", state)?;
    remove("rollback.xml")
}
fn apply(c: &Consent, state: &mut State) -> Result<()> {
    let pending = state.pending.clone().context("No pending certificate")?;
    if pending.config != config_hash()? {
        bail!("PIF, patch or device configuration changed during renewal");
    }
    let candidate = artifacts::read_private(&pending.id)?;
    if sha256(&candidate) != pending.target_hash {
        bail!("Pending artifact changed");
    }
    let expiry = keybox::rkp_expiry(&candidate, false)?;
    let source = read_keybox()?;
    if sha256(&source) != pending.source_hash
        || expiry <= keybox::rkp_expiry(&source, true)?
        || expiry <= now()? as i64 + DAY as i64
    {
        bail!("Candidate is stale, shorter-lived, or active Keybox changed");
    }
    let before = receipt()?;
    if before.sha256 != pending.source_hash {
        bail!("Active Keybox has not been loaded by OMK");
    }
    keybox::require_live_rkp_status(&candidate)?;
    if config_hash()? != pending.config {
        bail!("Configuration changed before replacement");
    }
    same_consent(c)?;
    write_private("rollback.xml", &source)?;
    state.transaction = Some(Transaction {
        source_hash: pending.source_hash.clone(),
        target_hash: pending.target_hash.clone(),
    });
    save("state.json", state)?;
    same_consent(c)?;
    keybox::replace_keybox_if_current(&pending.source_hash, &candidate)?;
    if let Err(error) = await_load(&pending.target_hash, &before, &pending.config) {
        recover(state).context("Automatic rollback needs attention")?;
        return Err(error);
    }
    state.transaction = None;
    state.pending = None;
    state.issuing_source = None;
    state.last_success = now()?;
    state.blocked = None;
    save("state.json", state)?;
    remove("rollback.xml")?;
    cleanup(state)
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
fn recover_completed_issuance(state: &mut State) -> Result<()> {
    if let Some(source_hash) = state.issuing_source.clone() {
        let trace: Issuance = load("issuance.json")?;
        if trace.stage == "completed" {
            let id = trace
                .artifact_id
                .context("Completed issuance has no artifact")?;
            let bytes = artifacts::read_private(&id)?;
            let hash = sha256(&bytes);
            state.pending = Some(Pending {
                config: state.issuing_config.clone(),
                id: id.clone(),
                source_hash,
                target_hash: hash.clone(),
            });
            if !state.owned.iter().any(|item| item.id == id) {
                state.owned.push(Owned {
                    id,
                    hash,
                    expiry: keybox::rkp_expiry(&bytes, true)?,
                });
            }
            state.issuing_source = None;
            save("state.json", state)?;
        } else {
            bail!("Previous automatic issuance was interrupted; review its submission state");
        }
    }
    Ok(())
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
    let source = read_keybox()?;
    let expiry = keybox::rkp_expiry(&source, true)?;
    let should_issue = due(time, &state, expiry)?;
    if time < state.next_check {
        return Ok(());
    }
    state.last_check = time;
    state.next_check = time + INTERVAL;
    save("state.json", &state)?;
    cleanup(&mut state)?;
    if state.pending.is_some() {
        return apply(&c, &mut state);
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
    state.attempts.retain(|t| time.saturating_sub(*t) < DAY);
    state.attempts.push(time);
    save("state.json", &state)?;
    begin_manual_issuance(Protocol::parse(&c.protocol)?)?;
    state.issuing_source = Some(sha256(&source));
    state.issuing_config = config_hash()?;
    save("state.json", &state)?;
    let id = match local_rkp::issue_locked(Protocol::parse(&c.protocol)?, Some(&c.token)) {
        Ok(id) => id,
        Err(e) => {
            if load::<Issuance>("issuance.json")?.stage == "submitted" {
                state.blocked =
                    Some("Submission outcome is uncertain; inspect before resuming".into());
                save("state.json", &state)?;
            }
            return Err(e);
        }
    };
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
    apply(&c, &mut state)
}
fn module_active() -> bool {
    let module = Path::new("/data/adb/modules/oh_my_keymint");
    module.is_dir() && !module.join("disable").exists() && !module.join("remove").exists()
}
pub fn start_worker() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("Renewal worker requires root");
    }
    if !Path::new(ROOT).try_exists()? {
        return Ok(());
    }
    root()?;
    let state: State = load("state.json")?;
    if consent()?.is_none() && state.transaction.is_none() {
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
pub fn worker() -> Result<()> {
    root()?;
    let _singleton = lock(&path("worker.lock"), 0, true)?;
    loop {
        if !module_active() {
            return Ok(());
        }
        if rsproperties::get::<String>("sys.boot_completed").is_ok_and(|value| value == "1") {
            if let Ok(_lock) = operation_lock() {
                if tick().is_err() {
                    let mut state: State = load("state.json")?;
                    // Safe local errors only: never store network response bodies or CSR data.
                    state.blocked =
                        Some("Renewal paused; review local state before resuming".into());
                    save("state.json", &state)?;
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
}
fn status() -> Result<String> {
    let state: State = load("state.json")?;
    let trace: Issuance = load("issuance.json")?;
    let c = consent()?;
    serde_json::to_string(&Status {
        enabled: c.is_some(),
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
    fn state_rejects_unknown_fields_and_corruption() {
        assert!(serde_json::from_str::<State>(r#"{"private_key":"secret"}"#).is_err());
        assert!(serde_json::from_str::<Consent>(r#"{"protocol":"v1"}"#).is_err());
        let s = State::default();
        let roundtrip: State = serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
        assert!(roundtrip.transaction.is_none());
    }
}
