// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ffi::CString;
use std::format;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::{
    fd::{AsRawFd, FromRawFd},
    unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
};
use std::path::Path;

use anyhow::Context;
use rand::Rng as _;

pub fn atomic_replace_preserving_metadata(
    path: &Path,
    contents: &[u8],
    default_mode: u32,
    default_uid: u32,
    default_gid: u32,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;

    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    let name = CString::new(
        path.file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing file name"))?
            .as_bytes(),
    )?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    let existing = if fd >= 0 {
        Ok(unsafe { File::from_raw_fd(fd) }.metadata()?)
    } else {
        Err(io::Error::last_os_error())
    };
    let (mode, uid, gid) = match existing {
        // Another atomic writer may have unlinked the opened inode before stat.
        Ok(metadata) if metadata.is_file() && metadata.nlink() <= 1 => {
            (metadata.mode() & 0o777, metadata.uid(), metadata.gid())
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "replacement target must be a regular file with one link",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            (default_mode, default_uid, default_gid)
        }
        Err(error) => return Err(error),
    };
    let mut random = [0u8; 16];
    rand::rng().fill_bytes(&mut random);
    let suffix = random
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<std::string::String>();
    let temp_name = CString::new(format!(".omk-tmp-{suffix}"))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temp_name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };

    let result = (|| {
        file.write_all(contents)?;
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
            return Err(io::Error::last_os_error());
        }
        file.sync_all()?;
        if unsafe {
            libc::renameat(
                directory.as_raw_fd(),
                temp_name.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        directory.sync_all()
    })();

    if result.is_err() {
        unsafe {
            libc::unlinkat(directory.as_raw_fd(), temp_name.as_ptr(), 0);
        }
    }
    result
}

pub fn backup_file_with_reason(
    path: &Path,
    backup: &Path,
    reason_header: &str,
    reason: &str,
    allow_copy_fallback: bool,
) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }

    if backup.exists() {
        fs::remove_file(backup)
            .with_context(|| format!("failed to remove stale backup {}", backup.display()))?;
    }

    if let Err(rename_error) = fs::rename(path, backup) {
        if !allow_copy_fallback {
            return Err(rename_error)
                .with_context(|| format!("failed to move invalid file to {}", backup.display()));
        }

        fs::copy(path, backup)
            .with_context(|| {
                format!(
                    "failed to copy invalid file to backup {} after rename error {rename_error}",
                    backup.display()
                )
            })
            .and_then(|_| {
                fs::remove_file(path)
                    .with_context(|| format!("failed to remove original file {}", path.display()))
            })
            .with_context(|| format!("failed to move invalid file to {}", backup.display()))?;
    }

    let mut file = OpenOptions::new()
        .append(true)
        .open(backup)
        .with_context(|| format!("failed to open backup {}", backup.display()))?;
    writeln!(file)?;
    writeln!(file, "# {reason_header}:")?;
    for line in reason.lines() {
        writeln!(file, "# {line}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{symlink, PermissionsExt},
        path::PathBuf,
        sync::Arc,
    };
    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let mut random = [0u8; 16];
            rand::rng().fill_bytes(&mut random);
            let suffix = random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<std::string::String>();
            let path = std::env::temp_dir().join(format!("omk-atomic-{suffix}"));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn replace(&self, target: &Path, bytes: &[u8]) -> io::Result<()> {
            atomic_replace_preserving_metadata(
                target,
                bytes,
                0o600,
                unsafe { libc::geteuid() },
                unsafe { libc::getegid() },
            )
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn atomic_replace_never_follows_target_or_legacy_temp_links() {
        let dir = TestDir::new();
        let victim = dir.0.join("victim");
        fs::write(&victim, b"unchanged").unwrap();
        let target = dir.0.join("state.json");
        symlink(&victim, &target).unwrap();
        assert!(dir.replace(&target, b"bad").is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        fs::remove_file(&target).unwrap();
        let legacy = dir
            .0
            .join(format!(".state.json.tmp-{}", std::process::id()));
        symlink(&victim, &legacy).unwrap();
        dir.replace(&target, b"safe").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"safe");
        assert_eq!(fs::read(&victim).unwrap(), b"unchanged");
        assert!(!fs::symlink_metadata(&target)
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_file(&target).unwrap();
        fs::hard_link(&victim, &target).unwrap();
        assert!(dir.replace(&target, b"bad").is_err());
    }
    #[test]
    fn atomic_replace_rejects_symlinked_parent_and_preserves_file_metadata() {
        let dir = TestDir::new();
        let real = dir.0.join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.0.join("link");
        symlink(&real, &link).unwrap();
        assert!(dir.replace(&link.join("state"), b"bad").is_err());
        let target = real.join("state");
        dir.replace(&target, b"one").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&target).unwrap();
        dir.replace(&target, b"two").unwrap();
        let after = fs::metadata(&target).unwrap();
        assert_eq!(
            (before.uid(), before.gid(), before.mode() & 0o777),
            (after.uid(), after.gid(), after.mode() & 0o777)
        );
    }
    #[test]
    fn simultaneous_replacements_use_distinct_temporary_files() {
        let dir = Arc::new(TestDir::new());
        let target = dir.0.join("state");
        dir.replace(&target, b"initial").unwrap();
        let threads: std::vec::Vec<_> = (0..8)
            .map(|index| {
                let dir = Arc::clone(&dir);
                let target = target.clone();
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        dir.replace(&target, &[index; 1024]).unwrap();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let bytes = fs::read(target).unwrap();
        assert_eq!(bytes.len(), 1024);
        assert!(bytes.iter().all(|b| *b == bytes[0]));
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 1);
    }
}
