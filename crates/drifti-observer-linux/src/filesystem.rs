// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Filesystem syscall decoding while a Linux tracee is stopped.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use drifti_observer::{ObservedResource, Operation, Outcome};

use crate::memory::{read_remote_memory, RemoteReadError, MAX_REMOTE_READ};
use crate::syscall::{ObservedSyscall, SyscallStop};

/// A semantic filesystem fact ready for an observed event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemFact {
    pub tid: u32,
    pub operation: Operation,
    pub resource: ObservedResource,
    pub outcome: Outcome,
}

/// A filesystem operation could not be represented safely.
#[derive(Debug)]
pub enum FilesystemDecodeError {
    Remote(RemoteReadError),
    PathTooLong,
    InvalidPath,
    Proc(std::io::Error),
    NamespaceMismatch,
    PhaseMismatch { tid: u32 },
    Capacity,
}

impl Display for FilesystemDecodeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Remote(error) => write!(f, "filesystem pathname read: {error}"),
            Self::PathTooLong => f.write_str("filesystem pathname exceeds remote read bound"),
            Self::InvalidPath => f.write_str("filesystem pathname cannot be represented"),
            Self::Proc(error) => write!(f, "filesystem /proc resolution: {error}"),
            Self::NamespaceMismatch => {
                f.write_str("tracee filesystem namespace differs from tracer")
            }
            Self::PhaseMismatch { tid } => {
                write!(f, "filesystem syscall phase mismatch on tid {tid}")
            }
            Self::Capacity => f.write_str("filesystem pending syscall capacity exceeded"),
        }
    }
}

impl std::error::Error for FilesystemDecodeError {}

#[derive(Debug)]
struct Pending {
    number: u64,
    operations: Vec<Operation>,
    paths: Vec<PathBuf>,
    open_fd: bool,
}

/// Entry/exit decoder scoped to one execution.
///
/// Feed every syscall stop in order. The caller must fail observation or
/// degrade coverage on an error; it must never ignore a decode error.
#[derive(Debug)]
pub struct FilesystemDecoder {
    pending: BTreeMap<u32, Pending>,
    max_threads: usize,
}

impl FilesystemDecoder {
    #[must_use]
    pub fn new(max_threads: usize) -> Self {
        Self {
            pending: BTreeMap::new(),
            max_threads,
        }
    }

    pub fn on_syscall(
        &mut self,
        stop: &SyscallStop,
    ) -> Result<Vec<FilesystemFact>, FilesystemDecodeError> {
        match stop.observed() {
            ObservedSyscall::Entry => self.entry(stop),
            ObservedSyscall::Exit => self.exit(stop),
        }
    }

    /// Clear an incomplete entry after a lifecycle gap. The caller also marks
    /// execution coverage incomplete.
    pub fn on_gap(&mut self, tid: u32) {
        self.pending.remove(&tid);
    }

    fn entry(&mut self, stop: &SyscallStop) -> Result<Vec<FilesystemFact>, FilesystemDecodeError> {
        let tid = stop.tid();
        if self.pending.contains_key(&tid) {
            return Err(FilesystemDecodeError::PhaseMismatch { tid });
        }
        let number = stop
            .number()
            .ok_or(FilesystemDecodeError::PhaseMismatch { tid })?;
        let mut args = stop.args();
        if number == 437 {
            if args[3] < 8 {
                return Err(FilesystemDecodeError::InvalidPath);
            }
            let flags =
                read_remote_memory(tid, args[2], 8).map_err(FilesystemDecodeError::Remote)?;
            args[2] = u64::from_ne_bytes(
                flags
                    .try_into()
                    .map_err(|_| FilesystemDecodeError::InvalidPath)?,
            );
        }
        let Some(spec) = syscall_spec(number, args) else {
            return Ok(Vec::new());
        };
        if self.pending.len() >= self.max_threads {
            return Err(FilesystemDecodeError::Capacity);
        }
        let mut paths = Vec::with_capacity(spec.path_args.len());
        for arg in spec.path_args {
            let bytes = read_path(tid, stop.args()[arg.index])?;
            let nofollow = match number {
                6 | 82 | 83 | 84 | 86 | 87 | 88 | 89 | 258 | 263 | 264 | 266 | 316 => true,
                265 => arg.index == 3 || args[4] & libc::AT_SYMLINK_FOLLOW as u64 == 0,
                262 => args[3] & libc::AT_SYMLINK_NOFOLLOW as u64 != 0,
                2 => args[1] & libc::O_NOFOLLOW as u64 != 0,
                257 | 437 => args[2] & libc::O_NOFOLLOW as u64 != 0,
                _ => false,
            };
            paths.push(resolve_path(
                tid,
                &bytes,
                arg.dirfd.map(|index| stop.args()[index]),
                !nofollow,
            )?);
        }
        self.pending.insert(
            tid,
            Pending {
                number,
                operations: spec.operations,
                paths,
                open_fd: spec.open_fd,
            },
        );
        Ok(Vec::new())
    }

    fn exit(&mut self, stop: &SyscallStop) -> Result<Vec<FilesystemFact>, FilesystemDecodeError> {
        let tid = stop.tid();
        let Some(mut pending) = self.pending.remove(&tid) else {
            if stop
                .number()
                .is_some_and(|n| syscall_spec(n, [0; 6]).is_some())
            {
                return Err(FilesystemDecodeError::PhaseMismatch { tid });
            }
            return Ok(Vec::new());
        };
        if stop.number() != Some(pending.number) {
            return Err(FilesystemDecodeError::PhaseMismatch { tid });
        }
        let value = stop
            .return_value()
            .ok_or(FilesystemDecodeError::PhaseMismatch { tid })?;
        let success = !stop.is_error();
        if success && pending.open_fd {
            if let Ok(fd) = i32::try_from(value) {
                pending.paths[0] = fs::read_link(format!("/proc/{tid}/fd/{fd}"))
                    .map_err(FilesystemDecodeError::Proc)?;
            }
        }
        let outcome = if success {
            Outcome::success()
        } else {
            Outcome::failure(i32::try_from(-value).ok(), None)
        };
        let mut facts = Vec::new();
        for path in pending.paths {
            let text = path
                .into_os_string()
                .into_string()
                .map_err(|_| FilesystemDecodeError::InvalidPath)?;
            let resource =
                ObservedResource::file(text).map_err(|_| FilesystemDecodeError::InvalidPath)?;
            for operation in &pending.operations {
                facts.push(FilesystemFact {
                    tid,
                    operation: *operation,
                    resource: resource.clone(),
                    outcome: outcome.clone(),
                });
            }
        }
        Ok(facts)
    }
}

#[derive(Clone, Copy)]
struct PathArg {
    index: usize,
    dirfd: Option<usize>,
}

struct Spec {
    path_args: Vec<PathArg>,
    operations: Vec<Operation>,
    open_fd: bool,
}

fn spec(paths: &[(usize, Option<usize>)], operation: Operation) -> Spec {
    Spec {
        path_args: paths
            .iter()
            .map(|&(index, dirfd)| PathArg { index, dirfd })
            .collect(),
        operations: vec![operation],
        open_fd: false,
    }
}

// x86_64 Linux syscall numbers. Another architecture requires its own table
// and must not advertise complete filesystem coverage.
#[cfg(target_arch = "x86_64")]
fn syscall_spec(number: u64, args: [u64; 6]) -> Option<Spec> {
    use Operation::{FilesystemMetadata as M, FilesystemRead as R, FilesystemWrite as W};
    let open = |paths: &[(usize, Option<usize>)], flags: u64| {
        let access = flags & libc::O_ACCMODE as u64;
        let mut operations = Vec::new();
        if flags & libc::O_PATH as u64 != 0 {
            operations.push(M);
        } else {
            if access == libc::O_RDONLY as u64 || access == libc::O_RDWR as u64 {
                operations.push(R);
            }
            if access == libc::O_WRONLY as u64
                || access == libc::O_RDWR as u64
                || flags & (libc::O_CREAT | libc::O_TRUNC) as u64 != 0
            {
                operations.push(W);
            }
        }
        Spec {
            path_args: paths
                .iter()
                .map(|&(index, dirfd)| PathArg { index, dirfd })
                .collect(),
            operations,
            open_fd: true,
        }
    };
    match number {
        2 => Some(open(&[(0, None)], args[1])),
        85 => Some(open(
            &[(0, None)],
            libc::O_WRONLY as u64 | libc::O_CREAT as u64,
        )),
        257 | 437 => Some(open(&[(1, Some(0))], args[2])),
        87 | 84 | 83 | 76 => Some(spec(&[(0, None)], W)),
        90 | 92 => Some(spec(&[(0, None)], M)),
        88 => Some(spec(&[(1, None)], W)),
        263 | 258 => Some(spec(&[(1, Some(0))], W)),
        268 | 260 => Some(spec(&[(1, Some(0))], M)),
        82 | 86 => Some(spec(&[(0, None), (1, None)], W)),
        264 | 265 | 316 => Some(spec(&[(1, Some(0)), (3, Some(2))], W)),
        266 => Some(spec(&[(2, Some(1))], W)),
        4 | 6 | 21 | 89 => Some(spec(&[(0, None)], M)),
        262 | 269 | 267 => Some(spec(&[(1, Some(0))], M)),
        _ => None,
    }
}

#[cfg(not(target_arch = "x86_64"))]
fn syscall_spec(_number: u64, _args: [u64; 6]) -> Option<Spec> {
    None
}

fn read_path(tid: u32, address: u64) -> Result<Vec<u8>, FilesystemDecodeError> {
    if address == 0 {
        return Err(FilesystemDecodeError::InvalidPath);
    }
    let mut bytes = Vec::new();
    for offset in 0..MAX_REMOTE_READ {
        let pointer = address
            .checked_add(offset as u64)
            .ok_or(FilesystemDecodeError::InvalidPath)?;
        let byte = read_remote_memory(tid, pointer, 1).map_err(FilesystemDecodeError::Remote)?[0];
        if byte == 0 {
            return if bytes.is_empty() {
                Err(FilesystemDecodeError::InvalidPath)
            } else {
                Ok(bytes)
            };
        }
        bytes.push(byte);
    }
    Err(FilesystemDecodeError::PathTooLong)
}

fn resolve_path(
    tid: u32,
    bytes: &[u8],
    dirfd: Option<u64>,
    follow_leaf: bool,
) -> Result<PathBuf, FilesystemDecodeError> {
    // The path is canonicalized through the tracer's filesystem. If the
    // tracee sees a different mount namespace or root, that result could name
    // the wrong object. Fail closed until namespace-aware resolution exists.
    let tracee_mount =
        fs::read_link(format!("/proc/{tid}/ns/mnt")).map_err(FilesystemDecodeError::Proc)?;
    let tracer_mount = fs::read_link("/proc/self/ns/mnt").map_err(FilesystemDecodeError::Proc)?;
    let tracee_root =
        fs::read_link(format!("/proc/{tid}/root")).map_err(FilesystemDecodeError::Proc)?;
    if tracee_mount != tracer_mount || tracee_root != Path::new("/") {
        return Err(FilesystemDecodeError::NamespaceMismatch);
    }
    let path = Path::new(OsStr::from_bytes(bytes));
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let base = match dirfd.map(|fd| fd as i32) {
            None | Some(libc::AT_FDCWD) => fs::read_link(format!("/proc/{tid}/cwd")),
            Some(fd) => fs::read_link(format!("/proc/{tid}/fd/{fd}")),
        }
        .map_err(FilesystemDecodeError::Proc)?;
        base.join(path)
    };
    let (mut ancestor, mut suffix) = if !follow_leaf {
        match (absolute.parent(), absolute.file_name()) {
            (Some(parent), Some(name)) => (parent, vec![name.to_os_string()]),
            _ => (absolute.as_path(), Vec::<OsString>::new()),
        }
    } else {
        (absolute.as_path(), Vec::<OsString>::new())
    };
    loop {
        if let Ok(real) = fs::canonicalize(ancestor) {
            let mut resolved = real;
            for component in suffix.iter().rev() {
                resolved.push(component);
            }
            return Ok(normalize(&resolved));
        }
        let name = ancestor
            .file_name()
            .ok_or(FilesystemDecodeError::InvalidPath)?;
        suffix.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or(FilesystemDecodeError::InvalidPath)?;
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut parts = Vec::<OsString>::new();
    for part in path.components() {
        match part {
            Component::RootDir => parts.clear(),
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(name) => parts.push(name.to_os_string()),
            Component::CurDir | Component::Prefix(_) => {}
        }
    }
    let mut output = PathBuf::from("/");
    for part in parts {
        output.push(part);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn open_flags_classify_read_write_and_metadata() {
        assert_eq!(
            syscall_spec(2, [0, libc::O_RDONLY as u64, 0, 0, 0, 0])
                .unwrap()
                .operations,
            vec![Operation::FilesystemRead]
        );
        assert_eq!(
            syscall_spec(257, [0, 0, libc::O_RDWR as u64, 0, 0, 0])
                .unwrap()
                .operations,
            vec![Operation::FilesystemRead, Operation::FilesystemWrite]
        );
        assert_eq!(
            syscall_spec(2, [0, libc::O_PATH as u64, 0, 0, 0, 0])
                .unwrap()
                .operations,
            vec![Operation::FilesystemMetadata]
        );
    }

    #[test]
    fn symlink_resolves_to_target() {
        let root = std::env::temp_dir().join(format!("drifti-fs-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            resolve_path(std::process::id(), link.as_os_str().as_bytes(), None, true).unwrap(),
            target
        );
        assert_eq!(
            resolve_path(std::process::id(), link.as_os_str().as_bytes(), None, false).unwrap(),
            link
        );
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn failed_open_is_attempted_only() {
        let mut decoder = FilesystemDecoder::new(1);
        let path = b"/definitely/not/a/drifti/path\0";
        let mut args = [0_u64; 6];
        args[0] = path.as_ptr() as u64;
        decoder
            .on_syscall(&SyscallStop::entry(std::process::id(), 2, args))
            .unwrap();
        let facts = decoder
            .on_syscall(&SyscallStop::exit(std::process::id(), Some(2), -2, true))
            .unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].outcome, Outcome::failure(Some(2), None));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn dirfd_open_uses_returned_fd_target() {
        let root = std::env::temp_dir().join(format!("drifti-fs-dirfd-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let directory = fs::File::open(&root).unwrap();
        let file = fs::File::open(&link).unwrap();
        let path = b"link\0";
        let mut args = [0_u64; 6];
        args[0] = directory.as_raw_fd() as u64;
        args[1] = path.as_ptr() as u64;
        args[2] = libc::O_RDONLY as u64;
        let tid = std::process::id();
        let mut decoder = FilesystemDecoder::new(1);
        decoder
            .on_syscall(&SyscallStop::entry(tid, 257, args))
            .unwrap();
        let facts = decoder
            .on_syscall(&SyscallStop::exit(
                tid,
                Some(257),
                i64::from(file.as_raw_fd()),
                false,
            ))
            .unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].operation, Operation::FilesystemRead);
        assert_eq!(
            facts[0].resource,
            ObservedResource::file(target.to_str().unwrap()).unwrap()
        );
        assert_eq!(facts[0].outcome, Outcome::success());
        drop(file);
        drop(directory);
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn create_write_is_exercised_and_phase_mismatch_is_an_error() {
        let root = std::env::temp_dir().join(format!("drifti-fs-write-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("created");
        let bytes = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        let file = fs::File::create(&path).unwrap();
        let mut args = [0_u64; 6];
        args[0] = bytes.as_ptr() as u64;
        args[1] = libc::O_CREAT as u64 | libc::O_WRONLY as u64;
        let tid = std::process::id();
        let mut decoder = FilesystemDecoder::new(1);
        decoder
            .on_syscall(&SyscallStop::entry(tid, 2, args))
            .unwrap();
        assert!(matches!(
            decoder.on_syscall(&SyscallStop::entry(tid, 2, args)),
            Err(FilesystemDecodeError::PhaseMismatch { .. })
        ));
        let facts = decoder
            .on_syscall(&SyscallStop::exit(
                tid,
                Some(2),
                i64::from(file.as_raw_fd()),
                false,
            ))
            .unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].operation, Operation::FilesystemWrite);
        assert_eq!(facts[0].outcome, Outcome::success());
        drop(file);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
