// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Filesystem syscall decoding while a Linux tracee is stopped.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display, Formatter};
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use drifti_observer::{ObservedResource, Operation, Outcome};

use crate::memory::{read_remote_memory, RemoteReadError, MAX_REMOTE_READ};
use crate::proc_status::{parse_tgid, MAX_PROC_STATUS};
use crate::syscall::{ObservedSyscall, SyscallStop};

/// Linux `MAXSYMLINKS`. A longer chain is a decode error, not a partial path.
const MAX_SYMLINKS: u32 = 40;

/// x86_64 `openat2`. Other architectures do not reuse this number.
const OPENAT2_X86_64: u64 = 437;

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
    PhaseMismatch {
        tid: u32,
    },
    Capacity,
    /// This build has no filesystem syscall table. Callers degrade coverage.
    /// `Ok` with an empty fact list is not this condition.
    UnsupportedAbi,
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
            Self::UnsupportedAbi => {
                f.write_str("filesystem syscall numbers are not decoded for this architecture")
            }
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
    tgid: u32,
}

/// Entry/exit decoder scoped to one execution.
///
/// Feed every syscall stop in order. The caller must fail observation or
/// degrade coverage on an error; it must never ignore a decode error.
/// [`FilesystemDecodeError::UnsupportedAbi`] is that degradation for a
/// build without an x86_64 table. It is not an empty success.
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

    /// Whether `tid` has a filesystem syscall waiting for its exit.
    #[must_use]
    pub(crate) fn has_pending(&self, tid: u32) -> bool {
        self.pending.contains_key(&tid)
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
        let mut resolve_flags = 0_u64;
        // Only the x86_64 openat2 number has this argument layout. The read is
        // capped at the published `open_how` prefix, never at the size register.
        if cfg!(target_arch = "x86_64") && number == OPENAT2_X86_64 && args[3] >= 8 && args[2] != 0
        {
            let (flags, resolve) = read_open_how(tid, args[2], args[3])?;
            args[2] = flags;
            resolve_flags = resolve;
        }
        let spec = match classify(number, args)? {
            Some(spec) => spec,
            None => return Ok(Vec::new()),
        };
        if self.pending.len() >= self.max_threads {
            return Err(FilesystemDecodeError::Capacity);
        }
        let tgid = thread_group_id(tid)?;
        let mut paths = Vec::with_capacity(spec.path_args.len());
        for arg in &spec.path_args {
            let allow_empty = allows_empty_path(number, args);
            let bytes = read_path_bytes(tid, args[arg.index], allow_empty)?;
            let follow_leaf = !leaf_nofollow(number, args, arg.index);
            paths.push(resolve_path(
                tid,
                tgid,
                &bytes,
                arg.dirfd.map(|index| args[index]),
                follow_leaf,
                resolve_flags,
            )?);
        }
        self.pending.insert(
            tid,
            Pending {
                number,
                operations: spec.operations,
                paths,
                open_fd: spec.open_fd,
                tgid,
            },
        );
        Ok(Vec::new())
    }

    fn exit(&mut self, stop: &SyscallStop) -> Result<Vec<FilesystemFact>, FilesystemDecodeError> {
        let tid = stop.tid();
        let Some(mut pending) = self.pending.remove(&tid) else {
            let number = stop.number().unwrap_or(0);
            return match classify(number, [0; 6])? {
                Some(_) => Err(FilesystemDecodeError::PhaseMismatch { tid }),
                None => Ok(Vec::new()),
            };
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
                if fd >= 0 {
                    let linked = fs::read_link(format!("/proc/{tid}/fd/{fd}"))
                        .map_err(FilesystemDecodeError::Proc)?;
                    let path = pending
                        .paths
                        .first_mut()
                        .ok_or(FilesystemDecodeError::InvalidPath)?;
                    *path = normalize(&rewrite_proc(&linked, pending.tgid, tid));
                }
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

/// `Ok(None)` means the number is not a filesystem syscall on the x86_64 table.
/// A missing table is [`FilesystemDecodeError::UnsupportedAbi`], never `Ok(None)`.
fn classify(number: u64, args: [u64; 6]) -> Result<Option<Spec>, FilesystemDecodeError> {
    classify_abi(cfg!(target_arch = "x86_64"), number, args)
}

fn classify_abi(
    x86_64: bool,
    number: u64,
    args: [u64; 6],
) -> Result<Option<Spec>, FilesystemDecodeError> {
    if !x86_64 {
        let _ = (number, args);
        return Err(FilesystemDecodeError::UnsupportedAbi);
    }
    #[cfg(target_arch = "x86_64")]
    {
        Ok(syscall_spec(number, args))
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (number, args);
        Err(FilesystemDecodeError::UnsupportedAbi)
    }
}

// x86_64 Linux syscall numbers. Another architecture uses [`classify_abi`]
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
        257 | OPENAT2_X86_64 => Some(open(&[(1, Some(0))], args[2])),
        87 | 84 | 83 | 76 => Some(spec(&[(0, None)], W)),
        90 | 92 | 94 => Some(spec(&[(0, None)], M)),
        88 => Some(spec(&[(1, None)], W)),
        133 => Some(spec(&[(0, None)], W)),
        263 | 258 | 259 => Some(spec(&[(1, Some(0))], W)),
        268 | 260 | 280 | 332 => Some(spec(&[(1, Some(0))], M)),
        82 | 86 => Some(spec(&[(0, None), (1, None)], W)),
        264 | 265 | 316 => Some(spec(&[(1, Some(0)), (3, Some(2))], W)),
        266 => Some(spec(&[(2, Some(1))], W)),
        4 | 6 | 21 | 89 => Some(spec(&[(0, None)], M)),
        262 | 269 | 267 | 439 => Some(spec(&[(1, Some(0))], M)),
        _ => None,
    }
}

fn leaf_nofollow(number: u64, args: [u64; 6], index: usize) -> bool {
    match number {
        6 | 82 | 83 | 84 | 86 | 87 | 88 | 89 | 94 | 133 | 258 | 259 | 263 | 264 | 266 | 316 => true,
        265 => index == 3 || args[4] & libc::AT_SYMLINK_FOLLOW as u64 == 0,
        262 | 269 | 439 | 280 => args[3] & libc::AT_SYMLINK_NOFOLLOW as u64 != 0,
        260 => args[4] & libc::AT_SYMLINK_NOFOLLOW as u64 != 0,
        332 => args[2] & libc::AT_SYMLINK_NOFOLLOW as u64 != 0,
        2 => args[1] & libc::O_NOFOLLOW as u64 != 0,
        257 | OPENAT2_X86_64 => args[2] & libc::O_NOFOLLOW as u64 != 0,
        _ => false,
    }
}

fn allows_empty_path(number: u64, args: [u64; 6]) -> bool {
    let flag = libc::AT_EMPTY_PATH as u64;
    match number {
        262 | 269 | 439 | 280 | 265 => args[3] & flag != 0,
        332 => args[2] & flag != 0,
        260 => args[4] & flag != 0,
        _ => false,
    }
}

/// Reads the `open_how` prefix. `size` may be larger than the struct; only 24
/// bytes are transferred, and never more than [`MAX_REMOTE_READ`].
fn read_open_how(tid: u32, address: u64, size: u64) -> Result<(u64, u64), FilesystemDecodeError> {
    if address == 0 || size < 8 {
        return Err(FilesystemDecodeError::InvalidPath);
    }
    let len = if size >= 24 { 24 } else { 8 };
    debug_assert!(len <= MAX_REMOTE_READ);
    let bytes = read_remote_memory(tid, address, len).map_err(FilesystemDecodeError::Remote)?;
    let flags = u64_at(&bytes, 0)?;
    let resolve = if len == 24 { u64_at(&bytes, 16)? } else { 0 };
    Ok((flags, resolve))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, FilesystemDecodeError> {
    let end = offset
        .checked_add(8)
        .ok_or(FilesystemDecodeError::InvalidPath)?;
    let slice = bytes
        .get(offset..end)
        .ok_or(FilesystemDecodeError::InvalidPath)?;
    let array: [u8; 8] = slice
        .try_into()
        .map_err(|_| FilesystemDecodeError::InvalidPath)?;
    Ok(u64::from_ne_bytes(array))
}

fn read_path_bytes(
    tid: u32,
    address: u64,
    allow_empty: bool,
) -> Result<Vec<u8>, FilesystemDecodeError> {
    if address == 0 {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(FilesystemDecodeError::InvalidPath)
        };
    }
    let mut bytes = Vec::new();
    for offset in 0..MAX_REMOTE_READ {
        let pointer = address
            .checked_add(offset as u64)
            .ok_or(FilesystemDecodeError::InvalidPath)?;
        let byte = read_remote_memory(tid, pointer, 1).map_err(FilesystemDecodeError::Remote)?[0];
        if byte == 0 {
            if bytes.is_empty() && !allow_empty {
                return Err(FilesystemDecodeError::InvalidPath);
            }
            return Ok(bytes);
        }
        bytes.push(byte);
    }
    Err(FilesystemDecodeError::PathTooLong)
}

#[derive(Clone, Copy)]
struct WalkOptions {
    follow_leaf: bool,
    no_symlinks: bool,
    no_magiclinks: bool,
    no_xdev: bool,
    beneath: bool,
    in_root: bool,
    tgid: u32,
    tid: u32,
}

impl WalkOptions {
    fn from_flags(resolve: u64, follow_leaf: bool, tgid: u32, tid: u32) -> Self {
        let no_symlinks = resolve & libc::RESOLVE_NO_SYMLINKS != 0;
        Self {
            follow_leaf: follow_leaf && !no_symlinks,
            no_symlinks,
            no_magiclinks: resolve & libc::RESOLVE_NO_MAGICLINKS != 0,
            no_xdev: resolve & libc::RESOLVE_NO_XDEV != 0,
            beneath: resolve & libc::RESOLVE_BENEATH != 0,
            // `RESOLVE_CACHED` does not change which object the attempt names.
            in_root: resolve & libc::RESOLVE_IN_ROOT != 0,
            tgid,
            tid,
        }
    }
}

fn resolve_path(
    tid: u32,
    tgid: u32,
    bytes: &[u8],
    dirfd: Option<u64>,
    follow_leaf: bool,
    resolve_flags: u64,
) -> Result<PathBuf, FilesystemDecodeError> {
    // The tracee and the tracer must share a mount namespace and root.
    // Otherwise a path resolved here could name the wrong object.
    ensure_same_namespace(tid)?;
    let options = WalkOptions::from_flags(resolve_flags, follow_leaf, tgid, tid);
    let user = Path::new(OsStr::from_bytes(bytes));
    if user.as_os_str().is_empty() {
        return canonical_directory(tid, tgid, dirfd);
    }
    // An absolute path under `RESOLVE_BENEATH` is rejected by the kernel
    // before symlink follow. Keep the tracee's proc identity and do not walk.
    if options.beneath && !options.in_root && user.is_absolute() {
        return Ok(normalize(&rewrite_proc(user, tgid, tid)));
    }
    let anchor = canonical_directory(tid, tgid, dirfd)?;
    let (current, pending) = if options.in_root || !user.is_absolute() {
        (anchor.clone(), components_of(user))
    } else {
        (PathBuf::from("/"), components_of(user))
    };
    let limit = if options.beneath || options.in_root {
        Some(anchor)
    } else {
        None
    };
    let origin = if options.no_xdev {
        Some(device_of(&current)?)
    } else {
        None
    };
    walk(
        current,
        pending,
        tgid,
        tid,
        &options,
        limit.as_deref(),
        origin,
    )
}

fn ensure_same_namespace(tid: u32) -> Result<(), FilesystemDecodeError> {
    let tracee_mount =
        fs::read_link(format!("/proc/{tid}/ns/mnt")).map_err(FilesystemDecodeError::Proc)?;
    let tracer_mount = fs::read_link("/proc/self/ns/mnt").map_err(FilesystemDecodeError::Proc)?;
    let tracee_root =
        fs::read_link(format!("/proc/{tid}/root")).map_err(FilesystemDecodeError::Proc)?;
    if tracee_mount != tracer_mount || tracee_root != Path::new("/") {
        return Err(FilesystemDecodeError::NamespaceMismatch);
    }
    Ok(())
}

fn thread_group_id(tid: u32) -> Result<u32, FilesystemDecodeError> {
    let mut file =
        File::open(format!("/proc/{tid}/status")).map_err(FilesystemDecodeError::Proc)?;
    let mut buf = [0_u8; 512];
    let mut collected = Vec::new();
    while collected.len() < MAX_PROC_STATUS {
        let n = file.read(&mut buf).map_err(FilesystemDecodeError::Proc)?;
        if n == 0 {
            break;
        }
        let room = MAX_PROC_STATUS - collected.len();
        collected.extend_from_slice(&buf[..n.min(room)]);
        if n > room {
            break;
        }
    }
    let text = std::str::from_utf8(&collected).map_err(|_| FilesystemDecodeError::InvalidPath)?;
    parse_tgid(text).ok_or(FilesystemDecodeError::InvalidPath)
}

fn directory_anchor(tid: u32, dirfd: Option<u64>) -> Result<PathBuf, FilesystemDecodeError> {
    let fd = dirfd.map(|value| value as i32);
    let link = match fd {
        None | Some(libc::AT_FDCWD) => format!("/proc/{tid}/cwd"),
        Some(fd) => format!("/proc/{tid}/fd/{fd}"),
    };
    let path = fs::read_link(link).map_err(FilesystemDecodeError::Proc)?;
    if path.as_os_str().len() > MAX_REMOTE_READ {
        return Err(FilesystemDecodeError::PathTooLong);
    }
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(Path::new("/").join(path))
    }
}

fn canonical_directory(
    tid: u32,
    tgid: u32,
    dirfd: Option<u64>,
) -> Result<PathBuf, FilesystemDecodeError> {
    let raw = directory_anchor(tid, dirfd)?;
    // Rewrite before `canonicalize`. `/proc/self` in the tracer is not the tracee.
    let rewritten = rewrite_proc(&raw, tgid, tid);
    if let Ok(canonical) = fs::canonicalize(&rewritten) {
        return Ok(canonical);
    }
    Ok(normalize(&rewritten))
}

fn device_of(path: &Path) -> Result<u64, FilesystemDecodeError> {
    let meta = fs::symlink_metadata(path).map_err(FilesystemDecodeError::Proc)?;
    Ok(meta.dev())
}

fn existing_device(path: &Path) -> Option<u64> {
    let mut cursor = path.to_path_buf();
    loop {
        if let Ok(meta) = fs::symlink_metadata(&cursor) {
            return Some(meta.dev());
        }
        if !cursor.pop() {
            return None;
        }
    }
}

fn components_of(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::CurDir => Some(OsString::from(".")),
            Component::RootDir | Component::Prefix(_) => None,
        })
        .collect()
}

fn walk(
    mut current: PathBuf,
    mut pending: VecDeque<OsString>,
    tgid: u32,
    tid: u32,
    options: &WalkOptions,
    limit: Option<&Path>,
    origin: Option<u64>,
) -> Result<PathBuf, FilesystemDecodeError> {
    let mut links = 0_u32;
    loop {
        let Some(component) = pending.pop_front() else {
            return Ok(normalize(&current));
        };
        if component == "." {
            continue;
        }
        if component == ".." {
            if let Some(finished) = step_parent(&mut current, &mut pending, options, limit) {
                return Ok(finished);
            }
            continue;
        }
        let component = proc_identity(&current, &component, tgid, tid);
        let next = current.join(&component);
        let is_last = pending.is_empty();
        match fs::symlink_metadata(&next) {
            Err(error) if is_missing(&error) => {
                current = next;
                push_pending(&mut current, pending);
                return Ok(normalize(&current));
            }
            Err(error) => return Err(FilesystemDecodeError::Proc(error)),
            Ok(meta) => {
                if crossed_mount(options.no_xdev, origin, &meta) {
                    current = next;
                    push_pending(&mut current, pending);
                    return Ok(normalize(&current));
                }
                if should_follow(options, is_last) && meta.file_type().is_symlink() {
                    match follow_symlink(&current, &next, &pending, options, limit, origin)? {
                        Follow::Stop(path) => return Ok(path),
                        Follow::Restart {
                            current: base,
                            pending: rest,
                        } => {
                            links = links.saturating_add(1);
                            if links > MAX_SYMLINKS {
                                return Err(FilesystemDecodeError::InvalidPath);
                            }
                            current = base;
                            pending = rest;
                        }
                    }
                    continue;
                }
                current = next;
            }
        }
    }
}

fn step_parent(
    current: &mut PathBuf,
    pending: &mut VecDeque<OsString>,
    options: &WalkOptions,
    limit: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(root) = limit {
        if current.as_path() == root {
            if options.in_root {
                return None;
            }
            current.push("..");
            push_pending(current, std::mem::take(pending));
            return Some(current.clone());
        }
    }
    current.pop();
    None
}

fn should_follow(options: &WalkOptions, is_last: bool) -> bool {
    !options.no_symlinks && (!is_last || options.follow_leaf)
}

fn crossed_mount(no_xdev: bool, origin: Option<u64>, meta: &fs::Metadata) -> bool {
    if !no_xdev || meta.file_type().is_symlink() {
        return false;
    }
    origin.is_some_and(|origin| meta.dev() != origin)
}

enum Follow {
    Stop(PathBuf),
    Restart {
        current: PathBuf,
        pending: VecDeque<OsString>,
    },
}

fn follow_symlink(
    parent: &Path,
    link: &Path,
    pending: &VecDeque<OsString>,
    options: &WalkOptions,
    limit: Option<&Path>,
    origin: Option<u64>,
) -> Result<Follow, FilesystemDecodeError> {
    if options.no_magiclinks && is_magic_proc_link(link) {
        return Ok(stop_at(link, pending));
    }
    let target = read_link_bounded(link)?;
    // Relative targets still contain `..`. Rewriting those here would drop it.
    // Absolute targets can name `/proc/self`, which must not be the tracer.
    let target = if target.is_absolute() {
        rewrite_proc(&target, options.tgid, options.tid)
    } else {
        target
    };
    if refuse_target(parent, &target, options, origin) {
        return Ok(stop_at(link, pending));
    }
    let (base, comps) = retarget(parent, &target, options, limit);
    let mut rest = comps;
    rest.extend(pending.iter().cloned());
    Ok(Follow::Restart {
        current: base,
        pending: rest,
    })
}

fn stop_at(link: &Path, pending: &VecDeque<OsString>) -> Follow {
    let mut path = link.to_path_buf();
    push_pending(&mut path, pending.iter().cloned());
    Follow::Stop(normalize(&path))
}

fn refuse_target(parent: &Path, target: &Path, options: &WalkOptions, origin: Option<u64>) -> bool {
    if options.beneath && !options.in_root && target.is_absolute() {
        return true;
    }
    if options.no_xdev {
        let landed = if target.is_absolute() {
            target.to_path_buf()
        } else {
            parent.join(target)
        };
        if let (Some(origin), Some(dev)) = (origin, existing_device(&landed)) {
            if dev != origin {
                return true;
            }
        }
    }
    false
}

fn retarget(
    parent: &Path,
    target: &Path,
    options: &WalkOptions,
    limit: Option<&Path>,
) -> (PathBuf, VecDeque<OsString>) {
    if target.is_absolute() {
        if options.in_root {
            let root = limit.unwrap_or(Path::new("/")).to_path_buf();
            (root, components_of(target))
        } else {
            (PathBuf::from("/"), components_of(target))
        }
    } else {
        (parent.to_path_buf(), components_of(target))
    }
}

fn push_pending(path: &mut PathBuf, pending: impl IntoIterator<Item = OsString>) {
    for component in pending {
        path.push(component);
    }
}

fn is_missing(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory)
}

fn read_link_bounded(path: &Path) -> Result<PathBuf, FilesystemDecodeError> {
    let target = fs::read_link(path).map_err(FilesystemDecodeError::Proc)?;
    if target.as_os_str().len() > MAX_REMOTE_READ {
        return Err(FilesystemDecodeError::PathTooLong);
    }
    Ok(target)
}

/// Replaces `/proc/self` and `/proc/thread-self` with the tracee's ids.
///
/// Those names are magic links. Canonicalizing them in the tracer names the
/// tracer, not the tracee.
fn rewrite_proc(path: &Path, tgid: u32, tid: u32) -> PathBuf {
    let mut out = PathBuf::new();
    if path.is_absolute() {
        out.push("/");
    }
    for component in path.components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => {
                out.push(proc_identity(&out, name, tgid, tid));
            }
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from("/")
    } else {
        out
    }
}

fn proc_identity(parent: &Path, component: &OsStr, tgid: u32, tid: u32) -> OsString {
    if parent == Path::new("/proc") && component == OsStr::new("self") {
        return OsString::from(tgid.to_string());
    }
    if parent == Path::new("/proc") && component == OsStr::new("thread-self") {
        return OsString::from(tid.to_string());
    }
    component.to_os_string()
}

fn is_magic_proc_link(path: &Path) -> bool {
    let names: Vec<&OsStr> = path
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(name),
            _ => None,
        })
        .collect();
    let Some((root, tail)) = names.split_first() else {
        return false;
    };
    if *root != OsStr::new("proc") {
        return false;
    }
    magic_proc_tail(tail)
}

fn magic_proc_tail(names: &[&OsStr]) -> bool {
    match names {
        [name] if *name == OsStr::new("self") || *name == OsStr::new("thread-self") => true,
        [id, tail @ ..] if is_proc_id(id) => magic_proc_entry(tail),
        _ => false,
    }
}

fn magic_proc_entry(tail: &[&OsStr]) -> bool {
    match tail {
        [kind] if is_pid_magic(kind) => true,
        [kind, _]
            if *kind == OsStr::new("fd")
                || *kind == OsStr::new("ns")
                || *kind == OsStr::new("map_files") =>
        {
            true
        }
        [task, id, rest @ ..] if *task == OsStr::new("task") && is_proc_id(id) => {
            magic_proc_entry(rest)
        }
        _ => false,
    }
}

fn is_pid_magic(kind: &OsStr) -> bool {
    kind == OsStr::new("exe") || kind == OsStr::new("cwd") || kind == OsStr::new("root")
}

fn is_proc_id(name: &OsStr) -> bool {
    name == OsStr::new("self")
        || name == OsStr::new("thread-self")
        || name
            .to_str()
            .is_some_and(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
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
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

    fn temp_tree(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "drifti-fs-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn unsupported_abi_is_not_an_empty_success() {
        let error = match classify_abi(false, 2, [0; 6]) {
            Err(error) => error,
            Ok(_) => panic!("unsupported abi returned a decoded syscall"),
        };
        assert!(matches!(error, FilesystemDecodeError::UnsupportedAbi));
        let text = error.to_string();
        assert!(!text.contains('/'));
        assert!(!text.contains("SUPER_SECRET"));
    }

    #[test]
    fn proc_identity_uses_tracee_ids() {
        assert_eq!(
            proc_identity(Path::new("/proc"), OsStr::new("self"), 10, 11),
            OsString::from("10")
        );
        assert_eq!(
            proc_identity(Path::new("/proc"), OsStr::new("thread-self"), 10, 11),
            OsString::from("11")
        );
        assert_eq!(
            proc_identity(Path::new("/tmp"), OsStr::new("self"), 10, 11),
            OsString::from("self")
        );
        assert_eq!(
            rewrite_proc(Path::new("/proc/self/fd/3"), 10, 11),
            PathBuf::from("/proc/10/fd/3")
        );
        assert_eq!(
            rewrite_proc(Path::new("/proc/thread-self/comm"), 10, 11),
            PathBuf::from("/proc/11/comm")
        );
        assert!(!is_magic_proc_link(Path::new("/tmp/self")));
        assert!(is_magic_proc_link(Path::new("/proc/10/exe")));
        assert!(is_magic_proc_link(Path::new("/proc/self")));
    }

    #[test]
    fn proc_self_is_not_resolved_through_the_calling_process_magic_link() {
        let tid = std::process::id();
        let held = resolve_path(
            tid,
            tid,
            b"/proc/self/exe",
            None,
            true,
            libc::RESOLVE_NO_MAGICLINKS,
        )
        .unwrap();
        assert_eq!(held, PathBuf::from(format!("/proc/{tid}/exe")));
        let followed = resolve_path(tid, tid, b"/proc/self/exe", None, true, 0).unwrap();
        let exe = fs::read_link("/proc/self/exe").unwrap();
        let canonical = fs::canonicalize(&exe).unwrap_or(exe);
        assert_eq!(followed, canonical);
        assert_ne!(held, followed);
        let thread = resolve_path(tid, tid, b"/proc/thread-self/comm", None, true, 0).unwrap();
        assert_eq!(thread, PathBuf::from(format!("/proc/{tid}/comm")));
    }

    #[test]
    fn symlink_resolves_to_target() {
        let root = temp_tree("link");
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let tid = std::process::id();
        assert_eq!(
            resolve_path(tid, tid, link.as_os_str().as_bytes(), None, true, 0).unwrap(),
            fs::canonicalize(&target).unwrap()
        );
        assert_eq!(
            resolve_path(tid, tid, link.as_os_str().as_bytes(), None, false, 0).unwrap(),
            fs::canonicalize(&root).unwrap().join("link")
        );
        let _ = fs::remove_dir_all(&root);
    }

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
        assert_eq!(
            syscall_spec(libc::SYS_statx as u64, [0; 6])
                .unwrap()
                .operations,
            vec![Operation::FilesystemMetadata]
        );
        assert_eq!(
            syscall_spec(libc::SYS_faccessat2 as u64, [0; 6])
                .unwrap()
                .operations,
            vec![Operation::FilesystemMetadata]
        );
        assert_eq!(
            syscall_spec(libc::SYS_utimensat as u64, [0; 6])
                .unwrap()
                .operations,
            vec![Operation::FilesystemMetadata]
        );
        assert_eq!(
            syscall_spec(libc::SYS_mknod as u64, [0; 6])
                .unwrap()
                .operations,
            vec![Operation::FilesystemWrite]
        );
        assert_eq!(
            syscall_spec(libc::SYS_mknodat as u64, [0; 6])
                .unwrap()
                .operations,
            vec![Operation::FilesystemWrite]
        );
        assert_eq!(
            syscall_spec(libc::SYS_lchown as u64, [0; 6])
                .unwrap()
                .operations,
            vec![Operation::FilesystemMetadata]
        );
        assert_eq!(libc::SYS_openat2 as u64, OPENAT2_X86_64);
    }

    #[cfg(target_arch = "x86_64")]
    fn sign_extend(fd: i32) -> u64 {
        fd as u64
    }

    #[cfg(target_arch = "x86_64")]
    fn decode_pair(
        number: u64,
        args: [u64; 6],
        exit_value: i64,
        is_error: bool,
    ) -> Vec<FilesystemFact> {
        let tid = std::process::id();
        let mut decoder = FilesystemDecoder::new(1);
        decoder
            .on_syscall(&SyscallStop::entry(tid, number, args))
            .unwrap();
        decoder
            .on_syscall(&SyscallStop::exit(tid, Some(number), exit_value, is_error))
            .unwrap()
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn failed_open_is_attempted_only() {
        let path = CString::new("/definitely/not/a/drifti/path").unwrap();
        let mut args = [0_u64; 6];
        args[0] = path.as_ptr() as u64;
        args[1] = libc::O_RDONLY as u64;
        let facts = decode_pair(2, args, -2, true);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].outcome, Outcome::failure(Some(2), None));
        assert_eq!(facts[0].operation, Operation::FilesystemRead);
        assert_eq!(
            facts[0].resource,
            ObservedResource::file("/definitely/not/a/drifti/path").unwrap()
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn dirfd_failure_resolves_at_entry_without_a_returned_fd() {
        let root = temp_tree("dirfd-miss");
        let directory = fs::File::open(&root).unwrap();
        let path = CString::new("missing-entry").unwrap();
        let mut args = [0_u64; 6];
        args[0] = directory.as_raw_fd() as u64;
        args[1] = path.as_ptr() as u64;
        args[2] = libc::O_RDONLY as u64;
        let facts = decode_pair(257, args, -2, true);
        let expected = fs::canonicalize(&root).unwrap().join("missing-entry");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].operation, Operation::FilesystemRead);
        assert_eq!(facts[0].outcome, Outcome::failure(Some(2), None));
        assert_eq!(
            facts[0].resource,
            ObservedResource::file(expected.to_str().unwrap()).unwrap()
        );
        drop(directory);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn dirfd_open_uses_returned_fd_target() {
        let root = temp_tree("dirfd");
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let directory = fs::File::open(&root).unwrap();
        let file = fs::File::open(&link).unwrap();
        let path = CString::new("link").unwrap();
        let mut args = [0_u64; 6];
        args[0] = directory.as_raw_fd() as u64;
        args[1] = path.as_ptr() as u64;
        args[2] = libc::O_RDONLY as u64;
        let facts = decode_pair(257, args, i64::from(file.as_raw_fd()), false);
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].operation, Operation::FilesystemRead);
        assert_eq!(facts[0].outcome, Outcome::success());
        assert_eq!(
            facts[0].resource,
            ObservedResource::file(fs::canonicalize(&target).unwrap().to_str().unwrap()).unwrap()
        );
        drop(file);
        drop(directory);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn create_write_is_exercised_and_phase_mismatch_is_an_error() {
        let root = temp_tree("write");
        let path = root.join("created");
        let bytes = CString::new(path.as_os_str().as_bytes()).unwrap();
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
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn lchown_and_statx_nofollow_keep_the_symlink() {
        let root = temp_tree("meta");
        let target = root.join("target");
        let link = root.join("link");
        fs::write(&target, b"x").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let path = CString::new(link.as_os_str().as_bytes()).unwrap();
        let mut lchown_args = [0_u64; 6];
        lchown_args[0] = path.as_ptr() as u64;
        let facts = decode_pair(libc::SYS_lchown as u64, lchown_args, 0, false);
        assert_eq!(facts[0].operation, Operation::FilesystemMetadata);
        match &facts[0].resource {
            ObservedResource::File { path } => {
                assert!(path.ends_with("/link"), "{path}");
                assert!(!path.ends_with("/target"), "{path}");
            }
            other => panic!("unexpected resource {other:?}"),
        }
        let mut statx_args = [0_u64; 6];
        statx_args[0] = sign_extend(libc::AT_FDCWD);
        statx_args[1] = path.as_ptr() as u64;
        statx_args[2] = libc::AT_SYMLINK_NOFOLLOW as u64;
        let held = decode_pair(libc::SYS_statx as u64, statx_args, 0, false);
        match &held[0].resource {
            ObservedResource::File { path } => assert!(path.ends_with("/link"), "{path}"),
            other => panic!("unexpected resource {other:?}"),
        }
        statx_args[2] = 0;
        let followed = decode_pair(libc::SYS_statx as u64, statx_args, 0, false);
        match &followed[0].resource {
            ObservedResource::File { path } => assert!(path.ends_with("/target"), "{path}"),
            other => panic!("unexpected resource {other:?}"),
        }
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_arch = "x86_64")]
    fn decode_openat2(
        dirfd: i32,
        path: &CString,
        resolve: u64,
        exit_value: i64,
        is_error: bool,
    ) -> FilesystemFact {
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let how = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve,
        };
        let mut args = [0_u64; 6];
        args[0] = sign_extend(dirfd);
        args[1] = path.as_ptr() as u64;
        args[2] = &how as *const OpenHow as u64;
        args[3] = u64::MAX;
        let facts = decode_pair(OPENAT2_X86_64, args, exit_value, is_error);
        assert_eq!(facts.len(), 1);
        facts.into_iter().next().unwrap()
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn openat2_failed_attempts_honor_resolve_flags() {
        let root = temp_tree("openat2");
        let outside = root.join("outside");
        let jail = root.join("jail");
        let target = root.join("target");
        fs::create_dir_all(&outside).unwrap();
        fs::create_dir_all(&jail).unwrap();
        fs::write(&target, b"x").unwrap();
        let link = jail.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let escape = jail.join("escape");
        std::os::unix::fs::symlink(&outside, &escape).unwrap();
        let link_path = CString::new(link.as_os_str().as_bytes()).unwrap();
        let nosym = decode_openat2(
            libc::AT_FDCWD,
            &link_path,
            libc::RESOLVE_NO_SYMLINKS,
            -libc::ELOOP as i64,
            true,
        );
        match nosym.resource {
            ObservedResource::File { path } => {
                assert!(path.ends_with("/link"), "{path}");
                assert!(!path.ends_with("/target"), "{path}");
            }
            other => panic!("unexpected resource {other:?}"),
        }
        assert!(matches!(nosym.outcome, Outcome::Failure { .. }));

        let directory = fs::File::open(&jail).unwrap();
        let absolute = CString::new("/drifti-openat2-missing").unwrap();
        let in_root = decode_openat2(
            directory.as_raw_fd(),
            &absolute,
            libc::RESOLVE_IN_ROOT,
            -libc::ENOENT as i64,
            true,
        );
        let expected = fs::canonicalize(&jail)
            .unwrap()
            .join("drifti-openat2-missing");
        assert_eq!(
            in_root.resource,
            ObservedResource::file(expected.to_str().unwrap()).unwrap()
        );
        assert!(matches!(in_root.outcome, Outcome::Failure { .. }));

        let relative = CString::new("escape").unwrap();
        let beneath = decode_openat2(
            directory.as_raw_fd(),
            &relative,
            libc::RESOLVE_BENEATH,
            -libc::EXDEV as i64,
            true,
        );
        match beneath.resource {
            ObservedResource::File { path } => {
                assert!(path.ends_with("/escape"), "{path}");
                assert!(!path.ends_with("/outside"), "{path}");
            }
            other => panic!("unexpected resource {other:?}"),
        }

        let magic = CString::new("/proc/self/exe").unwrap();
        let no_magic = decode_openat2(
            libc::AT_FDCWD,
            &magic,
            libc::RESOLVE_NO_MAGICLINKS,
            -libc::ELOOP as i64,
            true,
        );
        let tid = std::process::id();
        assert_eq!(
            no_magic.resource,
            ObservedResource::file(format!("/proc/{tid}/exe")).unwrap()
        );
        drop(directory);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn openat2_cross_device_symlink_is_not_followed() {
        let root = temp_tree("xdev");
        let link = root.join("to-proc");
        std::os::unix::fs::symlink("/proc/self/stat", &link).unwrap();
        let tmp_dev = fs::metadata(&root).unwrap().dev();
        let proc_dev = fs::metadata("/proc").unwrap().dev();
        let path = CString::new(link.as_os_str().as_bytes()).unwrap();
        let held = decode_openat2(
            libc::AT_FDCWD,
            &path,
            libc::RESOLVE_NO_XDEV,
            -libc::EXDEV as i64,
            true,
        );
        let followed = decode_openat2(libc::AT_FDCWD, &path, 0, -libc::ENOENT as i64, true);
        if tmp_dev != proc_dev {
            match held.resource {
                ObservedResource::File { path } => {
                    assert!(path.ends_with("/to-proc"), "{path}");
                    assert!(!path.contains("/proc/"), "{path}");
                }
                other => panic!("unexpected resource {other:?}"),
            }
            match followed.resource {
                ObservedResource::File { path } => assert!(path.contains("/proc/"), "{path}"),
                other => panic!("unexpected resource {other:?}"),
            }
        }
        let _ = fs::remove_dir_all(root);
    }
}
