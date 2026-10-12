// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Controlled tracee for filesystem observation tests.
//!
//! Each mode performs one syscall family and then exits. File bytes are not
//! written to stdout or stderr.

#![deny(unsafe_code)]

fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("filesystem-tracee requires Linux");
        std::process::exit(2);
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux {
    use std::env;
    use std::ffi::CString;
    use std::process::exit;
    use std::thread;

    pub fn run() {
        let mut args = env::args().skip(1);
        let mode = args.next();
        match mode.as_deref() {
            Some("read") => open_path(&required(&mut args), libc::O_RDONLY),
            Some("write") => open_path(
                &required(&mut args),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            ),
            Some("metadata") => utimens(&required(&mut args)),
            Some("statx") => statx(&required(&mut args), 0),
            Some("faccessat2") => faccessat2(&required(&mut args)),
            Some("mknod") => mknod(&required(&mut args)),
            Some("mknodat") => {
                let dir = required(&mut args);
                let name = required(&mut args);
                mknodat(&dir, &name);
            }
            Some("lchown") => lchown(&required(&mut args)),
            Some("relative") => open_path(&required(&mut args), libc::O_RDONLY),
            Some("dirfd") => {
                let dir = required(&mut args);
                let name = required(&mut args);
                open_at(&dir, &name, libc::O_RDONLY);
            }
            Some("symlink-follow") => open_path(&required(&mut args), libc::O_RDONLY),
            Some("symlink-nofollow") => {
                open_path(&required(&mut args), libc::O_RDONLY | libc::O_NOFOLLOW)
            }
            Some("fail") => open_path(&required(&mut args), libc::O_RDONLY),
            Some("proc-self") => open_path("/proc/self/drifti-kan49-missing", libc::O_RDONLY),
            Some("thread-self") => thread_self(),
            Some("openat2-nosym") => openat2(
                libc::AT_FDCWD,
                &required(&mut args),
                libc::RESOLVE_NO_SYMLINKS,
            ),
            Some("openat2-in-root") => {
                let dir = required(&mut args);
                let path = required(&mut args);
                let fd = open_dir(&dir);
                openat2(fd, &path, libc::RESOLVE_IN_ROOT);
                close_fd(fd);
            }
            Some("openat2-beneath") => {
                let dir = required(&mut args);
                let name = required(&mut args);
                let fd = open_dir(&dir);
                openat2(fd, &name, libc::RESOLVE_BENEATH);
                close_fd(fd);
            }
            Some("openat2-magic") => openat2(
                libc::AT_FDCWD,
                "/proc/self/exe",
                libc::RESOLVE_NO_MAGICLINKS,
            ),
            Some("openat2-noxdev") => {
                openat2(libc::AT_FDCWD, &required(&mut args), libc::RESOLVE_NO_XDEV)
            }
            _ => exit(2),
        }
    }

    fn required(args: &mut impl Iterator<Item = String>) -> String {
        args.next().unwrap_or_else(|| exit(2))
    }

    fn cstr(text: &str) -> CString {
        CString::new(text).unwrap_or_else(|_| exit(2))
    }

    fn open_path(path: &str, flags: i32) {
        let path = cstr(path);
        // SAFETY: `path` is NUL-terminated and lives for the call. `open`
        // does not retain the pointer. A returned descriptor is closed below.
        let fd = unsafe { libc::open(path.as_ptr(), flags, 0o644) };
        close_fd(fd);
    }

    fn open_dir(path: &str) -> i32 {
        let path = cstr(path);
        // SAFETY: `path` is NUL-terminated and lives for the call. `open`
        // does not retain the pointer.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        if fd < 0 {
            exit(1);
        }
        fd
    }

    fn open_at(dir: &str, name: &str, flags: i32) {
        let fd = open_dir(dir);
        let name = cstr(name);
        // SAFETY: `name` is NUL-terminated and `fd` is a live descriptor from
        // `open` in this process. Neither pointer is retained.
        let opened = unsafe { libc::openat(fd, name.as_ptr(), flags, 0o644) };
        close_fd(opened);
        close_fd(fd);
    }

    fn close_fd(fd: i32) {
        if fd < 0 {
            return;
        }
        // SAFETY: `fd` was returned by `open` or `openat` in this process, or
        // the caller already rejected a negative value.
        unsafe { libc::close(fd) };
    }

    fn utimens(path: &str) {
        let path = cstr(path);
        // SAFETY: `path` is NUL-terminated. A null `times` pointer asks the
        // kernel to set both timestamps to now and is not retained.
        unsafe {
            libc::utimensat(libc::AT_FDCWD, path.as_ptr(), std::ptr::null(), 0);
        }
    }

    fn statx(path: &str, flags: i32) {
        let path = cstr(path);
        let mut buf = [0_u8; 256];
        // SAFETY: `path` is NUL-terminated. `buf` is 256 bytes, which covers
        // the kernel `statx` buffer. The kernel does not retain either pointer.
        // The buffer is discarded and is not an observed event.
        unsafe {
            libc::syscall(
                libc::SYS_statx,
                libc::AT_FDCWD,
                path.as_ptr(),
                flags,
                libc::STATX_BASIC_STATS,
                buf.as_mut_ptr(),
            );
        }
    }

    fn faccessat2(path: &str) {
        let path = cstr(path);
        // SAFETY: `path` is NUL-terminated and lives for the call. `faccessat2`
        // does not retain it and does not write file bytes.
        unsafe {
            libc::syscall(
                libc::SYS_faccessat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::R_OK,
                0,
            );
        }
    }

    fn mknod(path: &str) {
        let path = cstr(path);
        // SAFETY: `path` is NUL-terminated. The mode is a fifo, not a device
        // node, so this does not require extra capability. The pointer is not retained.
        unsafe {
            libc::mknod(path.as_ptr(), fifo_mode(), 0);
        }
    }

    fn mknodat(dir: &str, name: &str) {
        let fd = open_dir(dir);
        let name = cstr(name);
        // SAFETY: `fd` is a directory descriptor from `open` and `name` is
        // NUL-terminated. Both live for the call and are not retained.
        unsafe {
            libc::mknodat(fd, name.as_ptr(), fifo_mode(), 0);
        }
        close_fd(fd);
    }

    fn lchown(path: &str) {
        let path = cstr(path);
        // SAFETY: `path` is NUL-terminated. The ids are this process's own
        // uid and gid. `lchown` does not follow a symlink and does not retain
        // the pointer.
        unsafe {
            libc::lchown(path.as_ptr(), libc::getuid(), libc::getgid());
        }
    }

    fn openat2(dirfd: i32, path: &str, resolve: u64) {
        let path = cstr(path);
        let how = OpenHow {
            flags: libc::O_RDONLY as u64,
            mode: 0,
            resolve,
        };
        // SAFETY: `path` is NUL-terminated and `how` lives for the call. The
        // size is the three published `open_how` fields. The kernel copies
        // both before returning and does not retain the pointers.
        unsafe {
            libc::syscall(
                libc::SYS_openat2,
                dirfd,
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            );
        }
    }

    fn thread_self() {
        let worker = thread::spawn(|| {
            open_path("/proc/thread-self/drifti-kan49-missing", libc::O_RDONLY);
        });
        worker.join().unwrap_or_else(|_| exit(1));
    }

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    fn fifo_mode() -> libc::mode_t {
        libc::S_IFIFO | 0o600 as libc::mode_t
    }
}
