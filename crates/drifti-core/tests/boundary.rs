// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Architecture boundary for `drifti-core`.
//!
//! The token scan covers library sources, the build script, examples,
//! benches, and files named by `include!` or `#[path]`. `include!` accepts
//! `(`, `{`, or `[`. Whitespace and comments may sit between the token and
//! that delimiter, or around `=`. A referenced file is scanned even when its
//! name does not end in `.rs`. A value that is not a plain string, or an
//! unclosed comment in that position, fails the scan. `tests/` is not
//! scanned: this harness has to name the forbidden tokens in order to reject
//! them.
//!
//! The manifest scan reads normal, dev, and build dependency tables,
//! including inline and target-specific tables.
//!
//! Both checks are text scans. They do not parse Rust or TOML.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use proptest::prelude::*;
use proptest::test_runner::{TestRng, TestRunner};

const FORBIDDEN_SOURCE_TOKENS: &[&str] = &[
    "pid_t",
    "ptrace",
    "SYS_openat",
    "sockaddr_in",
    "std::os::",
    "/proc",
];

const FORBIDDEN_DEPENDENCIES: &[&str] = &[
    "clap",
    "libc",
    "libsqlite3-sys",
    "linux-raw-sys",
    "nix",
    "rusqlite",
    "sqlx",
];

const ALLOWED_DEPENDENCIES: &[&str] = &["serde"];
const ALLOWED_DEV_DEPENDENCIES: &[&str] = &["proptest", "serde_json"];

const LICENSE_HEADER: &str = "\
// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0
";

fn crate_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_manifest() -> PathBuf {
    crate_dir().join("../../Cargo.toml")
}

fn tokens_in(source: &str) -> Vec<&'static str> {
    FORBIDDEN_SOURCE_TOKENS
        .iter()
        .copied()
        .filter(|token| source.contains(token))
        .collect()
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = fs::read_dir(&current).unwrap_or_else(|error| {
            panic!("read {}: {error}", current.display());
        });
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!("read entry under {}: {error}", current.display());
            });
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DepClass {
    Normal,
    Dev,
    Build,
}

struct ManifestDeps {
    normal: BTreeSet<String>,
    dev: BTreeSet<String>,
    build: BTreeSet<String>,
}

impl ManifestDeps {
    fn new() -> Self {
        Self {
            normal: BTreeSet::new(),
            dev: BTreeSet::new(),
            build: BTreeSet::new(),
        }
    }

    fn set_mut(&mut self, class: DepClass) -> &mut BTreeSet<String> {
        match class {
            DepClass::Normal => &mut self.normal,
            DepClass::Dev => &mut self.dev,
            DepClass::Build => &mut self.build,
        }
    }
}

enum Inclusion {
    Dynamic,
    Literal(String),
}

struct TempTree(PathBuf);

impl TempTree {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("drifti-boundary-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
        Self(path)
    }
}

impl Drop for TempTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn manifest_deps(manifest: &str) -> ManifestDeps {
    let mut deps = ManifestDeps::new();
    let mut current: Option<DepClass> = None;
    let mut inline_name: Option<String> = None;
    let mut inline_package: Option<String> = None;

    let flush_inline = |deps: &mut ManifestDeps,
                        current: &mut Option<DepClass>,
                        inline_name: &mut Option<String>,
                        inline_package: &mut Option<String>| {
        if let (Some(class), Some(name)) = (*current, inline_name.take()) {
            let package = inline_package.take().unwrap_or(name);
            deps.set_mut(class).insert(package);
        } else {
            inline_package.take();
        }
        *current = None;
    };

    for line in manifest.lines() {
        let trimmed = strip_toml_comment(line).trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(header) = table_header(&trimmed) {
            flush_inline(
                &mut deps,
                &mut current,
                &mut inline_name,
                &mut inline_package,
            );
            if let Some((class, name)) = classify_table(&header) {
                current = Some(class);
                inline_name = name;
            }
            continue;
        }
        let Some(class) = current else {
            continue;
        };
        if inline_name.is_some() {
            if let Some(package) = package_field(&trimmed) {
                inline_package = Some(package);
            }
            continue;
        }
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            if key.is_empty() {
                continue;
            }
            let name = package_field(value).unwrap_or_else(|| key.to_string());
            deps.set_mut(class).insert(name);
        }
    }
    flush_inline(
        &mut deps,
        &mut current,
        &mut inline_name,
        &mut inline_package,
    );
    deps
}

fn table_header(trimmed: &str) -> Option<String> {
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?;
    Some(inner.trim().to_string())
}

fn classify_table(header: &str) -> Option<(DepClass, Option<String>)> {
    let parts = split_dotted(header);
    let mut found = None;
    for (index, part) in parts.iter().enumerate() {
        let class = match part.as_str() {
            "dependencies" => DepClass::Normal,
            "dev-dependencies" => DepClass::Dev,
            "build-dependencies" => DepClass::Build,
            _ => continue,
        };
        let inline = parts.get(index + 1).map(|name| unquote(name).to_string());
        found = Some((class, inline));
    }
    found
}

fn split_dotted(header: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for ch in header.chars() {
        if let Some(open) = quote {
            current.push(ch);
            if ch == open {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                current.push(ch);
            }
            '.' => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

fn unquote(value: &str) -> &str {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return value;
    };
    let Some(last) = chars.next_back() else {
        return value;
    };
    if (first == '"' || first == '\'') && first == last {
        &value[first.len_utf8()..value.len() - last.len_utf8()]
    } else {
        value
    }
}

fn package_field(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let marker = b"package";
    let mut index = 0;
    while index + marker.len() <= bytes.len() {
        if &bytes[index..index + marker.len()] == marker {
            let before_ok = index == 0 || !is_ident_byte(bytes[index - 1]);
            let after = index + marker.len();
            let after_ok = after == bytes.len() || !is_ident_byte(bytes[after]);
            if before_ok && after_ok {
                let rest = value[after..].trim_start();
                if let Some(rest) = rest.strip_prefix('=') {
                    return quoted_string(rest.trim_start());
                }
            }
        }
        index += 1;
    }
    None
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn quoted_string(input: &str) -> Option<String> {
    let mut chars = input.chars();
    let quote = chars.next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut value = String::new();
    for ch in chars {
        if ch == quote {
            return Some(value);
        }
        value.push(ch);
    }
    None
}

fn strip_toml_comment(line: &str) -> String {
    let mut kept = String::new();
    let mut quote = None;
    for ch in line.chars() {
        if let Some(open) = quote {
            kept.push(ch);
            if ch == open {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                kept.push(ch);
            }
            '#' => break,
            _ => kept.push(ch),
        }
    }
    kept
}

fn rust_inclusions(source: &str) -> Vec<Inclusion> {
    let chars: Vec<char> = source.chars().collect();
    let mut found = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if starts_with_token(&chars, index, "include!") {
            let after_token = index + "include!".chars().count();
            let cursor = match skip_trivia(&chars, after_token) {
                Ok(cursor) => cursor,
                Err(()) => {
                    found.push(Inclusion::Dynamic);
                    index += 1;
                    continue;
                }
            };
            if cursor < chars.len() && matches!(chars[cursor], '(' | '{' | '[') {
                let cursor = match skip_trivia(&chars, cursor + 1) {
                    Ok(cursor) => cursor,
                    Err(()) => {
                        found.push(Inclusion::Dynamic);
                        index += 1;
                        continue;
                    }
                };
                found.push(inclusion_at(&chars, cursor));
            }
            index += 1;
            continue;
        }
        if starts_with_token(&chars, index, "path") {
            let after_token = index + "path".chars().count();
            let cursor = match skip_trivia(&chars, after_token) {
                Ok(cursor) => cursor,
                Err(()) => {
                    found.push(Inclusion::Dynamic);
                    index += 1;
                    continue;
                }
            };
            if cursor < chars.len() && chars[cursor] == '=' {
                let cursor = match skip_trivia(&chars, cursor + 1) {
                    Ok(cursor) => cursor,
                    Err(()) => {
                        found.push(Inclusion::Dynamic);
                        index += 1;
                        continue;
                    }
                };
                found.push(inclusion_at(&chars, cursor));
            }
        }
        index += 1;
    }
    found
}

fn starts_with_token(chars: &[char], index: usize, token: &str) -> bool {
    let token: Vec<char> = token.chars().collect();
    let end = index + token.len();
    if end > chars.len() || chars[index..end] != token[..] {
        return false;
    }
    let before_ok = index == 0 || !is_ident_char(chars[index - 1]);
    let after_ok = end == chars.len() || !is_ident_char(chars[end]);
    before_ok && after_ok
}

fn is_ident_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '_'
}

fn skip_trivia(chars: &[char], mut index: usize) -> Result<usize, ()> {
    loop {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index + 1 < chars.len() && chars[index] == '/' && chars[index + 1] == '/' {
            index += 2;
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        if index + 1 < chars.len() && chars[index] == '/' && chars[index + 1] == '*' {
            index += 2;
            let mut closed = false;
            while index + 1 < chars.len() {
                if chars[index] == '*' && chars[index + 1] == '/' {
                    index += 2;
                    closed = true;
                    break;
                }
                index += 1;
            }
            if !closed {
                return Err(());
            }
            continue;
        }
        if index < chars.len() && chars[index] == '/' {
            return Err(());
        }
        return Ok(index);
    }
}

fn inclusion_at(chars: &[char], index: usize) -> Inclusion {
    let tail: String = chars[index..].iter().collect();
    match parse_rust_string(&tail) {
        Some(path) => Inclusion::Literal(path),
        None => Inclusion::Dynamic,
    }
}

fn parse_rust_string(input: &str) -> Option<String> {
    let mut chars = input.chars();
    if chars.next() != Some('"') {
        return None;
    }
    let mut value = String::new();
    let mut escaped = false;
    for ch in chars {
        if escaped {
            value.push(match ch {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '\\' => '\\',
                '"' => '"',
                other => other,
            });
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' => return Some(value),
            other => value.push(other),
        }
    }
    None
}

fn normalize_lexically(base: &Path, relative: &str) -> PathBuf {
    let joined = if Path::new(relative).is_absolute() {
        PathBuf::from(relative)
    } else {
        base.join(relative)
    };
    let mut normal = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::ParentDir => {
                normal.pop();
            }
            Component::CurDir => {}
            Component::Prefix(prefix) => normal.push(prefix.as_os_str()),
            Component::RootDir => normal.push(component.as_os_str()),
            Component::Normal(part) => normal.push(part),
        }
    }
    normal
}

fn reference_escapes(file: &Path, source: &str, crate_root: &Path) -> bool {
    let Some(parent) = file.parent() else {
        return true;
    };
    rust_inclusions(source)
        .iter()
        .any(|inclusion| match inclusion {
            Inclusion::Dynamic => true,
            Inclusion::Literal(relative) => {
                !normalize_lexically(parent, relative).starts_with(crate_root)
            }
        })
}

fn scanned_library_files(crate_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let crate_root = fs::canonicalize(crate_dir)
        .map_err(|error| format!("canonicalize {}: {error}", crate_dir.display()))?;
    let mut pending: Vec<Pending> = library_roots(&crate_root)
        .into_iter()
        .map(Pending::Discovered)
        .collect();
    let mut scanned = Vec::new();
    let mut seen = BTreeSet::new();

    while let Some(current) = pending.pop() {
        let (path, included) = match current {
            Pending::Discovered(path) => (path, false),
            Pending::Included(path) => (path, true),
        };
        if path.is_dir() {
            let entries =
                fs::read_dir(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
            for entry in entries {
                let entry = entry
                    .map_err(|error| format!("read entry under {}: {error}", path.display()))?;
                pending.push(Pending::Discovered(entry.path()));
            }
            continue;
        }
        if !included && path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        if !path.is_file() {
            return Err(format!(
                "{} references missing {}",
                crate_root.display(),
                path.display()
            ));
        }
        let canonical = fs::canonicalize(&path)
            .map_err(|error| format!("canonicalize {}: {error}", path.display()))?;
        if !canonical.starts_with(&crate_root) {
            return Err(format!("{} resolves outside the crate", path.display()));
        }
        if !seen.insert(canonical.clone()) {
            continue;
        }
        let source = fs::read_to_string(&canonical)
            .map_err(|error| format!("read {}: {error}", canonical.display()))?;
        let parent = canonical
            .parent()
            .ok_or_else(|| format!("{} has no parent", canonical.display()))?;
        for inclusion in rust_inclusions(&source) {
            match inclusion {
                Inclusion::Dynamic => {
                    return Err(format!(
                        "{} has a dynamic include! or path attribute",
                        canonical.display()
                    ));
                }
                Inclusion::Literal(relative) => {
                    let resolved = normalize_lexically(parent, &relative);
                    if !resolved.starts_with(&crate_root) {
                        return Err(format!(
                            "{} references {} outside the crate",
                            canonical.display(),
                            resolved.display()
                        ));
                    }
                    pending.push(Pending::Included(resolved));
                }
            }
        }
        scanned.push(canonical);
    }

    scanned.sort();
    Ok(scanned)
}

enum Pending {
    Discovered(PathBuf),
    Included(PathBuf),
}

fn library_roots(crate_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let src = crate_root.join("src");
    if src.is_dir() {
        roots.push(src);
    }
    let build_rs = crate_root.join("build.rs");
    if build_rs.is_file() {
        roots.push(build_rs);
    }
    for name in ["examples", "benches"] {
        let path = crate_root.join(name);
        if path.is_dir() {
            roots.push(path);
        }
    }
    roots
}

fn direct_lock_deps(lockfile: &str, package: &str) -> Result<BTreeSet<String>, String> {
    let needle = format!("name = \"{package}\"");
    let start = lockfile
        .find(&needle)
        .ok_or_else(|| format!("lockfile has no {package}"))?;
    let after = &lockfile[start + needle.len()..];
    let region = match after.find("\n[[package]]") {
        Some(end) => &after[..end],
        None => after,
    };
    let Some(deps_at) = region.find("dependencies = [") else {
        return Ok(BTreeSet::new());
    };
    let list = &region[deps_at + "dependencies = [".len()..];
    let list = &list[..list.find(']').ok_or("unterminated dependency list")?];
    let mut names = BTreeSet::new();
    for line in list.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        let Some(quoted) = quoted_string(trimmed) else {
            continue;
        };
        let name = quoted.split_whitespace().next().unwrap_or(quoted.as_str());
        names.insert(name.to_string());
    }
    Ok(names)
}

fn deterministic_runner() -> TestRunner {
    let config = ProptestConfig {
        cases: 64,
        failure_persistence: None,
        ..ProptestConfig::default()
    };
    let algorithm = config.rng_algorithm;
    TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm))
}

fn short_alnum(max_len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::range('a', 'z'), 0..=max_len)
        .prop_map(|chars| chars.into_iter().collect())
}

fn short_digits(max_len: usize) -> impl Strategy<Value = String> {
    proptest::collection::vec(proptest::char::range('0', '9'), 0..=max_len)
        .prop_map(|chars| chars.into_iter().collect())
}

#[test]
fn library_sources_do_not_contain_forbidden_tokens() {
    let sources = scanned_library_files(crate_dir()).expect("scan library sources");
    assert!(
        sources.iter().any(|path| path.ends_with("src/lib.rs")),
        "library scan missed src/lib.rs"
    );
    assert!(
        sources.iter().all(|path| !path
            .components()
            .any(|component| component.as_os_str() == "tests")),
        "library scan included the test harness"
    );
    for path in sources {
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        let found = tokens_in(&source);
        assert!(
            found.is_empty(),
            "{} contains forbidden tokens: {}",
            path.display(),
            found.join(", ")
        );
    }
}

#[test]
fn included_file_without_rs_extension_is_scanned() {
    let tree = TempTree::new("include-inc");
    fs::create_dir_all(tree.0.join("src")).expect("create src");
    fs::write(tree.0.join("src/lib.rs"), "include!{\"hidden.inc\"}\n").expect("write lib");
    fs::write(
        tree.0.join("src/hidden.inc"),
        "const MARKER: &str = \"ptrace\";\n",
    )
    .expect("write hidden");
    let sources = scanned_library_files(&tree.0).expect("scan included file");
    let hidden = sources
        .iter()
        .find(|path| path.ends_with("hidden.inc"))
        .expect("included file is part of the scan");
    let source = fs::read_to_string(hidden).expect("read hidden");
    assert!(tokens_in(&source).contains(&"ptrace"));
}

#[test]
fn included_file_is_scanned_for_forbidden_tokens() {
    let tree = TempTree::new("include");
    fs::create_dir_all(tree.0.join("src")).expect("create src");
    fs::write(tree.0.join("src/lib.rs"), "include!(\"hidden.rs\");\n").expect("write lib");
    fs::write(
        tree.0.join("src/hidden.rs"),
        "const MARKER: &str = \"ptrace\";\n",
    )
    .expect("write hidden");
    let sources = scanned_library_files(&tree.0).expect("scan included file");
    let hidden = sources
        .iter()
        .find(|path| path.ends_with("hidden.rs"))
        .expect("included file is part of the scan");
    let source = fs::read_to_string(hidden).expect("read hidden");
    assert!(tokens_in(&source).contains(&"ptrace"));
}

#[test]
fn examples_are_part_of_the_library_scan() {
    let tree = TempTree::new("examples");
    fs::create_dir_all(tree.0.join("src")).expect("create src");
    fs::create_dir_all(tree.0.join("examples")).expect("create examples");
    fs::write(tree.0.join("src/lib.rs"), "\n").expect("write lib");
    fs::write(
        tree.0.join("examples/demo.rs"),
        "const MARKER: &str = \"ptrace\";\n",
    )
    .expect("write example");
    let sources = scanned_library_files(&tree.0).expect("scan examples");
    assert!(sources
        .iter()
        .any(|path| path.ends_with("examples/demo.rs")));
}

#[test]
fn build_script_is_part_of_the_library_scan() {
    let tree = TempTree::new("build-script");
    fs::create_dir_all(tree.0.join("src")).expect("create src");
    fs::write(tree.0.join("src/lib.rs"), "\n").expect("write lib");
    fs::write(
        tree.0.join("build.rs"),
        "const MARKER: &str = \"ptrace\";\n",
    )
    .expect("write build");
    let sources = scanned_library_files(&tree.0).expect("scan build script");
    assert!(sources.iter().any(|path| path.ends_with("build.rs")));
}

#[test]
fn include_outside_the_crate_is_rejected() {
    let crate_root = Path::new("/work/drifti-core");
    let file = crate_root.join("src/lib.rs");
    assert!(reference_escapes(
        &file,
        "include!(\"../../outside.rs\");\n",
        crate_root
    ));
    assert!(reference_escapes(
        &file,
        "#[path = \"../../secret.rs\"]\nmod secret;\n",
        crate_root
    ));
    assert!(reference_escapes(
        &file,
        "include!(concat!(\"generated.rs\"));\n",
        crate_root
    ));
    assert!(reference_escapes(
        &file,
        "include!{\"../../outside.rs\"}\n",
        crate_root
    ));
    assert!(reference_escapes(
        &file,
        "include! (\"../../outside.rs\");\n",
        crate_root
    ));
    assert!(reference_escapes(
        &file,
        "include! /* note */ {\"../../outside.rs\"}\n",
        crate_root
    ));
    assert!(reference_escapes(
        &file,
        "#[path /* note */ = \"../../secret.rs\"]\nmod secret;\n",
        crate_root
    ));
    assert!(reference_escapes(
        &file,
        "include! // note\n(\"../../outside.rs\");\n",
        crate_root
    ));
    assert!(reference_escapes(
        &file,
        "#[path\n= \"../../secret.rs\"]\nmod secret;\n",
        crate_root
    ));
    assert!(!reference_escapes(
        &file,
        "include!{\"hidden.inc\"}\n",
        crate_root
    ));
}

#[test]
fn rust_files_carry_the_license_header() {
    for dir in ["src", "tests"] {
        for path in rust_sources(&crate_dir().join(dir)) {
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            assert!(
                source.starts_with(LICENSE_HEADER),
                "{} is missing the license header",
                path.display()
            );
        }
    }
}

#[test]
fn dependencies_stay_inside_the_domain_boundary() {
    let manifest = fs::read_to_string(crate_dir().join("Cargo.toml")).expect("read crate manifest");
    let deps = manifest_deps(&manifest);
    assert_eq!(
        deps.normal.iter().map(String::as_str).collect::<Vec<_>>(),
        ALLOWED_DEPENDENCIES
    );
    assert_eq!(
        deps.dev.iter().map(String::as_str).collect::<Vec<_>>(),
        ALLOWED_DEV_DEPENDENCIES
    );
    assert!(
        deps.build.is_empty(),
        "build-dependencies: {:?}",
        deps.build
    );

    let workspace = fs::read_to_string(workspace_manifest()).expect("read workspace manifest");
    let workspace_deps = manifest_deps(&workspace);
    assert!(workspace_deps.normal.is_empty());
    assert!(workspace_deps.dev.is_empty());
    assert!(workspace_deps.build.is_empty());

    let lockfile = fs::read_to_string(crate_dir().join("../../Cargo.lock")).expect("read lockfile");
    let direct = direct_lock_deps(&lockfile, "drifti-core").expect("drifti-core lock entry");
    assert_eq!(
        direct.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["proptest", "serde", "serde_json"]
    );

    for name in deps
        .normal
        .iter()
        .chain(deps.dev.iter())
        .chain(deps.build.iter())
        .chain(direct.iter())
    {
        assert!(
            !FORBIDDEN_DEPENDENCIES.contains(&name.as_str()),
            "{name} crosses the drifti-core boundary"
        );
    }
}

#[test]
fn workspace_contains_only_drifti_core() {
    let manifest = fs::read_to_string(workspace_manifest()).expect("read workspace manifest");
    assert!(manifest.contains("members = [\"crates/drifti-core\"]"));
    for member in [
        "drifti-observer",
        "drifti-observer-linux",
        "drifti-store",
        "drifti-cli",
    ] {
        assert!(
            !manifest.contains(member),
            "workspace manifest names {member} before that crate is initialized"
        );
    }
}

#[test]
fn scanner_reports_a_forbidden_token() {
    let found = tokens_in("fn attach() { let _request = \"ptrace\"; }");
    assert_eq!(found, vec!["ptrace"]);
}

#[test]
fn scanner_accepts_a_clean_source() {
    assert!(tokens_in("const VALUE: u32 = 1;\n").is_empty());
}

#[test]
fn manifest_parser_sees_hidden_dependency_tables() {
    let manifest = "\
[dependencies.serde]
version = \"1\"

[dependencies.renamed]
package = \"nix\"

[target.'cfg(unix)'.dependencies]
libc = \"0.2\"

[build-dependencies]
cc = \"1\"

[target.\"cfg(windows)\".dev-dependencies]
proptest = \"1\"
";
    let deps = manifest_deps(manifest);
    assert!(deps.normal.contains("serde"));
    assert!(deps.normal.contains("nix"));
    assert!(deps.normal.contains("libc"));
    assert!(deps.build.contains("cc"));
    assert!(deps.dev.contains("proptest"));
    assert!(deps
        .normal
        .iter()
        .any(|name| FORBIDDEN_DEPENDENCIES.contains(&name.as_str())));
}

#[test]
fn source_scan_reports_every_present_token() {
    let mut runner = deterministic_runner();
    let strategy = (short_alnum(16), short_alnum(16));
    runner
        .run(&strategy, |(prefix, suffix)| {
            let source = format!("{prefix}pid_t{suffix}");
            let found = tokens_in(&source);
            prop_assert!(found.contains(&"pid_t"));
            prop_assert_eq!(found.clone(), tokens_in(&source));
            Ok(())
        })
        .expect("forbidden token scan");
}

#[test]
fn digit_sources_have_no_forbidden_tokens() {
    let mut runner = deterministic_runner();
    runner
        .run(&short_digits(32), |body| {
            let source = format!("const VALUE: u32 = {body};\n");
            prop_assert!(tokens_in(&source).is_empty());
            Ok(())
        })
        .expect("clean digit source");
}
