// Copyright 2026 Luca Becci
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Write one version-1 contract as stable YAML.
//!
//! Section order is [`SECTION_ORDER`]: `version`, `filesystem`, `process`,
//! then `network`. Inside a section, actions stay in model order. Effects
//! follow [`EFFECT_ORDER`]: `allow`, then `deny`. Resource lines are sorted
//! by authoring text. Empty sections, actions, and effect lists are omitted.
//! Indentation is two spaces. The text has no anchors, aliases, or tags.
//!
//! The in-memory document keeps the order it was given. Only the written
//! text is sorted. Writing does not accept the document as authority.

use super::{
    AllowDenyRules, AuthoringResource, ContractDocument, FilesystemContract, NetworkContract,
    ProcessContract, CONNECT_KEY, EFFECT_ORDER, EXECUTE_KEY, FILESYSTEM_KEY, LISTEN_KEY,
    NETWORK_KEY, PROCESS_KEY, READ_KEY, WRITE_KEY,
};

/// Writes a version-1 contract as stable YAML.
///
/// Two documents that name the same resources produce the same bytes, even
/// when those resources were supplied in different orders. The result is text
/// only. It is not an accepted contract.
#[must_use]
pub fn serialize_contract(document: &ContractDocument) -> String {
    let mut out = String::new();
    out.push_str("version: ");
    out.push_str(&document.version().get().to_string());
    out.push('\n');
    write_filesystem(&mut out, document.filesystem());
    write_process(&mut out, document.process());
    write_network(&mut out, document.network());
    out
}

fn write_filesystem(out: &mut String, section: &FilesystemContract) {
    if !has_rules(section.read()) && !has_rules(section.write()) {
        return;
    }
    write_header(out, FILESYSTEM_KEY);
    write_action(out, READ_KEY, section.read());
    write_action(out, WRITE_KEY, section.write());
}

fn write_process(out: &mut String, section: &ProcessContract) {
    if !has_rules(section.execute()) {
        return;
    }
    write_header(out, PROCESS_KEY);
    write_action(out, EXECUTE_KEY, section.execute());
}

fn write_network(out: &mut String, section: &NetworkContract) {
    if !has_rules(section.connect()) && !has_rules(section.listen()) {
        return;
    }
    write_header(out, NETWORK_KEY);
    write_action(out, CONNECT_KEY, section.connect());
    write_action(out, LISTEN_KEY, section.listen());
}

fn write_header(out: &mut String, key: &str) {
    out.push('\n');
    out.push_str(key);
    out.push_str(":\n");
}

fn write_action(out: &mut String, key: &str, rules: &AllowDenyRules) {
    if !has_rules(rules) {
        return;
    }
    out.push_str("  ");
    out.push_str(key);
    out.push_str(":\n");
    write_effect(out, EFFECT_ORDER[0], rules.allow());
    write_effect(out, EFFECT_ORDER[1], rules.deny());
}

fn write_effect(out: &mut String, key: &str, resources: &[AuthoringResource]) {
    if resources.is_empty() {
        return;
    }
    let mut texts: Vec<&str> = resources.iter().map(AuthoringResource::as_str).collect();
    texts.sort();
    out.push_str("    ");
    out.push_str(key);
    out.push_str(":\n");
    for text in texts {
        out.push_str("      - ");
        push_scalar(out, text);
        out.push('\n');
    }
}

fn has_rules(rules: &AllowDenyRules) -> bool {
    !rules.allow().is_empty() || !rules.deny().is_empty()
}

fn push_scalar(out: &mut String, text: &str) {
    if is_plain_scalar(text) {
        out.push_str(text);
        return;
    }
    out.push('"');
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if must_escape(ch) => {
                let code = u32::from(ch);
                if code <= 0xFFFF {
                    push_hex_escape(out, "\\u", code, 4);
                } else {
                    push_hex_escape(out, "\\U", code, 8);
                }
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn push_hex_escape(out: &mut String, prefix: &str, code: u32, width: usize) {
    out.push_str(prefix);
    let hex = format!("{code:0width$x}");
    out.push_str(&hex);
}

fn must_escape(ch: char) -> bool {
    ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}' | '\u{feff}')
}

fn is_plain_scalar(text: &str) -> bool {
    if text.is_empty() || text.trim() != text || is_reserved_plain(text) {
        return false;
    }
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !is_plain_start(first) || !is_plain_body(text) || colon_breaks_plain(text) {
        return false;
    }
    true
}

fn is_plain_start(ch: char) -> bool {
    !matches!(
        ch,
        '-' | '?'
            | ':'
            | ','
            | '['
            | ']'
            | '{'
            | '}'
            | '#'
            | '&'
            | '*'
            | '!'
            | '|'
            | '>'
            | '\''
            | '"'
            | '%'
            | '@'
            | '`'
    ) && !ch.is_whitespace()
        && !must_escape(ch)
}

fn is_plain_body(text: &str) -> bool {
    text.chars().all(is_plain_char)
}

fn is_plain_char(ch: char) -> bool {
    if ch == ' ' {
        return true;
    }
    ch != '#' && ch != '\\' && ch != '"' && ch != '\'' && !ch.is_whitespace() && !must_escape(ch)
}

fn colon_breaks_plain(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.iter().enumerate().any(|(index, byte)| {
        if *byte != b':' {
            return false;
        }
        match bytes.get(index + 1).copied() {
            None | Some(b' ' | b'\t') => true,
            Some(_) => false,
        }
    })
}

fn is_reserved_plain(text: &str) -> bool {
    matches!(
        text,
        "~" | "null"
            | "Null"
            | "NULL"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | "yes"
            | "Yes"
            | "YES"
            | "no"
            | "No"
            | "NO"
            | "on"
            | "On"
            | "ON"
            | "off"
            | "Off"
            | "OFF"
            | "---"
            | "..."
    ) || is_yaml_number(text)
}

fn is_yaml_number(text: &str) -> bool {
    let rest = text
        .strip_prefix('+')
        .or_else(|| text.strip_prefix('-'))
        .unwrap_or(text);
    let mut chars = rest.chars().peekable();
    if chars.peek() == Some(&'0') {
        let mut probe = chars.clone();
        probe.next();
        if matches!(probe.peek(), Some('x' | 'X' | 'o' | 'O' | 'b' | 'B')) {
            probe.next();
            let digits: Vec<char> = probe.collect();
            return !digits.is_empty() && digits.iter().all(|ch| ch.is_ascii_hexdigit());
        }
    }
    let mut seen_dot = false;
    let mut seen_exp = false;
    let mut seen_digit = false;
    while let Some(ch) = chars.next() {
        if ch.is_ascii_digit() {
            seen_digit = true;
            continue;
        }
        if ch == '.' && !seen_dot && !seen_exp {
            seen_dot = true;
            continue;
        }
        if (ch == 'e' || ch == 'E') && !seen_exp && seen_digit {
            seen_exp = true;
            if matches!(chars.peek(), Some('+' | '-')) {
                chars.next();
            }
            continue;
        }
        return false;
    }
    seen_digit
}

#[cfg(test)]
mod tests {
    use saphyr_parser::{Event, Parser};

    use super::{is_plain_scalar, serialize_contract};
    use crate::contract::{
        parse_contract, AllowDenyRules, AuthoringResource, ContractDocument, ContractVersion,
        FilesystemContract, NetworkContract, ProcessContract, ALLOW_KEY, DENY_KEY, EFFECT_ORDER,
        FILESYSTEM_KEY, NETWORK_KEY, PROCESS_KEY, SECTION_ORDER,
    };

    fn resource(text: &str) -> AuthoringResource {
        AuthoringResource::new(text).expect("resource")
    }

    fn rules(allow: &[&str], deny: &[&str]) -> AllowDenyRules {
        AllowDenyRules::new(
            allow.iter().copied().map(resource).collect(),
            deny.iter().copied().map(resource).collect(),
        )
    }

    fn document(
        read: AllowDenyRules,
        write: AllowDenyRules,
        execute: AllowDenyRules,
        connect: AllowDenyRules,
        listen: AllowDenyRules,
    ) -> ContractDocument {
        ContractDocument::new(
            ContractVersion::V1,
            FilesystemContract::new(read, write),
            ProcessContract::new(execute),
            NetworkContract::new(connect, listen),
        )
    }

    fn spec_document() -> ContractDocument {
        document(
            rules(&["./src/**"], &["~/.ssh/**"]),
            rules(&["./src/**"], &[]),
            rules(&["/usr/bin/cargo"], &[]),
            rules(&["tcp://203.0.113.0/24:443"], &[]),
            AllowDenyRules::empty(),
        )
    }

    fn spec_yaml() -> &'static str {
        "\
version: 1

filesystem:
  read:
    allow:
      - ./src/**
    deny:
      - ~/.ssh/**
  write:
    allow:
      - ./src/**

process:
  execute:
    allow:
      - /usr/bin/cargo

network:
  connect:
    allow:
      - tcp://203.0.113.0/24:443
"
    }

    fn top_level_keys(yaml: &str) -> Vec<&str> {
        yaml.lines()
            .filter(|line| !line.is_empty() && !line.starts_with(' '))
            .map(|line| line.split_once(':').map(|(key, _)| key).unwrap_or(line))
            .collect()
    }

    fn assert_section_order(yaml: &str) {
        let keys = top_level_keys(yaml);
        assert_eq!(keys.first().copied(), Some(SECTION_ORDER[0]));
        let mut cursor = 0;
        for key in &keys {
            let found = SECTION_ORDER[cursor..]
                .iter()
                .position(|section| section == key)
                .unwrap_or_else(|| panic!("section {key} is outside {SECTION_ORDER:?}"));
            cursor += found;
            cursor += 1;
        }
    }

    fn assert_allow_before_deny(yaml: &str) {
        assert_eq!(EFFECT_ORDER, [ALLOW_KEY, DENY_KEY]);
        let mut seen_deny = false;
        for line in yaml.lines() {
            let trimmed = line.trim_start();
            let indent = line.len() - trimmed.len();
            if indent == 2 && trimmed.ends_with(':') {
                seen_deny = false;
            }
            if trimmed == "allow:" {
                assert!(!seen_deny, "deny preceded allow");
            }
            if trimmed == "deny:" {
                seen_deny = true;
            }
        }
    }

    fn assert_two_space_indent(yaml: &str) {
        assert!(yaml.ends_with('\n'));
        assert!(!yaml.contains('\t'));
        assert!(!yaml.contains("\n\n\n"));
        for line in yaml.lines() {
            if line.is_empty() {
                continue;
            }
            let width = line.chars().take_while(|ch| *ch == ' ').count();
            assert_eq!(width % 2, 0, "{line}");
            assert!(width <= 6, "{line}");
            let body = &line[width..];
            match width {
                0 => assert!(
                    body.starts_with("version:")
                        || body == "filesystem:"
                        || body == "process:"
                        || body == "network:"
                ),
                2 => assert!(body.ends_with(':') && !body.starts_with('-')),
                4 => assert!(body == "allow:" || body == "deny:"),
                6 => assert!(body.starts_with("- ")),
                _ => panic!("unexpected indent {width} on {line}"),
            }
        }
    }

    fn assert_no_yaml_features(yaml: &str) {
        let mut parser = Parser::new_from_str(yaml);
        while let Some(event) = parser.next_event() {
            let (event, _) = event.expect("yaml event");
            match event {
                Event::Alias(_) => panic!("serialized YAML contains an alias"),
                Event::Scalar(_, _, anchor, tag) => {
                    assert_eq!(anchor, 0, "serialized YAML contains an anchor");
                    assert!(tag.is_none(), "serialized YAML contains a tag");
                }
                Event::SequenceStart(anchor, tag) | Event::MappingStart(anchor, tag) => {
                    assert_eq!(anchor, 0, "serialized YAML contains an anchor");
                    assert!(tag.is_none(), "serialized YAML contains a tag");
                }
                Event::StreamEnd => break,
                _ => {}
            }
        }
        assert!(parse_contract(yaml).is_ok());
    }

    fn listed(rules: &AllowDenyRules) -> (Vec<&str>, Vec<&str>) {
        (
            rules
                .allow()
                .iter()
                .map(AuthoringResource::as_str)
                .collect(),
            rules.deny().iter().map(AuthoringResource::as_str).collect(),
        )
    }

    #[test]
    fn spec_example_uses_section_order_and_two_space_indent() {
        let yaml = serialize_contract(&spec_document());
        assert_eq!(yaml, spec_yaml());
        assert_eq!(
            top_level_keys(&yaml),
            [SECTION_ORDER[0], FILESYSTEM_KEY, PROCESS_KEY, NETWORK_KEY]
        );
        assert_section_order(&yaml);
        assert_allow_before_deny(&yaml);
        assert_two_space_indent(&yaml);
        assert_no_yaml_features(&yaml);
        assert!(!yaml.contains('&'));
        assert!(!yaml.contains('!'));
        assert!(!yaml.contains("---"));
        assert!(!yaml.contains("[]"));
        assert!(!yaml.contains("{}"));
    }

    #[test]
    fn resource_order_is_deterministic_and_keeps_duplicates() {
        let shuffled = document(
            rules(&["./b", "./a", "./a"], &["./d", "./c"]),
            rules(&[], &["./z", "./m"]),
            rules(&["/usr/bin/git", "/usr/bin/cargo"], &[]),
            rules(&["tcp://10.0.0.2:443", "tcp://10.0.0.1:80"], &[]),
            rules(
                &["tcp://0.0.0.0:22", "tcp://0.0.0.0:443"],
                &["udp://127.0.0.1:9"],
            ),
        );
        let sorted = document(
            rules(&["./a", "./a", "./b"], &["./c", "./d"]),
            rules(&[], &["./m", "./z"]),
            rules(&["/usr/bin/cargo", "/usr/bin/git"], &[]),
            rules(&["tcp://10.0.0.1:80", "tcp://10.0.0.2:443"], &[]),
            rules(
                &["tcp://0.0.0.0:443", "tcp://0.0.0.0:22"],
                &["udp://127.0.0.1:9"],
            ),
        );
        let yaml = serialize_contract(&shuffled);
        assert_eq!(yaml, serialize_contract(&sorted));
        assert_ne!(shuffled, sorted);
        assert_section_order(&yaml);
        assert_allow_before_deny(&yaml);
        assert_two_space_indent(&yaml);
        assert_no_yaml_features(&yaml);

        let expected = "\
version: 1

filesystem:
  read:
    allow:
      - ./a
      - ./a
      - ./b
    deny:
      - ./c
      - ./d
  write:
    deny:
      - ./m
      - ./z

process:
  execute:
    allow:
      - /usr/bin/cargo
      - /usr/bin/git

network:
  connect:
    allow:
      - tcp://10.0.0.1:80
      - tcp://10.0.0.2:443
  listen:
    allow:
      - tcp://0.0.0.0:22
      - tcp://0.0.0.0:443
    deny:
      - udp://127.0.0.1:9
";
        assert_eq!(yaml, expected);
        let parsed = parse_contract(&yaml).expect("round trip");
        assert_eq!(
            listed(parsed.filesystem().read()),
            (vec!["./a", "./a", "./b"], vec!["./c", "./d"])
        );
        assert_eq!(
            listed(parsed.filesystem().write()),
            (Vec::<&str>::new(), vec!["./m", "./z"])
        );
        assert!(parsed.process().execute().deny().is_empty());
        assert_eq!(
            listed(parsed.network().listen()),
            (
                vec!["tcp://0.0.0.0:22", "tcp://0.0.0.0:443"],
                vec!["udp://127.0.0.1:9"]
            )
        );
    }

    #[test]
    fn equivalent_documents_serialize_to_the_same_bytes() {
        let first = parse_contract(
            "\
version: 1
network:
  listen:
    deny:
      - tcp://0.0.0.0:22
      - tcp://127.0.0.1:80
filesystem:
  write:
    allow:
      - ./z
      - ./a
",
        )
        .expect("first");
        let second = parse_contract(
            "\
version: 1

filesystem:
  write:
    allow:
      - ./a
      - ./z
network:
  listen:
    deny:
      - tcp://127.0.0.1:80
      - tcp://0.0.0.0:22
",
        )
        .expect("second");
        assert_ne!(first, second);
        let yaml = serialize_contract(&first);
        assert_eq!(yaml, serialize_contract(&second));
        let again = parse_contract(&yaml).expect("stable");
        assert_eq!(
            again,
            parse_contract(&serialize_contract(&again)).expect("stable again")
        );
        assert_eq!(
            top_level_keys(&yaml),
            [SECTION_ORDER[0], FILESYSTEM_KEY, NETWORK_KEY]
        );
        assert_section_order(&yaml);
        assert_two_space_indent(&yaml);
        assert_no_yaml_features(&yaml);
    }

    #[test]
    fn empty_document_is_only_the_version() {
        let empty = document(
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
        );
        let yaml = serialize_contract(&empty);
        assert_eq!(yaml, "version: 1\n");
        assert_eq!(top_level_keys(&yaml), [SECTION_ORDER[0]]);
        assert_two_space_indent(&yaml);
        assert_no_yaml_features(&yaml);
        assert_eq!(parse_contract(&yaml).expect("empty"), empty);
    }

    #[test]
    fn quoted_resources_hide_anchors_aliases_and_tags() {
        let awkward = [
            "*alias",
            "&anchor",
            "!!int",
            "!local",
            "yes",
            "true",
            "null",
            "~",
            "---",
            "...",
            "1",
            "0x10",
            "has: space",
            "hash # comment",
            "  padded  ",
            "quote\"here",
            "line\nbreak",
            "tab\there",
            "back\\slash",
            ":colon",
            "star*inside",
        ];
        assert!(is_plain_scalar("./src/**"));
        assert!(is_plain_scalar("~/.ssh/**"));
        assert!(is_plain_scalar("tcp://203.0.113.0/24:443"));
        assert!(is_plain_scalar("star*inside"));
        assert!(!is_plain_scalar("*alias"));
        assert!(!is_plain_scalar("&anchor"));
        assert!(!is_plain_scalar("!!int"));
        assert!(!is_plain_scalar("!local"));

        let yaml = serialize_contract(&document(
            rules(&awkward, &["./src/**"]),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
            AllowDenyRules::empty(),
        ));
        assert_two_space_indent(&yaml);
        assert_no_yaml_features(&yaml);
        assert!(yaml.contains("\n      - \"*alias\"\n"));
        assert!(yaml.contains("\n      - \"&anchor\"\n"));
        assert!(yaml.contains("\n      - \"!!int\"\n"));
        assert!(yaml.contains("\n      - \"!local\"\n"));
        assert!(yaml.contains("\n      - ./src/**\n"));
        assert!(!yaml.contains("\n      - *alias\n"));
        assert!(!yaml.contains("\n      - &anchor\n"));
        assert!(!yaml.contains("\n      - !!int\n"));
        assert!(!yaml.contains("\n      - !local\n"));

        let parsed = parse_contract(&yaml).expect("quoted round trip");
        let mut expected: Vec<&str> = awkward.to_vec();
        expected.sort_unstable();
        let allow: Vec<&str> = parsed
            .filesystem()
            .read()
            .allow()
            .iter()
            .map(AuthoringResource::as_str)
            .collect();
        assert_eq!(allow, expected);
        assert_eq!(parsed.filesystem().read().deny()[0].as_str(), "./src/**");
    }

    #[test]
    fn shuffled_resources_keep_one_serialized_form() {
        use proptest::prelude::*;
        use proptest::test_runner::{TestRng, TestRunner};

        let config = ProptestConfig {
            cases: 64,
            failure_persistence: None,
            ..ProptestConfig::default()
        };
        let algorithm = config.rng_algorithm;
        let mut runner = TestRunner::new_with_rng(config, TestRng::deterministic_rng(algorithm));
        let text = proptest::collection::vec(
            proptest::collection::vec(
                proptest::char::any().prop_filter("nul", |character| *character != '\0'),
                1..=12,
            )
            .prop_map(|chars| chars.into_iter().collect::<String>()),
            0..=6,
        );
        runner
            .run(&text, |texts| {
                let forward: Vec<&str> = texts.iter().map(String::as_str).collect();
                let mut reversed = forward.clone();
                reversed.reverse();
                let left = document(
                    rules(&forward, &reversed),
                    AllowDenyRules::empty(),
                    rules(&forward, &[]),
                    AllowDenyRules::empty(),
                    rules(&reversed, &[]),
                );
                let right = document(
                    rules(&reversed, &forward),
                    AllowDenyRules::empty(),
                    rules(&reversed, &[]),
                    AllowDenyRules::empty(),
                    rules(&forward, &[]),
                );
                let yaml = serialize_contract(&left);
                prop_assert_eq!(&yaml, &serialize_contract(&right));
                assert_section_order(&yaml);
                assert_allow_before_deny(&yaml);
                assert_two_space_indent(&yaml);
                assert_no_yaml_features(&yaml);
                let parsed = parse_contract(&yaml).expect("property round trip");
                let mut expected = forward.clone();
                expected.sort_unstable();
                let read_allow: Vec<&str> = parsed
                    .filesystem()
                    .read()
                    .allow()
                    .iter()
                    .map(AuthoringResource::as_str)
                    .collect();
                let read_deny: Vec<&str> = parsed
                    .filesystem()
                    .read()
                    .deny()
                    .iter()
                    .map(AuthoringResource::as_str)
                    .collect();
                prop_assert_eq!(read_allow, expected.clone());
                prop_assert_eq!(read_deny, expected);
                let again = serialize_contract(&parsed);
                prop_assert_eq!(again, yaml);
                Ok(())
            })
            .expect("shuffled resources");
    }
}
