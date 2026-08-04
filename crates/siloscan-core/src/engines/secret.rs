use super::{LineIndex, Occurrences, applies, capture_span};
use crate::findings::{Finding, fingerprint};
use crate::rules::{CompiledPayload, CompiledRule};

/// Run every applicable secret rule over one file's contents. Findings are
/// returned in match-offset order; the caller is responsible for the global
/// ordering across files.
pub fn scan_file(
    rules: &[CompiledRule],
    path_rel: &str,
    language: Option<&str>,
    content: &str,
) -> Vec<Finding> {
    let mut lines = LineIndex::new(content);
    let mut occurrences = Occurrences::new();
    let mut lowered: Option<String> = None;
    let mut hits: Vec<(usize, Finding)> = Vec::new();

    for rule in rules {
        if !applies(rule, path_rel, language) {
            continue;
        }

        let CompiledPayload::Secret {
            pattern,
            group,
            entropy,
            keywords,
            allow_patterns,
            allow_paths,
            stopwords,
        } = &rule.payload
        else {
            continue;
        };

        if let Some(allow_paths) = allow_paths
            && allow_paths.is_match(path_rel)
        {
            continue;
        }

        if !keywords.is_empty() {
            let lowered = lowered.get_or_insert_with(|| content.to_lowercase());
            if !keywords.iter().any(|keyword| lowered.contains(keyword)) {
                continue;
            }
        }

        // Compiled here and not before: the envelope, the allowlisted paths and
        // the keyword prefilter above reject most rules for most files, and a
        // rejected rule must not pay for its pattern. `None` means the pattern
        // is valid but too big to compile, which is nothing this engine can
        // report on, so the rule sits out.
        let Some(regex) = pattern.get() else {
            continue;
        };

        for caps in regex.captures_iter(content) {
            // A `None` span means an optional capture did not participate.
            let Some(span) = capture_span(&caps, *group) else {
                continue;
            };

            let matched = span.as_str();

            if !stopwords.is_empty() {
                let lowered_match = matched.to_lowercase();
                if stopwords.iter().any(|word| lowered_match.contains(word)) {
                    continue;
                }
            }

            if allow_patterns
                .iter()
                .filter_map(|allow| allow.get())
                .any(|allow| allow.is_match(matched))
            {
                continue;
            }

            if let Some(threshold) = entropy
                && shannon_entropy(matched) < *threshold
            {
                continue;
            }

            let occurrence = occurrences.next(rule.id.as_str(), matched);
            let (line, column) = lines.position(span.start());

            hits.push((
                span.start(),
                Finding {
                    rule_id: rule.id.clone(),
                    severity: rule.severity,
                    message: rule.message.clone(),
                    path: path_rel.to_string(),
                    line,
                    column,
                    matched: matched.to_string(),
                    fingerprint: fingerprint(&rule.id, path_rel, matched, occurrence),
                },
            ));
        }
    }

    hits.sort_by_key(|(offset, _)| *offset);
    hits.into_iter().map(|(_, finding)| finding).collect()
}

/// Shannon entropy in bits per byte over the span's byte frequency
/// distribution. Summed in fixed byte order so the result is reproducible.
fn shannon_entropy(span: &str) -> f64 {
    let bytes = span.as_bytes();
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for &count in counts.iter() {
        if count == 0 {
            continue;
        }
        let p = f64::from(count) / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Severity, load_str};

    const AWS_KEY: &str = "AKIA2E0PZXQ7VJ4NLMK3";

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    #[test]
    fn entropy_of_uniform_input_is_zero() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
        assert_eq!(shannon_entropy(""), 0.0);
        assert!((shannon_entropy("ab") - 1.0).abs() < 1e-12);
    }

    #[test]
    fn regex_rules_are_ignored() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.plain
    severity: info
    message: m
    regex:
      pattern: 'needle'
"#,
        );
        assert!(scan_file(&compiled, "f.txt", None, "needle\n").is_empty());
    }

    #[test]
    fn language_and_path_envelope_gates_the_rule() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.scoped
    severity: info
    message: m
    languages: ["rust"]
    paths:
      include: ["src/**/*.rs"]
      exclude: ["**/tests/**"]
    secret:
      pattern: 'needle'
"#,
        );
        let content = "needle\n";
        assert_eq!(
            scan_file(&compiled, "src/a.rs", Some("rust"), content).len(),
            1
        );
        assert!(scan_file(&compiled, "src/a.rs", None, content).is_empty());
        assert!(scan_file(&compiled, "docs/a.rs", Some("rust"), content).is_empty());
        assert!(scan_file(&compiled, "src/tests/a.rs", Some("rust"), content).is_empty());
    }

    #[test]
    fn allow_paths_skips_the_file() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.key
    severity: error
    message: m
    secret:
      pattern: 'needle'
      allowlist:
        paths: ["**/testdata/**"]
"#,
        );
        let content = "needle\n";
        assert_eq!(scan_file(&compiled, "src/a.rs", None, content).len(), 1);
        assert!(scan_file(&compiled, "src/testdata/a.rs", None, content).is_empty());
    }

    #[test]
    fn keywords_gate_the_regex_run() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.key
    severity: error
    message: m
    secret:
      pattern: 'needle'
      keywords: ["Haystack"]
"#,
        );
        assert!(scan_file(&compiled, "f.txt", None, "needle\n").is_empty());
        // The keyword match is case-insensitive on both sides.
        assert_eq!(
            scan_file(&compiled, "f.txt", None, "HAYSTACK\nneedle\n").len(),
            1
        );
    }

    #[test]
    fn group_narrows_the_reported_span() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.key
    severity: error
    message: m
    secret:
      pattern: 'token\s*=\s*"([^"]*)"'
      group: 1
"#,
        );
        let found = scan_file(&compiled, "cfg.py", None, "cfg = {}\ntoken = \"hunter2\"\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "hunter2");
        assert_eq!((found[0].line, found[0].column), (2, 10));
    }

    #[test]
    fn stopwords_skip_the_match() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.key
    severity: error
    message: m
    secret:
      pattern: 'token-[a-z]+'
      allowlist:
        stopwords: ["Example"]
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "token-example\ntoken-real\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "token-real");
    }

    #[test]
    fn allow_patterns_skip_the_match() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.key
    severity: error
    message: m
    secret:
      pattern: 'token-[A-Za-z]+'
      allowlist:
        patterns: ["TEST$"]
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "token-TEST\ntoken-Real\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "token-Real");
    }

    #[test]
    fn entropy_threshold_skips_low_entropy_matches() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.key
    severity: error
    message: m
    secret:
      pattern: 'key-[A-Za-z0-9]{8}'
      entropy: 2.5
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "key-aaaaaaaa\nkey-Xq7Zp2Wm\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "key-Xq7Zp2Wm");
    }

    #[test]
    fn aws_key_passes_the_entropy_gate() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: aws.access-key
    severity: error
    message: aws access key
    secret:
      pattern: '(AKIA[0-9A-Z]{16})'
      group: 1
      entropy: 3.0
      keywords: ["AKIA"]
      allowlist:
        stopwords: ["EXAMPLE"]
"#,
        );
        let content = format!("aws_access_key_id = {AWS_KEY}\n");
        let found = scan_file(&compiled, "config/aws.ini", None, &content);

        assert_eq!(found.len(), 1);
        let finding = &found[0];
        assert_eq!(finding.rule_id, "aws.access-key");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(finding.matched, AWS_KEY);
        assert_eq!((finding.line, finding.column), (1, 21));
        assert_eq!(
            finding.fingerprint,
            fingerprint("aws.access-key", "config/aws.ini", AWS_KEY, 0)
        );
    }

    #[test]
    fn aws_key_fails_a_higher_entropy_gate() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: aws.access-key
    severity: error
    message: aws access key
    secret:
      pattern: '(AKIA[0-9A-Z]{16})'
      group: 1
      entropy: 4.5
      keywords: ["AKIA"]
"#,
        );
        let content = format!("aws_access_key_id = {AWS_KEY}\n");
        assert!(scan_file(&compiled, "config/aws.ini", None, &content).is_empty());
    }

    #[test]
    fn identical_matches_get_increasing_occurrence_index() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.key
    severity: error
    message: m
    secret:
      pattern: 'AKIA[0-9A-Z]{16}'
"#,
        );
        let content = format!("{AWS_KEY}\n{AWS_KEY}\n");
        let found = scan_file(&compiled, "f.txt", None, &content);

        assert_eq!(found.len(), 2);
        assert_eq!(
            found[0].fingerprint,
            fingerprint("a.key", "f.txt", AWS_KEY, 0)
        );
        assert_eq!(
            found[1].fingerprint,
            fingerprint("a.key", "f.txt", AWS_KEY, 1)
        );
    }

    #[test]
    fn findings_are_ordered_by_offset_across_rules() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.late
    severity: info
    message: m
    secret:
      pattern: 'gamma'
  - id: a.early
    severity: info
    message: m
    secret:
      pattern: 'alpha'
"#,
        );
        let found = scan_file(&compiled, "f.txt", None, "alpha\nbeta\ngamma\n");
        assert_eq!(
            found.iter().map(|f| f.rule_id.as_str()).collect::<Vec<_>>(),
            vec!["a.early", "a.late"]
        );
    }
}
