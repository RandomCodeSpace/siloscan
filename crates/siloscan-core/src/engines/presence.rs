use super::applies;
use crate::findings::{Finding, fingerprint};
use crate::rules::{CompiledPayload, CompiledRule};

/// Report every presence rule against the paths a walk produced.
///
/// A presence rule has no content matcher: the file existing where its
/// envelope points is the finding. That is what a committed keystore is - the
/// bytes inside a `.p12` are opaque, and reading them would decide nothing -
/// so this engine takes paths and never opens a file.
///
/// It follows that the paths handed in are every walked path, binary and
/// unreadable files included, and not just the ones that made it through the
/// text reader. A keystore is binary by definition; a rule that fired only on
/// files the scanner could read as text would never fire on one.
///
/// One finding per matching file, at line 1 column 1, with the file's name as
/// the match text: the name is what the rule matched, and there is no span in
/// the file to point at. The fingerprint is the ordinary one over the rule id,
/// the path and that name at occurrence 0 - a file has one existence, so there
/// is never a second occurrence to distinguish.
///
/// Nothing here is cached. The per-file cache stores what the content engines
/// produced for one file's bytes; a presence finding is a function of the path
/// and the loaded rules alone, both of which the cache key already covers (the
/// entry hash spans the path and the content, and [`crate::cache::Cache::bind`]
/// folds the rule sources into the scope). Recomputing it is a glob match per
/// walked path, so filing it would buy nothing and would make a finding that
/// does not depend on content depend on a content hash.
///
/// `paths` are repository-relative, forward-slash paths, in walk order; the
/// findings come back in that order, one rule at a time per path.
pub fn scan_paths(rules: &[CompiledRule], paths: &[String]) -> Vec<Finding> {
    let presence: Vec<&CompiledRule> = rules
        .iter()
        .filter(|rule| matches!(rule.payload, CompiledPayload::Presence))
        .collect();
    if presence.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    for path_rel in paths {
        for rule in &presence {
            // No language is detected for a file nothing read, and a presence
            // rule may not carry a `languages` filter for exactly that reason.
            if !applies(rule, path_rel, None) {
                continue;
            }

            let matched = file_name(path_rel);
            findings.push(Finding {
                rule_id: rule.id.clone(),
                severity: rule.severity,
                message: rule.message.clone(),
                path: path_rel.to_string(),
                line: 1,
                column: 1,
                column_utf16: 1,
                matched: matched.to_string(),
                fingerprint: fingerprint(&rule.id, path_rel, matched, 0),
            });
        }
    }
    findings
}

/// The last segment of a repository-relative path. Walk paths use forward
/// slashes on every platform, so this is the file's name wherever the scan ran.
fn file_name(path_rel: &str) -> &str {
    match path_rel.rsplit_once('/') {
        Some((_, name)) => name,
        None => path_rel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Severity, load_str};

    fn rules(src: &str) -> Vec<CompiledRule> {
        load_str(src, "test").expect("rules should load")
    }

    const KEYSTORE: &str = r#"
version: 1
rules:
  - id: secrets.pkcs12-file
    severity: error
    message: Found a PKCS #12 file, which commonly contain bundled private keys.
    paths:
      case_insensitive: true
      include: ['**/*.p12', '**/*.pfx']
"#;

    #[test]
    fn a_matching_path_is_one_finding_at_the_top_of_the_file() {
        let compiled = rules(KEYSTORE);
        let found = scan_paths(&compiled, &["certs/server.p12".to_string()]);

        assert_eq!(found.len(), 1);
        let finding = &found[0];
        assert_eq!(finding.rule_id, "secrets.pkcs12-file");
        assert_eq!(finding.severity, Severity::Error);
        assert_eq!(
            (finding.line, finding.column, finding.column_utf16),
            (1, 1, 1)
        );
        assert_eq!(finding.matched, "server.p12");
        assert_eq!(
            finding.fingerprint,
            fingerprint("secrets.pkcs12-file", "certs/server.p12", "server.p12", 0)
        );
    }

    #[test]
    fn the_case_insensitive_flag_decides_the_extension_match() {
        let compiled = rules(KEYSTORE);
        assert_eq!(
            scan_paths(&compiled, &["certs/Server.PFX".to_string()]).len(),
            1
        );

        let exact = rules(
            r#"
version: 1
rules:
  - id: a.keystore
    severity: error
    message: m
    paths:
      include: ['**/*.p12']
"#,
        );
        assert!(scan_paths(&exact, &["certs/server.P12".to_string()]).is_empty());
        assert_eq!(
            scan_paths(&exact, &["certs/server.p12".to_string()]).len(),
            1
        );
    }

    #[test]
    fn an_excluded_path_reports_nothing() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.keystore
    severity: error
    message: m
    paths:
      include: ['**/*.p12']
      exclude: ['**/testdata/**']
"#,
        );
        assert!(scan_paths(&compiled, &["testdata/server.p12".to_string()]).is_empty());
    }

    #[test]
    fn a_rule_with_a_payload_is_not_a_presence_rule() {
        let compiled = rules(
            r#"
version: 1
rules:
  - id: a.key
    severity: error
    message: m
    paths:
      include: ['**/*.p12']
    secret:
      pattern: 'needle'
"#,
        );
        assert!(scan_paths(&compiled, &["certs/server.p12".to_string()]).is_empty());
    }

    #[test]
    fn every_matching_path_reports_once_in_walk_order() {
        let compiled = rules(KEYSTORE);
        let paths = [
            "b/second.p12".to_string(),
            "a/first.pfx".to_string(),
            "a/notes.txt".to_string(),
        ];
        let found = scan_paths(&compiled, &paths);
        assert_eq!(
            found.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(),
            vec!["b/second.p12", "a/first.pfx"]
        );
        // Two files, two fingerprints: the path is part of every one of them.
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
    }

    #[test]
    fn a_path_with_no_directory_reports_its_own_name() {
        let compiled = rules(KEYSTORE);
        let found = scan_paths(&compiled, &["server.p12".to_string()]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].matched, "server.p12");
    }
}
