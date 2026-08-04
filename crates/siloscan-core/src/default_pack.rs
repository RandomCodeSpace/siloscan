/// The built-in secrets rule pack, translated from the gitleaks default config
/// (v8.30.1) by `scripts/convert_gitleaks.py`. See `NOTICE` for attribution.
///
/// Three gitleaks rules are intentionally dropped due to regex size constraints
/// (Rust regex crate's 10 MiB limit): `generic-api-key`, `pypi-upload-token`,
/// and `vault-batch-token`. Users needing generic high-entropy detection can add
/// custom `secret:` rules with narrower patterns or tighter keyword requirements.
pub fn default_rules() -> &'static str {
    include_str!("../rules/default/secrets.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pack_loads() {
        let rules =
            crate::rules::load_str(default_rules(), "default-pack").expect("default pack loads");
        assert!(
            rules.len() > 50,
            "expected a substantial pack, got {} rules",
            rules.len()
        );
    }

    /// Compiling the whole pack costs seconds of wall time and hundreds of
    /// megabytes of resident memory. Loading it must buy none of that: every
    /// pattern stays source until a rule has a file to match against.
    #[test]
    fn default_pack_compiles_no_patterns_at_load() {
        use crate::rules::CompiledPayload;

        let rules =
            crate::rules::load_str(default_rules(), "default-pack").expect("default pack loads");
        for rule in &rules {
            let CompiledPayload::Secret {
                pattern,
                allow_patterns,
                ..
            } = &rule.payload
            else {
                panic!("the default pack is secret rules only: {}", rule.id);
            };
            assert!(!pattern.is_compiled(), "{} compiled at load", rule.id);
            for allow in allow_patterns {
                assert!(
                    !allow.is_compiled(),
                    "{} allowlist compiled at load",
                    rule.id
                );
            }
        }
    }

    /// Deferring the compile moves one failure class out of load: a pattern that
    /// parses but whose program exceeds the regex size limit is discovered at
    /// first use, where it fails the scan instead of the load. Nothing in the
    /// shipped pack may be in that class - every pattern has to actually build,
    /// or a repository holding the right keyword cannot be scanned at all.
    #[test]
    fn every_default_pack_pattern_compiles() {
        use crate::rules::CompiledPayload;

        let rules =
            crate::rules::load_str(default_rules(), "default-pack").expect("default pack loads");
        for rule in &rules {
            let CompiledPayload::Secret {
                pattern,
                allow_patterns,
                ..
            } = &rule.payload
            else {
                panic!("the default pack is secret rules only: {}", rule.id);
            };
            assert!(
                pattern.get().is_ok(),
                "{} does not compile: {}",
                rule.id,
                pattern.pattern()
            );
            for allow in allow_patterns {
                assert!(
                    allow.get().is_ok(),
                    "{} allowlist does not compile: {}",
                    rule.id,
                    allow.pattern()
                );
            }
        }
    }
}
