use std::sync::OnceLock;

/// Translated from the gitleaks default config (v8.30.1) by
/// `scripts/convert_gitleaks.py`. See `NOTICE` for attribution. Regenerated
/// wholesale on every gitleaks bump, so nothing hand-written may live here.
const GITLEAKS_DOCUMENT: &str = include_str!("../rules/default/secrets.yaml");

/// Hand-written generic high-entropy rules. `generic-api-key`,
/// `pypi-upload-token` and `vault-batch-token` are dropped from the translation
/// above because their programs exceed the regex crate's size limit; these
/// cover the generic ground with narrower patterns of our own.
const GENERIC_DOCUMENT: &str = include_str!("../rules/default/generic.yaml");

/// Marks the end of a rule document's header. Everything after it is sequence
/// items that can be appended to another document's `rules:` list.
const RULES_HEADER: &str = "\nrules:\n";

/// The built-in rule pack: the gitleaks translation followed by the generic
/// high-entropy rules, served as one document so a rule set carries one source.
///
/// Both halves are complete rule documents on disk, so each loads and tests on
/// its own; the second one's header is stripped when they are joined.
pub fn default_rules() -> &'static str {
    static PACK: OnceLock<String> = OnceLock::new();
    PACK.get_or_init(|| {
        let mut pack = String::with_capacity(GITLEAKS_DOCUMENT.len() + GENERIC_DOCUMENT.len());
        pack.push_str(GITLEAKS_DOCUMENT);
        if !pack.ends_with('\n') {
            pack.push('\n');
        }
        pack.push_str(rule_items(GENERIC_DOCUMENT));
        pack
    })
}

/// The sequence items of a rule document, without its header.
///
/// Panics when the document has no `rules:` list. Returning nothing instead
/// would drop every rule in it and leave a scan that reports less than it
/// promises, which is indistinguishable from a clean tree.
fn rule_items(document: &str) -> &str {
    let at = document
        .find(RULES_HEADER)
        .expect("a shipped rule document declares a rules list");
    &document[at + RULES_HEADER.len()..]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every rule id the generic document ships. Named here so a rule that
    /// disappears from the pack fails a test instead of quietly scanning less.
    const GENERIC_RULE_IDS: [&str; 3] = [
        "secrets.generic-credentialed-url",
        "secrets.aws-secret-access-key",
        "secrets.generic-secret-assignment",
    ];

    fn scan(content: &str) -> Vec<String> {
        let rules = crate::rules::load_str(GENERIC_DOCUMENT, "generic").expect("generic loads");
        crate::engines::secret::scan_file(&rules, "fixture.txt", None, content)
            .expect("every pattern compiles")
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect()
    }

    /// [`scan`] against the whole shipped pack, which is what a user runs and
    /// so the only place a generic rule and a specific one can be seen to
    /// report the same credential twice.
    fn scan_pack(content: &str) -> Vec<String> {
        let rules =
            crate::rules::load_str(default_rules(), "default-pack").expect("default pack loads");
        crate::engines::secret::scan_file(&rules, "fixture.txt", None, content)
            .expect("every pattern compiles")
            .into_iter()
            .map(|finding| finding.rule_id)
            .collect()
    }

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

    /// The pack is two documents joined by hand, so the join has to be worth
    /// exactly the sum: a header left in place would fail the load, and a
    /// header eaten too greedily would silently drop the first generic rule.
    #[test]
    fn the_pack_is_both_documents() {
        let gitleaks =
            crate::rules::load_str(GITLEAKS_DOCUMENT, "gitleaks").expect("gitleaks doc loads");
        let generic =
            crate::rules::load_str(GENERIC_DOCUMENT, "generic").expect("generic doc loads");
        let pack =
            crate::rules::load_str(default_rules(), "default-pack").expect("default pack loads");

        assert_eq!(pack.len(), gitleaks.len() + generic.len());
        assert_eq!(generic.len(), GENERIC_RULE_IDS.len());

        let ids: Vec<&str> = pack.iter().map(|rule| rule.id.as_str()).collect();
        for id in GENERIC_RULE_IDS {
            assert!(ids.contains(&id), "{id} missing from the pack");
        }
    }

    /// The generic rules are the only hand-written ones, so they are the only
    /// place a duplicate id can be introduced without regenerating anything.
    #[test]
    fn the_pack_has_no_duplicate_ids() {
        let pack =
            crate::rules::load_str(default_rules(), "default-pack").expect("default pack loads");
        let mut ids: Vec<&str> = pack.iter().map(|rule| rule.id.as_str()).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(count, ids.len(), "duplicate rule id in the default pack");
    }

    #[test]
    fn a_credentialed_url_is_reported() {
        let hits =
            scan("const DSN = \"postgres://svc_app:8Kq2vRt7XwPmZn4L@db.internal:5432/prod\";\n");
        assert!(
            hits.contains(&"secrets.generic-credentialed-url".to_string()),
            "{hits:?}"
        );
    }

    #[test]
    fn an_aws_secret_access_key_is_reported() {
        let hits = scan("aws_secret_access_key = \"kJ7pQm2XvNb9RtWs4YzA1CdE6FgH0IjKlMnOpQrS\"\n");
        assert!(
            hits.contains(&"secrets.aws-secret-access-key".to_string()),
            "{hits:?}"
        );
    }

    /// An in-house key, with no vendor prefix for a specific rule to key on.
    /// That is deliberately not a `sk_live_` or `ghp_` value: those are the
    /// stripe and github rules' findings, and this rule is allowlisted off them
    /// so that one credential is one finding.
    #[test]
    fn a_hardcoded_api_key_is_reported() {
        let hits = scan("api_key = \"51H8xQ2LkT9vBnMwZ4pRqYcXd\"\n");
        assert!(
            hits.contains(&"secrets.generic-secret-assignment".to_string()),
            "{hits:?}"
        );
    }

    #[test]
    fn a_hardcoded_password_is_reported() {
        let hits = scan("PASSWORD = \"Tz9!fQ4wLp2XvEr8Sd1M\"\n");
        assert!(
            hits.contains(&"secrets.generic-secret-assignment".to_string()),
            "{hits:?}"
        );
    }

    /// Severity is an upgrade contract, not a preference. A rule that ships at
    /// `error` fails a build under the default `--fail-on error` on the first
    /// run after an upgrade, against a baseline that cannot cover it because
    /// its fingerprints never existed. The two precise rules are worth that;
    /// the heuristic one is not, and asserting it here is what stops it from
    /// being promoted without the decision being made again.
    #[test]
    fn the_generic_rules_ship_at_the_severities_they_were_tuned_for() {
        use crate::rules::Severity;

        let rules = crate::rules::load_str(GENERIC_DOCUMENT, "generic").expect("generic loads");
        let severity = |id: &str| {
            rules
                .iter()
                .find(|rule| rule.id == id)
                .unwrap_or_else(|| panic!("{id} is in the generic document"))
                .severity
        };

        assert_eq!(
            severity("secrets.generic-credentialed-url"),
            Severity::Error
        );
        assert_eq!(severity("secrets.aws-secret-access-key"), Severity::Error);
        assert_eq!(
            severity("secrets.generic-secret-assignment"),
            Severity::Warning
        );
    }

    /// Prefixes of vendor credential formats, split so that no line in this
    /// file spells a complete credential shape. The fixtures below assemble
    /// them at run time: a scanner reading this source - ours or anyone
    /// else's - has nothing to match, while the engine still sees the whole
    /// value it is being tested against.
    const SLACK_BOT_PREFIX: &str = concat!("xox", "b");
    const STRIPE_LIVE_PREFIX: &str = concat!("sk", "_live");

    /// One credential is one finding. The generic rule matches on the shape of
    /// the assignment, so every prefixed credential a specific rule already
    /// names is inside its reach - and reported twice it is noise in the
    /// listing and a double count in whatever gates on the report.
    #[test]
    fn a_credential_a_specific_rule_names_is_not_reported_twice() {
        for (line, expected) in [
            (
                "api_key = \"ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\"\n".to_string(),
                "secrets.github-pat",
            ),
            (
                "aws_secret_access_key = \"kJ7pQm2XvNb9RtWs4YzA1CdE6FgH0IjKlMnOpQrS\"\n"
                    .to_string(),
                "secrets.aws-secret-access-key",
            ),
            (
                format!(
                    "slack_token = \"{}-263594206564-2343594206574-FGqmpZm7Yd0Vy3bTk8vGrTs4\"\n",
                    SLACK_BOT_PREFIX
                ),
                "secrets.slack-bot-token",
            ),
            (
                format!(
                    "stripe_secret = \"{}_51H8xQ2LkT9vBnMwZ4pRqYcXdVfGhJkLmNbTr\"\n",
                    STRIPE_LIVE_PREFIX
                ),
                "secrets.stripe-access-token",
            ),
        ] {
            assert_eq!(scan_pack(&line), vec![expected.to_string()], "{line}");
        }
    }

    /// The other half of the same statement: narrowing the generic rule around
    /// the specific ones must not have narrowed it out of the job it exists
    /// for, which is the credential no specific rule has a shape for.
    #[test]
    fn a_generic_secret_is_still_reported_once() {
        assert_eq!(
            scan_pack("PASSWORD = \"Tz9!fQ4wLp2XvEr8Sd1M\"\n"),
            vec!["secrets.generic-secret-assignment".to_string()]
        );
    }

    /// A real password that spells `pass`, `word`, `secret` or `token` is the
    /// shape a leaked database credential most often has. Through 1.4.0 those
    /// were substring stopwords, and `engines::secret` tests a stopword with
    /// `lowercased.contains(word)`, so every one of these was allowlisted by
    /// the rule that exists to report it.
    #[test]
    fn a_real_password_that_spells_a_placeholder_word_is_still_reported() {
        for url in [
            "postgres://admin:s3cr3tPassw0rd99@db.internal:5432/prod",
            "mysql://root:MyPassword123@10.0.0.5/app",
            "amqp://svc:Xk7Qm2pLv9Rt4Ws8@broker:5672",
            "mongodb://u:P%40ssw0rd-2024@cluster0/db",
            "postgres://svc:Tokenb3arer-Xk29@db.internal/prod",
            "https://ci:Secr3tWord!7Qm2@registry.internal/repo",
        ] {
            let line = format!("db = \"{url}\"\n");
            assert!(
                scan(&line).contains(&"secrets.generic-credentialed-url".to_string()),
                "{url} was not reported"
            );
        }
    }

    /// The same defect in `secrets.generic-secret-assignment`: `password`,
    /// `secret`, `token` and `your` were substring stopwords there too. Each
    /// value here also has to clear the rule's own identifier and CamelCase
    /// allowlists, which is why they carry punctuation.
    #[test]
    fn a_real_secret_that_spells_a_placeholder_word_is_still_reported() {
        for line in [
            "db_password = \"s3cr3tPassword99!Xk2\"",
            "client_secret = \"MyPassword123!SuperQ7\"",
            "auth_token = \"Tokenb3arer!Xk29Qm2Lv9\"",
            "api_key = \"Yourk3y!Xk29Qm2Lv9Rt4W\"",
        ] {
            let hits = scan(&format!("{line}\n"));
            assert!(
                hits.contains(&"secrets.generic-secret-assignment".to_string()),
                "{line} reported {hits:?}"
            );
        }
    }

    /// The other side of the same change: replacing substring stopwords with
    /// anchored patterns must keep every placeholder quiet. A placeholder is a
    /// value built entirely out of placeholder words, which is what separates
    /// `your-password-here` from `MyPassword123`.
    #[test]
    fn placeholder_credentials_in_urls_are_not_reported() {
        for line in [
            "postgres://user:password@localhost:5432/db",
            "postgres://appuser:changeme@localhost/app",
            "redis://:${REDIS_PASSWORD}@redis:6379/0",
            "https://user:your-password-here@example.com",
            "postgres://u:$DB_PASS@host/db",
            "mysql://root:changeit@db/app",
            "amqp://svc:your_db_password@broker:5672",
            "https://user:replace-with-your-password@example.com",
            "postgres://u:placeholder@host/db",
            "postgres://u:credentials@host/db",
            "mongodb://u:xxxxxxxxxxxx@cluster0/db",
            "https://user:pass%20word@example.com",
        ] {
            let hits = scan(&format!("{line}\n"));
            assert!(hits.is_empty(), "{line} reported {hits:?}");
        }
    }

    /// A generic rule earns its place only if it stays quiet on the shapes that
    /// surround real code: placeholders, environment lookups, interpolated
    /// values, documentation, hashes and ordinary identifiers. Each line here
    /// was seen in a real tree during tuning.
    #[test]
    fn placeholders_and_identifiers_are_not_reported() {
        for line in [
            "password = 'changeme'",
            "token = \"xxx\"",
            "secret = os.environ['APP_SECRET']",
            "DATABASE_URL=postgres://appuser:changeme@localhost:5432/app",
            "REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379/0",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "api_key = \"your-api-key-here\"",
            "const encryptionKey = generateEncryptionKeyBase64;",
            "authHeader = \"Access-Control-Allow-Headers\";",
            "password = process.env.DB_PASSWORD",
            "db_password = \"${var.db_password}\"",
            "access_key: X509RequestInheritOptions",
            "private_key = \"rsa-2048-private-key.pk8\"",
            "token = \"<your-token-here>\"",
            "\"integrity\": \"sha512-7RdRZ8kx1uYW3rGkFyPQ0mYlRZ2xVnT4pLqAsDfGhJkLmNbVcXzQwErTyUiOpAsDfGhJ\"",
            "Set DATABASE_URL to postgres://user:password@host:5432/db",
            "apiKey = \"PLACEHOLDER_API_KEY_GOES_HERE\"",
            "secret_key = \"test-fixture-value-not-a-real-secret\"",
            "auth_token = f\"Bearer {token}\"",
            "client_secret = \"%(CLIENT_SECRET)s\"",
            "signing_key = \"/etc/ssl/private/app-signing.key\"",
            "credentials = base64.b64encode(f\"{user}:{password}\".encode())",
        ] {
            let hits = scan(&format!("{line}\n"));
            assert!(hits.is_empty(), "{line} reported {hits:?}");
        }
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
