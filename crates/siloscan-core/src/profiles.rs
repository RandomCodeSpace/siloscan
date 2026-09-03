//! Embedded bug-risk and maintainability profiles, and how a scan picks them.
//!
//! A profile is one complete rule document per (family, language) pair, shipped
//! in the binary the way the secrets pack is. [`REGISTRY`] is the whole list;
//! [`select`] is the one place that decides which of them a scan loads.
//!
//! Shipping a document is adding a file under
//! `crates/siloscan-core/rules/profiles/` and one [`Profile`] here, and nothing
//! else. Selection still defaults to [`ProfileSelection::None`], so a scan that
//! does not ask for a profile loads none of these and every byte of its report
//! is what it was.

/// One embedded profile document.
///
/// `identity` is what [`crate::plan::ScanSetupReport::rule_sources`] reports and
/// what a caller names to select the document explicitly, spelled like the
/// embedded pack's own identity: `reliability-rust@1`, `maintainability-go@1`.
/// The `@N` suffix is the document's contract generation, bumped only when a
/// rule id is removed or renamed.
///
/// `language` is one of [`crate::lang`]'s names, which is what project
/// detection reports, so `Auto` can compare the two without a translation
/// table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Profile {
    identity: &'static str,
    language: &'static str,
    document: &'static str,
}

impl Profile {
    /// A registry entry. `document` is an `include_str!` of a complete rule
    /// document, so a profile that does not parse fails the load rather than
    /// scanning less than it promises.
    pub const fn new(
        identity: &'static str,
        language: &'static str,
        document: &'static str,
    ) -> Self {
        Self {
            identity,
            language,
            document,
        }
    }

    pub fn identity(&self) -> &'static str {
        self.identity
    }

    pub fn language(&self) -> &'static str {
        self.language
    }

    pub fn document(&self) -> &'static str {
        self.document
    }
}

/// Every embedded profile document, ordered by identity.
///
/// One entry per (family, language) pair, and the document beside it under
/// `rules/profiles/`. `tests/profile_corpus.rs` refuses a document on disk that
/// no entry here names, and refuses an entry whose rules do not match its
/// identity.
pub const REGISTRY: &[Profile] = &[
    Profile::new(
        "maintainability-c@1",
        "c",
        include_str!("../rules/profiles/maintainability-c.yaml"),
    ),
    Profile::new(
        "maintainability-cpp@1",
        "cpp",
        include_str!("../rules/profiles/maintainability-cpp.yaml"),
    ),
    Profile::new(
        "maintainability-csharp@1",
        "csharp",
        include_str!("../rules/profiles/maintainability-csharp.yaml"),
    ),
    Profile::new(
        "maintainability-go@1",
        "go",
        include_str!("../rules/profiles/maintainability-go.yaml"),
    ),
    Profile::new(
        "maintainability-java@1",
        "java",
        include_str!("../rules/profiles/maintainability-java.yaml"),
    ),
    Profile::new(
        "maintainability-ruby@1",
        "ruby",
        include_str!("../rules/profiles/maintainability-ruby.yaml"),
    ),
    Profile::new(
        "maintainability-rust@1",
        "rust",
        include_str!("../rules/profiles/maintainability-rust.yaml"),
    ),
    Profile::new(
        "reliability-c@1",
        "c",
        include_str!("../rules/profiles/reliability-c.yaml"),
    ),
    Profile::new(
        "reliability-cpp@1",
        "cpp",
        include_str!("../rules/profiles/reliability-cpp.yaml"),
    ),
    Profile::new(
        "reliability-csharp@1",
        "csharp",
        include_str!("../rules/profiles/reliability-csharp.yaml"),
    ),
    Profile::new(
        "reliability-go@1",
        "go",
        include_str!("../rules/profiles/reliability-go.yaml"),
    ),
    Profile::new(
        "reliability-java@1",
        "java",
        include_str!("../rules/profiles/reliability-java.yaml"),
    ),
    Profile::new(
        "reliability-ruby@1",
        "ruby",
        include_str!("../rules/profiles/reliability-ruby.yaml"),
    ),
    Profile::new(
        "reliability-rust@1",
        "rust",
        include_str!("../rules/profiles/reliability-rust.yaml"),
    ),
];

/// Which embedded profiles a scan loads.
///
/// Not a flag with a default: the answer differs by how the scan was invoked,
/// and both invocations record it the same way, so a later stage never has to
/// ask which front end it is serving.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ProfileSelection {
    /// No embedded profile.
    #[default]
    None,
    /// Every profile that has a document for a detected language.
    Auto,
    /// Exactly these profile identities, whatever was detected.
    Named(Vec<String>),
}

/// The documents `selection` picks out of `registry`, ordered by identity.
///
/// `Auto` never picks a document for a language the detector did not report,
/// which is both the performance lever and the reason a Go-only repository
/// never sees a Ruby rule id.
///
/// `Named` deliberately ignores detection: a caller naming `reliability-rust@1`
/// on a tree the detector called generic asked for it, and silently loading
/// nothing would be the clean scan that proved nothing. A named identity with
/// no document is therefore an error listing what is available.
pub fn select<'a>(
    registry: &'a [Profile],
    selection: &ProfileSelection,
    languages: &[String],
) -> Result<Vec<&'a Profile>, String> {
    let mut selected: Vec<&Profile> = match selection {
        ProfileSelection::None => Vec::new(),
        ProfileSelection::Auto => registry
            .iter()
            .filter(|profile| {
                languages
                    .iter()
                    .any(|language| language == profile.language)
            })
            .collect(),
        ProfileSelection::Named(names) => {
            let mut picked = Vec::with_capacity(names.len());
            for name in names {
                let profile = registry
                    .iter()
                    .find(|profile| profile.identity == name)
                    .ok_or_else(|| unknown_profile(name, registry))?;
                picked.push(profile);
            }
            picked
        }
    };
    selected.sort_unstable_by_key(|profile| profile.identity);
    selected.dedup_by_key(|profile| profile.identity);
    Ok(selected)
}

fn unknown_profile(name: &str, registry: &[Profile]) -> String {
    let available = if registry.is_empty() {
        "none".to_string()
    } else {
        registry
            .iter()
            .map(|profile| profile.identity)
            .collect::<Vec<&str>>()
            .join(", ")
    };
    format!("unknown profile: {name}; available: {available}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUST_DOC: &str = "version: 1\nrules: []\n";

    const TEST_REGISTRY: &[Profile] = &[
        Profile::new("maintainability-rust@1", "rust", RUST_DOC),
        Profile::new("reliability-go@1", "go", RUST_DOC),
        Profile::new("reliability-rust@1", "rust", RUST_DOC),
    ];

    fn identities(selected: &[&Profile]) -> Vec<&'static str> {
        selected.iter().map(|profile| profile.identity()).collect()
    }

    /// Every shipped entry is a `<profile>-<language>@<n>` identity whose
    /// language is the entry's own, and the list is ordered by identity so a
    /// reader and `select` agree on what "first" means. What the documents
    /// themselves contain is held by `tests/profile_corpus.rs`.
    #[test]
    fn the_shipped_registry_is_ordered_and_self_consistent() {
        for profile in REGISTRY {
            let stem = profile
                .identity()
                .strip_suffix("@1")
                .unwrap_or_else(|| panic!("{} has no @1 suffix", profile.identity()));
            let (family, language) = stem
                .rsplit_once('-')
                .unwrap_or_else(|| panic!("{stem} is not <profile>-<language>"));
            assert!(
                family == "reliability" || family == "maintainability",
                "{family} is not a profile family"
            );
            assert_eq!(language, profile.language(), "{stem} disagrees with itself");
        }
        let identities: Vec<&str> = REGISTRY.iter().map(Profile::identity).collect();
        let mut sorted = identities.clone();
        sorted.sort_unstable();
        assert_eq!(
            identities, sorted,
            "the registry is not ordered by identity"
        );
        // `select` dedups on identity, so a repeat here would load once
        // and read as two documents in this list.
        let mut unique = identities.clone();
        unique.dedup();
        assert_eq!(identities, unique, "the registry repeats an identity");
    }

    #[test]
    fn none_selects_nothing() {
        let selected = select(
            TEST_REGISTRY,
            &ProfileSelection::None,
            &["rust".to_string()],
        )
        .expect("none cannot fail");
        assert!(selected.is_empty());
    }

    #[test]
    fn auto_selects_the_detected_languages_only() {
        let selected = select(
            TEST_REGISTRY,
            &ProfileSelection::Auto,
            &["rust".to_string()],
        )
        .expect("auto cannot fail");
        assert_eq!(
            identities(&selected),
            ["maintainability-rust@1", "reliability-rust@1"]
        );
    }

    #[test]
    fn auto_selects_nothing_when_no_detected_language_has_a_document() {
        let selected = select(
            TEST_REGISTRY,
            &ProfileSelection::Auto,
            &["python".to_string()],
        )
        .expect("auto cannot fail");
        assert!(selected.is_empty());
    }

    #[test]
    fn named_ignores_detection() {
        let selected = select(
            TEST_REGISTRY,
            &ProfileSelection::Named(vec!["reliability-go@1".to_string()]),
            &["rust".to_string()],
        )
        .expect("a known identity resolves");
        assert_eq!(identities(&selected), ["reliability-go@1"]);
    }

    #[test]
    fn a_repeated_identity_loads_once() {
        let selected = select(
            TEST_REGISTRY,
            &ProfileSelection::Named(vec![
                "reliability-go@1".to_string(),
                "reliability-go@1".to_string(),
            ]),
            &[],
        )
        .expect("a known identity resolves");
        assert_eq!(identities(&selected), ["reliability-go@1"]);
    }

    #[test]
    fn an_unknown_identity_names_itself_and_what_is_available() {
        let error = select(
            TEST_REGISTRY,
            &ProfileSelection::Named(vec!["reliability-elixir@1".to_string()]),
            &[],
        )
        .expect_err("an unknown identity is refused");
        assert_eq!(
            error,
            "unknown profile: reliability-elixir@1; available: \
             maintainability-rust@1, reliability-go@1, reliability-rust@1"
        );
    }

    #[test]
    fn an_unknown_identity_against_an_empty_registry_says_so() {
        let error = select(
            &[],
            &ProfileSelection::Named(vec!["reliability-rust@1".to_string()]),
            &[],
        )
        .expect_err("an unknown identity is refused");
        assert_eq!(
            error,
            "unknown profile: reliability-rust@1; available: none"
        );
    }
}
