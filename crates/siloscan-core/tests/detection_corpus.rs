//! Measures the shipped rule pack against the committed detection corpus.
//!
//! The corpus under `tests/corpus/tree` holds realistic configuration and
//! source files; `tests/corpus/manifest.tsv` says, for every line that is a
//! test case, whether the pack must report it and under which rule. This file
//! materializes the corpus, scans it with the default pack, and turns the
//! result into two numbers: recall over the positives and a precision proxy
//! over the negatives.
//!
//! No file in the repository spells a complete credential. Every credential is
//! assembled here at run time: vendor prefixes come from `concat!` halves, and
//! the entropy-bearing tail of each value is generated from a fixed seed keyed
//! by the marker's own name. The corpus files carry `{{KIND_PARAM_TAG}}`
//! markers where the credential goes, so a scanner reading this repository -
//! ours, GitHub's push protection, or a consumer's - has nothing to match,
//! while the engine under test still sees the whole value.
//!
//! The delimiter is braces because `{` sits outside every value class in the
//! pack, vendor and generic alike, so a marker cannot be read as the token it
//! stands in for by any rule - including the vendor rules, which are translated
//! wholesale from an upstream document and cannot be hand-edited to stand down
//! on a delimiter of ours.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use siloscan_core::default_pack::default_rules;
use siloscan_core::engines::secret;
use siloscan_core::rules::{CompiledRule, load_str};

/// Fraction of positives the pack must report. Chosen above what the 1.4.1
/// pack scores: the generic rules were tuned in one pass against no corpus,
/// and the gap between this floor and what they measure is the work.
const RECALL_FLOOR: f64 = 0.95;

/// Fraction of negatives the pack must leave alone. Every negative in the
/// manifest is justified one by one, so a single spurious hit is a defect and
/// nothing less than all of them is the floor. Widening a rule for recall at
/// the cost of one of these is the trade the 1.4.x generic rules were tuned
/// on, blind, and it is what this number exists to stop.
const PRECISION_FLOOR: f64 = 1.0;

const CORPUS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus");

// -------------------------------------------------------------- expectations

#[derive(Debug, PartialEq, Eq)]
enum Expect {
    /// The pack must report nothing on this line.
    Nothing,
    /// The pack must report something, exactly once; which rule owns the shape
    /// is the rule author's decision, so the id is not pinned.
    Anything,
    /// The pack must report one of these rule ids on this line, and nothing
    /// else. Listing several ids says every one of them is an acceptable
    /// owner of the shape, not that a second report is acceptable: a line the
    /// pack genuinely reports twice names both ids and argues it in the
    /// justification.
    OneOf(Vec<String>),
}

impl Expect {
    fn is_positive(&self) -> bool {
        !matches!(self, Expect::Nothing)
    }

    fn satisfied_by(&self, reported: &[String]) -> bool {
        match self {
            Expect::Nothing => reported.is_empty(),
            Expect::Anything => !reported.is_empty(),
            Expect::OneOf(ids) => reported.iter().any(|hit| ids.iter().any(|id| id == hit)),
        }
    }

    /// Rule ids reported on this line that the expectation does not account
    /// for. This is what `satisfied_by` cannot see: it asks whether the line
    /// was reported, and a credential reported twice is reported.
    fn unexpected<'a>(&self, reported: &'a [String]) -> Vec<&'a str> {
        match self {
            // Everything here is unexpected, and `spurious` already says so.
            // Counting it twice would turn one defect into two.
            Expect::Nothing => Vec::new(),
            // No single id is unexpected, because none is pinned. A second one
            // is: it is one credential reported twice.
            Expect::Anything => reported.iter().skip(1).map(String::as_str).collect(),
            Expect::OneOf(ids) => reported
                .iter()
                .filter(|hit| !ids.iter().any(|id| id == *hit))
                .map(String::as_str)
                .collect(),
        }
    }

    fn describe(&self) -> String {
        match self {
            Expect::Nothing => "NONE".to_string(),
            Expect::Anything => "ANY".to_string(),
            Expect::OneOf(ids) => ids.join("|"),
        }
    }
}

struct Row {
    path: String,
    line: u64,
    expect: Expect,
    justification: String,
}

fn load_manifest() -> Vec<Row> {
    let path = Path::new(CORPUS_DIR).join("manifest.tsv");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{} is readable: {error}", path.display()));

    let mut rows = Vec::new();
    for (number, raw) in text.lines().enumerate() {
        let number = number + 1;
        if raw.trim().is_empty() || raw.starts_with('#') || raw.starts_with("path\t") {
            continue;
        }
        let fields: Vec<&str> = raw.split('\t').collect();
        assert_eq!(
            fields.len(),
            4,
            "manifest.tsv line {number} has {} tab-separated fields, expected 4",
            fields.len()
        );
        let line: u64 = fields[1]
            .parse()
            .unwrap_or_else(|_| panic!("manifest.tsv line {number} has a non-numeric line number"));
        let expect = match fields[2] {
            "NONE" => Expect::Nothing,
            "ANY" => Expect::Anything,
            ids => Expect::OneOf(ids.split('|').map(str::to_string).collect()),
        };
        assert!(
            !fields[3].trim().is_empty(),
            "manifest.tsv line {number} carries no justification"
        );
        rows.push(Row {
            path: fields[0].to_string(),
            line,
            expect,
            justification: fields[3].to_string(),
        });
    }
    rows
}

// ------------------------------------------------------------------- corpus

/// Every corpus file, in a stable order, as repository-relative paths under
/// `tests/corpus/tree`.
fn corpus_files() -> Vec<String> {
    let root = Path::new(CORPUS_DIR).join("tree");
    let mut found = Vec::new();
    collect(&root, &root, &mut found);
    found.sort();
    found
}

fn collect(root: &Path, dir: &Path, found: &mut Vec<String>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("{} is readable: {error}", dir.display()));
    let mut paths: Vec<PathBuf> = entries
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("{} enumerates: {error}", dir.display()))
                .path()
        })
        .collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect(root, &path, found);
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("corpus paths sit under the corpus root");
            found.push(relative.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Whether the text between a pair of braces names a credential marker.
///
/// The corpus also carries template interpolations in the same brace shape -
/// `{{ .Values.database.password }}` is one of the negatives the pack must
/// leave alone - so a marker is recognised by its name: upper case, digits and
/// underscores, which no interpolation in the corpus spells.
fn is_marker_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Replace every `{{KIND_PARAM_TAG}}` marker with the credential it stands for,
/// leaving anything else in braces alone. Panics on a marker-shaped name no
/// generator knows, because a silently unreplaced marker would turn a positive
/// into a line the pack cannot possibly report.
fn materialize(path: &str, content: &str) -> String {
    let mut out = String::with_capacity(content.len() + content.len() / 4);
    let mut rest = content;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let close = after
            .find("}}")
            .unwrap_or_else(|| panic!("{path} has an unterminated credential marker"));
        let name = &after[..close];
        if is_marker_name(name) {
            out.push_str(&credential(name).unwrap_or_else(|| {
                panic!("{path} uses the credential marker {name}, which has no generator")
            }));
        } else {
            out.push_str("{{");
            out.push_str(name);
            out.push_str("}}");
        }
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    out
}

/// Every credential marker in `content`, in the order they appear.
fn markers(content: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = content;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            break;
        };
        let name = &after[..close];
        if is_marker_name(name) {
            found.push(name.to_string());
        }
        rest = &after[close + 2..];
    }
    found
}

// ------------------------------------------------------- credential material

/// SplitMix64. Fixed algorithm, fixed seed, integer arithmetic only: the same
/// marker yields the same credential on every platform and every run, so the
/// corpus is as reproducible as the files it is generated into.
struct Rng(u64);

impl Rng {
    fn seeded(name: &str) -> Self {
        // FNV-1a over the marker name, so each marker is independent and
        // adding one does not move any other.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in name.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Rng(hash ^ 0x5110_5CA4_C025_0000)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }

    fn take(&mut self, alphabet: &str, count: usize) -> String {
        let symbols: Vec<char> = alphabet.chars().collect();
        (0..count)
            .map(|_| symbols[self.below(symbols.len())])
            .collect()
    }
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGIT: &str = "0123456789";
const ALNUM: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const LOWER_ALNUM: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
const HEX: &str = "0123456789abcdef";
const BASE64: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
const BASE64URL: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
const BASE32: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const CLOUDFLARE: &str = "abcdefghijklmnopqrstuvwxyz0123456789_-";

/// Punctuation a password policy asks for, minus the characters that would
/// change how a URL or a quoted string parses. `PWQ` covers those separately.
const PUNCT: &str = "!$%^&*()-_+=[]{};,.?";
const PUNCT_WIDE: &str = "!@#$%^&*()-_+=[]{};:,.?~";
const NON_ASCII: &str = "\u{e1}\u{e9}\u{ed}\u{f3}\u{fa}\u{fc}\u{f1}\u{e7}\u{df}\u{4e2d}\u{6587}";

/// Words a real password is built out of, and which the pack's placeholder
/// allowlists match on. A password is not a placeholder because it spells one.
const WORDS: [&str; 5] = ["Passw0rd", "S3cretW", "T0kenB", "MyPassword", "Secr3tWord"];

// Vendor prefixes, split so no line in this file spells a credential format.
const AWS_KEY_ID_PREFIX: &str = concat!("AK", "IA");
const GITHUB_PAT_PREFIX: &str = concat!("gh", "p_");
const GITHUB_OAUTH_PREFIX: &str = concat!("gh", "o_");
const GITHUB_APP_SERVER_PREFIX: &str = concat!("gh", "s_");
const GITHUB_APP_USER_PREFIX: &str = concat!("gh", "u_");
const GITHUB_FINE_GRAINED_PREFIX: &str = concat!("github", "_pat_");
const GITLAB_PAT_PREFIX: &str = concat!("glp", "at-");
const SLACK_BOT_PREFIX: &str = concat!("xox", "b");
const SLACK_USER_PREFIX: &str = concat!("xox", "p");
const SLACK_WEBHOOK_HOST: &str = concat!("https://hooks.", "slack.com/services/");
const STRIPE_LIVE_PREFIX: &str = concat!("sk", "_live_");
const STRIPE_TEST_PREFIX: &str = concat!("sk", "_test_");
const NPM_PREFIX: &str = concat!("np", "m_");
const DIGITALOCEAN_PAT_PREFIX: &str = concat!("dop", "_v1_");
const DIGITALOCEAN_OAUTH_PREFIX: &str = concat!("doo", "_v1_");
const SENDGRID_PREFIX: &str = concat!("S", "G.");
const MAILGUN_PREFIX: &str = concat!("ke", "y-");
const TWILIO_PREFIX: &str = concat!("S", "K");
const AZURE_MARKER: &str = concat!("Q", "~");
const OPENAI_PREFIX: &str = concat!("sk", "-");
const OPENAI_MARKER: &str = concat!("T3Blb", "kFJ");
const ANTHROPIC_PREFIX: &str = concat!("sk-ant-", "api03-");
const ANTHROPIC_ADMIN_PREFIX: &str = concat!("sk-ant-", "admin01-");
const GCP_API_KEY_PREFIX: &str = concat!("AI", "za");
const JWT_SEGMENT_PREFIX: &str = concat!("e", "y");

/// The credential a marker stands for, or `None` when the kind is unknown.
///
/// The marker is `KIND_PARAM_TAG`: `KIND` selects the generator, `PARAM` is
/// its length where a length applies, and `TAG` makes the marker - and so the
/// value - unique.
fn credential(name: &str) -> Option<String> {
    let mut parts = name.rsplitn(3, '_');
    let _tag = parts.next()?;
    let param: usize = parts.next()?.parse().ok()?;
    let kind = parts.next()?;

    let mut rng = Rng::seeded(name);
    let value = match kind {
        // Generic shapes.
        "PWA" => password(&mut rng, param, ""),
        "PWP" => password(&mut rng, param, PUNCT),
        "PWQ" => password(&mut rng, param, PUNCT_WIDE),
        "PWU" => unicode_password(&mut rng, param),
        "PWSLASH" => infix(&mut rng, param, '/'),
        "PWAT" => infix(&mut rng, param, '@'),
        "PWPCT" => percent_encoded(&mut rng, param),
        "WORDPW" => word_password(&mut rng, param, name),
        "B64" => rng.take(BASE64, param),
        "B64URL" => rng.take(BASE64URL, param),
        "HEX" => rng.take(HEX, param),
        "PEM" => rng.take(BASE64, param),

        // Vendor formats. Lengths and alphabets are read off the pack's own
        // patterns in rules/default/secrets.yaml, not from memory.
        "AWSKEYID" => format!("{AWS_KEY_ID_PREFIX}{}", rng.take(BASE32, 16)),
        "AWSSECRET" => rng.take(BASE64, 40),
        "GHPAT" => format!("{GITHUB_PAT_PREFIX}{}", rng.take(ALNUM, 36)),
        "GHOAUTH" => format!("{GITHUB_OAUTH_PREFIX}{}", rng.take(ALNUM, 36)),
        "GHAPPS" => format!("{GITHUB_APP_SERVER_PREFIX}{}", rng.take(ALNUM, 36)),
        "GHAPPU" => format!("{GITHUB_APP_USER_PREFIX}{}", rng.take(ALNUM, 36)),
        "GHFINE" => format!("{GITHUB_FINE_GRAINED_PREFIX}{}", rng.take(ALNUM, 82)),
        "GLPAT" => format!("{GITLAB_PAT_PREFIX}{}", rng.take(ALNUM, 20)),
        "SLACKBOT" => format!(
            "{SLACK_BOT_PREFIX}-{}-{}-{}",
            rng.take(DIGIT, 12),
            rng.take(DIGIT, 12),
            rng.take(ALNUM, 24)
        ),
        "SLACKUSER" => format!(
            "{SLACK_USER_PREFIX}-{}-{}-{}-{}",
            rng.take(DIGIT, 12),
            rng.take(DIGIT, 12),
            rng.take(DIGIT, 12),
            rng.take(ALNUM, 32)
        ),
        "SLACKHOOK" => format!(
            "{SLACK_WEBHOOK_HOST}T{}/B{}/{}",
            rng.take(BASE32, 8),
            rng.take(BASE32, 9),
            rng.take(ALNUM, 24)
        ),
        "STRIPELIVE" => format!("{STRIPE_LIVE_PREFIX}{}", rng.take(ALNUM, 24)),
        "STRIPETEST" => format!("{STRIPE_TEST_PREFIX}{}", rng.take(ALNUM, 24)),
        "NPMTOKEN" => format!("{NPM_PREFIX}{}", rng.take(LOWER_ALNUM, 36)),
        "DOPAT" => format!("{DIGITALOCEAN_PAT_PREFIX}{}", rng.take(HEX, 64)),
        "DOOAUTH" => format!("{DIGITALOCEAN_OAUTH_PREFIX}{}", rng.take(HEX, 64)),
        "CFKEY" => rng.take(CLOUDFLARE, 40),
        "CFGLOBAL" => rng.take(HEX, 37),
        "SENDGRID" => format!(
            "{SENDGRID_PREFIX}{}.{}",
            rng.take(ALNUM, 22),
            rng.take(ALNUM, 43)
        ),
        "MAILGUN" => format!("{MAILGUN_PREFIX}{}", rng.take(HEX, 32)),
        "TWILIO" => format!("{TWILIO_PREFIX}{}", rng.take(HEX, 32)),
        "AZURE" => format!(
            "{}{}{AZURE_MARKER}{}",
            rng.take(ALNUM, 3),
            rng.take(DIGIT, 1),
            rng.take(ALNUM, 34)
        ),
        "OPENAI" => format!(
            "{OPENAI_PREFIX}{}{OPENAI_MARKER}{}",
            rng.take(ALNUM, 20),
            rng.take(ALNUM, 20)
        ),
        "ANTHROPIC" => format!("{ANTHROPIC_PREFIX}{}AA", rng.take(BASE64URL, 93)),
        "ANTHROPICADMIN" => format!("{ANTHROPIC_ADMIN_PREFIX}{}AA", rng.take(BASE64URL, 93)),
        "GCPKEY" => format!("{GCP_API_KEY_PREFIX}{}", rng.take(BASE64URL, 35)),
        "JWT" => format!(
            "{JWT_SEGMENT_PREFIX}{}.{JWT_SEGMENT_PREFIX}{}.{}",
            rng.take(ALNUM, 34),
            rng.take(BASE64URL, 40),
            rng.take(BASE64URL, 43)
        ),
        _ => return None,
    };
    Some(value)
}

/// An alphanumeric password of `length`, guaranteed to carry a lowercase
/// letter, an uppercase letter and a digit, so that a value never lands on the
/// pack's word-shape allowlists by accident and the corpus measures the rule
/// rather than the draw. `extra` adds punctuation from that alphabet.
fn password(rng: &mut Rng, length: usize, extra: &str) -> String {
    let mut value: Vec<char> = rng.take(ALNUM, length).chars().collect();
    let mut required: Vec<char> = vec![
        rng.take(LOWER, 1).chars().next().expect("one lower"),
        rng.take(UPPER, 1).chars().next().expect("one upper"),
        rng.take(DIGIT, 1).chars().next().expect("one digit"),
    ];
    if !extra.is_empty() {
        for _ in 0..3 {
            required.push(rng.take(extra, 1).chars().next().expect("one punctuation"));
        }
    }
    let last = value.len() - 1;
    let mut at = 0;
    for symbol in required {
        if at < value.len() {
            let slot = (at + rng.below((value.len() - at).max(1))).min(last);
            value[slot] = symbol;
            at = slot + 1;
        }
    }
    value.into_iter().collect()
}

/// A password of `length` carrying two non-ASCII letters, which is what a
/// password policy that accepts unicode produces.
fn unicode_password(rng: &mut Rng, length: usize) -> String {
    let mut value: Vec<char> = password(rng, length, "").chars().collect();
    for _ in 0..2 {
        let slot = rng.below(value.len());
        value[slot] = rng.take(NON_ASCII, 1).chars().next().expect("one letter");
    }
    value.into_iter().collect()
}

/// A password of `length` carrying one unencoded `symbol`, which is what a
/// generated password looks like when nobody encoded it before pasting it into
/// a URL.
fn infix(rng: &mut Rng, length: usize, symbol: char) -> String {
    let mut value: Vec<char> = password(rng, length, "").chars().collect();
    let last = value.len() - 1;
    let slot = (1 + rng.below(value.len().saturating_sub(2).max(1))).min(last);
    value[slot] = symbol;
    value.into_iter().collect()
}

/// A password whose special characters were percent-encoded on the way into a
/// URL, which is the correct way to carry one and still a credential.
fn percent_encoded(rng: &mut Rng, length: usize) -> String {
    let body = password(rng, length.saturating_sub(6).max(4), "");
    let cut = body.len() / 2;
    format!("{}%40{}%2F", &body[..cut], &body[cut..])
}

/// A password that spells a word the pack's placeholder allowlists match on.
/// This is the shape a leaked database credential most often has.
fn word_password(rng: &mut Rng, length: usize, name: &str) -> String {
    let word = WORDS[name.len() % WORDS.len()];
    let tail = length.saturating_sub(word.len()).max(4);
    format!("{word}{}", password(rng, tail, ""))
}

// -------------------------------------------------------------- measurement

struct Measurement {
    /// Rule ids reported per corpus line.
    reported: BTreeMap<(String, u64), Vec<String>>,
    rows: Vec<Row>,
    lines_per_file: BTreeMap<String, u64>,
}

fn measure() -> Measurement {
    let rules: Vec<CompiledRule> =
        load_str(default_rules(), "default-pack").expect("the default pack loads");

    let mut reported: BTreeMap<(String, u64), Vec<String>> = BTreeMap::new();
    let mut lines_per_file = BTreeMap::new();

    for relative in corpus_files() {
        let absolute = Path::new(CORPUS_DIR).join("tree").join(&relative);
        let raw = fs::read_to_string(&absolute)
            .unwrap_or_else(|error| panic!("{} is readable UTF-8: {error}", absolute.display()));
        lines_per_file.insert(relative.clone(), raw.lines().count() as u64);

        let content = materialize(&relative, &raw);
        let findings = secret::scan_file(&rules, &relative, None, &content)
            .expect("every pattern the corpus reaches compiles");
        for finding in findings {
            reported
                .entry((relative.clone(), finding.line))
                .or_default()
                .push(finding.rule_id);
        }
    }
    for hits in reported.values_mut() {
        hits.sort();
        hits.dedup();
    }

    Measurement {
        reported,
        rows: load_manifest(),
        lines_per_file,
    }
}

impl Measurement {
    fn hits(&self, path: &str, line: u64) -> &[String] {
        self.reported
            .get(&(path.to_string(), line))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Positives the pack failed to report, as `path:line expected got`.
    fn misses(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|row| row.expect.is_positive())
            .filter(|row| !row.expect.satisfied_by(self.hits(&row.path, row.line)))
            .map(|row| {
                format!(
                    "  MISS {}:{} expected {} got {:?} - {}",
                    row.path,
                    row.line,
                    row.expect.describe(),
                    self.hits(&row.path, row.line),
                    row.justification
                )
            })
            .collect()
    }

    /// Negatives the pack reported anyway.
    fn spurious(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|row| !row.expect.is_positive())
            .filter(|row| !row.expect.satisfied_by(self.hits(&row.path, row.line)))
            .map(|row| {
                format!(
                    "  SPURIOUS {}:{} reported {:?} - {}",
                    row.path,
                    row.line,
                    self.hits(&row.path, row.line),
                    row.justification
                )
            })
            .collect()
    }

    /// Classified lines carrying a rule id the manifest does not account for.
    /// A line reported by two rules is one credential reported twice, which
    /// neither the recall nor the precision number can see: both are satisfied
    /// by the first id and stop looking.
    fn unexpected(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter_map(|row| {
                let hits = self.hits(&row.path, row.line);
                let extra = row.expect.unexpected(hits);
                if extra.is_empty() {
                    return None;
                }
                Some(format!(
                    "  UNEXPECTED {}:{} expected {} got {:?}, unaccounted for: {:?} - {}",
                    row.path,
                    row.line,
                    row.expect.describe(),
                    hits,
                    extra,
                    row.justification
                ))
            })
            .collect()
    }

    /// Findings on lines the manifest does not classify. Not a failure on its
    /// own - a rule may legitimately report a line the corpus does not measure
    /// - but printed so that a new false positive cannot hide.
    fn unclassified(&self) -> Vec<String> {
        self.reported
            .iter()
            .filter(|((path, line), _)| {
                !self
                    .rows
                    .iter()
                    .any(|row| row.path == *path && row.line == *line)
            })
            .map(|((path, line), ids)| format!("  UNCLASSIFIED {path}:{line} reported {ids:?}"))
            .collect()
    }

    fn positives(&self) -> usize {
        self.rows
            .iter()
            .filter(|row| row.expect.is_positive())
            .count()
    }

    fn negatives(&self) -> usize {
        self.rows.len() - self.positives()
    }

    fn recall(&self) -> f64 {
        let total = self.positives();
        (total - self.misses().len()) as f64 / total as f64
    }

    fn precision(&self) -> f64 {
        let total = self.negatives();
        (total - self.spurious().len()) as f64 / total as f64
    }

    fn report(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "\ndetection corpus: {} files, {} positives, {} negatives\n",
            self.lines_per_file.len(),
            self.positives(),
            self.negatives()
        ));
        out.push_str(&format!(
            "RECALL    {:.4} ({} of {} positives reported, floor {RECALL_FLOOR:.2})\n",
            self.recall(),
            self.positives() - self.misses().len(),
            self.positives()
        ));
        out.push_str(&format!(
            "PRECISION {:.4} ({} of {} negatives left alone, floor {PRECISION_FLOOR:.2})\n",
            self.precision(),
            self.negatives() - self.spurious().len(),
            self.negatives()
        ));
        for line in self.misses() {
            out.push_str(&line);
            out.push('\n');
        }
        for line in self.spurious() {
            out.push_str(&line);
            out.push('\n');
        }
        for line in self.unexpected() {
            out.push_str(&line);
            out.push('\n');
        }
        for line in self.unclassified() {
            out.push_str(&line);
            out.push('\n');
        }
        out
    }
}

// -------------------------------------------------------------------- tests

/// The corpus and its manifest have to agree before either number means
/// anything: a row pointing at a line that does not exist measures nothing,
/// and a duplicated row would count one case twice.
#[test]
fn the_corpus_and_its_manifest_agree() {
    let measurement = measure();
    assert!(
        measurement.lines_per_file.len() >= 14,
        "the corpus spans at least fourteen file shapes, found {}",
        measurement.lines_per_file.len()
    );
    assert!(
        measurement.positives() >= 120,
        "the corpus carries at least 120 positives, found {}",
        measurement.positives()
    );
    assert!(
        measurement.negatives() >= 80,
        "the corpus carries at least 80 negatives, found {}",
        measurement.negatives()
    );

    let mut seen: Vec<(&str, u64)> = Vec::new();
    for row in &measurement.rows {
        let lines = measurement
            .lines_per_file
            .get(&row.path)
            .unwrap_or_else(|| panic!("manifest names {}, which is not in the corpus", row.path));
        assert!(
            row.line >= 1 && row.line <= *lines,
            "manifest points at {}:{}, which has {lines} lines",
            row.path,
            row.line
        );
        let key = (row.path.as_str(), row.line);
        assert!(
            !seen.contains(&key),
            "manifest carries {}:{} twice",
            row.path,
            row.line
        );
        seen.push(key);
    }
}

/// Every credential marker in the corpus resolves to a value. A marker that
/// did not would leave the literal text in place, and the line would be a
/// positive the pack could never report.
#[test]
fn every_credential_marker_resolves() {
    for relative in corpus_files() {
        let absolute = Path::new(CORPUS_DIR).join("tree").join(&relative);
        let raw = fs::read_to_string(&absolute)
            .unwrap_or_else(|error| panic!("{} is readable UTF-8: {error}", absolute.display()));
        let materialized = materialize(&relative, &raw);
        let left = markers(&materialized);
        assert!(
            left.is_empty(),
            "{relative} still carries credential markers after substitution: {left:?}"
        );
    }
}

/// No file in the repository may spell a complete credential: the corpus on
/// disk carries markers, and the values exist only in this process. This is
/// what keeps the corpus publishable - in a crate, in a push, in a mirror -
/// without arming every scanner that reads it.
///
/// Measured on the bytes as committed. A marker is itself a run of characters
/// sitting where a credential goes, and whether the pack reads it as one is the
/// whole question: substituting or redacting the markers first would measure a
/// file nobody has, not the one in the repository.
#[test]
fn no_corpus_file_spells_a_credential() {
    let rules: Vec<CompiledRule> =
        load_str(default_rules(), "default-pack").expect("the default pack loads");
    for relative in corpus_files() {
        let absolute = Path::new(CORPUS_DIR).join("tree").join(&relative);
        let raw = fs::read_to_string(&absolute)
            .unwrap_or_else(|error| panic!("{} is readable UTF-8: {error}", absolute.display()));
        let findings = secret::scan_file(&rules, &relative, None, &raw)
            .expect("every pattern the corpus reaches compiles");
        let reported: Vec<String> = findings
            .into_iter()
            .map(|finding| format!("{}:{} {}", relative, finding.line, finding.rule_id))
            .collect();
        assert!(
            reported.is_empty(),
            "the corpus source carries a detectable credential: {reported:?}"
        );
    }
}

#[test]
fn detection_recall_meets_its_floor() {
    let measurement = measure();
    let recall = measurement.recall();
    assert!(
        recall >= RECALL_FLOOR,
        "{}\nrecall {recall:.4} is below the floor {RECALL_FLOOR:.2}",
        measurement.report()
    );
}

/// Every rule id on a measured line is one the manifest accounts for. The two
/// floors are per line and are satisfied by the first matching id, so without
/// this a credential reported by two rules reads as a clean hit on both.
#[test]
fn no_measured_line_carries_an_unaccounted_rule() {
    let measurement = measure();
    let unexpected = measurement.unexpected();
    assert!(
        unexpected.is_empty(),
        "{}\n{} measured lines carry a rule id the manifest does not account for",
        measurement.report(),
        unexpected.len()
    );
}

#[test]
fn detection_precision_meets_its_floor() {
    let measurement = measure();
    let precision = measurement.precision();
    assert!(
        precision >= PRECISION_FLOOR,
        "{}\nprecision {precision:.4} is below the floor {PRECISION_FLOOR:.2}",
        measurement.report()
    );
}
