# Research: Secrets detection - gitleaks ruleset reuse and entropy strategy

Ticket: RandomCodeSpace/siloscan#5
Date: 2026-08-03
Method: primary sources only (GitHub repos, LICENSE files, rule configs).

## Question

Can the gitleaks ruleset be reused in siloscan? What is its exact license and is
redistribution/translation of the rules permitted? How feasible is translating
gitleaks rules (regex + entropy + keywords + allowlists) into siloscan's own
YAML schema? What entropy thresholds and false-positive mitigations do mature
scanners (gitleaks, trufflehog, detect-secrets) actually use?

## Findings

### 1. Licenses (verified against LICENSE files, 2026-08-03)

| Project | License | Ruleset reusable? |
|---|---|---|
| gitleaks/gitleaks | MIT License (Copyright 2019 Zachary Rice) | Yes. Redistribution and modification permitted; must retain copyright and permission notice. |
| trufflesecurity/trufflehog | GNU Affero General Public License, Version 3 (AGPL-3.0) | No, not for an MIT/Apache project. Copyleft; also detectors are Go code, not data. |
| Yelp/detect-secrets | Apache License, Version 2.0 (Copyright 2017-2018 Yelp Inc.) | Yes, with NOTICE/attribution obligations. Mostly useful for its entropy heuristics, not a ruleset. |

Sources:
- https://github.com/gitleaks/gitleaks/blob/master/LICENSE
- https://github.com/trufflesecurity/trufflehog/blob/main/LICENSE
- https://github.com/Yelp/detect-secrets/blob/master/LICENSE

Conclusion on reuse: the gitleaks default config (config/gitleaks.toml) is part
of the MIT-licensed repository. Translating it into siloscan's YAML schema is a
derivative work, which MIT explicitly permits, provided the MIT copyright and
permission notice is carried alongside the translated rules (e.g. a
rules/secrets/LICENSE.gitleaks file plus a provenance header in each generated
file).

### 2. Gitleaks rule model (config/gitleaks.toml)

Approximately 250+ rules. Each rule is declarative TOML with:

- id, description, tags
- regex: Go (RE2) regular expression
- secretGroup: capture group index containing the actual secret
- entropy: minimum Shannon entropy the secret group must exceed
- keywords: literal substrings used as a cheap pre-filter before regex runs
- path: optional file-path regex
- allowlists: rule-level exceptions

Example rules (from config/gitleaks.toml):

- anthropic-api-key: regex `\b(sk-ant-api03-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`,
  entropy 3.5, keyword `sk-ant-api03`
- stripe-access-token: regex `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)`,
  entropy 2, keywords `sk_test`, `sk_live`, ...
- github-fine-grained-pat: regex `github_pat_\w{82}`, entropy 3, keyword `github_pat_`

Entropy thresholds in the default config range roughly 1.0-4.5:
~2.0 for strongly-prefixed tokens (prefix already disambiguates),
3.0-3.5 for typical API tokens, 4.0+ for generic high-entropy rules.
Entropy is Shannon entropy (log2) computed over the extracted secret group,
used as a confirmation gate after the regex matches - never as a standalone
detector.

Global allowlist components:
- path excludes: lockfiles, vendored deps, binaries (.dll/.exe/.pdf/.docx),
  minified JS, go.mod, gitleaks' own config
- regex excludes: placeholder/template values ($VAR, {{var}}, %ENV%),
  trivially repetitive strings
- stopwords: ~1000 common programming words checked against the extracted
  secret value (e.g. "api", "token", "example")

Allowlist semantics worth copying: `condition = "OR" | "AND"` across
commit/path/regex/stopword criteria, and `regexTarget = secret | match | line`.
Config extension (`[extend] useDefault`, `disabledRules`) is a good model for
siloscan's rule layering.

Sources:
- https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml
- https://github.com/gitleaks/gitleaks (README, Configuration section)

### 3. Trufflehog strategy (for comparison only)

- ~800 detectors, each hand-written Go code, not declarative config.
  Not translatable as data, and AGPL-3.0 regardless.
- Primary false-positive strategy is live verification: call the service API
  (e.g. AWS GetCallerIdentity) and report verified/unverified/unknown;
  `--results=verified` filters to confirmed credentials only.
- Live verification is off the table for siloscan (offline, deterministic),
  which makes the gitleaks approach (keywords + regex + entropy + allowlists)
  the correct reference architecture, not trufflehog's.
- Also offers `--filter-entropy` for unverified results and
  `trufflehog:ignore` line comments.

Source: https://github.com/trufflesecurity/trufflehog (README)

### 4. detect-secrets strategy

- Two generic entropy plugins over string tokens:
  Base64HighEntropyString default limit 4.5 (charset of 64, max entropy 6.0)
  and HexHighEntropyString default limit 3.0 (charset of 16, max entropy 4.0).
  Limits are Shannon entropy, tunable 0.0-8.0.
- Plus regex detectors and a keyword detector (suspicious variable names like
  password/secret/api_key followed by a quoted value).
- False-positive mitigations: a .secrets.baseline snapshot file (only new
  findings alert), inline `# pragma: allowlist secret` comments,
  --exclude-lines / --exclude-files / --exclude-secrets regexes, word lists,
  and heuristic filters (e.g. is_prefixed_with_dollar_sign, is_likely_id_string,
  UUID/lockfile/templated-secret filters).

Source: https://github.com/Yelp/detect-secrets (README)

## Recommendation

1. Adopt gitleaks' default ruleset as siloscan's seed corpus for secrets
   detection. License is MIT; translation into siloscan YAML is permitted.
   Ship the MIT notice with the translated rules and record provenance
   (source rule id + gitleaks version/commit) per rule.
2. Build the translation as a one-shot converter (TOML -> siloscan YAML)
   rather than a hand port: the schema maps nearly 1:1
   (id/description/regex/secretGroup/entropy/keywords/path/allowlists).
   Two compatibility notes:
   - Gitleaks regexes are Go RE2. If siloscan uses the rust `regex` crate
     (also RE2-class, no backrefs/lookaround), translation is near-verbatim;
     validate each pattern at conversion time and flag failures.
   - Preserve keyword pre-filtering (Aho-Corasick over file content before
     regex) - it is the main performance lever in both gitleaks and trufflehog.
3. Entropy strategy: use entropy only as a per-rule confirmation gate on the
   extracted secret group (gitleaks model), thresholds per rule (2.0-4.5).
   If a generic high-entropy rule is added, use detect-secrets' defaults as
   the starting point: 4.5 for base64-charset strings, 3.0 for hex.
4. False-positive controls to implement, in priority order:
   a. global path allowlist (lockfiles, vendor dirs, minified assets, binaries)
   b. stopword check on the extracted secret value
   c. placeholder/template regex allowlist ($VAR, {{var}}, %s, xxxx...)
   d. rule-level allowlists with OR/AND conditions and regexTarget
   e. inline suppression comment (pick one marker, e.g. `siloscan:ignore`)
   f. optional baseline file (detect-secrets model) for brownfield adoption
5. Do not copy anything from trufflehog (AGPL-3.0, and code-based detectors);
   use it only as a design reference. Its verification feature does not fit
   siloscan's offline constraint.

## Caveats

- Rule count ("250+"), entropy distribution, and example rules were read from
  config/gitleaks.toml on master as of 2026-08-03; the file changes frequently.
  Pin a specific gitleaks release tag when converting.
- The gitleaks TOML is generated from Go generators in cmd/generate/config;
  both the generator and the generated TOML live in the same MIT-licensed
  repo, so either is a valid translation source. (Generator location:
  from memory, not re-verified this session.)
- MIT permits translation but this is not legal advice; the attribution
  approach above (carry LICENSE + provenance) is standard practice, not a
  reviewed legal opinion.
- detect-secrets' HexHighEntropyString applies an extra heuristic that
  discounts purely numeric strings (unverified: from memory, not re-checked
  against source this session).
- Exact per-rule entropy values should be taken from the pinned TOML at
  conversion time, not from this document.
