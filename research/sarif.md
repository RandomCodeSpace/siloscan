# Research: minimal SARIF 2.1.0 output profile for siloscan

Ticket: RandomCodeSpace/siloscan#6
Date: 2026-08-03

## Question

Should siloscan use the `serde-sarif` crate or hand-roll SARIF serialization?
What is the smallest SARIF 2.1.0 subset that GitHub code scanning accepts
(required fields, runs/results/rules structure, level mapping, location
format), and what are GitHub's documented limits (result counts, file size)?

## Sources

- OASIS SARIF 2.1.0 spec:
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
- GitHub "SARIF support for code scanning":
  https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- serde-sarif: https://crates.io/crates/serde-sarif /
  https://docs.rs/serde-sarif / https://github.com/psastras/sarif-rs

## Findings

### 1. Spec-level minimum (OASIS SARIF 2.1.0)

Properties the spec itself mandates ("SHALL"):

- `sarifLog.version` (sec 3.13.2) and `sarifLog.runs` (sec 3.13.4).
  `$schema` is optional at spec level.
- `run.tool` (sec 3.14.6); `toolComponent.name` (sec 3.19.8).
- `result.message` (sec 3.27.11). `ruleId` and `level` are optional;
  `level` values are `none | note | warning | error` (sec 3.27.10) with
  default `warning`, overridable per rule via
  `reportingDescriptor.defaultConfiguration.level`.
- `physicalLocation`: at least one of `artifactLocation` or `address`
  (sec 3.29.2). `artifactLocation`: at least one of `uri` or `index`
  (sec 3.4.2). `region.startLine` is not spec-required.

### 2. GitHub code scanning profile (stricter than the spec)

Per GitHub's supported-properties tables:

- Required on `sarifLog`: `$schema`, `version: "2.1.0"`, `runs[]`.
  Suggested schema URI: `https://json.schemastore.org/sarif-2.1.0.json`.
- Required on `run`: `tool.driver`. `results[]` is listed optional but is
  the whole point of the upload.
- Required on `tool.driver` (toolComponent): `name`, `rules[]`.
  Optional: `version`, `semanticVersion`.
- Required on each rule (`reportingDescriptor`): `id`,
  `shortDescription.text`, `fullDescription.text`, `help.text`.
  Recommended: `help.markdown`, `properties.precision`
  (`very-high | high | medium | low`), `properties.problem.severity`
  (`error | warning | recommendation`), `properties.security-severity`
  (numeric string 0.1-10.0; >=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium,
  0.1-3.9 low). Optional: `defaultConfiguration.level`, `properties.tags[]`.
- Required on each `result`: `message.text`, `locations[]`,
  `partialFingerprints`. `ruleId`, `ruleIndex`, `level` optional.
  Note: `partialFingerprints` is marked required to prevent duplicate
  alerts; the `github/codeql-action/upload-sarif` action computes
  `primaryLocationLineHash` if absent, but direct API uploads should
  include it. (The exact fingerprint key GitHub computes is
  `primaryLocationLineHash`; unverified: its exact hashing algorithm is
  not documented.)
- Required on `physicalLocation`: `artifactLocation.uri` plus
  `region.startLine`, `region.startColumn`, `region.endLine`,
  `region.endColumn` per GitHub's table. `uri` must be a path relative to
  the repository root for alerts to be shown in-file.
- Empty strings are rejected for any required property.

Level mapping (GitHub alert severity): result `level` `error | warning |
note` maps directly; if `level` is absent, `defaultConfiguration.level` of
the matching rule applies, else spec default `warning`. For security
severity classification GitHub uses the rule's
`properties.security-severity` score instead.

### 3. GitHub documented limits

| Constraint                        | Limit                              |
|-----------------------------------|------------------------------------|
| SARIF upload size (gzip)          | 10 MB                              |
| Runs per file                     | 20                                 |
| Results per run                   | 25,000 (top 5,000 displayed)       |
| Rules per run                     | 25,000                             |
| Locations per result              | 1,000 (100 displayed)              |
| threadFlow locations per result   | 10,000 (top 1,000 displayed)       |
| Tags per rule                     | 20 (10 displayed)                  |

siloscan should cap or truncate at 25,000 results per run and emit a
warning when it does.

### 4. serde-sarif crate assessment

- Version 0.8.0, MIT, published 2025-05-09. ~2.4M total downloads.
- Repo psastras/sarif-rs: active (last push 2026-07-30), not archived,
  22 open issues, MIT.
- Types are generated at build time from the SARIF JSON schema (vendored;
  build is offline). Construction is via `TypedBuilder`-derived builders;
  optional converter feature flags (clippy, clang-tidy, etc.) are
  irrelevant here.
- Cost: it materializes the entire SARIF 2.1.0 schema (hundreds of
  optional fields), adds a build script plus the `typed-builder`
  dependency, and its output shape is dictated by generated structs.

## Minimal skeleton accepted by GitHub

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "siloscan",
          "version": "0.1.0",
          "informationUri": "https://github.com/RandomCodeSpace/siloscan",
          "rules": [
            {
              "id": "SILO001",
              "shortDescription": { "text": "Hardcoded secret" },
              "fullDescription": { "text": "A credential is embedded in source." },
              "help": { "text": "Move the secret to environment configuration." },
              "defaultConfiguration": { "level": "error" },
              "properties": {
                "precision": "high",
                "problem.severity": "error",
                "security-severity": "8.5"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "SILO001",
          "ruleIndex": 0,
          "level": "error",
          "message": { "text": "Hardcoded secret detected." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "src/config.rs" },
                "region": {
                  "startLine": 12,
                  "startColumn": 5,
                  "endLine": 12,
                  "endColumn": 42
                }
              }
            }
          ],
          "partialFingerprints": {
            "primaryLocationLineHash": "39fa2ee980eb94b0:1"
          }
        }
      ]
    }
  ]
}
```

## Recommendation

Hand-roll the minimal profile with plain `serde` derive structs.

Rationale:

- The accepted subset above is roughly a dozen structs with `Serialize`
  derives and `skip_serializing_if = "Option::is_none"`. That is under
  200 lines, fully controlled, and trivially deterministic (struct field
  order fixes JSON key order, which matters for siloscan's determinism
  guarantee).
- siloscan already needs `serde`/`serde_json` for its JSON output mode,
  so the SARIF writer adds zero new dependencies. `serde-sarif` would add
  a generated full-schema surface plus `typed-builder` for a subset we
  can type in an afternoon.
- Determinism and offline goals favor owning the output shape outright.

Guardrails for the hand-rolled writer:

- Validate serialized output against the official SARIF 2.1.0 JSON schema
  in a unit test (schema vendored into the repo; `jsonschema` crate as a
  dev-dependency only).
- Always emit `$schema`, `version`, non-empty required strings,
  repo-relative `uri` paths, all four region fields, and a stable
  `partialFingerprints` entry (e.g. hash of rule id + relative path +
  line content) so duplicate alerts do not appear on API uploads.
- Enforce the 25,000 results/run cap with truncation plus a stderr
  warning; keep gzip size under 10 MB.

Fallback: if siloscan later needs codeFlows, taxonomies, or SARIF
ingestion (reading, not writing), switch to `serde-sarif` 0.8.0 (MIT,
actively maintained) rather than growing the hand-rolled model.

## Open caveats

- unverified: the exact algorithm behind GitHub's
  `primaryLocationLineHash` fingerprint is not publicly documented; any
  stable per-result hash siloscan emits under `partialFingerprints` is
  acceptable to GitHub as long as it is consistent across runs.
- GitHub's table marks `region.startColumn`/`endLine`/`endColumn` as
  required; other validators accept `startLine` alone (spec-legal).
  Emitting all four costs nothing - do it.
- Message display truncates to the first sentence in tight UI; no hard
  character limit is documented.
- Limits table is GitHub's current documentation as of 2026-08-03;
  GitHub adjusts these occasionally.
