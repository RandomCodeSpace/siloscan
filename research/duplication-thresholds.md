# Duplication thresholds and density formula: what the industry uses

Resolves RandomCodeSpace/siloscan#23. Researched 2026-08-04 against primary
sources (official docs and release notes) for PMD CPD, SonarQube, and jscpd.

## Question

What minimum duplicate-block sizes (lines/tokens) and density formulas do
PMD CPD, SonarQube, and jscpd use, how do they handle overlapping blocks,
and what should siloscan v1.1 adopt for its line-based detector?

## Findings

### 1. Default minimum block sizes

| Tool | Unit | Default | Notes |
|------|------|---------|-------|
| PMD CPD (CLI) | tokens | none - `--minimum-tokens` is required | "The minimum token length which should be reported as a duplicate." Marked required in the CLI docs. |
| PMD CPD (Maven plugin) | tokens | 100 | `minimumTokens` default: 100. The de facto industry default. |
| SonarQube (non-Java) | tokens + lines | 100 tokens spanning >= 10 lines | 30 lines for COBOL, 20 for ABAP, 10 for other languages. Not configurable. |
| SonarQube (Java) | statements | 10 successive statements | "whatever the number of tokens and lines" |
| jscpd | tokens and lines | `min-tokens` 50, `min-lines` 5 | Blocks smaller than either are skipped. `max-lines` 1000 skips oversized files. |

Sources:
- PMD CPD docs: https://docs.pmd-code.org/latest/pmd_userdocs_cpd.html
- Maven PMD plugin: https://maven.apache.org/plugins/maven-pmd-plugin/cpd-mojo.html
- SonarQube metric definitions (2025.4 LTA):
  https://docs.sonarsource.com/sonarqube-server/2025.4/user-guide/code-metrics/metrics-definition
- jscpd README: https://github.com/kucherenko/jscpd/blob/master/apps/jscpd/README.md

Per-language differences exist only in SonarQube (COBOL 30 / ABAP 20 /
Java 10 statements / others 10 lines). PMD CPD and jscpd use one global
default across languages.

SonarQube also states: "Differences in indentation and in string literals
are ignored while detecting duplications" - i.e. it normalizes before
hashing, the same family of approach as siloscan's normalized line-hash.

### 2. SonarQube density formula and quality gate

Exact formula from the metric definitions page:

    duplicated_lines_density = duplicated_lines / lines * 100

where `duplicated_lines` is "the number of lines involved in duplications"
and `lines` is total lines. Companion metrics: `duplicated_blocks`
("the number of duplicated blocks of lines") and `duplicated_files`.

Quality gate: the built-in "Sonar way" gate fails when duplicated lines
density on new code exceeds 3.0% ("duplication in the new code is less
than or equal to 3.0%").
https://docs.sonarsource.com/sonarqube-server/quality-standards-administration/managing-quality-gates/introduction-to-quality-gates

jscpd reports the same shape of number (e.g. "3414(46.81%) duplicated
lines"), i.e. duplicated lines / total lines. Its `threshold` option
(default null) makes the tool "exit with error" when the duplication
level exceeds it - same gate mechanic as SonarQube's.

### 3. Overlapping and nested blocks

- PMD CPD: since 7.1.0, "CPD will report only the longest non-overlapping
  duplicate." Before that it could "report duplicate overlapping or
  partially overlapping matches", which was treated as a bug and fixed.
  https://pmd.github.io/2024/04/26/PMD-7.1.0/
- SonarQube: docs do not describe overlap resolution. Unverified, but the
  density formula only works sanely if each line is counted at most once
  in `duplicated_lines` regardless of how many blocks contain it.
- jscpd: overlap handling is not documented. It uses Rabin-Karp over a
  token stream ("jscpd implements the Rabin-Karp algorithm to find
  duplicated code blocks across files"); merge/extension behavior of
  adjacent windows is unverified from docs.

Industry consensus where stated: report the longest match, never
overlapping fragments of the same region, and count each line once
in the density numerator.

### 4. Recommendation for siloscan v1.1

1. Minimum block size: default `min_lines = 10` for the line-based
   detector. This matches SonarQube's "10 lines of code for other
   languages" floor and sits above jscpd's noisy 5-line default. Since
   siloscan hashes normalized lines rather than tokens, a token minimum
   does not apply; 10 normalized (non-blank, post-normalization) lines
   approximates CPD's 100-token default for typical code.
2. Density formula: adopt SonarQube's exactly -
   `duplicated_lines / total_lines * 100`, with each physical line
   counted at most once in the numerator no matter how many clone pairs
   cover it. Report `duplicated_blocks` and `duplicated_files` alongside,
   same names, for familiarity.
3. Overlap handling: extend rolling-window matches greedily and emit only
   the longest non-overlapping block per region (PMD 7.1.0 behavior).
   Suppress nested sub-matches of an already-reported block.
4. Configuration: put `min_lines` and a fail `threshold` (density %) in
   siloscan.toml under a `[duplication]` table, defaults `min_lines = 10`,
   `threshold` unset (report-only). Every surveyed tool exposes exactly
   these two knobs (CPD: minimum-tokens; jscpd: min-lines/min-tokens +
   threshold; SonarQube: fixed detector but gate threshold 3%). Hardcoding
   them in v1.1 would only guarantee a v1.2 request. Keep the detection
   internals (normalization rules, window mechanics) fixed and
   non-configurable, as SonarQube does.

## Caveats

- PMD CLI has no default minimum-tokens; 100 is the Maven plugin default
  and the value used throughout PMD's own examples. Other wrappers
  (Gradle, Ant) were not checked.
- SonarQube's overlap/line-counting behavior is inferred, not documented
  (marked unverified above).
- jscpd overlap/merge behavior: unverified; not in the README.
- All numbers were read from live docs on 2026-08-04; versioned links
  point at SonarQube Server 2025.4 LTA and current PMD/jscpd docs.
