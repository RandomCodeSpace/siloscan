# Cross-platform saved-report contract

- Date: 2026-08-31
- Decision ticket: [Choose the cross-platform saved-report contract](https://github.com/RandomCodeSpace/siloscan/issues/61)
- Compatibility baseline: `880d211a463e97eb3c188f957e5592d88f36dcf8`

## Decision

The bare no-argument `siloscan` journey writes one canonical JSON report.
`ss` behaves identically. An explicit `PATH` or existing scan option keeps its
v1.5.1 no-write meaning unless the user adds the new `--save` flag or
`--output FILE`; `--no-save` disables the bare-command default. Baseline,
rule-test, cache, and review commands do not create a scan report.

The automatic destination for bare `siloscan` or `--save` is the current
user's platform state directory, grouped by a stable hash of the canonical
requested scan scope:

```text
<state>/siloscan/reports/<scope-key>/latest.json
```

An explicit `--output FILE` selects that file instead of the automatic
destination. `--save`, `--output`, and `--no-save` are mutually exclusive, so
one scan writes at most one report. `siloscan review` opens an explicit report
when given one; otherwise it resolves the requested scan scope exactly as a
scan does and opens that scope's `latest.json`.

The writer serializes the complete report into a unique temporary file beside
`latest.json`, synchronizes it, then publishes it with the platform's atomic
replacement primitive. It never truncates or deletes the old file first.
Readers therefore get the old complete report or the new complete report on
the supported local filesystems. Temporary files are never review candidates.

This is one replaceable report, as the map requires. There is no hidden report
history, latest index, cache fallback, or automatic repository write.

## Contract summary

| Concern | Chosen contract |
| --- | --- |
| Linux state root | `$XDG_STATE_HOME`, else `$HOME/.local/state` |
| macOS state root | User Application Support directory |
| Windows state root | `FOLDERID_LocalAppData` |
| Application path | `siloscan/reports/<scope-key>/latest.json` |
| Repository isolation | Reject an automatic report directory inside the scan boundary or nearest `.git` boundary |
| Scope key | Full SHA-256 of a versioned, platform-native encoding of the canonical requested scan path and its file kind |
| Automatic save | Bare `siloscan` and `ss`; `--save` opts an explicit scan into its scope's latest slot |
| Explicit file | `--output FILE` writes there instead of updating `latest.json` |
| Stateless scan | Existing explicit invocations remain stateless; `--no-save` disables bare auto-save |
| Persistence conflicts | `--save`, `--output`, and `--no-save` are pairwise exclusive |
| Successful scan and save | Existing status 0 or 1, decided by findings |
| Save failure | Status 2; never claim that a report was saved |
| Replacement | Unique same-directory temporary, serialize, flush, sync, then platform-atomic replacement |
| Interrupted write | Old `latest.json` stays authoritative; temporary is ignored |
| Invalid latest report | Review fails with status 2; it does not pretend a temporary or unrelated report is current |
| Review with explicit report | Load that file directly with the extended version-tolerant snapshot reader |
| Review without explicit report | Resolve the same requested scan scope, derive its key, load its `latest.json` |
| Serialized time or host | None; the canonical report stays deterministic |
| Performance | No second walk, rescan, or cloned report; saved and stateless paths must pass the map's 5% gates |

## Why this fits the existing code

The pinned JSON writer already emits a deterministic, pretty-printed report
with tool version, schema version, findings, skipped files, metrics, anchor,
warnings, and output filtering. It also redacts secret matches before they
reach the serialized report. The new saved file should use that writer instead
of creating another report format. [Pinned JSON writer](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/output.rs#L9-L172)

The snapshot reader accepts supported `1.x` reports, ignores unknown fields,
and rejects unreadable JSON and unsupported major versions. Its legacy report
test is deliberately minimal: a `1.x` `schema_version` alone is currently
enough, so v2 must also require `report_kind = "scan"`, while retaining a
`findings`-array discriminator for genuine older reports. [Pinned snapshot reader](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-tui/src/snapshot.rs#L1-L234)

The baseline writer already proves the repository's preferred replacement
shape: serialize first, write beside the target, call `sync_all`, and rename.
The report writer should follow that tested shape on Unix and use the
Windows-specific publication call below. This ticket does not need to refactor
the already-correct baseline path merely to share a helper. [Pinned baseline writer](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/baseline.rs#L77-L166)

The current cache keys a scan root by its canonical path so relative, absolute,
and symlinked spellings meet at one directory. The saved-report key keeps that
useful behavior but uses a stable native encoding suitable for state that must
survive a Rust upgrade. Rust documents `OsStr::as_encoded_bytes` as unspecified
and only comparable within the same Rust version and target, so it is not the
right persisted identity encoding. [Pinned cache key](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/cache.rs#L1189-L1208), [Rust `OsStr` encoding](https://doc.rust-lang.org/std/ffi/struct.OsStr.html#method.as_encoded_bytes)

## State location

The report is durable local state. It is not a cache because `siloscan review`
depends on it remaining after the scan and across restarts. It is not project
data because a default scan must not dirty the scanned repository.

### Linux

Resolve the base in this order:

1. Use `XDG_STATE_HOME` when it is non-empty and absolute.
2. Otherwise use `$HOME/.local/state` when `HOME` is absolute.
3. If neither yields an absolute path, automatic persistence is unavailable.

The XDG Base Directory Specification defines state as data that persists
across application restarts but is not portable enough for the data directory.
It sets the fallback to `$HOME/.local/state`, requires XDG paths to be absolute,
and says an application should create a missing destination with mode `0700`.
[XDG Base Directory Specification](https://specifications.freedesktop.org/basedir/0.8/)

A relative `XDG_STATE_HOME` is invalid. Do not resolve it against the current
working directory. That would let the launch directory move Siloscan's own
state into the repository.

Default example:

```text
/home/alice/.local/state/siloscan/reports/<scope-key>/latest.json
```

### macOS

Ask the user-domain Application Support API for the base, then append
`siloscan/reports/<scope-key>/latest.json`. Do not hard-code a home-directory
string in the contract. Apple defines Application Support as the standard
location for app-managed support and state files. For a non-sandboxed CLI it
normally resolves under `~/Library/Application Support`. [Apple Application Support directory](https://developer.apple.com/documentation/foundation/url/applicationsupportdirectory), [Apple file-system guidance](https://developer.apple.com/documentation/foundation/using-the-file-system-effectively)

Typical non-sandboxed example:

```text
/Users/alice/Library/Application Support/siloscan/reports/<scope-key>/latest.json
```

### Windows

Call `SHGetKnownFolderPath` for `FOLDERID_LocalAppData`, then append
`siloscan\reports\<scope-key>\latest.json`. `FOLDERID_LocalAppData` is the
per-user, non-roaming application-data folder and normally maps to
`%LOCALAPPDATA%`. That matches a report whose identity is tied to a local
checkout path. [Microsoft Known Folder IDs](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid#folderid_localappdata), [SHGetKnownFolderPath](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath)

Typical example:

```text
C:\Users\Alice\AppData\Local\siloscan\reports\<scope-key>\latest.json
```

### No fallback location

If Siloscan cannot resolve or use the platform state root, it must not fall
back to any of these locations:

- the scanned repository;
- the current working directory;
- the cache directory;
- a shared temporary directory;
- the system-wide application-data directory.

The bare default or a `--save` scan reports the problem and exits 2. The message
points to `--no-save` for a deliberate stateless run and `--output FILE` for a
deliberate destination. A normal explicit scan that requested no persistence
never resolves the state root. Guessing a writable directory would make review
lookup depend on where the scan happened to fail.

### Keep automatic state outside the scan scope

Before creating anything, resolve the complete automatic report directory
`<state>/siloscan/reports/<scope-key>` through its longest existing canonical
ancestor and append the remaining fixed components. Protect both the requested
scope's canonical directory and the nearest ancestor repository boundary
identified by the same `.git` marker that bounds current config discovery. The
repository lookup exists only to prevent a write; it does not promote scan
scope or add a project fact. [Pinned repository boundary](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-core/src/config.rs#L214-L256)

Reject the automatic destination when that report directory is equal to or
below either protected boundary. For a single-file scan, protect its parent
directory plus the same repository boundary. This catches an `XDG_STATE_HOME`
inside a repository, a symlink at any existing state-path component that leads
into it, and the normal `$HOME/.local/state` fallback when the user is scanning
`$HOME` or an ancestor.

The containment failure exits 2 before creating a state directory or starting
the scan. It points to an outside `XDG_STATE_HOME`, `--no-save`, or an explicit
`--output FILE`. This is required by the settled walker contract: automatic
state must never become an input that the same scan discovers.

An explicit `--output FILE` is different. The user selected that path, and
Siloscan writes it only after the scan finishes. It may be inside the scope;
the no-repository-write promise applies to automatic state, not a named output.

### Permissions needed for correctness

On Unix, Siloscan creates its missing application, report, and scope-key
directories with mode `0700`, and creates automatic-report temporary files with
mode `0600`. On Linux it also creates a missing selected XDG state root with
mode `0700`, as the XDG specification requires. It sets those modes on objects
it just created so an unusually restrictive umask cannot leave the writer
unable to open its own report on the next run. It does not chmod an existing
parent or attempt an ownership audit.

On Windows, created objects inherit the ACL of `FOLDERID_LocalAppData`. No new
ACL policy belongs in this ticket.

For `--output`, Siloscan does not create missing parent directories or modify
their permissions. The user chose that location. The temporary file still sits
in the chosen file's existing parent so atomic publication cannot cross a file
system.

## Canonical saved-report identity

The state identity is the `scan_root` selected by `ResolvedScanPlan`. The
project-detection decision fixes that value to an explicit `PATH`, or `.` when
the user supplied none. Detection must not promote it to a Git root, manifest
directory, workspace root, or common ancestor because the requested path owns
scan scope, fingerprints, and state identity. [Project-detection scan-root decision](https://github.com/RandomCodeSpace/siloscan/blob/039565b66a16695e5084628a8de5a33f5f61d80f/research/project-detection-semantics.md#scan-root-and-ownership)

Resolve the requested path against the working directory, require it to be a
regular file or directory, and call `std::fs::canonicalize`. Rust defines
canonicalization as an absolute path with intermediate components normalized
and symbolic links resolved. On Windows it uses `CreateFile` and
`GetFinalPathNameByHandle`. [Rust `canonicalize`](https://doc.rust-lang.org/std/fs/fn.canonicalize.html)

Hash this byte sequence with SHA-256:

```text
"siloscan-scan-scope\0sha256-v1\0" || scope-kind || platform-encoding || canonical-path-bytes
```

`scope-kind` is exactly `"directory\0"` or `"file\0"`. Use these platform
encodings for the canonical path:

| Platform | `platform-encoding` | `canonical-path-bytes` |
| --- | --- | --- |
| Unix, including Linux and macOS | `"unix-bytes\0"` | `OsStrExt::as_bytes()` |
| Windows | `"windows-utf16le\0"` | Every lossless `encode_wide()` code unit written little-endian |

Rust exposes the underlying Unix byte view and a lossless Windows wide encoding
through platform-specific standard-library traits. [Unix `OsStrExt`](https://doc.rust-lang.org/std/os/unix/ffi/trait.OsStrExt.html), [Windows `OsStrExt`](https://doc.rust-lang.org/std/os/windows/ffi/trait.OsStrExt.html)

The directory name is the full 64-character lowercase digest. Do not truncate
it. The report records the self-describing value
`sha256-v1:<64-lowercase-hex>`.

This identity has deliberate local semantics:

- Relative, absolute, and symlinked spellings that canonicalize to one
  requested path and kind share a report.
- A repository-root scan, a nested-directory scan, and a single-file scan have
  different report slots. Review must be given the same scope to find latest.
- Separate Git worktrees have separate reports because their files can differ.
- Moving a scope creates a new identity. The old report remains reachable only
  by an explicit report path.
- Replacing a checkout at the same canonical path and kind reuses that slot.
- Detected units, manifests, Git remotes, branch names, and repository IDs do
  not enter the key. They are report facts, not scan-scope authority.

A requested path that cannot be canonicalized is a setup error for a saved or
JSON report. Siloscan must not hash a lossy display string or an unnormalized
input path. A human or SARIF `--no-save` run need not compute the identity.

## Directory and filename layout

The complete automatic layout is:

```text
<platform-state>/
  siloscan/
    reports/
      <64-hex-scope-key>/
        latest.json
        latest.json.<pid>.<counter>.tmp    # after an interrupted write only
```

`latest.json` is the only automatic review candidate. A temporary name uses the
destination's file name, process ID, and a process-local monotonic counter, then
opens with `create_new`. The automatic target therefore uses
`latest.json.<pid>.<counter>.tmp`; an explicit `report.json` uses
`report.json.<pid>.<counter>.tmp`. If a stale file collides after PID reuse,
increment and retry. Rust documents `create_new` as an atomic create-if-absent
operation. [Rust `File::create_new`](https://doc.rust-lang.org/std/fs/struct.File.html#method.create_new)

The layout intentionally has no date directory, report history, mutable index,
symlink, or pointer file. One successful scan replaces one file.

## Atomic replacement and recovery

### Write protocol

The writer follows this order:

1. When persistence was selected, resolve the final destination before
   scanning. For the bare default or `--save`, create missing directories under
   the resolved state root. For `--output`, require the parent to exist.
2. Complete the scan and prepare one immutable view of the report. Do not clone
   its finding or metrics collections for persistence.
3. Open the destination's unique sibling temporary with `create_new`.
4. Serialize one canonical JSON document to the temporary file and add one
   trailing newline. A serialization or write failure removes that temporary
   when possible and leaves the old report alone. A buffered writer must flush
   before the next step.
5. Call `sync_all` on the temporary file and handle the result. Rust says this
   attempts to synchronize file contents and metadata, while dropping a file
   ignores close errors. [Rust `File::sync_all`](https://doc.rust-lang.org/std/fs/struct.File.html#method.sync_all)
6. Publish with the platform operation below. The temporary and destination
   are siblings, so publication stays on one file system.
7. On Linux, open and synchronize the parent directory after publication.
   Linux documents that file `fsync` does not necessarily persist the
   directory entry and requires a separate directory `fsync`. [Linux `fsync(2)`](https://man7.org/linux/man-pages/man2/fsync.2.html)
8. Print the saved path only after the required publication steps succeed.

Do not use `std::fs::write` on `latest.json`. Rust implements that helper as
`File::create` followed by `write_all`, so an existing file is replaced before
the new bytes are complete and no synchronization step is included. [Rust `std::fs::write`](https://doc.rust-lang.org/std/fs/fn.write.html)

On Linux and macOS, close the temporary and use `std::fs::rename` over the
destination. Rust maps that operation to POSIX `rename` on Unix. POSIX requires
the destination name to remain visible throughout replacement and to refer to
either the old or new file. Linux documents the same namespace-atomic result.
[Rust `std::fs::rename`](https://doc.rust-lang.org/std/fs/fn.rename.html), [POSIX `rename`](https://pubs.opengroup.org/onlinepubs/9799919799/functions/rename.html), [Linux `rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)

On Windows, keep the synchronized temporary handle open with delete access and
call `SetFileInformationByHandle` using `FileRenameInfoEx` and both
`REPLACE_IF_EXISTS` (`0x1`) and `POSIX_SEMANTICS` (`0x2`) flags. Microsoft
specifies the required reader
semantics: an existing handle to the replaced file stays valid, while every
subsequent open of the destination gets the renamed file. Close the handle only
after the call succeeds. [Microsoft `SetFileInformationByHandle`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle), [Microsoft `FILE_RENAME_INFO`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info), [Microsoft `FileRenameInformationEx`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4217551b-d2c0-42cb-9dc1-69a716cf6d0c)

If `FileRenameInfoEx` or those semantics are unavailable on the running Windows
version or destination file system, saving fails with status 2. Do not fall
back to `MoveFileExW`, `ReplaceFileW`, delete-then-rename, or direct overwrite:
their cited contracts do not provide the same old-reader/new-reader guarantee.
The error points to `--no-save`; a supported Windows release target must pass
the replacement tests rather than silently weaken the contract.

The product claim stays precise: on a supported local file system, a concurrent
reader or normal process interruption sees an old complete report or a new
complete report, never a partially written document. Siloscan does not promise
survival after every device, network-file-system, kernel, or power failure.

### Failure and recovery table

| Failure point | Authoritative state | Required behavior |
| --- | --- | --- |
| Before temporary creation | Existing `latest.json`, or none | Return save error |
| During serialization or write | Existing `latest.json`; partial temporary may exist | Best-effort remove this run's temporary; review ignores it |
| During `sync_all` | Existing `latest.json`; temporary may exist | Return save error; review ignores temporary |
| Before publication | Existing `latest.json`; complete temporary may exist | Return save error; do not promote temporary on review |
| Atomic publication failure | Existing `latest.json` | Return save error; remove this run's temporary when possible; never retry with a weaker operation |
| Linux publication succeeds, directory sync fails | New complete `latest.json` is visible | Return save error and state that replacement may already be visible |
| Process exits after successful publication | New complete `latest.json` | Review loads it |
| Stale temporary beside a valid latest | Valid `latest.json` | Ignore temporary |
| Missing latest with one or more temporaries | No committed report | Report no saved report; never guess which interrupted write won |
| Invalid or unsupported latest | Invalid committed report | Exit 2 with the loader error; do not fall back to a temporary or another scope |

Only the process that created a temporary removes it on a handled failure.
Normal scans do not sweep other temporary files because another scan may still
be writing one. Interrupted temporaries remain ignored and are not report
history.

Concurrent scans need no report lock. Each writes a distinct temporary file;
the last successful atomic publication wins. Every winner is a complete
report. "Latest" means the report whose replacement committed last, not the
scan that started last.

## CLI persistence semantics

`--format` controls stdout. Persistence always uses canonical Siloscan JSON.
The two choices are independent.

| Invocation | Stdout | Saved report |
| --- | --- | --- |
| `siloscan` | Human | Automatic `latest.json` for `.` |
| `siloscan --no-save` | Human | Nothing; the bare default is disabled |
| `siloscan PATH [existing scan options]` | Selected format | Nothing; v1 explicit behavior is preserved |
| `siloscan [PATH] --save` | Selected format | Automatic `latest.json` for the exact requested scope |
| `siloscan [PATH] --output report.json` | Selected stdout format | Canonical JSON at `report.json`; automatic latest is not updated |
| `siloscan [PATH] --format json --save` | JSON | Automatic `latest.json`, with the same canonical JSON payload |
| `siloscan [PATH] --format sarif --save` | SARIF | Automatic canonical JSON `latest.json` |
| `siloscan [PATH] --no-save` | Selected stdout format | Nothing; valid even when the invocation was already stateless |
| `siloscan [PATH] --no-save --output report.json` | None | Argument conflict, status 2 |
| `siloscan [PATH] --save --output report.json` | None | Argument conflict, status 2 |
| `siloscan [PATH] --save --no-save` | None | Argument conflict, status 2 |

`--output -` is invalid. Existing `--format json` and `--format sarif` already
own machine stdout. Overloading `--output` with `-` would give the flag two
unrelated meanings. Resolve a relative `--output` path against the process
working directory. Accept any file name, create it when absent, and atomically
replace it when present; do not require a `.json` suffix.

`--no-save` bypasses state-root lookup and all persistence-only work. `--save`
selects the automatic scope-keyed path even on an otherwise explicit scan.
`--output` bypasses only the platform state-root lookup; the report still
records the canonical scope metadata used by every v2 scan report.

The saved report contains exactly the findings left after the existing
`--min-severity` output filter, and it records that filter as the writer does
today. The outcome metadata also records `--fail-on` and whether the unfiltered
new-finding set reached it. A review can then distinguish a clean scan from a
filtered failing scan. The current CLI already decides failure before applying
the output filter; that order must not change. [Pinned CLI result handling](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan/src/main.rs#L476-L573)

For a persisted human scan, print `Report: <path>` only after publication
succeeds. For JSON or SARIF stdout, send the saved-path notice to stderr so
stdout remains one parseable document. A stateless scan prints no report
notice.

### Save failures and exit status

When persistence was selected, destination preparation happens before scanning.
An unavailable state root, scope-identity error, automatic-directory creation
failure, missing explicit parent, or invalid output target fails immediately
with status 2 and no scan stdout. The error names `--no-save` and `--output`
when either can resolve it.

After a scan completes, a temporary-create, serialization, write,
synchronization, or publication failure still emits the selected scan result,
then writes one specific error to stderr and exits 2. Status 2 takes precedence
over status 1 because the requested command did not complete its persistence
contract. It must not print a success path.

Machine stdout must remain one syntactically complete document on every
post-scan save failure. This split is deliberate: cheap deterministic setup
errors do not waste a scan, while a completed scan result is not discarded
because its durable publication failed.

Automatic saving is a deliberate change only for bare `siloscan` and `ss`.
Migration material must name it, and a bare stateless CI invocation should add
`--no-save`. Existing invocations that name a path or scan option remain
stateless unless they add `--save` or `--output`. Findings, fingerprints,
baseline behavior, filtering, and existing result lines remain governed by
their current contracts. The documented human report line and additive JSON
metadata are the only stdout-shape changes from this ticket; SARIF remains
unchanged.

## Report metadata

Keep the current flat JSON report and append fields. Do not wrap it in a new
envelope. Wrapping would make the current tolerant snapshot reader see no
findings and render an empty report.

The saved canonical JSON appends these stable fields after the existing report
fields:

```json
{
  "report_kind": "scan",
  "scope": {
    "identity": "sha256-v1:<64-lowercase-hex>",
    "kind": "directory",
    "path_base_ancestor_levels": 0
  },
  "outcome": {
    "fail_on": "error",
    "threshold_reached": false
  }
}
```

Field rules:

- `report_kind` is the stable discriminator for a scan report. Any present
  value other than `scan` is rejected.
- `scope.identity` must match the directory key during implicit latest lookup.
  An explicit report may come from any scope.
- `scope.kind` is `directory` or `file`, matching the identity input.
- `scope.path_base_ancestor_levels` is an unsigned integer. It is `0` under
  scan-root anchoring. For a config-anchored scan it is the number of native
  path components from the config directory down to the selected scope's
  measured directory; `modules/api` therefore records `2`. For a single-file
  scope, the measured directory is the file's parent, matching the current
  scanner.
- `outcome.fail_on` records the threshold used for status 1.
- `outcome.threshold_reached` records the result before `--min-severity`
  filtering.

All fields above are required in a v2 scan report, whether it is saved or sent
to JSON stdout. Keep the existing top-level field order untouched, then append
`report_kind`, `scope`, and `outcome` in that order; nested fields serialize in
the order shown. A future resolved-plan schema may be appended under its own
decision; this saved-report contract does not invent its still-open fields or
depend on them.

Classify a loaded document as v2 when the top-level product `version` has a
semantic major of 2 or greater, or when any of `report_kind`, `scope`, or
`outcome` is present. A present but non-string or malformed product `version`
is a parse error. A v2 document must contain all three appended fields with the
shapes above. A document with no v2 marker is a legacy candidate and is
accepted only when its supported `1.x` schema rules pass and `findings` is an
array. These rules make malformed-v2 rejection deterministic even though the
additive report schema remains `1.2`.

Do not serialize the canonical absolute root, current working directory,
hostname, output destination, command line, save timestamp, or temporary name.
They are not needed for lookup and would make identical scans produce different
report bytes. The state file's modification time may be shown as local display
information, but it is not part of the report contract.

The ancestor count deliberately carries no path text. Identity remains lossless
for Unix non-UTF-8 paths and Windows wide paths, and review can recover the
source base without asking JSON to round-trip a native path that is not valid
Unicode.

These additions do not require a JSON major-version break. The existing
contract allows additive fields within `1.x`, and the snapshot reader ignores
unknown fields. This contract keeps schema `1.2`; the new fields do not change
an existing field's meaning. Old explicit `1.x` reports remain reviewable even
though they lack v2 scope metadata. A v2 automatic latest report must include
the new fields because implicit lookup validates its scope identity.

Baselines remain unchanged. Saved reports do not become baseline inputs, and
no field in this contract changes a finding fingerprint.

## Performance constraint

Persistence is not permission to weaken the map's performance contract. The
implementation must not walk the requested scope twice, rescan files, clone
the full `ScanReport`, or serialize the saved JSON more than once. The requested
scope and identity are resolved once as part of `ResolvedScanPlan`; a human or
SARIF `--no-save` run skips the identity work.

Keep the current `to_json` result for callers that need a `String`, but add an
internal writer form that can serialize directly to the buffered temporary
file. JSON stdout may reuse one serialized byte buffer for stdout and the saved
file. When stdout is human or SARIF, serialize the separate saved JSON directly
to the temporary file without building an extra full-report buffer solely for
persistence.

The compatibility oracle must measure two paths:

- unchanged explicit path and option invocations against their pinned v1.5.1
  forms, proving that integration did not slow or enlarge the existing
  stateless path;
- bare `siloscan --no-save` against pinned bare `siloscan`, plus bare v2
  `siloscan` with its automatic save, including serialization,
  synchronization, and replacement.

A repeated result more than 5% slower or 5% larger in peak RSS on the map's
representative cold or warm scans blocks the candidate. Do not drop
`sync_all`, omit report data, or move saving into an unjoined background task
to make the benchmark green. Those changes would make the command finish
before the report contract finishes.

## Review lookup

The integration decision fixes the two saved-review forms as
`siloscan review [PATH]` and `siloscan review --report FILE`. This ticket owns
their lookup and validation behavior. [One-command integration decision](https://github.com/RandomCodeSpace/siloscan/blob/8de56740887619a51e851a6d14e48eaba81011c3/research/one-command-integration.md#command-contract)

That integration report delegates the latest-path and source-base details to
this ticket. Its shorthand phrases "project owning `PATH`" and "run
`siloscan [PATH]`" therefore do not create root-promotion or implicit-save
semantics: `PATH` identifies the exact requested scan scope settled by the
project-detection decision, and a missing latest report is created either by
running bare `siloscan` from that scope or by running `siloscan PATH --save`.
[Project-detection decision](https://github.com/RandomCodeSpace/siloscan/blob/039565b66a16695e5084628a8de5a33f5f61d80f/research/project-detection-semantics.md#scan-root-and-ownership)

### Explicit report

For `siloscan review --report FILE`:

1. Resolve a relative file against the process working directory.
2. Load that exact file with the extended snapshot loader.
3. Apply the v2-marker rules above. Require the complete v2 metadata set for a
   v2 document. Accept a supported legacy `1.x` report only when `findings` is
   an array; a schema-version string alone is not a report discriminator.
4. Do not resolve a scan scope, compare scope identity, search state, or rescan.
5. On read, parse, or schema error, print the exact loader error and exit 2.

This is the portable-report path. A moved or copied report remains reviewable.
An explicit report does not carry a machine-specific absolute root. When it is
config-anchored and the user supplies `--config FILE`, use that config file's
directory as the source base. Otherwise retain today's process-working-directory
fallback. Moving a report never makes its findings unreadable, but opening it
outside its source checkout may leave the source pane unavailable.

### Latest report for a scan scope

For `siloscan review [PATH]`:

1. Use the supplied scan path, or `.` when none is given.
2. Apply the same relative-path, existence, file-kind, and canonicalization
   rules used before a scan. Do not walk the tree or run project detection.
3. Derive the scope key from that canonical requested path and kind.
4. Resolve the platform state root and open only
   `siloscan/reports/<scope-key>/latest.json`.
5. Parse the report and require `report_kind = "scan"` plus the expected
   `scope.identity` and `scope.kind`.
6. Starting at the canonical scope's measured directory, walk up exactly
   `scope.path_base_ancestor_levels` parents. Fail if that many parents do not
   exist; otherwise pass the resulting source base and loaded snapshot to the
   read-only UI.

An optional review `--config FILE` may shape the snapshot's silo views, as it
does today. It does not change the scope key or override a v2 latest report's
recorded ancestor count.

There is no fallback to the newest report for another scope, a global
most-recent index, the cache, a temporary file, or a new live scan. If latest
is missing, the error names the expected scope and tells the user to run bare
`siloscan` from that scope, run `siloscan PATH --save`, or provide an explicit
report.

The current snapshot loader reads the whole file before returning data, so it
does not need to hold `latest.json` open while the TUI runs. A concurrent scan
can replace the path without changing the in-memory snapshot already under
review. [Pinned snapshot load](https://github.com/RandomCodeSpace/siloscan/blob/880d211a463e97eb3c188f957e5592d88f36dcf8/crates/siloscan-tui/src/snapshot.rs#L146-L203)

Extend that tolerant parse to retain optional `report_kind`, scope metadata,
and outcome metadata in `SnapshotData`, and tighten the legacy discriminator
as specified above. Explicit mode accepts their absence for supported older
reports; implicit mode validates all required v2 values. Read and parse the
file once rather than preflighting it with a second JSON parse.

Snapshot review presents `outcome.fail_on` and `outcome.threshold_reached` in
its read-only status. A filtered report whose threshold was reached must still
look failed even when no displayed finding reaches the output filter. A legacy
report without outcome metadata says that the saved outcome is unavailable; it
must not be presented as a clean scan.

If a user moves the requested scope, implicit review uses the new scope key.
Review of the old location's report requires its explicit file path. Siloscan
does not scan every state directory trying to infer that two paths used to be
one.

## Required acceptance tests

The implementation is complete only when these behaviors pass on the pinned
compatibility fixtures and the release targets.

### Location and identity

- Linux accepts an absolute `XDG_STATE_HOME`, ignores a relative value, and
  uses the documented absolute `HOME` fallback.
- macOS uses the user Application Support result.
- Windows uses the current user's `FOLDERID_LocalAppData` result.
- Missing platform state returns an actionable status-2 error and never writes
  inside the scanned tree.
- An automatic state root inside the scope, its single-file parent, or the
  nearest `.git` repository boundary is rejected before any directory is
  created. A symlinked state ancestor into those boundaries is rejected too.
- Scanning `$HOME` with the normal Linux fallback fails early rather than
  creating `$HOME/.local/state` inside the scan.
- Relative, absolute, and symlinked spellings of the same requested path and
  kind produce one key.
- Repository-root, nested-directory, and single-file scopes produce different
  keys; implicit review finds only the exact scope it was given.
- Separate worktrees produce different keys.
- Unix non-UTF-8 paths and Windows lossless wide paths produce stable keys
  across repeated runs.

### Publication and recovery

- A first save creates exactly one valid `latest.json` plus no completed
  history.
- Repeating the same scan with one binary and unchanged inputs produces
  byte-identical report content.
- Injected serialization, create, write, sync, and pre-publication failures
  leave a prior latest report byte-for-byte intact.
- A successful replacement leaves no temporary from that process.
- A stale temporary is ignored by review.
- A missing latest plus a complete temporary still reports no committed report.
- Concurrent writers never expose partial JSON; the last successful atomic
  publication is the report loaded.
- Invalid and unsupported latest reports fail closed with status 2.
- A JSON object with `schema_version = "1.2"` but no `report_kind` or legacy
  `findings` array is rejected as unrelated.
- A product `version` of `2.x` with any required v2 metadata missing is
  rejected. A supported product `version` of `1.x` with a `findings` array and
  no v2 marker follows the legacy path.
- Linux tests synchronize the directory after replacement.
- macOS and Windows tests hold the old report open through replacement: that
  handle reads the old complete bytes, while a new open reads the new complete
  bytes. Windows also proves the `FileRenameInfoEx` path and proves that an
  unsupported publication fails without calling a weaker fallback.

### CLI and schema

- The invocation table above has black-box tests for stdout, stderr, written
  paths, and statuses 0, 1, and 2.
- Bare `siloscan` and `ss` update latest; existing explicit path and option
  invocations perform no write unless `--save` or `--output` is present.
- `--save` selects the exact scope's automatic latest path. `--output` selects
  one explicit file and requires an existing parent.
- `--no-save` performs no report write. Its conflicts with `--save` and
  `--output`, and the conflict between `--save` and `--output`, fail in argument
  parsing.
- JSON and SARIF stdout contain no human report-path line.
- A destination-preparation failure emits no scan stdout. A post-scan save
  failure does not truncate or suppress otherwise valid machine stdout.
- The saved report's finding lists match the selected `--min-severity`, while
  its outcome preserves the unfiltered `--fail-on` result.
- Snapshot review shows a reached threshold even when filtering hides every
  failing finding; a legacy report labels its outcome unavailable.
- A v2 reader opens prior supported `1.x` snapshots.
- A v1.5.1 reader ignores the additive fields and still shows findings and
  metrics from a v2 report.
- Automatic lookup rejects a scope-identity or scope-kind mismatch; explicit
  lookup does not.
- Config-anchored directory and single-file reports restore their source base
  from `scope.path_base_ancestor_levels` without serializing path text or an
  absolute path.
- No saved-report behavior changes baseline bytes or finding fingerprints.

### Stop condition

Do not claim the saved-report contract complete from unit tests on one host.
The final candidate must run a no-config scan, replace `latest.json`, and open
it through `siloscan review` on Linux, macOS, and Windows. The exact candidate
commit must also pass the compatibility and performance oracle from the map.

## Rejected alternatives

| Alternative | Reason for rejection |
| --- | --- |
| Write `.siloscan/report.json` | Dirties the input repository and makes a scan observe its own output unless every front end excludes it correctly |
| Store reports beside cache entries | Cache is disposable and version pruning may remove it; review requires durable state |
| Directly write `latest.json` | Truncates the only valid copy before the replacement is complete |
| Keep immutable report history and rebuild latest | Better power-loss recovery, but it contradicts the map's one-report scope and creates retention work that the map deliberately deferred |
| Keep `previous.json` | It is report history under another name and still needs rotation and recovery rules |
| Promote a leftover temporary during review | A temporary has no committed ordering against another interrupted or concurrent scan |
| Use a detected Git, manifest, or workspace root as identity | Conflicts with the settled scan-scope contract and makes nested scans overwrite a report for different admitted files |
| Use manifest content or Git remote as identity | Ordinary edits, missing remotes, and separate worktrees make lookup unstable or incorrectly shared |
| Use `MoveFileExW`, `ReplaceFileW`, or delete-then-rename on Windows | Their documented contracts do not preserve the required old-reader/new-reader visibility; unsupported atomic publication must fail visibly |
| Hash a lossy path string | Distinct non-Unicode paths can collapse to the same display text |
| Store a relative path string for the review source base | JSON cannot losslessly round-trip every native path; an ancestor count recovers the same base without path text |
| Serialize absolute root and timestamp | Makes otherwise identical reports differ by machine and run without helping lookup |
| Fall back to the newest report anywhere | Can open the wrong scope's findings, which is worse than a clear missing-report error |

## Implementation boundary

This report chooses behavior, not a dependency. The contract can be backed by
small platform adapters or by a maintained directory-location crate after the
repository's dependency review. Whichever implementation is chosen must return
the exact locations and failure behavior above.

The smallest owning change is one persistence module at the CLI and review
integration boundary. It provides:

```text
state_root() -> Result<PathBuf>
canonical_scope(requested_path) -> Result<CanonicalScope>
automatic_report_path(state_root, scope) -> Result<PathBuf>
write_report_atomic(destination, report_view) -> Result<()>
latest_report_path(requested_path) -> Result<PathBuf>
source_base(scope, ancestor_levels) -> Result<PathBuf>
```

CLI and review call this module. Its Windows publisher owns the documented
`FileRenameInfoEx` call; it does not hide a weaker fallback. The one-command
integration layer loads the returned path through the additively extended
snapshot reader. Do not refactor the already-correct baseline writer merely to
share a helper. Cache storage remains separate.
