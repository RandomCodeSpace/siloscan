//! Enumerating the files a scan reads, and reading them.
//!
//! # Which ignore sources a scan consults
//!
//! A scan must be a function of the tree it was pointed at. Anything else means
//! two machines scanning the same commit can disagree about whether a secret is
//! there, and the disagreement is silent: an ignored file produces no finding
//! and no skipped-file record, so the report says "clean" rather than "did not
//! look". [`IgnoreOptions`] makes every ignore source an explicit, named
//! decision instead of an inherited default.
//!
//! ## Deliberate behavior change (1.1.2)
//!
//! Up to 1.1.1 the walker enabled the `ignore` crate's standard filters, which
//! turned on *every* ignore source git knows. Three of them read files outside
//! the scan root, and each could erase findings with no trace in the report:
//!
//! - a `.gitignore` in any *parent* directory of the scan root,
//! - `.git/info/exclude`, which is untracked and so invisible to review,
//! - git's global `core.excludesFile`, which belongs to whoever invoked the
//!   scan, not to the repository being scanned.
//!
//! All three now default to **off** ([`IgnoreOptions::respect_parent_ignores`],
//! [`IgnoreOptions::respect_git_exclude`],
//! [`IgnoreOptions::respect_global_gitignore`]). A scan is therefore
//! self-contained: it depends on the scan root's contents and nothing above or
//! outside it, and the same tree scanned in CI, in a container, and on a
//! developer's laptop yields the same files.
//!
//! Consequence worth stating plainly: a repository that relied on a parent
//! `.gitignore` or on `.git/info/exclude` to keep files out of a scan will see
//! those files scanned from 1.1.2 on, and may see new findings. That is the
//! point - those findings were always there. Callers that want the old,
//! environment-dependent behavior can opt back into each source individually.
//!
//! Ignore files *inside* the scan root are unchanged: `.gitignore` and
//! `.ignore` are still honored by default, because they are part of the tree
//! under review. [`IgnoreOptions::respect_gitignore`] and
//! [`IgnoreOptions::respect_dot_ignore`] exist so a caller can turn even those
//! off - a one-line `.gitignore` must not be able to hide a live secret with no
//! way to look past it - and [`IgnoreOptions::all_files`] turns off the lot.
//!
//! ## Saying where the scan did not look (1.2.1)
//!
//! Honoring an in-root ignore file was never the problem; doing it in silence
//! was. Up to 1.2.0 a `.gitignore` line took a file - a tracked one, even - out
//! of the scan with no finding, no skipped entry and no count anywhere in the
//! report, which is the same output as a tree that has nothing in it. That is
//! the silence this crate condemned for the three out-of-root sources, and it
//! applied just as much to the two in-root ones.
//!
//! [`collect_files_counted`] therefore returns an [`Ignored`] alongside the
//! files: how many entries the ignore machinery kept out, counted at the point
//! of exclusion. Paths are deliberately not collected - a `node_modules` tree
//! would swamp the report - and neither are the contents of an excluded
//! directory: counting those would mean walking the tree the ignore rule exists
//! to keep the walker out of. An excluded directory is one count, and
//! [`Ignored::directories`] is named for what it counts. "Clean" and "did not
//! look" are then two different reports.
//!
//! Walk order is unaffected by any of this: results are sorted bytewise by
//! path after collection, and the counts are sums over set membership, so they
//! do not depend on the order any directory was read in.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};

use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use serde::Serialize;

pub enum FileKind {
    Text(String),
    Binary,
    Unreadable(String),
}

/// Version-control internals, excluded by name at every depth.
///
/// Hidden files are scanned, so nothing else keeps the walker out of `.git`,
/// and a repository's object store is thousands of files with no source in
/// them. A submodule or worktree checkout has `.git` as a file rather than a
/// directory, so the name is matched regardless of entry type.
///
/// `.jj` and `.bzr` are here for the same reason: a jujutsu repository
/// colocated with git keeps a second object store under `.jj`, and scanning it
/// would double the walk over content that is not source.
const VCS_DIR_NAMES: [&str; 5] = [".git", ".hg", ".svn", ".jj", ".bzr"];

/// siloscan's own state directory, excluded for the same reason.
///
/// It holds the cache and the baseline, and it appears - along with the
/// `.gitignore` marker written beside the cache - only after a scan has run.
/// Scanning it would make a warm run's output differ from a cold run's, which
/// is exactly the determinism the tool promises not to break.
const STATE_DIR_NAME: &str = ".siloscan";

fn is_excluded_name(name: &OsStr) -> bool {
    name == OsStr::new(STATE_DIR_NAME) || VCS_DIR_NAMES.iter().any(|vcs| name == OsStr::new(vcs))
}

/// Which ignore sources a walk consults.
///
/// Every field is a decision about whether some file may remove other files
/// from the scan. See the [module docs](self) for why the defaults are what
/// they are; the short version is that a scan depends on the scan root and
/// nothing above or outside it.
///
/// [`Default`] is the shipped behavior. Constructing this struct literally is
/// deliberate: adding a field is a breaking change for anyone who did, which is
/// the right amount of friction for "a new way to not scan something".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IgnoreOptions {
    /// Honor `.gitignore` files found inside the scan root. Default `true`.
    pub respect_gitignore: bool,
    /// Honor `.ignore` files found inside the scan root. Default `true`.
    ///
    /// Same format as `.gitignore`, understood by ripgrep and friends. It is
    /// separate from `respect_gitignore` only so that turning off one does not
    /// silently leave the other hiding files.
    pub respect_dot_ignore: bool,
    /// Honor git's global `core.excludesFile`. Default `false`.
    ///
    /// That file belongs to whoever invoked the scan, not to the repository
    /// under review, so honoring it makes results differ between machines
    /// scanning the same commit.
    pub respect_global_gitignore: bool,
    /// Honor ignore files in directories *above* the scan root. Default
    /// `false`.
    ///
    /// A file outside the tree siloscan was told to scan must not be able to
    /// remove findings from inside it.
    pub respect_parent_ignores: bool,
    /// Honor `<root>/.git/info/exclude`. Default `false`.
    ///
    /// It is untracked, so it never appears in review, and it is per-clone, so
    /// it is not part of the repository's own definition of what to skip.
    pub respect_git_exclude: bool,
}

impl Default for IgnoreOptions {
    fn default() -> Self {
        IgnoreOptions {
            respect_gitignore: true,
            respect_dot_ignore: true,
            respect_global_gitignore: false,
            respect_parent_ignores: false,
            respect_git_exclude: false,
        }
    }
}

impl IgnoreOptions {
    /// Every ignore source off: nothing but the walker's own exclusions
    /// (version-control internals, siloscan's state directory) keeps a file out
    /// of the scan.
    ///
    /// This is what a `--no-ignore` style flag wants. It does not re-enable the
    /// out-of-root sources - "scan everything under the root" is not a reason
    /// to start reading files above it.
    pub fn all_files() -> Self {
        IgnoreOptions {
            respect_gitignore: false,
            respect_dot_ignore: false,
            respect_global_gitignore: false,
            respect_parent_ignores: false,
            respect_git_exclude: false,
        }
    }

    /// Whether any ignore source is consulted at all.
    ///
    /// All of them off means no ignore rule can have removed anything, so the
    /// exclusion count is zero without a directory being read to establish it.
    fn consults_any_source(&self) -> bool {
        self.respect_gitignore
            || self.respect_dot_ignore
            || self.respect_global_gitignore
            || self.respect_parent_ignores
            || self.respect_git_exclude
    }
}

/// How much of the tree the ignore machinery kept out of a walk.
///
/// Counted at the point of exclusion, which is the only place it can be counted
/// honestly: an excluded directory is one entry here, and what is inside it was
/// never enumerated. A scan that reported "0 findings" and a scan that reported
/// "0 findings, 4 files and 1 directory ignored" are then different reports.
///
/// What is *not* counted, because none of it is an ignore rule's doing: version
/// control internals and siloscan's own `.siloscan` state directory, which the
/// walker excludes as policy under every [`IgnoreOptions`]. Keeping the state
/// directory out matters twice over - it appears only after a scan has run, so
/// counting it would make a warm run's numbers differ from a cold run's.
///
/// The one imprecision worth stating: an entry the walk could not read (a
/// directory it lacks permission on, a file removed mid-walk) is not
/// distinguishable here from an excluded one and is counted. Over-reporting
/// what the scan did not look at is the safe direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Ignored {
    /// Entries excluded one by one: files, and anything else that is not a
    /// directory, such as a symbolic link.
    pub files: usize,
    /// Directories excluded whole. The walker did not descend into them, so
    /// their contents are counted nowhere - one excluded `node_modules` is one.
    pub directories: usize,
}

impl Ignored {
    /// True when no ignore rule removed anything, so the scan looked at every
    /// entry under the root.
    pub fn is_empty(self) -> bool {
        self.files == 0 && self.directories == 0
    }

    /// One line for a human summary, or `None` when nothing was excluded.
    ///
    /// It lives here rather than in a rendering module because the wording is
    /// part of what the count means: the directory clause is what stops the
    /// number being read as a file count.
    pub fn summary_line(self) -> Option<String> {
        let files = quantity(self.files, "file", "files");
        let directories = quantity(self.directories, "directory", "directories");
        match (self.files, self.directories) {
            (0, 0) => None,
            (_, 0) => Some(format!("{files} ignored by .gitignore/.ignore")),
            // "1 directory ... their contents" reads as a typo, and the clause
            // is the part that stops the number being taken for a file count,
            // so it is the part that has to be readable.
            (0, 1) => Some(
                "1 directory ignored by .gitignore/.ignore; its contents were not walked and are \
                 not counted"
                    .to_string(),
            ),
            (0, _) => Some(format!(
                "{directories} ignored by .gitignore/.ignore; their contents were not walked and \
                 are not counted"
            )),
            (_, _) => Some(format!(
                "{files} and {directories} ignored by .gitignore/.ignore; directory contents were \
                 not walked and are not counted"
            )),
        }
    }
}

fn quantity(count: usize, singular: &str, plural: &str) -> String {
    match count {
        1 => format!("1 {singular}"),
        _ => format!("{count} {plural}"),
    }
}

/// Everything a walk has to say: the files to scan, and how much was kept out
/// of them.
pub struct WalkResult {
    /// Files to scan, sorted bytewise by path.
    pub files: Vec<PathBuf>,
    /// What the ignore machinery excluded on the way.
    pub ignored: Ignored,
}

/// Walk root directory using the ignore crate, with the default
/// [`IgnoreOptions`].
///
/// Equivalent to [`collect_files_with`] passing `&IgnoreOptions::default()`.
pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    collect_files_with(root, &IgnoreOptions::default())
}

/// Walk root directory using the ignore crate: honors the ignore sources
/// `opts` selects, scans hidden files and directories, excludes version-control
/// internals (`.git`, `.hg`, `.svn`, `.jj`, `.bzr`) and siloscan's own
/// `.siloscan` state directory anywhere below the scan root.
/// Files only, sorted bytewise by path, walk errors silently skipped.
///
/// hidden(false): dotfiles carry secrets as often as any other file - `.env`,
/// `.npmrc`, `.github/workflows/` - so skipping them would silently hide the
/// findings this scanner exists to report. Ignore-file semantics are unchanged
/// by this: a dotfile listed in a respected `.gitignore` stays ignored.
///
/// require_git(false): `.gitignore` inside the root is honored whether or not a
/// `.git` entry exists, so a scan of an exported tree sees what a scan of the
/// checkout sees. This knob does not widen where ignore files are read from -
/// that is `respect_parent_ignores`, which is off by default.
pub fn collect_files_with(root: &Path, opts: &IgnoreOptions) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in walker(root, opts, &[]).build().flatten() {
        if entry.file_type().is_some_and(|ft| ft.is_file()) {
            files.push(entry.path().to_path_buf());
        }
    }
    sort_paths(&mut files);
    files
}

/// As [`collect_files_with`], and it also counts what the ignore machinery
/// excluded, so the caller can report where the scan did not look.
///
/// The files are exactly the ones [`collect_files_with`] returns, in the same
/// order: counting observes the walk, it does not change it. Nothing pruned is
/// descended into - an excluded directory is counted once, from the outside,
/// and its contents are never enumerated.
///
/// How it is counted, since the `ignore` crate does not report the entries it
/// dropped: the walk tallies what it visited in each directory, and each
/// visited directory is then read once more and its children tallied the same
/// way. The difference per kind is what the walk did not see. The extra work is
/// one `read_dir` per directory the scan is going to read files out of anyway,
/// and none at all for the trees an ignore rule pruned - which is the cost of
/// being able to tell "clean" from "did not look". Under
/// [`IgnoreOptions::all_files`] nothing can be excluded, so the second read is
/// skipped entirely.
///
/// The second read is not avoidable: `ignore` yields only the entries that
/// survived, and reproducing its decisions well enough to count the rest would
/// mean reimplementing gitignore matching against the same precedence rules -
/// a far worse trade than one `read_dir` of directories already in the page
/// cache. What the tally does avoid is a second copy of the tree's *names*: the
/// record is two counters per visited directory rather than a set of every
/// child name, so the memory is proportional to the directory count and not to
/// the entry count.
///
/// The read is not free, and the number is worth having written down. Measured
/// on a warm cache over 88,608 files in 15,067 directories, best of five:
/// 0.358s for the plain walk, 0.615s counted - 0.257s, or 72%, for knowing
/// where the scan did not look. It is a fixed cost per directory rather than
/// per file, and it is dwarfed by the per-file read and match the walk exists
/// to feed.
pub fn collect_files_counted(root: &Path, opts: &IgnoreOptions) -> WalkResult {
    collect_files_counted_in_project(root, opts, &[])
}

/// As [`collect_files_counted`], and it also reads the ignore files in
/// `project_dirs` - directories above the scan root that the loaded config
/// declares part of the same project, outermost first.
///
/// This is the whole of the anchor-aware walk. Under `anchor = "config"` a
/// module scan has to exclude what the project root's `.gitignore` excludes,
/// or a file the repository ignores appears in a module scan and in no other,
/// and a baseline written at the root does not cover it. Under
/// `anchor = "scan-root"` the list is empty and this is
/// [`collect_files_counted`] exactly.
///
/// Passing directories the config did not produce would let a path outside the
/// scan remove files from inside it, which is the thing
/// [`IgnoreOptions::respect_parent_ignores`] exists to keep off by default;
/// [`Config::project_ignore_dirs`](crate::config::Config::project_ignore_dirs)
/// is bounded by the config root and is the only intended source.
pub fn collect_files_counted_in_project(
    root: &Path,
    opts: &IgnoreOptions,
    project_dirs: &[PathBuf],
) -> WalkResult {
    let mut files = Vec::new();
    // What the walk saw in each directory it entered, so entries are compared
    // against the walk's own record rather than against a second, differently
    // configured walk that could disagree with it. A directory the walk entered
    // has a record even when nothing inside it survived, which is what makes
    // "everything here was excluded" countable.
    let mut visited: HashMap<PathBuf, Tally> = HashMap::new();

    for entry in walker(root, opts, project_dirs).build().flatten() {
        let path = entry.path();
        let is_dir = entry.file_type().is_some_and(|kind| kind.is_dir());
        if is_dir {
            visited.entry(path.to_path_buf()).or_default();
        } else if entry.file_type().is_some_and(|kind| kind.is_file()) {
            files.push(path.to_path_buf());
        }
        // The root is visited at depth 0; its parent is outside the scan and
        // has no place in the record.
        if entry.depth() > 0
            && let Some(parent) = path.parent()
        {
            visited.entry(parent.to_path_buf()).or_default().add(is_dir);
        }
    }

    sort_paths(&mut files);
    WalkResult {
        files,
        ignored: count_ignored(opts, &visited),
    }
}

/// Entries of one directory, split the way [`Ignored`] splits them: directories,
/// and everything that is not one.
///
/// Symbolic links land in `others` on both sides of the comparison - the walk
/// does not follow them, so a link to a directory is a link to the walk and a
/// link to `read_dir`.
#[derive(Default)]
struct Tally {
    directories: usize,
    others: usize,
}

impl Tally {
    fn add(&mut self, is_dir: bool) {
        if is_dir {
            self.directories += 1;
        } else {
            self.others += 1;
        }
    }
}

/// Entries the walk did not visit, counted from the directories it did.
///
/// Deterministic: the per-directory differences are summed, and addition does
/// not care what order the directories come out of the map in. A directory that
/// has become unreadable since the walk contributes nothing rather than failing
/// the scan - the files under it are equally absent from the walk's own results.
///
/// The subtraction saturates because the tree can move underneath a scan: a file
/// the walk saw and that is gone by the time the directory is read back would
/// otherwise make a count negative. Over-reporting what the scan did not look at
/// is the safe direction, and zero is as far down as that goes.
fn count_ignored(opts: &IgnoreOptions, visited: &HashMap<PathBuf, Tally>) -> Ignored {
    if !opts.consults_any_source() {
        return Ignored::default();
    }

    let mut ignored = Ignored::default();
    for (directory, seen) in visited {
        let Ok(entries) = fs::read_dir(directory) else {
            continue;
        };
        let mut present = Tally::default();
        for entry in entries.flatten() {
            // Excluded by the walker as policy, not by any ignore rule, so it
            // is absent from both tallies rather than counted in one.
            if is_excluded_name(&entry.file_name()) {
                continue;
            }
            present.add(entry.file_type().is_ok_and(|kind| kind.is_dir()));
        }
        ignored.directories += present.directories.saturating_sub(seen.directories);
        ignored.files += present.others.saturating_sub(seen.others);
    }
    ignored
}

/// The ignore files of the directories above the scan root, each matched at the
/// directory it came from.
///
/// [`ignore::WalkBuilder::add_ignore`] cannot express that, which is why this
/// exists: it builds every added file's matcher at the process working
/// directory, not at the directory the file was read from. An anchored pattern
/// (one with a leading `/`, or any pattern containing a `/`, which is most of a
/// real root `.gitignore`: `/target`, `/dist`, `modules/api/vendor/`) then
/// resolves against wherever siloscan happened to be invoked from. A root
/// `.gitignore` line `/modules/api/secrets/` excluded that directory when the
/// scan ran from the repository root and excluded nothing when the same
/// absolute scan root was given from anywhere else: same tree, same config, two
/// verdicts, and the CI-versus-laptop direction of that disagreement is the one
/// that matters. A scan is a function of the tree it was pointed at, so the
/// matcher is built here with the project directory as its root and consulted
/// directly.
///
/// Paths are compared in resolved form ([`resolve`]) on both sides, so the
/// spelling of the scan root - relative, symlinked, `..`-laden - decides
/// nothing either.
struct ProjectIgnores {
    /// The scan root as the walk spells it. Entry paths start with it, and it
    /// is what a resolved path is rebuilt from.
    walk_root: PathBuf,
    /// The same directory resolved, so an entry path can be compared with
    /// matcher roots that were resolved the same way.
    resolved_root: PathBuf,
    /// Each matcher with the directory it was built at, nearest the scan root
    /// first: gitignore semantics give the file closest to the entry the final
    /// say, so the first decisive match wins.
    matchers: Vec<(PathBuf, Gitignore)>,
}

impl ProjectIgnores {
    /// Matchers for `project_dirs` - directories above the scan root, outermost
    /// first, as
    /// [`Config::project_ignore_dirs`](crate::config::Config::project_ignore_dirs)
    /// produces them. `None` when there is nothing to consult.
    ///
    /// Each file is honored only through the switch that already governs its
    /// kind: with `respect_gitignore` off no `.gitignore` is read here either. A
    /// project boundary widens *where* ignore files are read from; it never
    /// overrides a decision to stop reading them.
    fn build(root: &Path, opts: &IgnoreOptions, project_dirs: &[PathBuf]) -> Option<Self> {
        let mut matchers = Vec::new();
        for dir in project_dirs.iter().rev() {
            let dir = resolve(dir);
            let mut builder = GitignoreBuilder::new(&dir);
            // Later patterns take precedence, so `.ignore` outranks
            // `.gitignore` in the same directory, as it does for every other
            // walker that reads both.
            if opts.respect_gitignore {
                let _ = builder.add(dir.join(".gitignore"));
            }
            if opts.respect_dot_ignore {
                let _ = builder.add(dir.join(".ignore"));
            }
            // A directory with neither file is the common case, and a pattern
            // that will not compile leaves nothing to consult. Both mean this
            // directory removes nothing from the walk, which is the direction
            // that scans more rather than less.
            if let Ok(matcher) = builder.build()
                && !matcher.is_empty()
            {
                matchers.push((dir, matcher));
            }
        }
        match matchers.is_empty() {
            true => None,
            false => Some(ProjectIgnores {
                walk_root: root.to_path_buf(),
                resolved_root: resolve(root),
                matchers,
            }),
        }
    }

    /// Whether the project's ignore files exclude `path`.
    fn excludes(&self, path: &Path, is_dir: bool) -> bool {
        let Ok(tail) = path.strip_prefix(&self.walk_root) else {
            return false;
        };
        let resolved = self.resolved_root.join(tail);
        for (dir, matcher) in &self.matchers {
            // `matched_path_or_any_parents` requires its argument to be under
            // the matcher's root and panics otherwise, so a path that is not is
            // not this matcher's to judge.
            if !resolved.starts_with(dir) {
                continue;
            }
            // The parent walk matters here and nowhere else: a pattern may
            // exclude a directory that sits between the project root and the
            // scan root, and the walk never visits those, so no per-entry match
            // would ever apply it.
            match matcher.matched_path_or_any_parents(&resolved, is_dir) {
                Match::Ignore(_) => return true,
                Match::Whitelist(_) => return false,
                Match::None => {}
            }
        }
        false
    }
}

/// A path in the form both sides of a project-ignore comparison use: absolute
/// and symlink-free where the filesystem allows it, and the path itself where
/// it does not.
///
/// It is the same resolution
/// [`Config::project_ignore_dirs`](crate::config::Config::project_ignore_dirs)
/// applies to the directories it hands over, so a tree reached through a
/// symlink does not resolve one way there and another way here.
fn resolve(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

/// The one walker configuration, so a counted walk and an uncounted one cannot
/// drift apart in what they consider a file.
///
/// `project_dirs` are directories above the scan root whose ignore files are in
/// scope for this walk, outermost first - see
/// [`Config::project_ignore_dirs`](crate::config::Config::project_ignore_dirs),
/// which is the only thing that produces a non-empty list. They are applied by
/// [`ProjectIgnores`] rather than handed to the `ignore` crate, which cannot
/// root them where they came from.
fn walker(root: &Path, opts: &IgnoreOptions, project_dirs: &[PathBuf]) -> ignore::WalkBuilder {
    let project = ProjectIgnores::build(root, opts, project_dirs);
    let mut builder = ignore::WalkBuilder::new(root);
    builder
        .hidden(false)
        .parents(opts.respect_parent_ignores)
        .ignore(opts.respect_dot_ignore)
        .git_ignore(opts.respect_gitignore)
        .git_global(opts.respect_global_gitignore)
        .git_exclude(opts.respect_git_exclude)
        .require_git(false)
        .filter_entry(move |entry| {
            if is_excluded_name(entry.file_name()) {
                return false;
            }
            // The scan root is what the caller asked for, so it is walked even
            // when a project pattern covers it. Nothing is smuggled in by that:
            // its children are matched against the same pattern through their
            // parents, so an excluded root is an empty walk and a count of what
            // was left out.
            if entry.depth() == 0 {
                return true;
            }
            match &project {
                Some(project) => !project.excludes(
                    entry.path(),
                    entry.file_type().is_some_and(|kind| kind.is_dir()),
                ),
                None => true,
            }
        });
    builder
}

fn sort_paths(paths: &mut [PathBuf]) {
    paths.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
}

/// Read file contents. Returns Binary if first 8000 bytes contain NUL.
/// IO errors and invalid UTF-8 return Unreadable with reason.
pub fn read_text(path: &Path) -> FileKind {
    match fs::read(path) {
        Ok(bytes) => {
            let check_len = bytes.len().min(8000);
            if bytes[..check_len].contains(&0) {
                return FileKind::Binary;
            }

            match String::from_utf8(bytes) {
                Ok(text) => FileKind::Text(text),
                Err(_) => FileKind::Unreadable("not valid UTF-8".to_string()),
            }
        }
        Err(e) => FileKind::Unreadable(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Paths relative to `root`, forward-slashed, in walk order.
    fn relative_names(root: &Path) -> Vec<String> {
        names_with(root, &IgnoreOptions::default())
    }

    /// As [`relative_names`], under an explicit ignore policy.
    fn names_with(root: &Path, opts: &IgnoreOptions) -> Vec<String> {
        collect_files_with(root, opts)
            .iter()
            .map(|p| {
                p.strip_prefix(root)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn gitignored_file_excluded() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.txt\n").unwrap();
        fs::write(dir.path().join("ignored.txt"), "content").unwrap();

        let files = collect_files(dir.path());
        let names: Vec<_> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();

        assert!(!names.contains(&"ignored.txt"));
        assert!(names.contains(&"main.rs"));
    }

    #[test]
    fn nul_byte_detected_as_binary() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.bin");
        let mut bytes = vec![0x89, 0x50, 0x4E, 0x47];
        bytes.push(0);
        fs::write(&path, bytes).unwrap();

        match read_text(&path) {
            FileKind::Binary => {}
            _ => panic!("expected Binary"),
        }
    }

    #[test]
    fn invalid_utf8_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.txt");
        fs::write(&path, b"\xff\xfe").unwrap();

        match read_text(&path) {
            FileKind::Unreadable(reason) => {
                assert_eq!(reason, "not valid UTF-8");
            }
            _ => panic!("expected Unreadable"),
        }
    }

    #[test]
    fn io_error_unreadable() {
        let path = Path::new("/nonexistent/dir/file.txt");
        match read_text(path) {
            FileKind::Unreadable(reason) => {
                assert!(!reason.is_empty());
            }
            _ => panic!("expected Unreadable"),
        }
    }

    #[test]
    fn text_file_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file.txt");
        let content = "hello world";
        fs::write(&path, content).unwrap();

        match read_text(&path) {
            FileKind::Text(text) => {
                assert_eq!(text, content);
            }
            _ => panic!("expected Text"),
        }
    }

    #[test]
    fn sort_order_stable() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("z.txt"), "z").unwrap();
        fs::write(dir.path().join("a.txt"), "a").unwrap();
        fs::write(dir.path().join("m.txt"), "m").unwrap();

        let files = collect_files(dir.path());
        let names: Vec<_> = files
            .iter()
            .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
            .collect();

        assert_eq!(names, vec!["a.txt", "m.txt", "z.txt"]);
    }

    #[test]
    fn hidden_files_and_directories_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let workflows = dir.path().join(".github/workflows");
        fs::create_dir_all(&workflows).unwrap();
        fs::write(workflows.join("ci.yml"), "on: push\n").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();
        fs::write(dir.path().join(".npmrc"), "//registry/:_authToken=x\n").unwrap();
        let src = dir.path().join("src");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("visible.js"), "const a = 1;\n").unwrap();

        let names = relative_names(dir.path());

        assert!(names.contains(&".env".to_string()), "{names:?}");
        assert!(names.contains(&".npmrc".to_string()), "{names:?}");
        assert!(
            names.contains(&".github/workflows/ci.yml".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"src/visible.js".to_string()), "{names:?}");
    }

    #[test]
    fn vcs_internals_excluded() {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join(".git");
        fs::create_dir_all(git.join("objects/ab")).unwrap();
        fs::write(git.join("config"), "[core]\n").unwrap();
        fs::write(git.join("objects/ab/cdef"), "blob").unwrap();
        for vcs in [".hg", ".svn", ".bzr"] {
            let root = dir.path().join(vcs);
            fs::create_dir_all(&root).unwrap();
            fs::write(root.join("internal"), "state").unwrap();
        }
        // A jujutsu repo colocated with git: its own store under `.jj`.
        let jj = dir.path().join(".jj/repo/store/git/objects/ab");
        fs::create_dir_all(&jj).unwrap();
        fs::write(jj.join("cdef"), "blob").unwrap();
        fs::write(dir.path().join(".jj/working_copy"), "state").unwrap();
        // A vendored submodule keeps its own VCS directory below the root.
        let vendored = dir.path().join("vendor/dep/.git");
        fs::create_dir_all(&vendored).unwrap();
        fs::write(vendored.join("config"), "[core]\n").unwrap();
        fs::write(dir.path().join("vendor/dep/lib.rs"), "fn f() {}").unwrap();

        let names = relative_names(dir.path());

        assert_eq!(names, vec!["vendor/dep/lib.rs".to_string()], "{names:?}");
    }

    #[test]
    fn vcs_gitlink_file_excluded() {
        // A worktree or submodule checkout has `.git` as a file, not a
        // directory.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".git"), "gitdir: /elsewhere/.git\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(dir.path());

        assert_eq!(names, vec!["main.rs".to_string()], "{names:?}");
    }

    #[test]
    fn own_state_directory_excluded() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join(".siloscan/cache/ab");
        fs::create_dir_all(&state).unwrap();
        fs::write(state.join("entry.json"), "{}").unwrap();
        fs::write(dir.path().join(".siloscan/.gitignore"), "cache/\n").unwrap();
        fs::write(dir.path().join(".siloscan/baseline.json"), "{}").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(dir.path());

        assert_eq!(names, vec!["main.rs".to_string()], "{names:?}");
    }

    #[test]
    fn gitignored_dotfile_still_excluded() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), ".env.local\nsecrets/\n").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();
        fs::write(dir.path().join(".env.local"), "TOKEN=local\n").unwrap();
        fs::create_dir(dir.path().join("secrets")).unwrap();
        fs::write(dir.path().join("secrets/.keys"), "TOKEN=deep\n").unwrap();

        let names = relative_names(dir.path());

        assert!(names.contains(&".env".to_string()), "{names:?}");
        assert!(names.contains(&".gitignore".to_string()), "{names:?}");
        assert!(!names.contains(&".env.local".to_string()), "{names:?}");
        assert!(!names.contains(&"secrets/.keys".to_string()), "{names:?}");
    }

    #[test]
    fn walk_order_deterministic_with_hidden_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
        fs::create_dir_all(dir.path().join(".circleci")).unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::create_dir_all(dir.path().join(".git")).unwrap();
        fs::write(dir.path().join(".git/config"), "[core]\n").unwrap();
        fs::write(dir.path().join(".github/workflows/ci.yml"), "on: push\n").unwrap();
        fs::write(dir.path().join(".circleci/config.yml"), "version: 2\n").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();
        fs::write(dir.path().join("src/visible.js"), "const a = 1;\n").unwrap();
        fs::write(dir.path().join("README.md"), "# readme\n").unwrap();

        let expected = vec![
            ".circleci/config.yml".to_string(),
            ".env".to_string(),
            ".github/workflows/ci.yml".to_string(),
            "README.md".to_string(),
            "src/visible.js".to_string(),
        ];

        for _ in 0..5 {
            assert_eq!(relative_names(dir.path()), expected);
        }
    }

    /// A `.gitignore` above the scan root used to erase findings from inside
    /// it, with nothing in the report to say so.
    #[test]
    fn parent_gitignore_does_not_suppress_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir(&root).unwrap();
        fs::write(dir.path().join(".gitignore"), "secret.txt\n").unwrap();
        fs::write(root.join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(&root);
        assert!(names.contains(&"secret.txt".to_string()), "{names:?}");

        // The setup does suppress once the walk is told to read upward, which
        // is what 1.1.1 did unconditionally.
        let opted_in = IgnoreOptions {
            respect_parent_ignores: true,
            ..IgnoreOptions::default()
        };
        let names = names_with(&root, &opted_in);
        assert!(!names.contains(&"secret.txt".to_string()), "{names:?}");
    }

    /// `.git/info/exclude` is untracked and per-clone, so it never shows up in
    /// review. It no longer removes files from a scan unless asked.
    #[test]
    fn git_info_exclude_does_not_suppress_by_default() {
        let dir = tempfile::tempdir().unwrap();
        let info = dir.path().join(".git/info");
        fs::create_dir_all(&info).unwrap();
        fs::write(info.join("exclude"), "secret.txt\n").unwrap();
        fs::write(dir.path().join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(dir.path());
        assert!(names.contains(&"secret.txt".to_string()), "{names:?}");
        // The `.git` directory itself is still not walked.
        assert!(!names.iter().any(|n| n.starts_with(".git/")), "{names:?}");

        let opted_in = IgnoreOptions {
            respect_git_exclude: true,
            ..IgnoreOptions::default()
        };
        let names = names_with(dir.path(), &opted_in);
        assert!(!names.contains(&"secret.txt".to_string()), "{names:?}");
    }

    /// Marks the re-executed child of the test below, and carries the repo it
    /// is to walk. Set with `Command::env` on a child process, never on this one.
    const GLOBAL_IGNORE_CHILD: &str = "SILOSCAN_TEST_GLOBAL_IGNORE_ROOT";

    /// Printed by the child and required by the parent, so a filter that
    /// matched no test fails the parent instead of passing it vacuously.
    const CHILD_RAN: &str = "global-ignore child ran";

    /// Git's global `core.excludesFile` belongs to the invoking user, not to
    /// the repository, so a scan must not consult it.
    ///
    /// The behaviour is exercised in a child process, and the reason is that
    /// the `ignore` crate leaves no other way in. It resolves the global
    /// excludes path from the environment alone - `GIT_CONFIG_GLOBAL`, then
    /// `$HOME/.gitconfig`, then the XDG and system files
    /// (`ignore::gitignore::global`) - and `WalkBuilder` exposes `git_global`
    /// as a bool with no path beside it. Pointing it at a fixture in-process
    /// therefore means `std::env::set_var`, which is `unsafe` for a reason:
    /// it races every concurrent `getenv` in the process, and the sibling tests
    /// in this binary call `tempfile::tempdir`, which reads `TMPDIR`. That race
    /// is a real one, and it can take the whole suite down rather than fail a
    /// test.
    ///
    /// `Command::env` sets the variable on a process that does not exist yet,
    /// which races nothing. The child re-runs this same test with the fixture
    /// path handed to it, takes the other branch, and asserts both directions
    /// for real. The parent requires [`CHILD_RAN`] on the child's stdout: a
    /// renamed test would otherwise filter to zero tests, exit 0, and quietly
    /// assert nothing.
    #[test]
    fn global_excludes_file_does_not_suppress_by_default() {
        let Some(root) = std::env::var_os(GLOBAL_IGNORE_CHILD) else {
            return spawn_global_ignore_child();
        };

        // Child: `GIT_CONFIG_GLOBAL` is already in this process's environment,
        // inherited at spawn. Nothing here mutates it.
        let root = PathBuf::from(root);
        let default_names = relative_names(&root);
        let opted_in = IgnoreOptions {
            respect_global_gitignore: true,
            ..IgnoreOptions::default()
        };
        let opted_in_names = names_with(&root, &opted_in);

        assert!(
            default_names.contains(&"secret.txt".to_string()),
            "the user's global excludes must not reach a default scan: {default_names:?}"
        );
        // The setup does suppress once the walk is told to read the user's
        // config, which is what 1.1.1 did unconditionally. Without this the
        // test above would pass on a fixture that never worked.
        assert!(
            !opted_in_names.contains(&"secret.txt".to_string()),
            "--respect-global-gitignore must reach the walker: {opted_in_names:?}"
        );
        println!("{CHILD_RAN}");
    }

    /// Build the fixture, then re-run this test binary against just the test
    /// above with `GIT_CONFIG_GLOBAL` pointed at it.
    fn spawn_global_ignore_child() {
        let dir = tempfile::tempdir().unwrap();
        let global_ignore = dir.path().join("global_ignore");
        fs::write(&global_ignore, "secret.txt\n").unwrap();
        let gitconfig = dir.path().join("gitconfig");
        fs::write(
            &gitconfig,
            format!("[core]\nexcludesFile = {}\n", global_ignore.display()),
        )
        .unwrap();

        let root = dir.path().join("repo");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "walk::tests::global_excludes_file_does_not_suppress_by_default",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(GLOBAL_IGNORE_CHILD, &root)
            .env("GIT_CONFIG_GLOBAL", &gitconfig)
            .output()
            .expect("re-running the test binary");

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "child failed:\n{stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains(CHILD_RAN),
            "the child never ran the test - has it been renamed?\n{stdout}"
        );
    }

    /// An ignore file inside the root is part of the tree under review, so it
    /// keeps its say by default.
    #[test]
    fn in_root_ignore_files_still_suppress_by_default() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "hidden_by_git.txt\n").unwrap();
        fs::write(dir.path().join(".ignore"), "hidden_by_dot.txt\n").unwrap();
        fs::write(dir.path().join("hidden_by_git.txt"), "a").unwrap();
        fs::write(dir.path().join("hidden_by_dot.txt"), "b").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = relative_names(dir.path());

        assert!(
            !names.contains(&"hidden_by_git.txt".to_string()),
            "{names:?}"
        );
        assert!(
            !names.contains(&"hidden_by_dot.txt".to_string()),
            "{names:?}"
        );
        assert!(names.contains(&"main.rs".to_string()), "{names:?}");
    }

    /// A one-line ignore file must not be able to hide a live secret with no
    /// way to look past it.
    #[test]
    fn all_files_scans_ignored_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "hidden_by_git.txt\n").unwrap();
        fs::write(dir.path().join(".ignore"), "hidden_by_dot.txt\n").unwrap();
        fs::write(dir.path().join("hidden_by_git.txt"), "a").unwrap();
        fs::write(dir.path().join("hidden_by_dot.txt"), "b").unwrap();

        let names = names_with(dir.path(), &IgnoreOptions::all_files());

        assert!(
            names.contains(&"hidden_by_git.txt".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"hidden_by_dot.txt".to_string()),
            "{names:?}"
        );
    }

    /// Turning off one in-root source leaves the other alone.
    #[test]
    fn gitignore_and_dot_ignore_toggle_independently() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "hidden_by_git.txt\n").unwrap();
        fs::write(dir.path().join(".ignore"), "hidden_by_dot.txt\n").unwrap();
        fs::write(dir.path().join("hidden_by_git.txt"), "a").unwrap();
        fs::write(dir.path().join("hidden_by_dot.txt"), "b").unwrap();

        let no_git = IgnoreOptions {
            respect_gitignore: false,
            ..IgnoreOptions::default()
        };
        let names = names_with(dir.path(), &no_git);
        assert!(
            names.contains(&"hidden_by_git.txt".to_string()),
            "{names:?}"
        );
        assert!(
            !names.contains(&"hidden_by_dot.txt".to_string()),
            "{names:?}"
        );

        let no_dot = IgnoreOptions {
            respect_dot_ignore: false,
            ..IgnoreOptions::default()
        };
        let names = names_with(dir.path(), &no_dot);
        assert!(
            !names.contains(&"hidden_by_git.txt".to_string()),
            "{names:?}"
        );
        assert!(
            names.contains(&"hidden_by_dot.txt".to_string()),
            "{names:?}"
        );
    }

    /// The exclusions the walker owns are policy, not ignore rules: they hold
    /// even when every ignore source is off.
    #[test]
    fn all_files_still_excludes_vcs_and_state_directories() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git/objects")).unwrap();
        fs::write(dir.path().join(".git/objects/blob"), "x").unwrap();
        fs::create_dir_all(dir.path().join(".siloscan/cache")).unwrap();
        fs::write(dir.path().join(".siloscan/cache/entry.json"), "{}").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let names = names_with(dir.path(), &IgnoreOptions::all_files());

        assert_eq!(names, vec!["main.rs".to_string()], "{names:?}");
    }

    /// An in-root `.gitignore` may hide a live credential, but it may not do it
    /// silently: the file is gone from the scan and present in the count.
    #[test]
    fn an_ignored_file_is_counted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), ".env\n").unwrap();
        fs::write(dir.path().join(".env"), "AWS_SECRET=AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let walked = collect_files_counted(dir.path(), &IgnoreOptions::default());

        let names: Vec<String> = walked
            .files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(!names.contains(&".env".to_string()), "{names:?}");
        assert_eq!(
            walked.ignored,
            Ignored {
                files: 1,
                directories: 0
            }
        );
        assert_eq!(
            walked.ignored.summary_line().as_deref(),
            Some("1 file ignored by .gitignore/.ignore")
        );
    }

    /// The count is a difference between two tallies, so the two sides have to
    /// agree on what a symbolic link is. The walk does not follow links and
    /// neither does `read_dir`, so a link is "not a directory" to both - an
    /// ignored one is counted as a file, and a surviving one cancels out
    /// instead of being counted as an exclusion.
    #[cfg(unix)]
    #[test]
    fn symlinks_are_classified_the_same_on_both_sides_of_the_count() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("real")).unwrap();
        fs::write(dir.path().join("real/a.rs"), "fn a() {}").unwrap();
        fs::write(dir.path().join(".gitignore"), "hidden_link\n").unwrap();
        // A link to a directory, ignored: one file, not one directory, because
        // its target is never descended into.
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("hidden_link"))
            .unwrap();
        // And one the ignore rules leave alone, which is not an exclusion.
        std::os::unix::fs::symlink(dir.path().join("real"), dir.path().join("kept_link")).unwrap();

        let walked = collect_files_counted(dir.path(), &IgnoreOptions::default());

        assert_eq!(
            walked.ignored,
            Ignored {
                files: 1,
                directories: 0
            }
        );
    }

    /// A `.ignore` file counts the same way a `.gitignore` does, and a nested
    /// ignore file counts in the directory it applies to.
    #[test]
    fn every_in_root_ignore_source_is_counted() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".ignore"), "hidden_by_dot.txt\n").unwrap();
        fs::write(dir.path().join("hidden_by_dot.txt"), "a").unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/.gitignore"), "generated.rs\n").unwrap();
        fs::write(dir.path().join("src/generated.rs"), "fn g() {}").unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();

        let walked = collect_files_counted(dir.path(), &IgnoreOptions::default());

        assert_eq!(
            walked.ignored,
            Ignored {
                files: 2,
                directories: 0
            }
        );
        assert_eq!(
            walked.ignored.summary_line().as_deref(),
            Some("2 files ignored by .gitignore/.ignore")
        );
    }

    /// A pruned directory is one count and nothing more. Counting what is
    /// inside it would mean walking the tree the ignore rule exists to keep the
    /// walker out of, which is what makes a `node_modules` line cheap to honor
    /// and expensive to enumerate.
    #[test]
    fn a_pruned_directory_counts_once_however_much_is_inside_it() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "node_modules/\n").unwrap();
        let deep = dir.path().join("node_modules/pkg/dist/nested");
        fs::create_dir_all(&deep).unwrap();
        for name in ["a.js", "b.js", "c.js"] {
            fs::write(deep.join(name), "module.exports = {};\n").unwrap();
        }
        fs::write(dir.path().join("node_modules/pkg/index.js"), "x").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let walked = collect_files_counted(dir.path(), &IgnoreOptions::default());

        assert_eq!(
            walked.ignored,
            Ignored {
                files: 0,
                directories: 1
            }
        );
        assert_eq!(
            walked.ignored.summary_line().as_deref(),
            Some(
                "1 directory ignored by .gitignore/.ignore; its contents were not walked and are \
                 not counted"
            )
        );

        // And the plural keeps its plural clause.
        assert_eq!(
            Ignored {
                files: 0,
                directories: 2
            }
            .summary_line()
            .as_deref(),
            Some(
                "2 directories ignored by .gitignore/.ignore; their contents were not walked and \
                 are not counted"
            )
        );
    }

    /// Both kinds of exclusion in one tree, and the wording says which is which.
    #[test]
    fn files_and_directories_are_counted_apart() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "target/\n*.log\n").unwrap();
        fs::create_dir_all(dir.path().join("target/debug")).unwrap();
        fs::write(dir.path().join("target/debug/app"), "binary").unwrap();
        fs::write(dir.path().join("build.log"), "line\n").unwrap();
        fs::write(dir.path().join("run.log"), "line\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let walked = collect_files_counted(dir.path(), &IgnoreOptions::default());

        assert_eq!(
            walked.ignored,
            Ignored {
                files: 2,
                directories: 1
            }
        );
        let line = walked
            .ignored
            .summary_line()
            .expect("something was ignored");
        assert!(
            line.starts_with("2 files and 1 directory ignored"),
            "{line}"
        );
    }

    /// Nothing ignored is a count of zero and no line at all, which is what
    /// makes a nonzero count mean something.
    #[test]
    fn a_tree_with_no_ignore_files_counts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join("README.md"), "# readme\n").unwrap();

        let walked = collect_files_counted(dir.path(), &IgnoreOptions::default());

        assert!(walked.ignored.is_empty());
        assert_eq!(walked.ignored, Ignored::default());
        assert_eq!(walked.ignored.summary_line(), None);
    }

    /// Turning the ignore sources off scans the files, so there is nothing left
    /// to report as unseen.
    #[test]
    fn all_files_leaves_nothing_to_count() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "secret.txt\nvendor/\n").unwrap();
        fs::write(dir.path().join("secret.txt"), "AKIAIOSFODNN7EXAMPLE\n").unwrap();
        fs::create_dir(dir.path().join("vendor")).unwrap();
        fs::write(dir.path().join("vendor/dep.rs"), "fn d() {}").unwrap();

        let walked = collect_files_counted(dir.path(), &IgnoreOptions::all_files());

        let names = names_with(dir.path(), &IgnoreOptions::all_files());
        assert!(names.contains(&"secret.txt".to_string()), "{names:?}");
        assert!(walked.ignored.is_empty(), "{:?}", walked.ignored);
    }

    /// The walker's own exclusions are policy, not ignore rules, so they are
    /// not counted. `.siloscan` matters twice: it exists only after a scan has
    /// run, so counting it would make a warm run's numbers differ from a cold
    /// run's.
    #[test]
    fn policy_exclusions_are_never_counted() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git/objects")).unwrap();
        fs::write(dir.path().join(".git/objects/blob"), "x").unwrap();
        fs::create_dir_all(dir.path().join(".siloscan/cache")).unwrap();
        fs::write(dir.path().join(".siloscan/cache/entry.json"), "{}").unwrap();
        fs::write(dir.path().join(".siloscan/.gitignore"), "cache/\n").unwrap();
        fs::write(dir.path().join("main.rs"), "fn main() {}").unwrap();

        let walked = collect_files_counted(dir.path(), &IgnoreOptions::default());

        assert_eq!(walked.files.len(), 1);
        assert!(walked.ignored.is_empty(), "{:?}", walked.ignored);
    }

    /// The count is a sum over set membership, so the order a directory is read
    /// in cannot move it.
    #[test]
    fn counts_are_stable_across_repeated_walks() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "*.log\nbuild/\n").unwrap();
        fs::create_dir_all(dir.path().join("build/out")).unwrap();
        fs::write(dir.path().join("build/out/app"), "x").unwrap();
        for name in ["a.log", "b.log", "c.log"] {
            fs::write(dir.path().join(name), "line\n").unwrap();
        }
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();

        let expected = Ignored {
            files: 3,
            directories: 1,
        };
        for _ in 0..5 {
            let walked = collect_files_counted(dir.path(), &IgnoreOptions::default());
            assert_eq!(walked.ignored, expected);
        }
    }

    /// Counting observes the walk; it does not change it.
    #[test]
    fn counting_returns_the_same_files_as_the_plain_walk() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(".gitignore"), "ignored.txt\nvendor/\n").unwrap();
        fs::write(dir.path().join("ignored.txt"), "x").unwrap();
        fs::create_dir(dir.path().join("vendor")).unwrap();
        fs::write(dir.path().join("vendor/dep.rs"), "fn d() {}").unwrap();
        fs::create_dir(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();

        for opts in [IgnoreOptions::default(), IgnoreOptions::all_files()] {
            assert_eq!(
                collect_files_counted(dir.path(), &opts).files,
                collect_files_with(dir.path(), &opts),
                "{opts:?}"
            );
        }
    }

    /// A project root's `.gitignore` under `anchor = "config"`, laid out the
    /// way a real one is.
    ///
    /// The scan root is `modules/api`, two levels below the project root whose
    /// ignore file is in scope, and the patterns are anchored - which is what
    /// `add_ignore` could not root correctly.
    fn anchored_project(root: &Path) {
        fs::create_dir_all(root.join("modules/api/secrets")).unwrap();
        fs::create_dir_all(root.join("modules/api/src")).unwrap();
        fs::create_dir_all(root.join("modules/api/api")).unwrap();
        fs::write(
            root.join(".gitignore"),
            "/modules/api/secrets/\n/modules/api/src/generated.rs\n/api/\n",
        )
        .unwrap();
        fs::write(
            root.join("modules/api/secrets/leak.txt"),
            "password = needle\n",
        )
        .unwrap();
        fs::write(root.join("modules/api/src/generated.rs"), "fn g() {}").unwrap();
        fs::write(root.join("modules/api/src/main.rs"), "fn main() {}").unwrap();
        fs::write(root.join("modules/api/api/keep.rs"), "fn keep() {}").unwrap();
    }

    /// The scan root and the project directories above it, as
    /// `Config::project_ignore_dirs` hands them over: outermost first.
    fn anchored_scan(root: &Path) -> (PathBuf, Vec<PathBuf>) {
        let root = root.canonicalize().unwrap();
        (
            root.join("modules/api"),
            vec![root.clone(), root.join("modules")],
        )
    }

    /// An anchored pattern in a project `.gitignore` is anchored at the
    /// directory that file came from, and at nothing else.
    ///
    /// `/api/` is in the fixture to prove the anchoring is real rather than
    /// incidental: it names a directory that exists directly under the scan
    /// root and not under the project root, so a matcher rooted anywhere but
    /// the project root would exclude the scan root's own `api` tree - or, as
    /// the shipped build did, exclude whatever the working directory made the
    /// pattern mean.
    #[test]
    fn an_anchored_project_pattern_is_rooted_at_the_file_that_declares_it() {
        let dir = tempfile::tempdir().unwrap();
        anchored_project(dir.path());
        let (scan_root, project_dirs) = anchored_scan(dir.path());

        let walked =
            collect_files_counted_in_project(&scan_root, &IgnoreOptions::default(), &project_dirs);
        let names: Vec<String> = walked
            .files
            .iter()
            .map(|path| {
                path.strip_prefix(&scan_root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();

        assert_eq!(
            names,
            vec!["api/keep.rs".to_string(), "src/main.rs".to_string()],
            "{names:?}"
        );
        assert_eq!(
            walked.ignored,
            Ignored {
                files: 1,
                directories: 1
            },
            "an excluded directory and an excluded file, both said out loud"
        );
    }

    /// Carries the project root to the re-executed child of the test below.
    const ANCHOR_CWD_CHILD: &str = "SILOSCAN_TEST_ANCHOR_CWD_ROOT";

    /// Printed by the child and required by the parent, so a filter that
    /// matched no test fails the parent instead of passing it vacuously.
    const ANCHOR_CHILD_RAN: &str = "anchor cwd child ran";

    /// The same tree, the same config and the same absolute scan root must
    /// produce the same walk from any working directory.
    ///
    /// This is the shipped defect: the project matcher was rooted at the
    /// process working directory, so a scan run from the repository root
    /// excluded `modules/api/secrets/` and a scan run from anywhere else did
    /// not. One of those reports the credential and exits nonzero and the other
    /// reports nothing and exits 0, which is a gate that passes locally and
    /// fails in CI, or the reverse.
    ///
    /// It runs in child processes because a working directory is process-global
    /// state: `set_current_dir` would move it under every other test in this
    /// binary, which run on other threads. `Command::current_dir` sets it on a
    /// process that does not exist yet and races nothing.
    #[test]
    fn an_anchored_project_pattern_does_not_depend_on_the_working_directory() {
        let Some(root) = std::env::var_os(ANCHOR_CWD_CHILD) else {
            return spawn_anchor_cwd_children();
        };

        let (scan_root, project_dirs) = anchored_scan(Path::new(&root));
        let walked =
            collect_files_counted_in_project(&scan_root, &IgnoreOptions::default(), &project_dirs);
        let names: Vec<String> = walked
            .files
            .iter()
            .map(|path| path.to_string_lossy().replace('\\', "/"))
            .collect();

        assert!(
            !names.iter().any(|name| name.ends_with("leak.txt")),
            "the project .gitignore excludes this file from {:?}: {names:?}",
            std::env::current_dir()
        );
        assert_eq!(
            walked.ignored,
            Ignored {
                files: 1,
                directories: 1
            },
            "from {:?}",
            std::env::current_dir()
        );
        println!("{ANCHOR_CHILD_RAN}");
    }

    /// Build the fixture, then re-run the test above from two working
    /// directories: the project root, and a directory outside the tree
    /// entirely. The old behavior differed between exactly those two.
    fn spawn_anchor_cwd_children() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir(&root).unwrap();
        anchored_project(&root);
        let elsewhere = tempfile::tempdir().unwrap();

        for cwd in [root.as_path(), elsewhere.path()] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "walk::tests::an_anchored_project_pattern_does_not_depend_on_the_working_\
                     directory",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(ANCHOR_CWD_CHILD, &root)
                .current_dir(cwd)
                .output()
                .expect("re-running the test binary");

            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "child in {cwd:?} failed:\n{stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                stdout.contains(ANCHOR_CHILD_RAN),
                "the child never ran the test - has it been renamed?\n{stdout}"
            );
        }
    }

    /// A project boundary widens where ignore files are read from; it does not
    /// override a decision to stop reading them.
    #[test]
    fn project_ignore_files_obey_the_switch_that_governs_their_kind() {
        let dir = tempfile::tempdir().unwrap();
        anchored_project(dir.path());
        fs::write(dir.path().join(".ignore"), "/modules/api/src/main.rs\n").unwrap();
        let (scan_root, project_dirs) = anchored_scan(dir.path());

        let no_git = IgnoreOptions {
            respect_gitignore: false,
            ..IgnoreOptions::default()
        };
        let walked = collect_files_counted_in_project(&scan_root, &no_git, &project_dirs);
        let names: Vec<String> = walked
            .files
            .iter()
            .map(|path| {
                path.strip_prefix(&scan_root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert!(
            names.contains(&"secrets/leak.txt".to_string()),
            "the project .gitignore was read with respect_gitignore off: {names:?}"
        );
        assert!(
            !names.contains(&"src/main.rs".to_string()),
            "the project .ignore was not read: {names:?}"
        );

        let walked = collect_files_counted_in_project(
            &scan_root,
            &IgnoreOptions::all_files(),
            &project_dirs,
        );
        assert_eq!(walked.files.len(), 4, "{:?}", walked.files);
        assert!(walked.ignored.is_empty(), "{:?}", walked.ignored);
    }

    /// Walk order is a property of the sort, not of the ignore policy.
    #[test]
    fn walk_order_deterministic_under_every_policy() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/b.rs"), "b").unwrap();
        fs::write(dir.path().join("src/a.rs"), "a").unwrap();
        fs::write(dir.path().join("README.md"), "r").unwrap();
        fs::write(dir.path().join(".env"), "TOKEN=value\n").unwrap();

        let expected = vec![
            ".env".to_string(),
            "README.md".to_string(),
            "src/a.rs".to_string(),
            "src/b.rs".to_string(),
        ];

        for opts in [IgnoreOptions::default(), IgnoreOptions::all_files()] {
            for _ in 0..5 {
                assert_eq!(names_with(dir.path(), &opts), expected, "{opts:?}");
            }
        }
    }
}
