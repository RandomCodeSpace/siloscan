# siloscan

A universal, rule-based static code scanner. Quick, deterministic, fully
offline.

siloscan walks a directory tree, applies declarative YAML rules to every text
file, and reports findings with stable SHA-256 fingerprints. No server, no
daemon, no network access - the same input always produces the same output,
byte for byte. A default secrets ruleset is embedded in the binary.

This crate is the command-line interface. It installs two binaries: `siloscan`
and `ss`, a short alias for the same program. Note that `ss` shadows the
iproute2 socket-statistics tool if `~/.cargo/bin` precedes `/usr/bin` in your
`PATH`.

## Install

```sh
cargo install siloscan
```

## Usage

```sh
siloscan .                     # scan with the embedded secrets ruleset
siloscan . --rules ./rules     # add your own rules
siloscan . --format json       # machine-readable
siloscan . --format sarif      # GitHub code scanning
siloscan baseline .            # accept current findings as debt
```

Exit codes: `0` clean, `1` new findings at or above the `--fail-on` threshold
(default `error`), `2` usage, config, or rule-load error.

## Documentation

See the [project README](https://github.com/RandomCodeSpace/siloscan#readme)
for the quick start, a custom rule example, baselines, terminal review, and CI
usage.

## License

MIT. See `LICENSE`. The embedded secrets ruleset is derived from
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT); see `NOTICE`.
