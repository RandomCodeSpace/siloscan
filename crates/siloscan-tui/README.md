# siloscan-tui

The interactive terminal UI for
[siloscan](https://github.com/RandomCodeSpace/siloscan), a universal,
rule-based static code scanner.

Built on ratatui, it offers a dashboard with KPI cards and a silo severity
matrix, a filterable triage board with code context, a ratchet console for
per-finding debt decisions, and a silo dependency matrix. Mouse and keyboard
are both supported. Snapshot mode loads an existing JSON report read-only.

The `siloscan` CLI links this crate, so `siloscan review` opens the same UI
without installing it. Install it on its own to triage without the scanner.

## Install

```sh
cargo install siloscan-tui
```

## Usage

```sh
siloscan-tui .                      # scan a tree and triage interactively
siloscan-tui --report report.json   # load a JSON report (read-only)
```

A report whose `findings` key is missing or null is rejected rather than shown
as an empty result.

## Documentation

See the [project README](https://github.com/RandomCodeSpace/siloscan#readme)
for installation, the first scan, custom rules, baselines, and CI reports.

## License

MIT. See `LICENSE`. The secrets rule pack shipped by `siloscan-core` is derived
from [gitleaks](https://github.com/gitleaks/gitleaks) (MIT); see `NOTICE`.
