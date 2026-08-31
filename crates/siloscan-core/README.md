# siloscan-core

The library behind [siloscan](https://github.com/RandomCodeSpace/siloscan), a
universal, rule-based static code scanner that runs fully offline and produces
byte-identical output for identical input.

This crate provides the scanning machinery: the ignore-aware file walker, the
strict YAML rule loader, the six rule engines (`regex`, `secret`, `ast`,
`boundary`, `coverage`, `duplication`), the semantic graph, the incremental
cache, baselines, metrics, and the text, JSON and SARIF writers. It also embeds
the default secrets rule pack.

Most users want the `siloscan` binary instead. Use this crate to embed scanning
in your own tool.

## Install

```sh
cargo add siloscan-core
```

Tree-sitter grammars sit behind per-language cargo features; `lang-all` is
enabled by default. Disable default features and select individual `lang-*`
features to trim the build.

## Documentation

See the [project README](https://github.com/RandomCodeSpace/siloscan#readme)
for the project overview, a custom rule example, repository defaults, and the
scanner workflow.

## License

MIT. See `LICENSE`. The embedded secrets rule pack is derived from
[gitleaks](https://github.com/gitleaks/gitleaks) (MIT); see `NOTICE`.
