/// The built-in secrets rule pack, translated from the gitleaks default config
/// by `scripts/convert_gitleaks.py`. See `NOTICE` for attribution and the tag
/// it was generated from.
pub fn default_rules() -> &'static str {
    include_str!("../rules/default/secrets.yaml")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pack_loads() {
        let rules =
            crate::rules::load_str(default_rules(), "default-pack").expect("default pack loads");
        assert!(
            rules.len() > 50,
            "expected a substantial pack, got {} rules",
            rules.len()
        );
    }
}
