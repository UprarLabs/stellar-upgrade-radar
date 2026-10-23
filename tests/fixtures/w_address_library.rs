// Address validation delegated to a maintained strkey library: not a defect.
fn valid_address(s: &str) -> bool {
    stellar_strkey::Strkey::from_string(s).is_ok()
}
