// A `//` appears inside a URL string literal on the same line as a genuine
// strkey prefix allowlist. It must NOT truncate the allowlist, so the file IS
// flagged (regression for the string-aware comment stripper).
fn valid_strkey_prefix(c: char) -> bool {
    let _ = "https://stellar.org/protocol/address";
    ['G', 'M', 'C', 'B', 'X', 'T'].contains(&c)
}
