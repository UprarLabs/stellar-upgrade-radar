// Escaped quotes plus `//` inside a string literal must not terminate the
// string early, so the genuine allowlist that follows is still detected.
fn valid_strkey_prefix(c: char) -> bool {
    let _ = "a\"b//c";
    ['G', 'M', 'C', 'B', 'X', 'T'].contains(&c)
}
