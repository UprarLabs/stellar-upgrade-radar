// A real line comment that mentions the word "address" must not, by itself,
// create address context. The genuine allowlist on the next line is flagged
// because the function name carries the `prefix` keyword, not because of the
// comment.
// This file intentionally documents an address allowlist.
fn valid_strkey_prefix(c: char) -> bool {
    ['G', 'M', 'C', 'B', 'X', 'T'].contains(&c)
}
