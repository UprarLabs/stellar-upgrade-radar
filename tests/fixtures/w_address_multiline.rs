// Allowlist written one character per line: must still be detected.
fn valid_strkey_prefix(c: char) -> bool {
    ['G',
     'M',
     'C',
     'B',
     'X',
     'T'].contains(&c)
}
