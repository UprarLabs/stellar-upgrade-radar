fn valid_strkey_prefix(c: char) -> bool {
    // émoji𐍈𐍈𐍈 then the allowlist
    ['G','M','C','B','X','T'].contains(&c)
}
