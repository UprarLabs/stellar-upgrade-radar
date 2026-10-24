// Special chars in filename: [] and &
fn valid_strkey_prefix(c: char) -> bool {
    ['G','M','C','B','X','T'].contains(&c)
}
