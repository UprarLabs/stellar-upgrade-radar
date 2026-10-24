// A match over an unrelated enum whose arm value is a string mentioning a
// stellar-value name must not be flagged as a StellarValue decoder.
fn kind(v: &StellarValue) -> &str {
    match v.level {
        Level::A => "stellar_value_signed",
        Level::B => "other",
    }
}
