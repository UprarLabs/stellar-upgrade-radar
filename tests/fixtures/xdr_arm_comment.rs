// A trailing comment mentioning the _MS arm must not mark the decoder updated.
fn f(v: &StellarValueType) {
    match v {
        StellarValueType::StellarValueSigned => a(), // TODO: StellarValueSignedMs
    }
}
