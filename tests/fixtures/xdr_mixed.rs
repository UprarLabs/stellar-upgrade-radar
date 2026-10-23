// One function handles the _MS arm; another still enumerates only the
// pre-Protocol-30 arms. The file-level presence of an _MS arm must not mask
// the incomplete decoder.
fn modern(v: &StellarValueType) {
    match v {
        StellarValueType::StellarValueSignedMs => emit(),
    }
}

fn legacy(v: &StellarValueType) {
    match v {
        StellarValueType::StellarValueSigned => emit(),
    }
}
