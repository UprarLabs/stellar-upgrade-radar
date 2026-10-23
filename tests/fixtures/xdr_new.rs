fn decode_value(v: &StellarValueType) {
    match v {
        StellarValueType::StellarValueSigned => emit(),
        StellarValueType::StellarValueSignedMs => emit(),
    }
}
