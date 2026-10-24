// A helper named closetime_ms on a legacy arm must not mark the decoder updated.
fn f(v: &StellarValueType) {
    match v {
        StellarValueType::StellarValueSigned => closetime_ms(v),
    }
}
