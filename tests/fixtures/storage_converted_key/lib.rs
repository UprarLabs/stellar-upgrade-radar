// Explicitly converted to a non-muxed address before storage: safe.
pub fn set_base(env: Env, who: MuxedAddress) {
    let base = who.to_address();
    env.storage().persistent().set(&base, &1u32);
}
