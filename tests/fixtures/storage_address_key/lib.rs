// A plain `Address` key: may or may not carry a muxed id at runtime.
pub fn set_plain(env: Env, who: Address) {
    env.storage().persistent().set(&who, &1u32);
}
