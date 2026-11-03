// CAP-84: a muxed contract address must not appear in a storage key.
pub fn set_muxed(env: Env, who: MuxedAddress) {
    env.storage().persistent().set(&who, &1u32);
}
