pub fn set_instance(env: Env, who: MuxedAddress) {
    env.storage().instance().set(&who, &1u32);
}
