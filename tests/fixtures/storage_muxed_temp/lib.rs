pub fn set_temp(env: Env, who: MuxedAddress) {
    env.storage().temporary().set(&who, &1u32);
}
