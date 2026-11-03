// Non-address keys are out of scope.
pub fn set_id(env: Env, id: u32, sym: Symbol) {
    env.storage().persistent().set(&id, &1u32);
    env.storage().instance().set(&sym, &2u32);
}
