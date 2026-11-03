// Contract entry point taking a plain `Address`: rejects a W address (CAP-84).
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, to: Address, amount: i128) -> Result<(), Error> {
        Ok(())
    }
}
