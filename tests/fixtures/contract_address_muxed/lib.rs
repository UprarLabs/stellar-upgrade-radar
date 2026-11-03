// Entry point taking `MuxedAddress`: accepts both muxed and non-muxed.
#[contractimpl]
impl Token {
    pub fn transfer(env: Env, to: MuxedAddress, amount: i128) -> Result<(), Error> {
        Ok(())
    }
}
