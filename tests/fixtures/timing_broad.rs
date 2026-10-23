// "per ledger" is not a one-second assumption; must not be flagged.
fn refresh(close_time: u64) -> u64 {
    close_time // close_time is refreshed per ledger
}
