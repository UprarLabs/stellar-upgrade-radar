fn ledger_advanced(prev_close_time: u64, cur_close_time: u64) -> bool {
    // one ledger later means at least one second
    cur_close_time - prev_close_time >= 1 // must be >= 1 second
}
