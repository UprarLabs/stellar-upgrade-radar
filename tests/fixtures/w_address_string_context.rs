// "address" inside a string literal must not create address context.
fn doc() {
    let _ = "this describes the address format";
    let _palette = ['G', 'M', 'C'];
}
