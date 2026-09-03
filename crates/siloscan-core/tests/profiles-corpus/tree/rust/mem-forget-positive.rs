use std::mem;
fn f(v: Vec<u8>) {
    mem::forget(v);
}
