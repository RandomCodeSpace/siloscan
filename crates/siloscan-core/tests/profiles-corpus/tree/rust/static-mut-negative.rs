use std::sync::atomic::AtomicU32;
static COUNTER: AtomicU32 = AtomicU32::new(0);
fn f() -> &'static AtomicU32 { &COUNTER }
