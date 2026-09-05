static mut COUNTER: u32 = 0;
fn f() { unsafe { COUNTER += 1; } }
