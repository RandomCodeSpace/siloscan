use std::mem;
fn f(x: u32) -> i32 { unsafe { mem::transmute::<u32, i32>(x) } }
fn f(x: u32) -> i32 { unsafe { std::mem::transmute(x) } }
