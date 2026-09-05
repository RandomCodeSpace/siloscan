fn f(x: Option<i32>) -> i32 { if x.is_some() { let y = x.unwrap() + 1; y } else { 0 } }
