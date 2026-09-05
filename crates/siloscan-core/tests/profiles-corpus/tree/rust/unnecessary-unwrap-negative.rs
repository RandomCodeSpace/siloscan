fn f(x: Option<i32>) -> i32 { if x.is_some() { x.unwrap_or(0) } else { 0 } }
