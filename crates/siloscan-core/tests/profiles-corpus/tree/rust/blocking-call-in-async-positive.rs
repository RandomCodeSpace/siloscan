use std::thread;
async fn f(c: bool) { if c { thread::sleep(std::time::Duration::from_secs(1)); } }
