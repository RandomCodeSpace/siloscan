fn f() -> u32 {
    return g();
    struct S;
}
fn g() -> u32 { 0 }
fn f() -> u32 {
    return g();
    #[cfg(test)]
    struct S;
}
fn g() -> u32 { 0 }
