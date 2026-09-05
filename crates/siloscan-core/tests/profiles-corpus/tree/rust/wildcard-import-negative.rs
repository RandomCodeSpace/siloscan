fn g() {}
#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;
    use crate::*;
    #[test]
    fn t() { g(); }
}
