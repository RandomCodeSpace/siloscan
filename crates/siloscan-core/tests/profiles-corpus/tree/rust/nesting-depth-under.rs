pub fn walk_under(values: &[i64]) -> i64 {
    let mut total = 0;
    for value in values {
        for value in values {
            for value in values {
                for value in values {
                    for value in values {
                        total += value;
                    }
                }
            }
        }
    }
    total
}
