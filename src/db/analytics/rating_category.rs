pub(crate) fn rating_category_rank(category: &str) -> usize {
    match category {
        "certificate" => 0,
        "protocol" => 1,
        "key_exchange" => 2,
        "cipher" => 3,
        _ => 4,
    }
}
