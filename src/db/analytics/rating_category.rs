pub(crate) fn rating_category_rank(category: &str) -> usize {
    match category {
        "certificate" => 0,
        "protocol" => 1,
        "key_exchange" => 2,
        "cipher" => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::rating_category_rank;

    #[test]
    fn unknown_categories_sort_after_known_categories() {
        assert_eq!(rating_category_rank("certificate"), 0);
        assert_eq!(rating_category_rank("unknown"), 4);
    }
}
