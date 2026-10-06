use libmkiso_fuzz::iso::{self, HEADER};

#[test]
fn complete_iso_profiles_reach_namespace_boot_and_extent_oracles() {
    let mut namespaces = 0;
    let mut links = 0;
    let mut multi = 0;
    let mut boot = 0;
    let mut hybrid = 0;
    for (name, recipe) in iso::seed_recipes() {
        let stats = iso::roundtrip(&recipe);
        assert!(stats.written, "{name}");
        namespaces += stats.namespaces;
        links += stats.links;
        multi += usize::from(stats.multi_extent);
        boot += usize::from(stats.boot);
        hybrid += usize::from(stats.hybrid);
    }
    assert!(namespaces > 58 && multi > 0 && boot > 0 && hybrid == 9);
    #[cfg(unix)]
    assert!(links > 0);
    #[cfg(not(unix))]
    assert_eq!(links, 0);
}

#[test]
fn cancellation_progress_errors_limits_and_overwrite_preserve_outputs() {
    let mut recipe = vec![0; HEADER];
    recipe.extend_from_slice(b"bounded payload");
    for flag in [1, 2, 4, 8, 16, 32, 64] {
        recipe[14] = flag;
        assert!(!iso::roundtrip(&recipe).written);
    }
    assert!(!iso::roundtrip(&[]).written);
    assert!(!iso::roundtrip(&vec![0; iso::RECIPE_LIMIT + 1]).written);
}
