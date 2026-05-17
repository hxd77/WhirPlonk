// ===========================================================================
// dump_challenge_indices.rs — 挑战索引生成 golden test。
//
// 运行: cargo run --example dump_challenge_indices --release > golden_ci_rs.txt
// 覆盖: entropy bytes → indices (8 组参数: 去重/不去重/单叶/零挑战等)
// ===========================================================================

fn from_entropy(entropy: &[u8], num_leaves: usize, count: usize, dedup: bool) -> Vec<usize> {
    if count == 0 { return Vec::new(); }
    assert!(num_leaves.is_power_of_two());
    if num_leaves == 1 {
        return if dedup { vec![0] } else { vec![0; count] };
    }
    let size_bytes = (num_leaves.ilog2() as usize).div_ceil(8);
    assert_eq!(entropy.len(), count * size_bytes);
    let mut indices: Vec<usize> = entropy
        .chunks_exact(size_bytes)
        .map(|chunk| chunk.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize) % num_leaves)
        .collect();
    if dedup { indices.sort_unstable(); indices.dedup(); }
    indices
}

fn main() {
    println!("# SECTION challenge_indices");

    let cases: &[(&str, usize, usize, bool, &[u8])] = &[
        ("128-5-dedup",     128,        5, true,  &[0x01,0x23,0x45,0x67,0x89]),
        ("128-5-nodedup",   128,        5, false, &[0x01,0x23,0x45,0x67,0x89]),
        ("8192-5-dedup",    8192,       5, true,  &[0x01,0x23, 0x45,0x67, 0x89,0xAB, 0xCD,0xEF, 0x12,0x34]),
        ("1m-4-dedup",      1usize<<20, 4, true,  &[0x12,0x34,0x56, 0x78,0x9A,0xBC, 0xDE,0xF0,0x11, 0x22,0x33,0x44]),
        ("128-5-dups",      128,        5, true,  &[0x20,0x40,0x20,0x60,0x40]),
        ("1leaf-3-dedup",   1,          3, true,  &[]),
        ("1leaf-3-nodedup", 1,          3, false, &[]),
        ("0count",          8,          0, true,  &[]),
    ];
    for (case_idx, &(label, num_leaves, count, dedup, entropy)) in cases.iter().enumerate() {
        let result = from_entropy(entropy, num_leaves, count, dedup);
        println!(
            "CASE {case_idx} {label} num_leaves={num_leaves} count={count} dedup={dedup} entropy_len={}",
            entropy.len()
        );
        print!("  indices");
        for v in &result { print!(" {v}"); }
        println!();
    }
}
