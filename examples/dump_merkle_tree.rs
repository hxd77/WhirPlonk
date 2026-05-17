// ===========================================================================
// dump_merkle_tree.rs — Merkle 树 golden test。
//
// 运行: cargo run --example dump_merkle_tree --release > golden_merkle_rs.txt
// 覆盖: build_tree + open_path (BLAKE3-16叶/BLAKE3-32叶/SHA2-8叶)
// ===========================================================================

use whir::engines::EngineId;
use whir::hash::{Hash, BLAKE3, SHA2, ENGINES};
use zerocopy::IntoBytes;

fn layers_for_size(size: usize) -> usize {
    if size <= 1 { return 0; }
    let mut p = 1usize; let mut k = 0usize;
    while p < size { p <<= 1; k += 1; }
    k
}

fn build_tree(hash_id: EngineId, num_leaves: usize, leaves: Vec<Hash>) -> Vec<Hash> {
    let layers = layers_for_size(num_leaves);
    let leaf_layer = 1usize << layers;
    let total = (1usize << (layers + 1)) - 1;
    let mut nodes = leaves;
    nodes.resize(total, Hash::default());
    let engine = ENGINES.retrieve(hash_id).expect("engine");
    let mut prev_off = 0usize; let mut prev_len = leaf_layer;
    let mut curr_off = leaf_layer;
    for _ in 0..layers {
        let curr_len = prev_len / 2;
        let (head, tail) = nodes.split_at_mut(curr_off);
        engine.hash_many(64, &head[prev_off..prev_off + prev_len].as_bytes(), &mut tail[..curr_len]);
        prev_off = curr_off; prev_len = curr_len; curr_off += curr_len;
    }
    nodes
}

fn open_path(num_leaves: usize, witness: &[Hash], indices: &[usize]) -> Vec<Hash> {
    let layers = layers_for_size(num_leaves);
    let mut idx: Vec<usize> = indices.to_vec();
    idx.sort_unstable(); idx.dedup();
    let mut hints = Vec::new();
    let mut layer_off = 0usize; let mut layer_len = 1usize << layers;
    while layer_len > 1 {
        let mut next = Vec::with_capacity(idx.len());
        let mut k = 0usize;
        while k < idx.len() {
            let a = idx[k];
            if k + 1 < idx.len() && idx[k + 1] == (a ^ 1) {
                next.push(a >> 1); k += 2;
            } else {
                hints.push(witness[layer_off + (a ^ 1)]);
                next.push(a >> 1); k += 1;
            }
        }
        idx = next; layer_off += layer_len; layer_len /= 2;
    }
    hints
}

fn main() {
    let dump_hash = |label: &str, h: &Hash| {
        print!("  {label} ");
        for byte in h.0.iter() { print!("{byte:02x}"); }
        println!();
    };

    println!("# SECTION merkle_tree");
    let cases: &[(&str, EngineId, usize, &[usize])] = &[
        ("blake3-16-2",  BLAKE3, 16, &[3, 5, 11]),
        ("blake3-32-3",  BLAKE3, 32, &[0, 1, 2, 31]),
        ("sha2-8-2",    SHA2,    8, &[2, 6]),
    ];
    for (case_idx, &(label, hash_id, num_leaves, indices)) in cases.iter().enumerate() {
        let leaves: Vec<Hash> = (0..num_leaves)
            .map(|i| {
                let mut h = [0u8; 32];
                for (j, b) in h.iter_mut().enumerate() { *b = ((i * 31 + j) & 0xFF) as u8; }
                Hash(h)
            })
            .collect();
        let witness = build_tree(hash_id, num_leaves, leaves);
        let layers = layers_for_size(num_leaves);
        let leaf_layer = 1usize << layers;
        let total = (1usize << (layers + 1)) - 1;
        let root = witness[total - 1];
        let hints = open_path(num_leaves, &witness, indices);
        println!("CASE {case_idx} {label} num_leaves={num_leaves}");
        dump_hash("root", &root);
        println!("  leaf_layer {leaf_layer}");
        println!("  num_hints {}", hints.len());
        for (i, h) in hints.iter().enumerate() { dump_hash(&format!("hint{i}"), h); }
    }
}
