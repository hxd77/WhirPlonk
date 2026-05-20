use whir::{algebra::fields::Field64, deterministic_rng::DeterministicRng};

fn dump_hex(label: &str, bytes: &[u8]) {
    print!("{label} ");
    for byte in bytes {
        print!("{byte:02x}");
    }
    println!();
}

fn main() {
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = i as u8;
    }

    let mut rng = DeterministicRng::new(seed, "WHIR_ZK:mask");

    println!("# SECTION rng");
    println!("domain {}", rng.domain());
    let bytes = rng.bytes(64);
    dump_hex("bytes_0_64", &bytes);

    print!("u64");
    for _ in 0..8 {
        print!(" {}", rng.u64());
    }
    println!();

    print!("field64");
    for _ in 0..8 {
        let value: Field64 = rng.field64();
        print!(" {value}");
    }
    println!();
}
