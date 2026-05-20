use ark_std::rand::{CryptoRng, Error, RngCore};

use crate::algebra::fields::Field64;

const PERSONALIZATION: &[u8] = b"WHIR_DETERMINISTIC_RNG_V1";

#[derive(Clone, Debug)]
pub struct DeterministicRng {
    seed: [u8; 32],
    domain: String,
    counter: u64,
    buffer: [u8; 32],
    buffer_pos: usize,
}

impl DeterministicRng {
    #[must_use]
    pub fn new(seed: [u8; 32], domain: impl Into<String>) -> Self {
        Self {
            seed,
            domain: domain.into(),
            counter: 0,
            buffer: [0; 32],
            buffer_pos: 32,
        }
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        let mut out = vec![0; n];
        self.fill_bytes(&mut out);
        out
    }

    pub fn u64(&mut self) -> u64 {
        let mut buf = [0; 8];
        self.fill_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }

    pub fn field64(&mut self) -> Field64 {
        Field64::from(self.u64())
    }

    pub fn field64_vec(&mut self, n: usize) -> Vec<Field64> {
        (0..n).map(|_| self.field64()).collect()
    }

    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    fn refill(&mut self) {
        let mut input = Vec::with_capacity(PERSONALIZATION.len() + 4 + self.domain.len() + 32 + 8);
        input.extend_from_slice(PERSONALIZATION);
        input.extend_from_slice(&(self.domain.len() as u32).to_le_bytes());
        input.extend_from_slice(self.domain.as_bytes());
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);

        self.buffer = *blake3::hash(&input).as_bytes();
        self.buffer_pos = 0;
    }
}

impl RngCore for DeterministicRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        self.u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut written = 0;
        while written < dest.len() {
            if self.buffer_pos == self.buffer.len() {
                self.refill();
            }
            let take = (dest.len() - written).min(self.buffer.len() - self.buffer_pos);
            dest[written..written + take]
                .copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + take]);
            self.buffer_pos += take;
            written += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for DeterministicRng {}
