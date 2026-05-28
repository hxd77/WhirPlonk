use std::{
    env,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

fn csv_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        env::var("WHIR_PROFILE")
            .map(|v| {
                let v = v.as_bytes();
                !v.is_empty()
                    && v[0] != b'0'
                    && v[0] != b'f'
                    && v[0] != b'F'
                    && v[0] != b'n'
                    && v[0] != b'N'
            })
            .unwrap_or(false)
    })
}

fn print_header_once() {
    static PRINTED: OnceLock<()> = OnceLock::new();
    PRINTED.get_or_init(|| {
        eprintln!("mode,phase,size,stage,time_ms");
    });
}

pub fn record(mode: &str, size: usize, stage: &str, elapsed: Duration) {
    if !csv_enabled() {
        return;
    }
    print_header_once();
    let phase = current_phase();
    eprintln!(
        "{mode},{phase},{size},{stage},{:.6}",
        elapsed.as_secs_f64() * 1000.0
    );
}

fn phase_cell() -> &'static Mutex<&'static str> {
    static PHASE: OnceLock<Mutex<&'static str>> = OnceLock::new();
    PHASE.get_or_init(|| Mutex::new("none"))
}

pub fn current_phase() -> &'static str {
    *phase_cell().lock().expect("profiling phase lock poisoned")
}

pub struct PhaseGuard {
    previous: &'static str,
}

impl PhaseGuard {
    pub fn new(phase: &'static str) -> Self {
        let mut current = phase_cell().lock().expect("profiling phase lock poisoned");
        let previous = *current;
        *current = phase;
        Self { previous }
    }
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        *phase_cell().lock().expect("profiling phase lock poisoned") = self.previous;
    }
}

pub struct ScopedTimer {
    mode: &'static str,
    stage: &'static str,
    size: usize,
    start: Option<Instant>,
}

impl ScopedTimer {
    pub fn new(mode: &'static str, size: usize, stage: &'static str) -> Self {
        Self {
            mode,
            stage,
            size,
            start: csv_enabled().then(Instant::now),
        }
    }
}

impl Drop for ScopedTimer {
    fn drop(&mut self) {
        if let Some(start) = self.start {
            record(self.mode, self.size, self.stage, start.elapsed());
        }
    }
}
