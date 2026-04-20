use crate::scanner::PingResult;

const COLS: usize = 32;
const MAX_BLOCKS: usize = 1024;

// bright white filled block
const ALIVE: &str = "\x1b[97m█\x1b[0m";
// terminal default light shade
const DEAD: &str = "░";

pub fn render(results: &[PingResult]) {
    let total = results.len();
    let active: usize = results.iter().filter(|r| r.alive).count();
    let inactive = total - active;
    let pct = if total > 0 {
        active as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    println!("Active: {active}/{total}  Inactive: {inactive}  ({pct:.1}%)");
    println!();

    // scale: one block represents `scale` IPs
    let scale = total.div_ceil(MAX_BLOCKS).max(1);

    let block_count = total.div_ceil(scale);

    for block_idx in 0..block_count {
        let start = block_idx * scale;
        let end = (start + scale).min(total);
        let slice = &results[start..end];

        // block is alive if majority of IPs in its range responded
        let alive_count = slice.iter().filter(|r| r.alive).count();
        let alive = alive_count * 2 >= slice.len();

        if alive {
            print!("{ALIVE}");
        } else {
            print!("{DEAD}");
        }

        if (block_idx + 1) % COLS == 0 {
            println!();
        }
    }

    // trailing newline if last row was partial
    if !block_count.is_multiple_of(COLS) {
        println!();
    }
}
