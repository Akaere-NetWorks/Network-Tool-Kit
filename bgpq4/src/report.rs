use std::fmt;

pub fn fatal(msg: &str) -> ! {
    eprintln!("FATAL ERROR: {msg}");
    std::process::exit(1)
}

pub fn error(msg: &str) {
    eprintln!("ERROR: {msg}");
}

pub fn debug(level: i32, msg: impl fmt::Display) {
    if level > 0 {
        eprintln!("Debug: {msg}");
    }
}
