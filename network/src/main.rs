//! Offline BAP timeline CLI — no sockets, no crypto, no live Destiny services.

use destiny1_network::cli;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(err) = cli::run(&args) {
        eprintln!("error: {err}");
        std::process::exit(err.exit_code());
    }
}
