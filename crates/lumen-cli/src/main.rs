use clap::Parser;
use lumen_cli::{Cli, execute};

fn main() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Tokio runtime starts");
    let result = runtime.block_on(execute(Cli::parse()));
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    match result {
        Ok(output) => println!("{output:?}"),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}
