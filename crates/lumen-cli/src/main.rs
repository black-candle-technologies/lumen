use clap::Parser;
use lumen_cli::{Cli, execute};

#[tokio::main]
async fn main() {
    match execute(Cli::parse()).await {
        Ok(output) => println!("{output:?}"),
        Err(error) => {
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}
