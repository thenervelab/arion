use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about = "Generate Ed25519 keypair for miner")]
struct Args {
    /// Output directory for keypair file
    #[arg(short, long)]
    output: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Generate keypair with random number generator
    let secret = iroh::SecretKey::generate(&mut rand::rng());
    let public = secret.public();

    // Create output directory if it doesn't exist
    std::fs::create_dir_all(&args.output)?;

    // Save keypair (to_bytes() returns the secret key bytes)
    let keypair_path = args.output.join("keypair");
    std::fs::write(&keypair_path, secret.to_bytes())?;

    // Output the node ID (public key in hex)
    let node_id_hex = format!("0x{}", hex::encode(public.as_bytes()));
    println!("{}", node_id_hex);

    Ok(())
}
