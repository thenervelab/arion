use anyhow::{Context, Result};
use subxt::{OnlineClient, config::PolkadotConfig, dynamic};

/// Quick test tool to verify we can read pallet-arion storage
#[tokio::main]
async fn main() -> Result<()> {
    let chain_ws_url =
        std::env::var("CHAIN_WS_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".to_string());

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  🔍 Testing Chain Storage Queries");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("Connecting to: {}", chain_ws_url);

    let client = OnlineClient::<PolkadotConfig>::from_url(&chain_ws_url)
        .await
        .context("connect chain ws")?;

    let block_number: u32 = client.blocks().at_latest().await?.number();
    println!("✅ Connected! Current block: {}", block_number);
    println!();

    // List all pallets
    println!("📋 Available pallets:");
    for pallet in client.metadata().pallets() {
        if pallet.name().to_lowercase().contains("arion")
            || pallet.name().to_lowercase().contains("registration")
            || pallet.name().to_lowercase().contains("proxy")
        {
            println!(
                "  - {} (calls: {:?})",
                pallet.name(),
                pallet.call_hash("registerChild").is_some()
            );
        }
    }
    println!();

    // Detect Arion pallet
    let pallet_name = std::env::var("ARION_PALLET_NAME").unwrap_or_else(|_| {
        for p in client.metadata().pallets() {
            if p.call_hash("register_child").is_some() {
                return p.name().to_string();
            }
        }
        "Arion".to_string()
    });

    println!("Using pallet name: {}", pallet_name);
    println!();

    // Test 1: Query FamilyChildren
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Test 1: FamilyChildren storage");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let keys: Vec<dynamic::Value> = vec![];
    let q = dynamic::storage(&pallet_name, "FamilyChildren", keys);

    match client.storage().at_latest().await?.iter(q).await {
        Ok(mut it) => {
            let mut count = 0;
            while let Some(result) = it.next().await {
                match result {
                    Ok(kv) => {
                        count += 1;
                        println!("  Entry {}: keys={:?}", count, kv.keys.len());
                        if count <= 3 {
                            println!("    Raw key data: {:?}", kv.keys);
                        }
                    }
                    Err(e) => {
                        println!("  ❌ Error reading entry: {}", e);
                    }
                }
            }
            println!("  ✅ Total FamilyChildren entries: {}", count);
        }
        Err(e) => {
            println!("  ❌ Failed to iterate FamilyChildren: {}", e);
        }
    }
    println!();

    // Test 2: Query ChildRegistrations
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Test 2: ChildRegistrations storage");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let keys: Vec<dynamic::Value> = vec![];
    let q = dynamic::storage(&pallet_name, "ChildRegistrations", keys);

    match client.storage().at_latest().await?.iter(q).await {
        Ok(mut it) => {
            let mut count = 0;
            while let Some(result) = it.next().await {
                match result {
                    Ok(kv) => {
                        count += 1;
                        println!("  Entry {}: keys={:?}", count, kv.keys.len());
                        if count <= 3 {
                            println!("    Key: {:?}", kv.keys);
                            println!("    Value type: {:?}", kv.value.to_value());
                        }
                    }
                    Err(e) => {
                        println!("  ❌ Error reading entry: {}", e);
                    }
                }
            }
            println!("  ✅ Total ChildRegistrations entries: {}", count);
        }
        Err(e) => {
            println!("  ❌ Failed to iterate ChildRegistrations: {}", e);
        }
    }
    println!();

    // Test 3: Query NodeIdToChild
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Test 3: NodeIdToChild storage");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    let keys: Vec<dynamic::Value> = vec![];
    let q = dynamic::storage(&pallet_name, "NodeIdToChild", keys);

    match client.storage().at_latest().await?.iter(q).await {
        Ok(mut it) => {
            let mut count = 0;
            while let Some(result) = it.next().await {
                match result {
                    Ok(kv) => {
                        count += 1;
                        println!("  Entry {}: keys={:?}", count, kv.keys.len());
                        if count <= 3 {
                            println!("    Key: {:?}", kv.keys);
                            println!("    Value: {:?}", kv.value.to_value());
                        }
                    }
                    Err(e) => {
                        println!("  ❌ Error reading entry: {}", e);
                    }
                }
            }
            println!("  ✅ Total NodeIdToChild entries: {}", count);
        }
        Err(e) => {
            println!("  ❌ Failed to iterate NodeIdToChild: {}", e);
        }
    }
    println!();

    // Test 4: Check specific storage item metadata
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Test 4: Storage Metadata");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    if let Some(pallet) = client.metadata().pallet_by_name(&pallet_name) {
        println!("  Pallet: {}", pallet.name());
        println!("  Storage items exist: {}", pallet.storage().is_some());
        if let Some(storage) = pallet.storage() {
            println!("  Available storage entries:");
            for entry in storage.entries() {
                println!("    - {}", entry.name());
            }
        }
    } else {
        println!("  ❌ Pallet '{}' not found!", pallet_name);
    }
    println!();

    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Summary");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!();
    println!("If all counts are 0 but you can see data in Polkadot.js Apps,");
    println!("the issue is likely:");
    println!("  1. Storage hasn't been finalized in blocks yet");
    println!("  2. Pallet name mismatch (case-sensitive!)");
    println!("  3. Storage item names are different in runtime");
    println!();
    println!("Next steps:");
    println!("  1. Check: https://polkadot.js.org/apps/?rpc=ws://127.0.0.1:9944");
    println!("  2. Go to: Developer > Chain State");
    println!("  3. Query: arion > childRegistrations()");
    println!("  4. If you see 'None', transactions weren't finalized!");
    println!();

    Ok(())
}
