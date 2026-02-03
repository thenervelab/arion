use common::FileManifest;

fn main() {
    let json = r#"{"file_hash":"ba9ed5df5604c519eef8cca382eeff692240fa2605a167a68e62603a6a1ec136","size":102400,"stripe_config":{"size":2097152,"k":10,"m":5},"shards":[{"index":0,"miner_uid":1663183147,"miner_addr":"http://miner-7:3007","blob_hash":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","ticket":"blobacu573tfxz5i3fsi6e7dmrko2lu6cll2sdsgweofymfyihkwlmnqwaaaac5hqfv7r4a472sbifan4xnoeir3aa3buolbo6u4wqip6ypsaak22"}]}"#;

    let manifest: FileManifest = serde_json::from_str(json).unwrap();
    println!("Successfully deserialized: {:?}", manifest);
}
