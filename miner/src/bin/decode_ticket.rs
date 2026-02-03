use iroh_blobs::ticket::BlobTicket;
use std::str::FromStr;

fn main() {
    let ticket_str = "blobaalku7xca5ik65zjqvsbshq3uwpdmednneij3hx7hh5hbykhgbukiaaaac2gf3ph5rgeqzlwmae5tyb7hogqlhhk65pkuerrqo37okcnm4nve";
    let ticket = BlobTicket::from_str(ticket_str).unwrap();
    println!("Hash: {}", ticket.hash());
    println!("NodeAddr: {:?}", ticket.addr());
}
