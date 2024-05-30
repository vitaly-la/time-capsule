use base64::prelude::*;
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{read_to_string, write};

fn b64_decode(line: String) -> Vec<u8> {
    BASE64_STANDARD.decode(line.as_bytes()).unwrap()
}

fn xor_digest(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    a.iter()
        .zip(b)
        .map(|(x, y)| x ^ y)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

fn recover(recovery_path: &String) {
    let contents = read_to_string(recovery_path).unwrap();
    let lines: Vec<_> = contents.lines().map(|line| line.trim()).collect();

    let hash_count: u32 = lines[0].parse().unwrap();

    let mut buffer: [_; 32];
    let mut hash = [0; 32];
    let mut final_hashes = Vec::<u8>::new();

    for line in lines.iter().skip(1) {
        buffer = b64_decode(line.to_string()).try_into().unwrap();
        hash = xor_digest(buffer, hash);
        for _ in 0..hash_count {
            hash = Sha256::digest(hash).into();
        }
        final_hashes.extend_from_slice(&hash);
    }

    let secret = hex::encode(Sha256::digest(final_hashes));
    println!("Secret key: {}", secret);

    let secret_path = recovery_path.replace("recovery", "secret");

    write(&secret_path, secret + "\n").unwrap();
    println!("Secret written to {}", secret_path);
}

fn main() {
    let args: Vec<_> = env::args().collect();

    if args.len() == 2 {
        let recovery_path = &args[1];
        recover(recovery_path);
    } else {
        println!("Usage: ./recover <recovery file path>");
    }
}
