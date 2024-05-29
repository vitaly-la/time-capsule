use sha2::{Digest, Sha256};
use std::env;
use std::fs::{read_to_string, write};

fn sha256_str(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn sha256_bytes(data: String) -> [u8; 32] {
    let result = Sha256::digest(data.as_bytes());
    let mut hash = [0; 32];
    hash.copy_from_slice(&result);
    hash
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
    let lines: Vec<_> = contents.lines().map(|s| s.trim()).collect();

    let salt = lines[0];
    let bound: u32 = lines[1].parse().unwrap();

    let mut number_hashes = Vec::new();
    for number in 0..bound {
        let number_hash = sha256_bytes(salt.to_owned() + &number.to_string());
        number_hashes.push(number_hash);
    }

    let mut secret_hashes = Vec::<String>::new();
    let mut acc = [0u8; 32];
    let mut recovered: u32 = 0;
    let mut percent: u32 = 0;
    for (lineno, line) in lines.iter().enumerate().skip(2) {
        for number in 0..bound {
            let number_hash = number_hashes[number as usize];
            let new_acc = xor_digest(acc, number_hash);

            if sha256_str(&new_acc) == *line {
                acc = new_acc;
                secret_hashes.push(sha256_str(
                    (salt.to_owned() + &number.to_string()).as_bytes(),
                ));

                recovered += 1;
                let new_percent = (100 * recovered) / (lines.len() as u32 - 2);
                if new_percent % 10 == 0 && new_percent > percent {
                    println!("Recovered {}%", new_percent);
                    percent = new_percent;
                }

                break;
            }
        }

        if sha256_str(&acc) != *line {
            panic!("Recovery file corrupted, line {}", lineno + 3);
        }
    }

    let secret = sha256_str(secret_hashes.join("").as_bytes());
    println!("Secret key: {}", secret);

    let secret_path = recovery_path.replace("recovery", "secret");

    write(secret_path.clone(), secret + "\n").unwrap();

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
