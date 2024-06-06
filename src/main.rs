use std::{env, fs, process};
use sha256::digest;
fn main() {
    let args: Vec<String> = env::args().collect();

    /*
    if args.len() != 3 {
        println!("The needs to be exactly 2 arguments, you have too few or too much");
        process::exit(1)
    }*/

    let file_bytes = fs::read(&args[1]).expect("Cannot find the specified file. Please check the file name and path.");
    let password = digest(&args[2]);

    let encrypted_blocks: Vec<String> = Vec::new();
    let blocks: Vec<[u8; 32]> = input_to_blocks(file_bytes);
    


    


}

fn input_to_blocks(file_bytes: Vec<u8>) -> Vec<[u8; 32]> {
    todo!()
}

