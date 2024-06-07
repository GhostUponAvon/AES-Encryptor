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

    let mut encrypted_blocks: Vec<String> = Vec::new();
    let blocks: Vec<Vec<u8>> = input_to_blocks(file_bytes);

    //let keys: Vec<Vec<u8>> = generate_keys(password, blocks.len());



    println!("{:?}", blocks);
    
    /*
    let num: u16 = 0b0110111101101011;
    let high: u8 = (&num >> 8) as u8;
    let low: u8 = (&num & 0xff) as u8;

    println!("high: {}, low: {}", high, low);
    println!("{}", num & 0xff);
    */



}

fn input_to_blocks(file_bytes: Vec<u8>) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = file_bytes.chunks(16).map(|x| x.to_owned()).collect();
    
    /*for chunk in file_bytes.chunks(32).collect() {
        blocks.push(chunk.to_owned());
    }*/

    blocks
}

fn generate_keys(password_hash: String, block_vec_length: usize) -> Vec<Vec<u8>> {
    let password: Vec<u8> = password_hash.into_bytes();

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(block_vec_length*14); keys.push(password);

    for i in 0..block_vec_length*14 {
        todo!()
    }

    keys

    

    
}