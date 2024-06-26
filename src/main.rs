use std::{env, fs, io::Write, process, sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex}, thread, time::Duration};
use sha256::digest;
use rayon::prelude::*;


static GLOBAL_ENCRYPTION_STATUS: AtomicUsize = AtomicUsize::new(1);


fn main() {
    let t = std::time::Instant::now();
    let args: Vec<String> = env::args().collect();

    
    if args.len() != 3 {
        println!("The needs to be exactly 2 arguments, you have too few or too much");
        process::exit(1)
    }

    let file_bytes = fs::read(&args[1]).expect("Cannot find the specified file. Please check the file name and path.");
    let password: String = digest(&args[2]);

    
    let blocks: Vec<Vec<u8>> = input_to_blocks(file_bytes); //each vector stores 16 u8's

    


    
    println!("Starting multi-threaded encryption");

    let encrypted_blocks: Vec<u8> = encrypt(blocks, password);

    let path: String = args[1].clone()+".aes";

    fs::write(path, encrypted_blocks).expect("Failed to write encrypted file to filesystem");
    
    /*
    let num: u16 = 0b0110111101101011;
    let high: u8 = (&num >> 8) as u8;
    let low: u8 = (&num & 0xff) as u8;

    println!("high: {}, low: {}", high, low);
    println!("{}", num & 0xff);
    */

    let elapsed = t.elapsed();
    println!("\nCompleted in: {:.5?}", elapsed)

}

fn encrypt(blocks: Vec<Vec<u8>>, password_hash: String) -> Vec<u8> {
    let keys: Vec<Vec<u8>> = generate_keys(password_hash, blocks.len());
    //let length = blocks.len();
    let encrypted_blocks: Vec<Vec<u8>> = blocks;//Vec::with_capacity(blocks.len()); // this will allow the threads to each work on an encryption block independently and return the value without conflicts
    
    let mut stdout = std::io::stdout();
    
    let keys: Vec<Vec<Vec<u8>>> = keys.chunks(15).map(|x| x.to_owned()).collect();
    print!("\rEncrypting Blocks...");
    let _ = stdout.flush();
    let encrypted_blocks: Vec<Vec<u8>> = encrypted_blocks.par_iter().zip(keys).map(|(block, keys)| encrypt_block(block, keys)).collect();
    print!("\rBlocks Encrypted    ");
    let _ = stdout.flush();
    //this will get reimplemented in future to monitor the above rayon crate instruction
    /*while GLOBAL_THREAD_COUNT.load(Ordering::SeqCst) != 0 {
        print!("\rEncrypting blocks: {:?}/{}", GLOBAL_ENCRYPTION_STATUS, length);
        let _ = stdout.flush();
        thread::sleep(Duration::from_micros(1))
    }*/
    
    encrypted_blocks.concat()
}

fn encrypt_block(block: &Vec<u8>, keys: Vec<Vec<u8>>) -> Vec<u8> {
    //initial add round key
    let mut block = block.clone();
    block = add_round_key(keys[0].clone(), block);

    for round in 0..13 {
        block = add_round_key(keys[round+1].clone(), mix_columns(shift_rows(sub_bytes(block))));
    }
    
    //final round minus the mix columns operation
    block = add_round_key(keys[14].clone(), shift_rows(sub_bytes(block)));

    GLOBAL_ENCRYPTION_STATUS.fetch_add(1, Ordering::SeqCst);
    
    block
}


//function will largely be a copy of the encryption function instead using the inverses of each encryption stage.
fn _decrypt(blocks: Vec<Vec<u8>>, password_hash: String) -> Vec<String> {
    todo!()
}


fn input_to_blocks(file_bytes: Vec<u8>) -> Vec<Vec<u8>> {
    let blocks: Vec<Vec<u8>> = file_bytes.chunks(16).map(|x| x.to_owned()).collect();
    
    /*for chunk in file_bytes.chunks(32).collect() {
        blocks.push(chunk.to_owned());
    }*/

    blocks
}

fn generate_keys(password_hash: String, block_vec_length: usize) -> Vec<Vec<u8>> {
    let mut stdout = std::io::stdout();
    let keys: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::with_capacity(block_vec_length*15)));
    static KEY_GEN_STATUS: AtomicUsize = AtomicUsize::new(0);
    let mut c_key: Vec<u8> = password_hash.into_bytes();
    
    let key_space = block_vec_length*8;
    let keys_thread_ref = Arc::clone(&keys);
    thread::spawn(move || {
        
    for _k in 0..block_vec_length*8 {
        let mut keys = keys_thread_ref.lock().unwrap();
        let mut left = c_key.clone();
        let right = left.split_off(16);
        keys.push(left);keys.push(right);
        KEY_GEN_STATUS.fetch_add(1, Ordering::SeqCst);
        
        if keys.len() == block_vec_length*16 {
            break;
        }

        let mut n_key: Vec<Vec<u8>> = c_key.chunks(8).map(|x| x.to_owned()).collect();
        
        //do initial xor
        n_key[0] = xor_word(&n_key[0], &rcon(sub_word(rot_word(&n_key[7]))));

        //then use loop to do remainder
        //NOTE: this is wrong, the vector is XORing itself, it should be XORing c_key
        for i in 1..n_key.len() {
            n_key[i] = xor_word(&n_key[i], &n_key[i-1]);
        }
        c_key = n_key.concat();


    }
    drop(keys_thread_ref);
});
    
    while KEY_GEN_STATUS.load(Ordering::SeqCst) != key_space {
        print!("\rGenerating Keys: {}/{}", KEY_GEN_STATUS.load(Ordering::SeqCst), key_space);
        let _ = stdout.flush();
        thread::sleep(Duration::from_micros(1))
    }
    
    
    println!("");

    let keys = Arc::try_unwrap(keys).expect("Arc is still owned").into_inner().expect("failed to extract generated keys from Mutex");
    //keys
    keys
}

const S_BOX: [[u8; 16]; 16] = [
[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
[0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
[0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
[0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
[0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
[0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
[0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
[0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
[0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
[0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
[0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
[0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
[0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
[0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
[0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
[0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]];


fn add_round_key(key: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    let mut xor_result: Vec<u8> = Vec::with_capacity(32);
    for (a, b) in data.iter().zip(key) {
        xor_result.push(a^b);
    }
    xor_result
}

fn sub_bytes(data: Vec<u8>) -> Vec<u8>{
    let mut sub_result: Vec<u8> = Vec::with_capacity(16);
    for byte in data {
        let nibble_a:usize = (byte >> 4) as usize;
        let nibble_b:usize = (byte & 0x0f) as usize;
        sub_result.push(S_BOX[nibble_a][nibble_b].clone());
    }
    sub_result
}

//this function is implemented wrong it needs to be fixed
fn shift_rows(data: Vec<u8>) -> Vec<u8> {
    let mut rows: Vec<Vec<u8>> = data.chunks(4).map(|x| x.to_owned()).collect();
    for (i, row) in rows.iter_mut().enumerate() {
        row.rotate_left(i);
    }
    rows.concat()
}

fn mix_columns(data: Vec<u8>) -> Vec<u8> {data}

fn rot_word(data: &Vec<u8>) -> Vec<u8> {data.clone()}

fn sub_word(data: Vec<u8>) -> Vec<u8> {data}

fn rcon(data: Vec<u8>) -> Vec<u8> {data}

fn xor_word(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let mut xor_result: Vec<u8> = Vec::with_capacity(32);
    for (a, b) in a.iter().zip(b) {
        xor_result.push(a^b);
    }
    xor_result
}

