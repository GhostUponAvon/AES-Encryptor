use std::{env, fs, io::Write, process, sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex}, thread, time::Duration};
use sha256::digest;
use rayon::prelude::*;
use clap::{Parser};
use aes_encryptor::aesfunctions::*;


static GLOBAL_ENCRYPTION_STATUS: AtomicUsize = AtomicUsize::new(1);

#[derive(Parser)]
struct Args {
    encryption_mode: String,
    file_path: String,
    password: String,
}

fn main() {
    let t = std::time::Instant::now();
    let args = Args::parse();


    /*if args.len() != 4 {
        println!("There needs to be exactly 3 arguments, you have too few or too much");
        process::exit(1)
    } else*/ if args.encryption_mode != "d" && args.encryption_mode != "e" {
        println!("You need to specify where to encrypt or decrypt using 'e' or 'd'. Usage: aes-encryptor.exe [e | d] [file] [password]");
        process::exit(1)
    }

    let file_bytes = fs::read(&args.file_path).expect("Cannot find the specified file. Please check the file name and path.");
    
    let password: String = digest(&args.password);
    let blocks: Vec<Block> = input_to_blocks(file_bytes); //each vector stores 16 u8's


    println!("Starting multi-threaded encryption");

    let processed_blocks: Vec<u8>;
    let path: String;
    if args.encryption_mode == "e" {
        path = args.file_path.clone()+".aes";
        processed_blocks = encrypt(blocks, password);
    } else {
        path = args.file_path.strip_suffix(".aes").unwrap().to_owned();
        processed_blocks = decrypt(blocks, password)
    }

    //convert blocks
    fs::write(path, processed_blocks).expect("Failed to write encrypted file to filesystem");

    println!("\nCompleted in: {:.5?}", t.elapsed())

}

fn encrypt(blocks: Vec<Block>, password_hash: String) -> Vec<u8> {
    let keys: Vec<Vec<u8>> = generate_keys(password_hash);
    let encrypted_blocks: Arc<Mutex<Vec<Block>>> = Arc::new(Mutex::new(Vec::from(Vec::new())));
    let length = blocks.len();
    
    let mut stdout = std::io::stdout();
    let encrypted_blocks_ref = Arc::clone(&encrypted_blocks);
    println!("\rEncrypting Blocks...");

    let handle = thread::spawn(move || {
        let mut encrypted_blocks = encrypted_blocks_ref.lock().unwrap();
        *encrypted_blocks = blocks.par_iter().map(|block| encrypt_block(block, &keys)).collect();
    });
    
    
    //this will get reimplemented in future to monitor the above rayon instruction
    while !handle.is_finished() {
        print!("\rEncrypting blocks: {:?}/{}", GLOBAL_ENCRYPTION_STATUS.load(Ordering::SeqCst)-1, length);
        let _ = stdout.flush();
        thread::sleep(Duration::from_micros(1))
    }
    print!("\rEncrypting blocks: {:?}/{}", GLOBAL_ENCRYPTION_STATUS.load(Ordering::SeqCst)-1, length);
    let _ = stdout.flush();
    
    let mut blocks = Arc::try_unwrap(encrypted_blocks).expect("").into_inner().expect("");
    let mut joined_blocks: Vec<Vec<u8>> = Vec::new();
    for block in blocks.iter_mut() {
        joined_blocks.push(block.bytes.try_into().unwrap());
    }
    joined_blocks.concat()
    
}

//Encryption tracking counter isn't working for smaller files
fn decrypt(blocks: Vec<Block>, password_hash: String) -> Vec<u8> {
    let mut keys: Vec<Vec<u8>> = generate_keys(password_hash); keys.pop(); keys.reverse();
    let decrypted_blocks: Arc<Mutex<Vec<Block>>> = Arc::new(Mutex::new(Vec::from(Vec::new())));
    let length = blocks.len();
    
    let mut stdout = std::io::stdout();
    let decrypted_blocks_ref = Arc::clone(&decrypted_blocks);
    println!("\rDecrypting Blocks...");

    let handle = thread::spawn(move || {
        let mut decrypted_blocks = decrypted_blocks_ref.lock().unwrap();
        *decrypted_blocks = blocks.par_iter().map(|block| decrypt_block(block, &keys)).collect();
    });
    
    
    //this will get reimplemented in future to monitor the above rayon instruction
    while !handle.is_finished() {
        print!("\rDecrypting blocks: {:?}/{}", GLOBAL_ENCRYPTION_STATUS.load(Ordering::SeqCst)-1, length);
        let _ = stdout.flush();
        thread::sleep(Duration::from_micros(1))
    }
    print!("\rDecrypting blocks: {:?}/{}", GLOBAL_ENCRYPTION_STATUS.load(Ordering::SeqCst)-1, length);
    let _ = stdout.flush();
    
    let mut blocks = Arc::try_unwrap(decrypted_blocks).expect("").into_inner().expect("");
    let mut joined_blocks: Vec<Vec<u8>> = Vec::new();
    for block in blocks.iter_mut() {
        joined_blocks.push(block.bytes.try_into().unwrap());
    }
    joined_blocks.concat()
}


fn encrypt_block(block: &Block, keys: &Vec<Vec<u8>>) -> Block {
    
    //initial add round key
    let mut block: Block = block.clone();
    block.add_round_key(&keys[0]);

    //round 2 to 14 
    for round in 0..13 {
        block.sub_bytes();
        block.shift_rows();
        block.mix_columns();
        block.add_round_key(&keys[round+1]);
    }
    
    //final round minus the mix columns operation
    block.sub_bytes();
    block.shift_rows();
    block.add_round_key(&keys[14]);

    GLOBAL_ENCRYPTION_STATUS.fetch_add(1, Ordering::SeqCst);
    
    block
}

fn decrypt_block(block: &Block, keys: &Vec<Vec<u8>>) -> Block {
    
    //initial round minus the mix columns operation
    let mut block: Block = block.clone();
    block.add_round_key(&keys[0]);
    block.inv_shift_rows();
    block.inv_sub_bytes();
    
    
    //round 2 to 14 
    for round in 0..13 {
        block.add_round_key(&keys[round+1]);
        block.inv_mix_columns();
        block.inv_shift_rows();
        block.inv_sub_bytes();
        
    }
    
    
    //final round with only add round key
    block.add_round_key(&keys[14]);

    GLOBAL_ENCRYPTION_STATUS.fetch_add(1, Ordering::SeqCst);
    
    block
}


fn input_to_blocks(file_bytes: Vec<u8>) -> Vec<Block> {
    let mut padding: bool = false;
    let mut blocks: Vec<Block> = file_bytes.chunks(16).enumerate().map(|(i, x)| { 
        
        if x.len() < 16 {
            let n: [u8;16] = pad_array(x);
            padding = true;
            return Block { id: i, bytes: n }
        }
        
        Block { id: i, bytes: x.try_into().unwrap() } 
    }).collect();

    if padding {
        blocks.push( Block { id: blocks.len(), bytes: [0x2d, 0x2d, 0x2d, 0x46, 0x49, 0x4c, 0x45, 0x50, 0x41, 0x44, 0x44, 0x45, 0x44, 0x2d, 0x2d, 0x2d] });
    }

    blocks
}
// pad array using ANSI X9.23 method
fn pad_array(slice: &[u8]) -> [u8;16] {
    let mut n: Vec<u8> = slice.try_into().unwrap();
    let mut count: u8 = 1;
    for _i in 0..15-slice.len() {
        n.push(0x00);
        count+=1;
    }
    n.push(count);
    
    
    n.try_into().unwrap()
}

fn generate_keys(password_hash: String) -> Vec<Vec<u8>> {
    let mut current_key: Vec<u8> = password_hash.into_bytes();

    let mut keys: Vec<Vec<u8>> = Vec::new();
    for _k in 0..8 {
        
        let mut left = current_key.clone();
        let right = left.split_off(16);
        keys.push(left);keys.push(right);
        
        if keys.len() == 16 {
            break;
        }

        //break the key into 8 columns
        let mut n_key: Vec<Vec<u8>> = current_key.chunks(8).map(|x| x.to_owned()).collect();
        
        //do initial xor
        n_key[0] = xor_word(&n_key[0], &rcon(sub_word(rot_word(n_key[7].clone()))));

        //then use loop to do the rest
        for i in 1..8 {
            n_key[i] = xor_word(&n_key[i], &n_key[i-1]);
        }
        current_key = n_key.concat();


    }
    
    
    
    
    
    keys
}


fn rot_word(mut data: Vec<u8>) -> Vec<u8> {
    data.rotate_left(1);
    data
}

fn sub_word(mut data: Vec<u8>) -> Vec<u8> {

    for byte in data.iter_mut() {
        let nibble_a:usize = (*byte >> 4) as usize;
        let nibble_b:usize = (*byte & 0x0f) as usize;
        *byte = S_BOX[nibble_a][nibble_b].clone();
    }
    data
}

fn rcon(data: Vec<u8>) -> Vec<u8> {data}

fn xor_word(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let mut xor_result: Vec<u8> = Vec::with_capacity(8);
    for (c, d) in a.iter().zip(b) {
        xor_result.push(c^d);
    }
    xor_result
}




#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = Block { id: 1, bytes: [0xFF, 0x00, 0xFF, 0x00,0xFF, 0x00,0xFF, 0x00,0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,0xFF, 0x00] };
        let password = sha256::digest("test");

        assert_eq!(plaintext.bytes.to_vec(), decrypt( vec![Block { id: 1, bytes: encrypt(vec![plaintext], password.clone()).try_into().unwrap() }], password ))
    }

    #[test]
    fn test_xor_word() {
        let vec_a: Vec<u8> = vec![0xFF; 8];
        let vec_b: Vec<u8> = vec![0xFF, 0x00, 0xFF, 0x00,0xFF, 0x00,0xFF, 0x00,0xFF, 0x00];
        assert_eq!(xor_word(&vec_a, &vec_b), vec![ 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00, 0xFF ])
    }

    #[test]
    fn test_sub_word() {
        let vec_a: Vec<u8> = vec![ 0xff, 0x65, 0xc7, 0xcc, 0x00, 0x7a, 0x5b, 0xbf];
        assert_eq!(sub_word(vec_a.clone()), vec![0x16, 0x4d, 0xc6, 0x4b, 0x63, 0xda, 0x39, 0x08]);
    }

    #[test]
    fn test_mix_columns() {
        let mut vec_a= Block { id: 1, bytes: [0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc]};
        vec_a.mix_columns();
        assert_eq!(vec_a.bytes.to_vec(), vec![65, 171, 64, 59, 65, 171, 64, 59, 65, 171, 64, 59, 65, 171, 64, 59]);
    }
    
    #[test]
    fn test_inv_mix_columns() {
        let mut vec_a = Block { id: 1, bytes: [0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc] };
        vec_a.mix_columns();
        vec_a.inv_mix_columns();
        assert_eq!(vec_a.bytes.to_vec(), vec![0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc]);
    }
}
