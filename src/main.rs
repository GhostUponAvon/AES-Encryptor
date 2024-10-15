use std::{env, fs, io::Write, process, sync::{atomic::{AtomicUsize, Ordering}, Arc, Mutex}, thread, time::Duration};
use sha256::digest;
use rayon::prelude::*;


static GLOBAL_ENCRYPTION_STATUS: AtomicUsize = AtomicUsize::new(1);


fn main() {
    let t = std::time::Instant::now();
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        println!("There needs to be exactly 3 arguments, you have too few or too much");
        process::exit(1)
    } else if args[1] != "d" && args[1] != "e" {
        println!("You need to specify where to encrypt or decrypt using 'e' or 'd'. Usage: aes-encryptor.exe [e | d] [file] [password]");
        process::exit(1)
    }

    let file_bytes = fs::read(&args[2]).expect("Cannot find the specified file. Please check the file name and path.");
    
    let password: String = digest(&args[3]);
    let blocks: Vec<Vec<u8>> = input_to_blocks(file_bytes); //each vector stores 16 u8's


    println!("Starting multi-threaded encryption");

    let processed_blocks: Vec<u8>;
    let path: String;
    if args[1] == "e" {
        path = args[2].clone()+".aes";
        processed_blocks = encrypt(blocks, password);
    } else {
        path = args[2].strip_suffix(".aes").unwrap().to_owned();
        processed_blocks = decrypt(blocks, password)
    }
    fs::write(path, processed_blocks).expect("Failed to write encrypted file to filesystem");
    
    /*
    let num: u16 = 0b0110111101101011;
    let high: u8 = (&num >> 8) as u8;
    let low: u8 = (&num & 0xff) as u8;

    println!("high: {}, low: {}", high, low);
    println!("{}", num & 0xff);
    */

    println!("\nCompleted in: {:.5?}", t.elapsed())

}

fn encrypt(blocks: Vec<Vec<u8>>, password_hash: String) -> Vec<u8> {
    let keys: Vec<Vec<u8>> = generate_keys(password_hash);
    let encrypted_blocks: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::from(Vec::new())));
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
    
    let blocks = Arc::try_unwrap(encrypted_blocks).expect("").into_inner().expect("").concat();
    blocks
}

//Encryption tracking counter isn't working for smaller files
fn decrypt(blocks: Vec<Vec<u8>>, password_hash: String) -> Vec<u8> {
    let mut keys: Vec<Vec<u8>> = generate_keys(password_hash); keys.pop(); keys.reverse();
    let decrypted_blocks: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::from(Vec::new())));
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
    
    let blocks = Arc::try_unwrap(decrypted_blocks).expect("").into_inner().expect("").concat();
    blocks
}


fn encrypt_block(block: &Vec<u8>, keys: &Vec<Vec<u8>>) -> Vec<u8> {
    //initial add round key

    let mut block = block.clone();
    block = add_round_key(keys[0].clone(), block);

    //round 2 to 14 
    for round in 0..13 {
        block = add_round_key(keys[round+1].clone(), mix_columns(shift_rows(sub_bytes(block))));
    }
    
    //final round minus the mix columns operation
    block = add_round_key(keys[14].clone(), shift_rows(sub_bytes(block)));

    GLOBAL_ENCRYPTION_STATUS.fetch_add(1, Ordering::SeqCst);
    
    block
}

fn decrypt_block(block: &Vec<u8>, keys: &Vec<Vec<u8>>) -> Vec<u8> {
    //initial add round key

    let mut block = block.clone();
    
    block = inv_sub_bytes(inv_shift_rows(add_round_key(keys[0].clone(), block)));
    //round 2 to 14 
    for round in 0..13 {
        block = inv_sub_bytes(inv_shift_rows(inv_mix_columns(add_round_key(keys[round+1].clone(), block))));
    }
    
    //final round minus the mix columns operation
    block = add_round_key(keys[14].clone(), block);

    GLOBAL_ENCRYPTION_STATUS.fetch_add(1, Ordering::SeqCst);
    
    block
}


fn input_to_blocks(file_bytes: Vec<u8>) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = file_bytes.chunks(16).map(|x| x.to_owned()).collect();
    /*for chunk in file_bytes.chunks(32).collect() {
        blocks.push(chunk.to_owned());
    }*/

    blocks
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
        n_key[0] = xor_word(&n_key[0], &rcon(sub_word(rot_word(&n_key[7]))));

        //then use loop to do the rest
        for i in 1..8 {
            n_key[i] = xor_word(&n_key[i], &n_key[i-1]);
        }
        current_key = n_key.concat();


    }
    
    
    
    
    
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

const INV_S_BOX: [[u8; 16]; 16] = [
[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
[0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
[0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
[0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
[0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
[0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
[0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
[0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
[0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
[0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
[0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
[0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
[0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
[0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
[0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
[0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]];





fn add_round_key(key: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    let mut xor_result: Vec<u8> = Vec::with_capacity(32);
    for (a, b) in data.iter().zip(key) {
        xor_result.push(a^b);
    }
    xor_result
}

fn sub_bytes(data: Vec<u8>) -> Vec<u8>{
    let mut sub_result: Vec<u8> = Vec::with_capacity(8);
    for byte in data {
        let nibble_a:usize = (byte >> 4) as usize;
        let nibble_b:usize = (byte & 0x0f) as usize;
        sub_result.push(S_BOX[nibble_a][nibble_b].clone());
    }
    sub_result
}



fn inv_sub_bytes(data: Vec<u8>) -> Vec<u8>{
    let mut sub_result: Vec<u8> = Vec::with_capacity(8);
    for byte in data {
        let nibble_a:usize = (byte >> 4) as usize;
        let nibble_b:usize = (byte & 0x0f) as usize;
        sub_result.push(INV_S_BOX[nibble_a][nibble_b].clone());
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

fn inv_shift_rows(data: Vec<u8>) -> Vec<u8> {
    let mut rows: Vec<Vec<u8>> = data.chunks(4).map(|x| x.to_owned()).collect();
    for (i, row) in rows.iter_mut().enumerate() {
        row.rotate_right(i);
    }
    rows.concat()
}

fn g_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;

    for _i in 0..8 {
       if (b & 1) != 0 {
           p ^= a;
       }

       let hi_bit_set: bool = (a & 0x80) != 0;
       a <<= 1;
       if hi_bit_set {
           a ^= 0x1b;
       }
       b >>= 1;
    }
    p
}

fn mix_columns(data: Vec<u8>) -> Vec<u8> {
    let mut data: Vec<Vec<u8>> = data.chunks(4).map(|x| x.to_owned()).collect();
    let mut mixed_data: Vec<Vec<u8>> = vec![vec![0,0,0,0]; 4];
    let mut pad: usize = 0;
    for (i, column) in data.iter_mut().enumerate() {
        if column.len() < 4 {
            pad = column.len();
            let mut padding: Vec<u8> = vec![0; 4-pad];
            column.append(&mut padding);
        }

        match pad {
            3 => {
                mixed_data[i][0] = g_mul(0x02, column[0]) ^ g_mul(0x03, column[1]) ^ g_mul(0x01, column[2]);
                mixed_data[i][1] = g_mul(0x01, column[0]) ^ g_mul(0x02, column[1]) ^ g_mul(0x03, column[2]);
                mixed_data[i][2] = g_mul(0x01, column[0]) ^ g_mul(0x01, column[1]) ^ g_mul(0x02, column[2]);

            },
            2 => {
                mixed_data[i][0] = g_mul(0x02, column[0]) ^ g_mul(0x03, column[1]);
                mixed_data[i][1] = g_mul(0x01, column[0]) ^ g_mul(0x02, column[1]);

            },
            1 => {
                mixed_data[i][0] = g_mul(0x02, column[0]);

            },
            _ => {
                mixed_data[i][0] = g_mul(0x02, column[0]) ^ g_mul(0x03, column[1]) ^ g_mul(0x01, column[2]) ^ g_mul(0x01, column[3]);
                mixed_data[i][1] = g_mul(0x01, column[0]) ^ g_mul(0x02, column[1]) ^ g_mul(0x03, column[2]) ^ g_mul(0x01, column[3]);
                mixed_data[i][2] = g_mul(0x01, column[0]) ^ g_mul(0x01, column[1]) ^ g_mul(0x02, column[2]) ^ g_mul(0x03, column[3]);
                mixed_data[i][3] = g_mul(0x03, column[0]) ^ g_mul(0x01, column[1]) ^ g_mul(0x01, column[2]) ^ g_mul(0x02, column[3]);

            }
        }

        if pad > 0 {
            mixed_data[i].truncate(pad);
        }
    }

    mixed_data.concat()
}

fn inv_mix_columns(data: Vec<u8>) -> Vec<u8> {
    let mut data: Vec<Vec<u8>> = data.chunks(4).map(|x| x.to_owned()).collect();
    let mut mixed_data: Vec<Vec<u8>> = vec![vec![0,0,0,0]; 4];
    let mut pad: usize = 0;
    for (i, column) in data.iter_mut().enumerate() {
        if column.len() < 4 {
            pad = column.len();
            let mut padding: Vec<u8> = vec![0; 4-pad];
            column.append(&mut padding);
        }


        match pad {
            3 => {
                mixed_data[i][0] = g_mul(0x0e, column[0]) ^ g_mul(0x0b, column[1]) ^ g_mul(0x0d, column[2]);
                mixed_data[i][1] = g_mul(0x09, column[0]) ^ g_mul(0x0e, column[1]) ^ g_mul(0x0b, column[2]);
                mixed_data[i][2] = g_mul(0x0d, column[0]) ^ g_mul(0x09, column[1]) ^ g_mul(0x0e, column[2]);

            },
            2 => {
                mixed_data[i][0] = g_mul(0x0e, column[0]) ^ g_mul(0x0b, column[1]);
                mixed_data[i][1] = g_mul(0x09, column[0]) ^ g_mul(0x0e, column[1]);

            },
            1 => {
                mixed_data[i][0] = g_mul(0x0e, column[0]);

            },
            _ => {
                mixed_data[i][0] = g_mul(0x0e, column[0]) ^ g_mul(0x0b, column[1]) ^ g_mul(0x0d, column[2]) ^ g_mul(0x09, column[3]);
                mixed_data[i][1] = g_mul(0x09, column[0]) ^ g_mul(0x0e, column[1]) ^ g_mul(0x0b, column[2]) ^ g_mul(0x0d, column[3]);
                mixed_data[i][2] = g_mul(0x0d, column[0]) ^ g_mul(0x09, column[1]) ^ g_mul(0x0e, column[2]) ^ g_mul(0x0b, column[3]);
                mixed_data[i][3] = g_mul(0x0b, column[0]) ^ g_mul(0x0d, column[1]) ^ g_mul(0x09, column[2]) ^ g_mul(0x0e, column[3]);
            }
        }

        if pad > 0 {
            mixed_data[i].truncate(pad);
        }
    }

    mixed_data.concat()
}

/*
fn galois_multiplication(byte: u8) -> u8 {
    if (byte & 0x80) != 0 {
        ((byte << 1) ^ 0x1b) & 0xff
    } else {
        byte << 1
    }
}

fn mix_columns(data: Vec<u8>) -> Vec<u8> {
    let mut data: Vec<Vec<u8>> = data.chunks(4).map(|x| x.to_owned()).collect();
    for (_i, column) in data.iter_mut().enumerate() {
        let t = column[0] ^ column[1] ^ column[2] ^ column[3];
        let u = column[0];
        column[0] ^= t ^ galois_multiplication(column[0] ^ column[1]);
        column[1] ^= t ^ galois_multiplication(column[1] ^ column[2]);
        column[2] ^= t ^ galois_multiplication(column[2] ^ column[3]);
        column[3] ^= t ^ galois_multiplication(column[3] ^ u);

    }

    data.concat()
}

fn inv_mix_columns(data: Vec<u8>) -> Vec<u8> {
    let mut data: Vec<Vec<u8>> = data.chunks(4).map(|x| x.to_owned()).collect();
    for i in 0..4 {
        let u = galois_multiplication(galois_multiplication(data[i][0] ^ data[i][2]));
        let v = galois_multiplication(galois_multiplication(data[i][1] ^ data[i][3]));
        data[i][0] ^= u;
        data[i][1] ^= v;
        data[i][2] ^= u;
        data[i][3] ^= v;
    }
    mix_columns(data.concat())
}*/

fn rot_word(data: &Vec<u8>) -> Vec<u8> {data.clone()}

fn sub_word(mut data: Vec<u8>) -> Vec<u8> {

    for byte in data.iter_mut() {
        let nibble_a:usize = (*byte >> 4) as usize;
        let nibble_b:usize = (*byte & 0x0f) as usize;
        *byte = S_BOX[nibble_a][nibble_b].clone();
    }
    data
}

fn inv_sub_word(mut data: Vec<u8>) -> Vec<u8> {

    for byte in data.iter_mut() {
        let nibble_a:usize = (*byte >> 4) as usize;
        let nibble_b:usize = (*byte & 0x0f) as usize;
        *byte = INV_S_BOX[nibble_a][nibble_b].clone();
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
        let plaintext = vec![vec![0xFF, 0x00, 0xFF, 0x00,0xFF, 0x00,0xFF, 0x00,0xFF, 0x00, 0xFF, 0x00, 0xFF, 0x00,0xFF, 0x00]];
        let password = sha256::digest("test");

        assert_eq!(plaintext.concat(), decrypt(encrypt(plaintext, password.clone()).chunks(16).map(|x| x.to_owned()).collect(), password))
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
        let vec_a: Vec<u8> = vec![0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc];
        assert_eq!(mix_columns(vec_a.clone()), vec![65, 171, 64, 59, 65, 171, 64, 59, 65, 171, 64, 59, 65, 171, 64, 59]);
    }
    
    #[test]
    fn test_inv_mix_columns() {
        let vec_a: Vec<u8> = vec![0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc];
        assert_eq!(inv_mix_columns(mix_columns(vec_a.clone())), vec![0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc]);
    }

    #[test]
    fn test_inv_mix_columns_shortened() {
        let vec_a: Vec<u8> = vec![0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65];
        assert_eq!(inv_mix_columns(mix_columns(vec_a.clone())), vec![0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65, 0xc7, 0xcc, 0xff, 0x65]);
    }


    #[test]
    fn test_inv_sub_word() {
        let vec_a: Vec<u8> = vec![0x16, 0x4d, 0xc6, 0x4b, 0x63, 0xda, 0x39, 0x08];
        assert_eq!(inv_sub_word(vec_a.clone()), vec![ 0xff, 0x65, 0xc7, 0xcc, 0x00, 0x7a, 0x5b, 0xbf]);
    }
}
