fn generate_keys(password_hash: String, block_vec_length: usize) -> Vec<Vec<u8>> {
    let mut stdout = std::io::stdout();
    let keys: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::with_capacity(block_vec_length*15)));
    static KEY_GEN_STATUS: AtomicUsize = AtomicUsize::new(0);
    let mut c_key: Vec<u8> = password_hash.into_bytes();
    println!("{}", block_vec_length);
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



//---------------------------------------------------------------

fn contains_duplicates(keys: &Vec<Vec<u8>>) -> bool {
    'outer: for k in 0..keys.len() {
        for i in 0..keys.len() {
            if k==i {continue;}
            if keys[k] == keys[i] {
                //println!("duplicate for key {} found at index {}",k , i);
                break 'outer;
                
            }
        }
    }
    if (0..keys.len()).any(|x| {
        if keys[x..].contains(&keys[x]) {
            //println!("dup at index: {}", x);
            true
        } else {
            false
        }
    
    }) {
        return true
    }
    false
}