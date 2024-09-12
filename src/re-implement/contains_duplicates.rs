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