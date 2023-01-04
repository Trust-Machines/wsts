pub trait Signer {
    fn new(num_keys: usize) -> Self;
    fn load(path: &str) -> Self;

    fn save(path: &str);
}
