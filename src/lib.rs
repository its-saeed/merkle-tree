use sha2::Digest;

pub type Data = Vec<u8>;
pub type Hash = Vec<u8>;

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    pub hashes: Vec<(HashDirection, &'a Hash)>,
}

pub fn hash_data<T: AsRef<[u8]>>(data: &T) -> Hash {
    sha2::Sha256::digest(data.as_ref()).to_vec()
}

pub fn hash_concat<T: AsRef<[u8]>>(h1: &T, h2: &T) -> Hash {
    hash_data(&[h1.as_ref(), h2.as_ref()].concat())
}
