use crate::hash::HashDirection;

pub mod hash;
pub mod tree;

pub use hash::{Data, Hash};
pub use tree::MerkleTree;

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    pub hashes: Vec<(HashDirection, &'a Hash)>,
}
