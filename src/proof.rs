use std::fmt;

use crate::hash::{Hash, HashDirection};

#[derive(Debug, Default)]
pub struct Proof<'a> {
    /// The hashes to use when verifying the proof
    /// The first element of the tuple is which side the hash should be on when concatinating
    pub hashes: Vec<(HashDirection, &'a Hash)>,
}

impl<'a> fmt::Display for Proof<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (direction, hash)) in self.hashes.iter().enumerate() {
            let dir_symbol = match direction {
                HashDirection::Left => "L",
                HashDirection::Right => "R",
            };
            writeln!(f, "#{i}: [{dir_symbol}] {}", hex::encode(hash))?;
        }
        Ok(())
    }
}
