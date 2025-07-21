use std::{
    fmt,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use hex::FromHexError;
use sha2::Digest;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Data(pub Vec<u8>);
pub type Hash = Data;

/// Which side to put Hash on when concatinating proof hashes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HashDirection {
    Left,
    Right,
}

pub fn hash_data<T: AsRef<[u8]>>(data: &T) -> Hash {
    sha2::Sha256::digest(data.as_ref()).to_vec().into()
}

pub fn hash_concat<T: AsRef<[u8]>>(h1: &T, h2: &T) -> Hash {
    hash_data(&[h1.as_ref(), h2.as_ref()].concat())
}

impl FromStr for Data {
    type Err = FromHexError;

    fn from_str(data: &str) -> Result<Self, Self::Err> {
        Ok(Data(hex::decode(data)?))
    }
}

impl fmt::Display for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl Deref for Data {
    type Target = Vec<u8>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Data {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for Data {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}
