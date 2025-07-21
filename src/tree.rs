use std::fmt;

use crate::{
    hash::{hash_concat, hash_data, Data, Hash, HashDirection},
    Proof,
};

/// Represents a binary Merkle tree for integrity verification.
/// Each node in the tree is a SHA256 hash, with the root being a hash over all data.
///
/// # Example
/// ```
/// use merkle_tree::{MerkleTree, Data};
///
/// let data: Vec<Data> = vec![vec![1].into(), vec![2].into(), vec![3].into(), vec![4].into()];
/// let tree = MerkleTree::construct(&data);
/// let root = tree.root().expect("Tree should have a root");
/// println!("Root hash: {}", hex::encode(root));
/// ```
pub struct MerkleTree {
    hashes: Vec<Hash>,
}

impl MerkleTree {
    /// Returns a reference to the root hash of the Merkle tree.
    /// This is the topmost node, representing the hash of all data combined.
    ///
    /// # Example
    /// ```
    /// use merkle_tree::{MerkleTree, Data};
    ///
    /// let data: Vec<Data> = vec![vec![1].into(), vec![2].into(), vec![3].into(), vec![4].into()];
    /// let tree = MerkleTree::construct(&data);
    /// let root = tree.root();
    /// assert!(root.is_some());
    /// ```
    pub fn root(&self) -> Option<&Hash> {
        self.hashes.first()
    }

    /// Constructs a binary Merkle tree from the given data.
    /// The input should represent leaf nodes. If the number of leaves is not a power of two,
    /// the behavior will depend on how you balance the tree (currently, no padding is applied).
    ///
    /// # Example
    /// ```
    /// use merkle_tree::{MerkleTree, Data};
    ///
    /// let data: Vec<Data> = vec![vec![1].into(), vec![2].into(), vec![3].into(), vec![4].into()];
    /// let tree = MerkleTree::construct(&data);
    /// assert!(tree.root().is_some());
    /// ```
    pub fn construct(input: &[Data]) -> MerkleTree {
        if input.is_empty() {
            return Self { hashes: vec![] };
        }

        let num_leaves = input.len().next_power_of_two();
        let total_nodes = 2 * num_leaves - 1;
        let padding_hash = hash_data(input.last().unwrap());

        let mut hashes = Vec::with_capacity(total_nodes);
        hashes.resize(total_nodes - num_leaves, Hash::default());

        hashes.extend(
            input
                .iter()
                .map(hash_data)
                .chain(std::iter::repeat_n(padding_hash, num_leaves - input.len())),
        );

        for i in (0..(total_nodes - num_leaves)).rev() {
            let left = &hashes[2 * i + 1];
            let right = &hashes[2 * i + 2];
            hashes[i] = hash_concat(left, right);
        }

        MerkleTree { hashes }
    }

    /// Verifies that the given input data reconstructs the specified root hash.
    ///
    /// # Example
    /// ```
    /// use merkle_tree::{MerkleTree, Data};
    ///
    /// let data: Vec<Data> = vec![vec![1].into(), vec![2].into(), vec![3].into(), vec![4].into()];
    /// let tree = MerkleTree::construct(&data);
    /// let root = tree.root().unwrap();
    /// assert!(MerkleTree::verify(&data, root));
    /// ```
    pub fn verify(input: &[Data], root_hash: &Hash) -> bool {
        if let Some(root) = MerkleTree::construct(input).root() {
            return root == root_hash;
        }

        false
    }

    /// Verifies that a single data element, along with a Merkle proof, resolves to the expected root hash.
    ///
    /// # Example
    /// ```
    /// use merkle_tree::{MerkleTree, Data};
    ///
    /// let data: Vec<Data> = vec![vec![1].into(), vec![2].into(), vec![3].into(), vec![4].into()];
    /// let tree = MerkleTree::construct(&data);
    /// let root = tree.root().unwrap();
    /// let proof = tree.prove(&data[1]).unwrap();
    /// assert!(MerkleTree::verify_proof(&data[1], &proof, root));
    /// ```
    pub fn verify_proof(data: &Data, proof: &Proof, root_hash: &Hash) -> bool {
        let mut calculated_root_hash = hash_data(data);
        for (direction, hash) in &proof.hashes {
            calculated_root_hash = match direction {
                HashDirection::Left => hash_concat(*hash, &calculated_root_hash),
                HashDirection::Right => hash_concat(&calculated_root_hash, *hash),
            }
        }
        calculated_root_hash == *root_hash
    }

    /// Returns a `Proof` object containing sibling hashes needed to prove the data’s presence in the Merkle tree.
    /// If the data is not found, returns `None`.
    ///
    /// # Example
    /// ```
    /// use merkle_tree::{MerkleTree, Data};
    ///
    /// let data: Vec<Data> = vec![vec![1].into(), vec![2].into(), vec![3].into(), vec![4].into()];
    /// let tree = MerkleTree::construct(&data);
    /// let proof = tree.prove(&data[2]);
    /// assert!(proof.is_some());
    /// ```
    pub fn prove(&self, data: &Data) -> Option<Proof> {
        let leaf_hash = hash_data(data);
        let num_leaves = self.hashes.len().div_ceil(2);
        let leaf_start = self.hashes.len() - num_leaves;

        let mut index = (leaf_start..self.hashes.len()).find(|&i| self.hashes[i] == leaf_hash)?;

        let mut proof = vec![];
        while index > 0 {
            let parent = (index - 1) / 2;
            let (sibling_index, direction) = if index & 1 == 1 {
                (index + 1, HashDirection::Right)
            } else {
                (index - 1, HashDirection::Left)
            };
            if let Some(hash) = self.hashes.get(sibling_index) {
                proof.push((direction, hash));
            }
            index = parent;
        }

        Some(Proof { hashes: proof })
    }
}

impl fmt::Display for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.hashes.is_empty() {
            return writeln!(f, "MerkleTree: <empty>");
        }

        writeln!(f, "MerkleTree:")?;
        draw_ascii_tree(&self.hashes, 0, 0, f)
    }
}

fn draw_ascii_tree(
    hashes: &[Hash],
    index: usize,
    depth: usize,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    if index >= hashes.len() {
        return Ok(()); // Out of bounds (missing child)
    }

    let indent = "  ".repeat(depth);

    // Draw right child first (for top-down view)
    let right_index = 2 * index + 2;
    draw_ascii_tree(hashes, right_index, depth + 1, f)?;

    // Print current node
    let short = hex::encode(&hashes[index][..6]);
    writeln!(f, "{}└──── [{}] {}", indent, index, short)?;

    // Then draw left child
    let left_index = 2 * index + 1;
    draw_ascii_tree(hashes, left_index, depth + 1, f)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn example_data(n: usize) -> Vec<Data> {
        let mut data = vec![];
        for i in 0..n {
            data.push(vec![i as u8].into());
        }
        data
    }

    #[test]
    fn test_constructions() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let expected_root = "9675e04b4ba9dc81b06e81731e2d21caa2c95557a85dcfa3fff70c9ff0f30b2e";
        assert_eq!(hex::encode(tree.root().unwrap()), expected_root);

        let data = example_data(8);
        let tree = MerkleTree::construct(&data);
        let expected_root = "0727b310f87099c1ba2ec0ba408def82c308237c8577f0bdfd2643e9cc6b7578";
        assert_eq!(hex::encode(tree.root().unwrap()), expected_root);
    }

    #[test]
    fn test_constructions_unbalanced() {
        let data = example_data(3);
        let tree = MerkleTree::construct(&data);
        let expected_root = "f2dcdd96791b6bac5d554f2d320e594b834f5da1981812c3707e7772234cb0ad";
        assert_eq!(hex::encode(tree.root().unwrap()), expected_root);
    }

    #[test]
    fn test_verify_valid() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let root = tree.root().clone();
        assert!(MerkleTree::verify(&data, &root.unwrap()));
    }

    #[test]
    fn test_verify_invalid_root() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let mut fake_root = tree.root().unwrap().clone();
        fake_root[0] ^= 0xff; // Flip a bit
        assert!(!MerkleTree::verify(&data, &fake_root));
    }

    #[test]
    fn test_prove_and_verify_proof_valid() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let root = tree.root().clone();

        let index = 2;
        let proof = tree.prove(&data[index]).expect("proof should exist");
        assert!(MerkleTree::verify_proof(
            &data[index],
            &proof,
            &root.unwrap()
        ));
    }
    #[test]
    fn test_prove_and_verify_proof_invalid_data() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let root = tree.root().clone();

        let index = 2;
        let proof = tree.prove(&data[index]).expect("proof should exist");
        let tampered = vec![0, 1, 2].into(); // invalid data
        assert!(!MerkleTree::verify_proof(&tampered, &proof, &root.unwrap()));
    }

    #[test]
    fn test_prove_returns_none_for_missing_data() {
        let data = example_data(4);
        let tree = MerkleTree::construct(&data);
        let not_in_tree = vec![255].into();

        assert!(tree.prove(&not_in_tree).is_none());
    }
}
