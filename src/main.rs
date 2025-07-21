/*

Building a simple Merkle Tree

Exercise 1:
    Given a set of data D, construct a Merkle Tree.

Assume that D is a power of 2 (the binary tree is perfect).

Example input:
    D = [A1, A2, A3, A4]

Example output:

                               Root
                           ┌──────────┐
                           │    H7    │
                           │ H(H5|H6) │
                  ┌────────┴──────────┴──────────┐
                  │                              │
                  │                              │
             ┌────┴─────┐                  ┌─────┴────┐
             │    H5    │                  │    H6    │
             │ H(H1|H2) │                  │ H(H3|H4) │
             └─┬─────┬──┘                  └─┬──────┬─┘
               │     │                       │      │
     ┌─────────┴┐   ┌┴─────────┐    ┌────────┴─┐  ┌─┴────────┐
     │   H1     │   │    H2    │    │    H3    │  │    H4    │
     │  H(A1)   │   │   H(A2)  │    │   H(A3)  │  │   H(A4)  │
     └───┬──────┘   └────┬─────┘    └────┬─────┘  └────┬─────┘
         │               │               │             │
         A1              A2              A3            A4


Exercise 1b:
    Write a function that will verify a given set of data with a given root hash.

Exercise 2:
    Write a function that will use a proof like the one in Exercise 3 to verify that the proof is indeed correct.

Exercise 3 (Hard):
    Write a function that returns a proof that a given data is in the tree.

    Hints:
        -   The proof should be a set of ordered data hashes and their positions (left 0 or right 1).
        -   Let's say we are asked to prove that H3 (A3) is in this tree. We have the entire tree so we can traverse it and find H3.
            Then we only need to return the hashes that can be used to calculate with the hash of the given data to calculate the root hash.
            i.e Given a data H3, a proof [(1, H4), (0, H5)] and a root:
                H3|H4 => H6 => H5|H6 => H7 = root

 */

use std::str::FromStr;

use anyhow::{anyhow, Result};
use clap::{command, Parser, Subcommand};
use merkle_tree::{Data, Hash, HashDirection, MerkleTree, Proof};

/// Merkle CLI - A command-line tool for building and verifying Merkle Trees.
///
/// This tool allows you to construct a Merkle tree from hex-encoded input values,
/// compute and verify Merkle roots, generate proofs of inclusion, and verify those proofs.
#[derive(Parser)]
#[command(name = "Merkle CLI")]
#[command(
    author,
    version,
    about = "Command-line tool for Merkle Tree operations"
)]
pub struct Cli {
    /// The top-level command to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Supported Merkle tree operations.
#[derive(Subcommand)]
pub enum Commands {
    /// Computes the Merkle root from a list of hex-encoded leaf values.
    ///
    /// Each input value should be a hex string (e.g., `deadbeef`), and the resulting
    /// Merkle root is printed as a hex-encoded string.
    Root {
        /// List of hex-encoded strings to construct the Merkle tree from.
        #[arg(required = true, value_name = "TREE LEAVES")]
        inputs: Vec<Data>,
    },

    /// Prints an ASCII tree representation of the Merkle tree built from the given leaves.
    ///
    /// This helps visualize the structure of the tree and the hashes at each node.
    ///
    /// Each input should be a hex-encoded string.
    Print {
        /// List of hex-encoded strings to construct the Merkle tree from.
        #[arg(required = true, value_name = "TREE LEAVES")]
        inputs: Vec<Data>,
    },

    /// Verifies that the computed Merkle root from a set of inputs matches the expected root.
    ///
    /// Useful for checking integrity of data in bulk without using a Merkle proof.
    Verify {
        /// Hex-encoded expected Merkle root.
        #[arg(short, long, required = true, value_name = "ROOT")]
        root: Hash,

        /// Hex-encoded leaf values used to reconstruct the Merkle tree.
        #[arg(required = true, value_name = "TREE LEAVES")]
        inputs: Vec<Data>,
    },

    /// Generates a Merkle proof for a specific value in a given dataset.
    ///
    /// The resulting proof can later be used to verify inclusion using `verify-proof`.
    Prove {
        /// The hex-encoded data value to prove membership for.
        #[arg(short, long, required = true, value_name = "DATA_TO_BE_PROVED")]
        data: Data,

        /// Hex-encoded leaf values used to construct the Merkle tree.
        #[arg(required = true, value_name = "TREE LEAVES")]
        inputs: Vec<Data>,
    },

    /// Verifies a Merkle proof for a single value against a given root hash.
    ///
    /// You must provide:
    /// - the data value being verified,
    /// - the expected Merkle root,
    /// - and a list of ordered proof steps in the format `L:<hash>` or `R:<hash>`,
    ///   where `L` or `R` indicates the sibling position during hash reconstruction.
    ///
    /// If the proof is valid, the tool will print `✅ Verified`; otherwise, it will return an error.
    VerifyProof {
        /// Hex-encoded data value to verify.
        #[arg(short, long, required = true, value_name = "DATA")]
        data: Data,

        /// Hex-encoded root hash to verify against.
        #[arg(short, long, required = true, value_name = "ROOT")]
        root: Hash,

        /// Ordered list of proof steps, each in the format `L:<hash>` or `R:<hash>`.
        ///
        /// Example:
        ///     --proof R:aabbccdd --proof L:11223344
        ///
        /// Means:
        ///     - First combine the data with `aabbccdd` on the right,
        ///     - then combine the result with `11223344` on the left.
        #[arg(short, long, required = true, value_name = "PROOF STEPS")]
        proof: Vec<ProofArg>,
    },
}

#[derive(Debug, Clone)]
pub struct ProofArg {
    pub direction: HashDirection,
    pub hash: Hash,
}

impl FromStr for ProofArg {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (dir_str, hash_str) = s
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Invalid proof element format: {}", s))?;

        let direction = match dir_str.to_uppercase().as_str() {
            "L" => HashDirection::Left,
            "R" => HashDirection::Right,
            _ => anyhow::bail!("Invalid direction: {}", dir_str),
        };

        let hash = hex::decode(hash_str)
            .map_err(|e| anyhow::anyhow!("Invalid hex in proof element '{}': {}", s, e))?
            .into();

        Ok(ProofArg { direction, hash })
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Root { inputs } => {
            let tree = MerkleTree::construct(&inputs);
            let root = tree.root().unwrap();
            println!("{}", hex::encode(root));
        }
        Commands::Verify { root, inputs } => {
            if MerkleTree::verify(&inputs, &root) {
                println!("✅ Verified")
            } else {
                println!("❌ Not verified");
            }
        }
        Commands::Prove { data, inputs } => {
            let tree = MerkleTree::construct(&inputs);
            let proof = tree
                .prove(&data)
                .ok_or(anyhow!("Failed to provide proof"))?;
            println!("{proof}");
        }
        Commands::VerifyProof { data, root, proof } => {
            let owned_hashes: Vec<Hash> = proof.iter().map(|p| p.hash.clone()).collect();
            let hashes: Vec<(HashDirection, &Hash)> = proof
                .iter()
                .zip(owned_hashes.iter())
                .map(|(p, h)| (p.direction, h))
                .collect();

            let proof = Proof { hashes };

            if MerkleTree::verify_proof(&data, &proof, &root) {
                println!("✅ Verified");
            } else {
                println!("❌ Not verified");
            }
        }
        Commands::Print { inputs } => {
            let tree = MerkleTree::construct(&inputs);
            println!("{tree}");
        }
    }

    Ok(())
}
