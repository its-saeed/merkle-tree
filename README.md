# Merkle Tree in Rust 🌳

A simple and efficient Merkle Tree implementation in Rust, with a command-line interface (CLI) and a reusable library.

---

## 🌐 What is a Merkle Tree?

A **Merkle Tree** is a binary tree where each leaf node is the hash of a piece of data, and each internal node is the hash of the concatenation of its children. It provides a way to verify the integrity of large datasets with minimal information.

### Example Use Cases:
- Blockchain and cryptocurrencies
- Version control systems (like Git)
- Distributed systems and peer-to-peer networks

---

## 🚀 Getting Started

### 🔧 Clone and Build

```bash
git clone https://github.com/its-saeed/merkle_tree.git
cd merkle_tree
cargo build --release
````

---

## 📚 Using the Library

You can use the library in your own Rust project by importing it as a dependency (if published to crates.io) or locally.

### Example

```rust
use merkle_tree::{MerkleTree, Data};

fn main() {
    let data: Vec<Data> = vec![
        vec![0x01].into(),
        vec![0x02].into(),
        vec![0x03].into(),
        vec![0x04].into(),
    ];

    let tree = MerkleTree::construct(&data);
    let root = tree.root().unwrap();
    println!("Merkle root: {}", root);
}
```

You can also verify data integrity or generate/verify proofs using `MerkleTree::verify`, `prove`, and `verify_proof`.

---

## 🖥️ Using the CLI

The CLI provides a simple interface for computing and verifying Merkle roots and inclusion proofs.

### Build the CLI

```bash
cargo build --release
```

### Run

#### 📌 Compute the root from a list of hex-encoded inputs

```bash
cargo run -- root 01 02 03 04

#output: 98d658fb28540a2eca2a8a5930c309a9c37f89979d48d025a72c36a77a74510d
```

#### 🛡️ Verify that a set of inputs reconstructs the given Merkle root

```bash
cargo run -- verify --root <hex_root> 01 02 03 04

# Example:
cargo run -- verify --root abcd1234deadbeef 01 02 03 04
# Output: ✅ Verified or ❌ Not verified
```

#### 📄 Generate a Merkle proof for a specific data element
```bash
cargo run -- prove --data <hex_value> 01 02 03 04

# Example:
cargo run -- prove --data 03 01 02 03 04

# output
#0: [R] e52d9c508c502347344d8c07ad91cbd6068afc75ff6292f062a09ca381c89e71
#1: [L] 42dbeeb4eb5d41bbdc93732c6a87ab3241ee03f44a0780a52ddf831f5fd88b53
```

#### ✅ Verify a Merkle inclusion proof
```bash
cargo run -- verify-proof \
  --data <hex_value> \
  --root <hex_root> \
  --proof <direction1:hash1> --proof<direction2:hash2> ...

# Example:
cargo run -- verify-proof \
  --data 03 \
  --root aabbccddeeff0011 \
  --proof R:1234567890abcdef --proof L:abcdef1234567890
# Output: ✅ Verified or ❌ Not verified
```

---

## 🧠 Performance Considerations

To make the Merkle Tree efficient:

* **Preallocated memory:** The internal hash vector is preallocated based on the number of input leaves to avoid reallocations.
* **Bottom-up construction:** Tree is built from leaves up to the root in a single pass using index math instead of allocating node structs.
* **Zero-copy hash references in proofs:** Proof hashes are borrowed (`&Hash`) instead of cloned wherever possible to reduce unnecessary memory usage.
* **Efficient hashing:** Uses `sha2::Sha256`, a fast and secure hashing algorithm with optimized implementations.

These optimizations ensure that the Merkle Tree can scale efficiently even for thousands of entries.

---

## 🧪 Testing

```bash
cargo test
```

Tests include:

* Tree construction and root computation
* Proof generation and verification
* Valid/invalid data verification scenarios

