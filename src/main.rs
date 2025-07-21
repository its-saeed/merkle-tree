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

fn main() {}
