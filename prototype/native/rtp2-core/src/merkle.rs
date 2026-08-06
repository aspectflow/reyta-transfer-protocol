// Copyright 2026 The Reyta Labs Authors.
// SPDX-License-Identifier: Apache-2.0

//! BLAKE3 Merkle commitment over ciphertext chunks (§12).

pub const LEAF_DOMAIN: &[u8] = b"RTP2-MERKLE-LEAF-v1\0";
pub const NODE_DOMAIN: &[u8] = b"RTP2-MERKLE-NODE-v1\0";
pub const EMPTY_DOMAIN: &[u8] = b"RTP2-MERKLE-EMPTY-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    IndexOutOfRange,
    DepthExceeded,
    TrailingSiblings,
    RootMismatch,
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Left,
    Right,
}

#[derive(Clone)]
pub struct ProofStep {
    pub direction: Direction,
    pub hash: [u8; 32],
}

/// §12.1 leaf hash: domain || U64BE(i) || U32BE(len) || ciphertext.
pub fn leaf_hash(index: u64, ciphertext: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(LEAF_DOMAIN);
    h.update(&index.to_be_bytes());
    h.update(&(ciphertext.len() as u32).to_be_bytes());
    h.update(ciphertext);
    *h.finalize().as_bytes()
}

/// §12.2 node hash.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(NODE_DOMAIN);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// §12.3 empty root.
pub fn empty_root() -> [u8; 32] {
    *blake3::hash(EMPTY_DOMAIN).as_bytes()
}

/// §12.4 canonical left-balanced tree. Split at the largest power of two
/// below n, and never duplicate an odd leaf.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = largest_power_of_two_below(n);
            let left = merkle_root(&leaves[..k]);
            let right = merkle_root(&leaves[k..]);
            node_hash(&left, &right)
        }
    }
}

fn largest_power_of_two_below(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Inclusion proof for `index` (§12.5). Siblings run leaf upward, and
/// `direction` says which side each one is on.
pub fn build_proof(leaves: &[[u8; 32]], index: usize) -> Result<Vec<ProofStep>, ProofError> {
    if index >= leaves.len() {
        return Err(ProofError::IndexOutOfRange);
    }
    let mut proof = Vec::new();
    build_proof_inner(leaves, index, &mut proof);
    Ok(proof)
}

fn build_proof_inner(leaves: &[[u8; 32]], index: usize, proof: &mut Vec<ProofStep>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = largest_power_of_two_below(leaves.len());
    if index < k {
        build_proof_inner(&leaves[..k], index, proof);
        proof.push(ProofStep {
            direction: Direction::Right,
            hash: merkle_root(&leaves[k..]),
        });
    } else {
        build_proof_inner(&leaves[k..], index - k, proof);
        proof.push(ProofStep {
            direction: Direction::Left,
            hash: merkle_root(&leaves[..k]),
        });
    }
}

/// Verifies an inclusion proof (§12.5).
///
/// `leaf_count` and `expected_root` must come from the authenticated manifest,
/// never from the proof. The path shape does not pin the tree size, so this
/// cannot be checked here: see `the_shape_check_cannot_validate_leaf_count`.
pub fn verify_proof(
    leaf: &[u8; 32],
    index: u64,
    leaf_count: u64,
    siblings: &[ProofStep],
    expected_root: &[u8; 32],
) -> Result<(), ProofError> {
    if index >= leaf_count {
        return Err(ProofError::IndexOutOfRange);
    }
    if leaf_count == 0 {
        return Err(ProofError::Malformed);
    }
    // Maximum depth implied by leaf_count: ceil(log2(leaf_count)).
    let max_depth = 64 - (leaf_count - 1).leading_zeros() as usize;
    if siblings.len() > max_depth {
        return Err(ProofError::DepthExceeded);
    }
    // The canonical shape fixes the whole path for a given (leaf_count,
    // index), so recompute both length and directions. A proof for another
    // position then cannot be replayed under a lying index (INV-40).
    let expected_dirs = expected_directions(leaf_count, index);
    if siblings.len() != expected_dirs.len() {
        return Err(ProofError::TrailingSiblings);
    }
    for (step, expected) in siblings.iter().zip(&expected_dirs) {
        if step.direction != *expected {
            return Err(ProofError::Malformed);
        }
    }

    let mut acc = *leaf;
    for step in siblings {
        acc = match step.direction {
            Direction::Left => node_hash(&step.hash, &acc),
            Direction::Right => node_hash(&acc, &step.hash),
        };
    }
    if crate::crypto::ct_eq(&acc, expected_root) {
        Ok(())
    } else {
        Err(ProofError::RootMismatch)
    }
}

/// Direction sequence, leaf upward, of the canonical path for `index`.
fn expected_directions(leaf_count: u64, index: u64) -> Vec<Direction> {
    let mut dirs = Vec::new();
    expected_directions_inner(leaf_count, index, &mut dirs);
    dirs
}

fn expected_directions_inner(leaf_count: u64, index: u64, dirs: &mut Vec<Direction>) {
    if leaf_count <= 1 {
        return;
    }
    // Largest power of two below `leaf_count`. Not `k * 2 < leaf_count`,
    // which wraps to 0 near u64::MAX and spins forever in release.
    // `leaf_count` is at least 2 here, so the subtraction is safe.
    let mut k = 1u64;
    while k <= (leaf_count - 1) / 2 {
        k *= 2;
    }
    if index < k {
        expected_directions_inner(k, index, dirs);
        dirs.push(Direction::Right);
    } else {
        expected_directions_inner(leaf_count - k, index - k, dirs);
        dirs.push(Direction::Left);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_leaves(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| leaf_hash(i as u64, format!("chunk-{i}").as_bytes()))
            .collect()
    }

    #[test]
    fn proofs_verify_for_all_shapes() {
        for n in 1..=17usize {
            let leaves = sample_leaves(n);
            let root = merkle_root(&leaves);
            for i in 0..n {
                let proof = build_proof(&leaves, i).unwrap();
                verify_proof(&leaves[i], i as u64, n as u64, &proof, &root)
                    .unwrap_or_else(|e| panic!("n={n} i={i}: {e:?}"));
            }
        }
    }

    #[test]
    fn substituted_leaf_fails() {
        let leaves = sample_leaves(8);
        let root = merkle_root(&leaves);
        let proof = build_proof(&leaves, 3).unwrap();
        // Same-size tree, different content (INV-41).
        let foreign = leaf_hash(3, b"foreign-chunk");
        assert_eq!(
            verify_proof(&foreign, 3, 8, &proof, &root),
            Err(ProofError::RootMismatch)
        );
    }

    #[test]
    fn wrong_position_fails() {
        let leaves = sample_leaves(8);
        let root = merkle_root(&leaves);
        let proof = build_proof(&leaves, 3).unwrap();
        // Valid leaf presented at a different index (INV-40).
        assert!(verify_proof(&leaves[3], 4, 8, &proof, &root).is_err());
        // Index beyond leaf_count.
        assert_eq!(
            verify_proof(&leaves[3], 9, 8, &proof, &root),
            Err(ProofError::IndexOutOfRange)
        );
    }

    #[test]
    fn trailing_or_missing_siblings_fail() {
        let leaves = sample_leaves(8);
        let root = merkle_root(&leaves);
        let mut proof = build_proof(&leaves, 3).unwrap();
        proof.push(ProofStep {
            direction: Direction::Left,
            hash: [0u8; 32],
        });
        assert!(verify_proof(&leaves[3], 3, 8, &proof, &root).is_err());
        proof.truncate(1);
        assert!(verify_proof(&leaves[3], 3, 8, &proof, &root).is_err());
    }

    #[test]
    fn the_shape_check_cannot_validate_leaf_count() {
        // A peer-supplied `leaf_count` is not made safe by the depth check:
        // in an 8-leaf tree, indices 0..4 share a proof shape across claimed
        // sizes 5, 6, 7 and 8, so all four verify against the real root. This
        // is why §12.5 requires it to come from the authenticated manifest.
        let leaves = sample_leaves(8);
        let root = merkle_root(&leaves);
        let proof = build_proof(&leaves, 3).unwrap();

        let mut accepted = Vec::new();
        for claimed in 1..=64u64 {
            if verify_proof(&leaves[3], 3, claimed, &proof, &root).is_ok() {
                accepted.push(claimed);
            }
        }
        assert_eq!(
            accepted,
            vec![5, 6, 7, 8],
            "if this set ever shrinks to [8] the shape check became decisive, \
             and the §12.5 requirement could be relaxed; if it grows, the \
             ambiguity got worse. Either way it is a deliberate change."
        );

        // Sizes whose shape really differs are still refused, so the check
        // earns its keep. It just cannot do the whole job.
        for wrong in [1u64, 2, 3, 4, 9, 16, 1024, u64::MAX] {
            assert!(
                verify_proof(&leaves[3], 3, wrong, &proof, &root).is_err(),
                "leaf_count={wrong} changes the path shape and must be refused"
            );
        }
    }

    #[test]
    fn a_subtree_root_is_not_the_object_root() {
        // The other half of the attack: in an 8-leaf tree the node above
        // leaves 0 and 1 is exactly what a 2-leaf tree's root would be.
        let leaves = sample_leaves(8);
        let root = merkle_root(&leaves);
        let internal = node_hash(&leaves[0], &leaves[1]);
        assert_ne!(internal, root, "test premise");

        let short = vec![ProofStep {
            direction: Direction::Right,
            hash: leaves[1],
        }];
        assert!(verify_proof(&leaves[0], 0, 2, &short, &root).is_err());
        // It proves membership in a different tree, which is why the root
        // must come from the manifest too.
        verify_proof(&leaves[0], 0, 2, &short, &internal).unwrap();
    }

    #[test]
    fn an_absurd_leaf_count_terminates() {
        // A peer can sign any chunk_count it likes. The old loop condition
        // never returned near u64::MAX: an unbounded CPU burn behind nothing
        // more than a completed handshake.
        let leaves = sample_leaves(8);
        let root = merkle_root(&leaves);
        let proof = build_proof(&leaves, 3).unwrap();

        for absurd in [
            u64::MAX,
            u64::MAX - 1,
            1u64 << 63,
            (1u64 << 63) + 1,
            (1u64 << 62) + 7,
        ] {
            assert!(
                verify_proof(&leaves[3], 3, absurd, &proof, &root).is_err(),
                "leaf_count={absurd} must be refused"
            );
        }
    }

    #[test]
    fn empty_and_single() {
        assert_eq!(merkle_root(&[]), empty_root());
        let leaves = sample_leaves(1);
        assert_eq!(merkle_root(&leaves), leaves[0]);
        let proof = build_proof(&leaves, 0).unwrap();
        assert!(proof.is_empty());
        verify_proof(&leaves[0], 0, 1, &proof, &leaves[0]).unwrap();
    }
}
