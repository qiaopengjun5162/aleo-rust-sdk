//! Merkle exclusion proofs for Sealance-style compliant stablecoin programs.
//!
//! Mirrors the JS SDK's `SealanceMerkleTree`
//! (`sdk/src/integrations/sealance/merkle-tree.ts`): convert addresses to fields,
//! build a Poseidon4 tree, locate the two leaves bracketing a target, and format
//! the sibling paths as a Leo program input.
//!
//! ## Two deliberate divergences from the JS SDK
//!
//! 1. **Hashing.** JS `hashTwoElements(prefix, el1, el2)` parses
//!    `[prefix,el1,el2]` as an *array Plaintext* and hashes
//!    `Plaintext.toFields()`. That returns the array's **4-field serialization**
//!    (length plus packed element bits), not the three field values, so JS
//!    hashes four fields. This crate hashes the three field values directly
//!    with `hash_psd4`, matching an on-chain
//!    `Poseidon4::hash([prefix, left, right])`. For `[1field,3field,4field]`
//!    JS yields `4560646903308595113151029585344265575242682454899063992850623350939538444867field`
//!    while this crate yields
//!    `1462380410393973232568205568760787070125811435977424069183384975770991170746field`.
//!    Both values are pinned by tests below, so a future edit cannot silently
//!    switch recipes.
//! 2. **`depth` in [`SealanceMerkleTree::get_sibling_path`].** JS pads to exactly
//!    `depth` siblings; this crate returns `depth + 1` (the leaf plus one per
//!    level), because the on-chain `MerkleProof.siblings` is `[field; 16u32]`.
//!    JS's documented `depth = 16` is therefore this crate's `depth = 15` —
//!    see CHANGELOG entry for issue #26.
//!
//! Everything else (address conversion, leaf sorting/padding, tree layout,
//! leaf-index search, sibling selection, proof string formatting) is
//! byte-for-byte compatible; `test_js_formatted_proof_vector` pins the JS test
//! vector end to end.

use snarkvm::prelude::{Address, Field, FromStr, Network, One, Result, ToField, Zero};

/// Implements the SealanceMerkleTree protocol for generating Merkle exclusion proofs
/// for compliant stablecoin programs (USAD/USDCx) on Aleo.
///
/// The exclusion proof proves that a given address is NOT in the freeze list,
/// using a Merkle tree built from freeze list addresses with Poseidon4 hashing.
pub struct SealanceMerkleTree;

/// Default tree depth, matching the JS SDK's `generateLeaves` default and the
/// on-chain `MerkleProof { siblings: [field; 16u32] }` (this crate emits
/// `depth + 1` siblings, so 15 produces the 16 the program expects).
///
/// Beware the off-by-one when comparing with JS examples: their
/// `getSiblingPath(tree, index, 16)` is this crate's `depth = 15`.
pub const DEFAULT_TREE_DEPTH: u32 = 15;

/// The JS SDK's `{ siblings, leaf_index }` proof object.
///
/// [`SealanceMerkleTree::get_sibling_path`] returns just the sibling vector;
/// this pairs it with its leaf index so two paths can be handed to
/// [`SealanceMerkleTree::format_merkle_proof_from_paths`] the same way the JS
/// SDK passes `[proofLeft, proofRight]` to `formatMerkleProof`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiblingPath<N: Network> {
    /// The sibling path, leaf first (see `get_sibling_path`).
    pub siblings: Vec<Field<N>>,
    /// Index of the leaf this path belongs to.
    pub leaf_index: usize,
}

impl SealanceMerkleTree {
    /// Converts an Aleo blockchain address string to a field element.
    ///
    /// This is the Rust equivalent of the JS `SealanceMerkleTree.convertAddressToField()`.
    /// It parses the bech32m-encoded address and extracts its field representation.
    ///
    /// # Arguments
    /// * `address` - The Aleo blockchain address (e.g. "aleo1...")
    ///
    /// # Returns
    /// A `Field<N>` representing the address.
    pub fn convert_address_to_field<N: Network>(address: &str) -> Result<Field<N>> {
        let addr = Address::<N>::from_str(address)?;
        addr.to_field()
    }

    /// Converts an array of decimal string representations of field elements to `Field<N>`.
    ///
    /// JS equivalent: `SealanceMerkleTree.convertTreeToBigInt()`.
    ///
    /// The Provable `merkle-tree` endpoint returns **bare decimal strings**
    /// (`"0"`, `"3501665755..."`), while snarkVM's `Field::from_str` requires
    /// the `field` suffix. Accept both spellings so the endpoint response can
    /// be passed verbatim; anything else is an error rather than a skipped
    /// element (a shorter tree would silently prove against the wrong root).
    pub fn convert_tree_to_fields<N: Network>(tree: &[String]) -> Result<Vec<Field<N>>> {
        tree.iter()
            .map(|element| {
                if element.ends_with("field") {
                    Field::<N>::from_str(element)
                } else {
                    Field::<N>::from_str(&format!("{element}field"))
                }
            })
            .collect()
    }

    /// Hashes two field elements using Poseidon4 with the given prefix for domain separation.
    ///
    /// JS equivalent: `SealanceMerkleTree.hashTwoElements()` — but see the
    /// module docs: JS hashes the *four-field array-Plaintext serialization*,
    /// this hashes the three field values directly. Public here so callers can
    /// build trees with the same recipe as [`Self::build_tree`].
    ///
    /// `prefix` is `Field::one()` ("1field") for leaf-level hashing and
    /// `Field::zero()` ("0field") for internal node hashing.
    pub fn hash_two_elements<N: Network>(
        prefix: Field<N>,
        el1: Field<N>,
        el2: Field<N>,
    ) -> Result<Field<N>> {
        N::hash_psd4(&[prefix, el1, el2])
    }

    /// Generates the leaf field elements from an array of Aleo addresses.
    ///
    /// JS equivalent: `SealanceMerkleTree.generateLeaves()`.
    ///
    /// * Filters out zero addresses.
    /// * Converts each address to a field element.
    /// * Sorts by field value.
    /// * Pads with zero fields to reach the next power of 2.
    ///
    /// # Arguments
    /// * `addresses` - Array of Aleo address strings.
    /// * `max_tree_depth` - Maximum depth of the Merkle tree (default: 15).
    ///
    /// # Returns
    /// A vector of `Field<N>` ready for Merkle tree construction.
    pub fn generate_leaves<N: Network>(
        addresses: &[String],
        max_tree_depth: u32,
    ) -> Result<Vec<Field<N>>> {
        if max_tree_depth == 0 {
            // `1 << (0 - 1)` used to underflow and panic.
            return Err(anyhow::anyhow!("max_tree_depth must be at least 1"));
        }
        let max_num_leaves = 1 << (max_tree_depth - 1);

        // Filter out zero addresses
        let addresses: Vec<&String> = addresses
            .iter()
            .filter(|addr| {
                *addr != "aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc"
            })
            .collect();

        let num_leaves = if addresses.len() <= 1 {
            2
        } else {
            let next_pow2 = (addresses.len() as f64).log2().ceil() as u32;
            1 << next_pow2
        };

        if addresses.len() > max_num_leaves {
            return Err(anyhow::anyhow!(
                "Leaves limit exceeded. Max: {}, provided: {}",
                max_num_leaves,
                addresses.len()
            ));
        }

        // Convert addresses to fields and sort
        let mut address_fields: Vec<Field<N>> = Vec::with_capacity(addresses.len());
        for addr in &addresses {
            address_fields.push(Self::convert_address_to_field(addr)?);
        }
        address_fields.sort();

        // Pad with zero fields to reach power of 2
        let mut full_tree: Vec<Field<N>> = Vec::with_capacity(num_leaves);
        for _ in 0..(num_leaves - address_fields.len()) {
            full_tree.push(Field::<N>::zero());
        }
        full_tree.extend(address_fields);

        Ok(full_tree)
    }

    /// Builds a Merkle tree from given leaf field elements using Poseidon4.
    ///
    /// JS equivalent: `SealanceMerkleTree.buildTree()`.
    /// The tree is built bottom-up, hashing pairs at each level.
    /// Leaf level uses prefix "1field", internal levels use "0field".
    ///
    /// Returns the complete Merkle tree as a flat array (leaves first, then internal nodes).
    pub fn build_tree<N: Network>(leaves: &[Field<N>]) -> Result<Vec<Field<N>>> {
        if leaves.is_empty() {
            return Err(anyhow::anyhow!("Leaves array cannot be empty"));
        }
        if !leaves.len().is_multiple_of(2) {
            return Err(anyhow::anyhow!(
                "Leaves array must have even number of elements"
            ));
        }

        let leaf_count = leaves.len();
        let one = Field::<N>::one(); // "1field"
        let zero = Field::<N>::zero(); // "0field"

        let mut current_level: Vec<Field<N>> = leaves.to_vec();
        let mut tree: Vec<Field<N>> = current_level.clone();
        let mut level_size = current_level.len();

        while level_size > 1 {
            let mut next_level = Vec::with_capacity(level_size / 2);
            for i in (0..level_size).step_by(2) {
                let left = current_level[i];
                let right = current_level[i + 1];
                // leaf level uses "1field" prefix, internal levels use "0field"
                let prefix = if leaf_count == level_size { one } else { zero };
                let hash = Self::hash_two_elements::<N>(prefix, left, right)?;
                next_level.push(hash);
            }
            tree.extend(next_level.clone());
            current_level = next_level;
            level_size = current_level.len();
        }

        Ok(tree)
    }

    /// Finds the leaf indices for a non-inclusion proof of an address.
    ///
    /// JS equivalent: `SealanceMerkleTree.getLeafIndices()`.
    /// Returns the indices of the two adjacent leaves that surround the target address.
    /// For non-inclusion proof, we need the siblings of these two leaves.
    pub fn get_leaf_indices<N: Network>(
        tree: &[Field<N>],
        address: &str,
    ) -> Result<(usize, usize)> {
        let num_leaves = tree.len().div_ceil(2);
        let address_field = Self::convert_address_to_field::<N>(address)?;
        let leaves = &tree[..num_leaves];

        // Find first leaf >= address_field
        let right_leaf_index = leaves.iter().position(|leaf| *leaf >= address_field);

        let (left_leaf_index, right_leaf_index) = match right_leaf_index {
            None => (num_leaves - 1, num_leaves - 1),
            Some(0) => (0, 0),
            Some(idx) => (idx - 1, idx),
        };

        Ok((left_leaf_index, right_leaf_index))
    }

    /// Generates the sibling path (Merkle proof) for a given leaf index.
    ///
    /// JS equivalent: `SealanceMerkleTree.getSiblingPath()`.
    ///
    /// Element 0 is the leaf itself, followed by one sibling per level, so the
    /// returned vector has **`depth + 1`** elements — matching the JS SDK
    /// ("the returned siblings array will have maxTreeDepth + 1 elements") and
    /// the on-chain `struct MerkleProof { siblings: [field; 16u32] }`, which is
    /// 16 elements for the default `depth` of 15.
    ///
    /// Returning exactly `depth` elements (the previous behaviour) produced a
    /// 15-element array that cannot be cast to `[field; 16u32]`, so the call
    /// only failed on chain.
    pub fn get_sibling_path<N: Network>(
        tree: &[Field<N>],
        leaf_index: usize,
        depth: u32,
    ) -> Result<Vec<Field<N>>> {
        let num_leaves = tree.len().div_ceil(2);
        let mut sibling_path: Vec<Field<N>> = Vec::with_capacity(depth as usize + 1);
        let mut index = leaf_index;
        let mut parent_offset = num_leaves;
        let mut level = 1u32;

        // Push the leaf itself as the first element
        sibling_path.push(tree[index]);

        // Walk up through internal nodes
        while parent_offset < tree.len() {
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };
            sibling_path.push(tree[sibling_index]);

            // Calculate the next parent level
            index = parent_offset + leaf_index / (1 << level);
            parent_offset += num_leaves / (1 << level);
            level += 1;
        }

        // Pad remaining levels with zero fields. `level` counts the elements
        // already pushed (the leaf plus one per level walked), so the target is
        // `depth + 1`, not `depth`.
        while level <= depth {
            sibling_path.push(Field::<N>::zero());
            level += 1;
        }

        Ok(sibling_path)
    }

    /// Formats a pair of sibling paths into an Aleo-compatible exclusion proof string.
    ///
    /// JS equivalent: `SealanceMerkleTree.formatMerkleProof()`.
    /// Produces output like:
    /// `[{ siblings: [0field, 1field, ...], leaf_index: 0u32 }, { siblings: [...], leaf_index: 1u32 }]`
    pub fn format_merkle_proof(proofs: &[(Vec<Field<impl Network>>, usize)]) -> String {
        let formatted: Vec<String> = proofs
            .iter()
            .map(|(siblings, leaf_index)| {
                let sib_str: Vec<String> = siblings.iter().map(|s| format!("{}", s)).collect();
                format!(
                    "{{siblings: [{}], leaf_index: {}u32}}",
                    sib_str.join(", "),
                    leaf_index
                )
            })
            .collect();
        format!("[{}]", formatted.join(", "))
    }

    /// Generates a complete Merkle exclusion proof for a target address against a freeze list.
    ///
    /// This is the main entry point combining all steps into one call.
    ///
    /// # Arguments
    /// * `addresses` - Freeze list addresses (from Provable API or local)
    /// * `target_address` - The address to prove is NOT on the freeze list
    /// * `depth` - Merkle tree depth, i.e. Leo's `MAX_TREE_DEPTH` (default: 15,
    ///   matching Sealance). Each returned sibling path has `depth + 1` elements,
    ///   which is the length the on-chain `MerkleProof.siblings` array is
    ///   declared with (`[field; 16u32]` for the default depth).
    ///
    /// # Returns
    /// A tuple of (left_sibling_path, right_sibling_path, left_leaf_index, right_leaf_index)
    #[allow(clippy::type_complexity)]
    pub fn generate_exclusion_proof<N: Network>(
        addresses: &[String],
        target_address: &str,
        depth: u32,
    ) -> Result<(Vec<Field<N>>, Vec<Field<N>>, usize, usize)> {
        // 1. Generate leaves
        let leaves = Self::generate_leaves::<N>(addresses, depth)?;

        // 2. Build tree
        let tree = Self::build_tree::<N>(&leaves)?;

        // 3. Find leaf indices
        let (left_idx, right_idx) = Self::get_leaf_indices::<N>(&tree, target_address)?;

        // 4. Get sibling paths
        let left_path = Self::get_sibling_path::<N>(&tree, left_idx, depth)?;
        let right_path = Self::get_sibling_path::<N>(&tree, right_idx, depth)?;

        Ok((left_path, right_path, left_idx, right_idx))
    }

    /// [`Self::generate_leaves`] using [`DEFAULT_TREE_DEPTH`].
    ///
    /// # Errors
    ///
    /// Fails when an address is invalid or the freeze list exceeds the depth.
    pub fn generate_leaves_default<N: Network>(addresses: &[String]) -> Result<Vec<Field<N>>> {
        Self::generate_leaves::<N>(addresses, DEFAULT_TREE_DEPTH)
    }

    /// [`Self::generate_exclusion_proof`] using [`DEFAULT_TREE_DEPTH`].
    ///
    /// # Errors
    ///
    /// Fails when an address is invalid or the freeze list exceeds the depth.
    #[allow(clippy::type_complexity)]
    pub fn generate_exclusion_proof_default<N: Network>(
        addresses: &[String],
        target_address: &str,
    ) -> Result<(Vec<Field<N>>, Vec<Field<N>>, usize, usize)> {
        Self::generate_exclusion_proof::<N>(addresses, target_address, DEFAULT_TREE_DEPTH)
    }

    /// [`Self::get_sibling_path`] packaged as the JS SDK's proof object.
    ///
    /// # Errors
    ///
    /// Fails when `leaf_index` is out of range for `tree`.
    pub fn get_sibling_path_object<N: Network>(
        tree: &[Field<N>],
        leaf_index: usize,
        depth: u32,
    ) -> Result<SiblingPath<N>> {
        Ok(SiblingPath {
            siblings: Self::get_sibling_path::<N>(tree, leaf_index, depth)?,
            leaf_index,
        })
    }

    /// Formats JS-shaped proof objects; identical output to
    /// [`Self::format_merkle_proof`].
    pub fn format_merkle_proof_from_paths<N: Network>(proofs: &[SiblingPath<N>]) -> String {
        let tuples: Vec<(Vec<Field<N>>, usize)> =
            proofs.iter().map(|proof| (proof.siblings.clone(), proof.leaf_index)).collect();
        Self::format_merkle_proof(&tuples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{Field, TestnetV0};

    type N = TestnetV0;

    #[test]
    fn test_convert_address_to_field() {
        let address = "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px";
        let field = SealanceMerkleTree::convert_address_to_field::<N>(address).unwrap();
        // The field should be non-zero
        assert_ne!(field, Field::<N>::zero());
        println!("Address field: {}", field);
    }

    #[test]
    fn test_generate_leaves() {
        let addresses = vec![
            "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px".to_string(),
            "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t".to_string(),
        ];
        let leaves = SealanceMerkleTree::generate_leaves::<N>(&addresses, 15).unwrap();
        // Should have 2 leaves (already power of 2)
        assert_eq!(leaves.len(), 2);
        println!(
            "Leaves: {:?}",
            leaves.iter().map(|f| format!("{}", f)).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_build_tree() {
        let addresses = vec![
            "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px".to_string(),
            "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t".to_string(),
        ];
        let leaves = SealanceMerkleTree::generate_leaves::<N>(&addresses, 15).unwrap();
        let tree = SealanceMerkleTree::build_tree::<N>(&leaves).unwrap();
        // Tree should have 3 elements: 2 leaves + 1 root
        assert_eq!(tree.len(), 3);
        println!(
            "Tree: {:?}",
            tree.iter().map(|f| format!("{}", f)).collect::<Vec<_>>()
        );
        println!("Root: {}", tree.last().unwrap());
    }

    #[test]
    fn test_get_leaf_indices() {
        let addresses = vec![
            "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px".to_string(),
            "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t".to_string(),
        ];
        let leaves = SealanceMerkleTree::generate_leaves::<N>(&addresses, 15).unwrap();
        let tree = SealanceMerkleTree::build_tree::<N>(&leaves).unwrap();

        // Test with a non-freeze-list address
        let target = "aleo1kypwp5m7qtk9mwazgcpg0tq8aal23mnrvwfvug65qgcg9xvsrqgspyjm6n";
        let (left, right) = SealanceMerkleTree::get_leaf_indices::<N>(&tree, target).unwrap();
        println!("Left index: {}, Right index: {}", left, right);
        assert!(left <= right);
    }

    #[test]
    fn test_get_sibling_path() {
        let addresses = vec![
            "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px".to_string(),
            "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t".to_string(),
        ];
        let leaves = SealanceMerkleTree::generate_leaves::<N>(&addresses, 15).unwrap();
        let tree = SealanceMerkleTree::build_tree::<N>(&leaves).unwrap();

        let path = SealanceMerkleTree::get_sibling_path::<N>(&tree, 0, 15).unwrap();
        assert_eq!(
            path.len(),
            16,
            "depth 15 must yield 16 siblings (leaf + 15 levels), per the JS SDK"
        );
        assert_eq!(
            path[0], tree[0],
            "element 0 is the leaf itself, as the JS SDK's [leaf, sibling_1, ...] layout"
        );
        println!(
            "Sibling path (16 elements): {:?}",
            path.iter().map(|f| format!("{}", f)).collect::<Vec<_>>()
        );
    }

    /// The length is not cosmetic: Aleo programs declare
    /// `struct MerkleProof { siblings: [field; 16u32]; leaf_index: u32 }`, and a
    /// 15-element array fails the cast on chain. Depth 16 has to grow with it.
    #[test]
    fn test_sibling_path_length_tracks_the_on_chain_array() {
        let addresses =
            vec!["aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px".to_string()];
        let leaves = SealanceMerkleTree::generate_leaves::<N>(&addresses, 15).unwrap();
        let tree = SealanceMerkleTree::build_tree::<N>(&leaves).unwrap();

        for depth in [2u32, 15, 16] {
            let path = SealanceMerkleTree::get_sibling_path::<N>(&tree, 0, depth).unwrap();
            assert_eq!(
                path.len(),
                depth as usize + 1,
                "path length must be depth + 1 for depth {depth}"
            );
        }
    }

    #[test]
    fn test_generate_leaves_rejects_zero_depth() {
        let addresses =
            vec!["aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px".to_string()];
        let err = SealanceMerkleTree::generate_leaves::<N>(&addresses, 0).unwrap_err();
        assert!(
            format!("{err}").contains("at least 1"),
            "depth 0 must be a clean error, not a subtraction overflow panic: {err}"
        );
    }

    // ── convert_tree_to_fields ──────────────────────────────────────────

    /// The Provable `merkle-tree` endpoint returns decimal strings; a single
    /// unparsable element must fail loudly instead of silently producing a
    /// shorter tree (which would still build, and would silently produce a
    /// proof for the wrong root).
    #[test]
    fn test_convert_tree_to_fields() {
        let one = Field::<N>::one();
        let tree = vec![format!("{one}"), format!("{}", Field::<N>::zero())];
        let fields = SealanceMerkleTree::convert_tree_to_fields::<N>(&tree).unwrap();
        assert_eq!(fields, vec![one, Field::<N>::zero()]);

        let bad = vec!["1field".to_string(), "not_a_field".to_string()];
        assert!(
            SealanceMerkleTree::convert_tree_to_fields::<N>(&bad).is_err(),
            "an unparsable element must be an error, not a skipped element"
        );
    }

    // ── format_merkle_proof ─────────────────────────────────────────────
    //
    // This string is passed verbatim as a program input, so the punctuation
    // is part of the contract: `[{siblings: [...], leaf_index: Nu32}, ...]`.
    #[test]
    fn test_format_merkle_proof_matches_program_input_syntax() {
        let one = Field::<N>::one();
        let zero = Field::<N>::zero();
        let proofs = [(vec![one, zero], 0usize), (vec![zero, one], 1usize)];
        let formatted = SealanceMerkleTree::format_merkle_proof(&proofs);
        assert_eq!(
            formatted,
            "[{siblings: [1field, 0field], leaf_index: 0u32}, {siblings: [0field, 1field], leaf_index: 1u32}]",
            "the formatted proof is a program input; any change here breaks on-chain calls"
        );
    }

    #[test]
    fn test_format_merkle_proof_empty() {
        let empty: Vec<(Vec<Field<N>>, usize)> = Vec::new();
        assert_eq!(SealanceMerkleTree::format_merkle_proof(&empty), "[]");
    }

    // ── generate_exclusion_proof (the documented entry point) ───────────

    /// End-to-end: two freeze-list addresses plus a target that is not on the
    /// list. Both sibling paths must be exactly `depth` long (the on-chain
    /// function indexes them positionally), and the two leaves must bracket
    /// the target in the sorted leaf order.
    #[test]
    fn test_generate_exclusion_proof_brackets_the_target() {
        let addresses = vec![
            "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px".to_string(),
            "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t".to_string(),
        ];
        let target = "aleo1kypwp5m7qtk9mwazgcpg0tq8aal23mnrvwfvug65qgcg9xvsrqgspyjm6n";

        let (left_path, right_path, left_idx, right_idx) =
            SealanceMerkleTree::generate_exclusion_proof::<N>(&addresses, target, 15).unwrap();

        assert_eq!(
            left_path.len(),
            16,
            "left sibling path must match the on-chain [field; 16u32]"
        );
        assert_eq!(
            right_path.len(),
            16,
            "right sibling path must match the on-chain [field; 16u32]"
        );
        assert!(
            left_idx <= right_idx,
            "left leaf must not be right of the right leaf"
        );

        // Rebuild the tree by hand to confirm the indices really bracket the
        // target: leaves[left_idx] <= target < leaves[right_idx].
        let leaves = SealanceMerkleTree::generate_leaves::<N>(&addresses, 15).unwrap();
        let target_field = SealanceMerkleTree::convert_address_to_field::<N>(target).unwrap();
        let below = leaves[..left_idx].iter().filter(|leaf| **leaf > target_field).count();
        assert_eq!(
            below, 0,
            "no leaf before left_idx may be greater than the target"
        );
    }

    /// A freeze list containing only the zero address is empty after filtering;
    /// `generate_leaves` must still return a well-formed (zero-padded) leaf set
    /// rather than panicking on `num_leaves - len`.
    #[test]
    fn test_generate_leaves_filters_zero_address_and_pads() {
        let zero_addr =
            "aleo1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq3ljyzc".to_string();
        let leaves = SealanceMerkleTree::generate_leaves::<N>(&[zero_addr], 15).unwrap();
        assert_eq!(leaves.len(), 2, "empty freeze list still yields 2 leaves");
        assert!(leaves.iter().all(|leaf| *leaf == Field::<N>::zero()));

        // Padding goes at the front, so real addresses stay at the tail.
        let addresses = vec![
            "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px".to_string(),
            "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t".to_string(),
            "aleo1kypwp5m7qtk9mwazgcpg0tq8aal23mnrvwfvug65qgcg9xvsrqgspyjm6n".to_string(),
        ];
        let leaves = SealanceMerkleTree::generate_leaves::<N>(&addresses, 15).unwrap();
        assert_eq!(leaves.len(), 4, "3 addresses pad to the next power of two");
        assert_eq!(
            leaves[0],
            Field::<N>::zero(),
            "padding sits before the sorted addresses"
        );
        assert!(
            leaves[1..].iter().all(|leaf| *leaf != Field::<N>::zero()),
            "real addresses must not be replaced by padding"
        );
    }

    #[test]
    fn test_generate_leaves_rejects_more_than_the_depth_allows() {
        // depth 2 => 1 << 1 == 2 leaves max, so 3 addresses must be rejected.
        let addresses: Vec<String> = (0..3)
            .map(|i| {
                // Distinct valid addresses: reuse one and vary it is not
                // possible, so build from a known list and repeat with the
                // zero address excluded differently.
                [
                    "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px",
                    "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t",
                    "aleo1kypwp5m7qtk9mwazgcpg0tq8aal23mnrvwfvug65qgcg9xvsrqgspyjm6n",
                ][i]
                    .to_string()
            })
            .collect();
        let err = SealanceMerkleTree::generate_leaves::<N>(&addresses, 2).unwrap_err();
        assert!(
            format!("{err}").contains("Leaves limit exceeded"),
            "expected a leaves-limit error, got: {err}"
        );
    }

    // ── build_tree validation ───────────────────────────────────────────

    #[test]
    fn test_build_tree_rejects_empty_and_odd_input() {
        let empty: Vec<Field<N>> = vec![];
        assert!(SealanceMerkleTree::build_tree::<N>(&empty).is_err());

        let odd = vec![Field::<N>::one(), Field::<N>::zero(), Field::<N>::one()];
        let err = SealanceMerkleTree::build_tree::<N>(&odd).unwrap_err();
        assert!(
            format!("{err}").contains("even number"),
            "expected an even-length error, got: {err}"
        );
    }

    // ── JS SDK vectors (sdk/tests/sealance-merkle-tree.test.ts) ─────────

    /// The Provable `merkle-tree` endpoint and the JS test suite both feed
    /// **bare decimal strings** here. `Field::from_str("0")` rejects those, so
    /// before this was fixed the very first step of building a proof failed.
    #[test]
    fn test_convert_tree_to_fields_accepts_bare_decimal_strings() {
        let input = vec![
            "0".to_string(),
            "3501665755452795161867664882580888971213780722176652848275908626939553697821"
                .to_string(),
        ];
        let fields = SealanceMerkleTree::convert_tree_to_fields::<N>(&input).unwrap();
        assert_eq!(fields[0], Field::<N>::zero());
        assert_eq!(
            fields[1].to_string(),
            "3501665755452795161867664882580888971213780722176652848275908626939553697821field"
        );

        // The `field`-suffixed form keeps working.
        let suffixed = vec!["1field".to_string(), "0field".to_string()];
        assert_eq!(
            SealanceMerkleTree::convert_tree_to_fields::<N>(&suffixed).unwrap(),
            vec![Field::<N>::one(), Field::<N>::zero()]
        );

        // Garbage still fails loudly rather than shrinking the tree.
        assert!(SealanceMerkleTree::convert_tree_to_fields::<N>(&["nope".to_string()]).is_err());
    }

    /// JS `should sort leaves correctly` / `should filter ZERO_ADDRESS`.
    #[test]
    fn test_address_and_leaf_vectors_match_js() {
        const A: &str = "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px";
        const B: &str = "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t";
        let a = "3501665755452795161867664882580888971213780722176652848275908626939553697821field";
        let b = "1295133970529764960316948294624974168921228814652993007266766481909235735940field";
        assert_eq!(
            SealanceMerkleTree::convert_address_to_field::<N>(A).unwrap().to_string(),
            a
        );
        assert_eq!(
            SealanceMerkleTree::convert_address_to_field::<N>(B).unwrap().to_string(),
            b
        );

        let leaves =
            SealanceMerkleTree::generate_leaves_default::<N>(&[A.to_string(), B.to_string()])
                .unwrap();
        assert_eq!(
            leaves.iter().map(|f| f.to_string()).collect::<Vec<_>>(),
            [b, a]
        );
    }

    /// End-to-end byte-for-byte vector from JS `formatMerkleProof should format
    /// merkle proof correctly`. The tree is supplied by the endpoint, so no
    /// hashing is involved: indices, sibling selection and the final program
    /// input string must all match. JS `depth = 15` yields 15 siblings; this
    /// crate yields `depth + 1`, so `depth = 14` is the equivalent call.
    #[test]
    fn test_js_formatted_proof_vector() {
        let tree_strings: Vec<String> = [
            "0",
            "3501665755452795161867664882580888971213780722176652848275908626939553697821",
            "4539470720491009302557179633742244202521723448302096289013203539461297095738",
            "7426353931016374702593127301815460123689343416970811802742952620156952318730",
            "7052697765310872540032307615262912043079143561812812402660738198777516992718",
            "7162588494104628985065247846816902886874444240334527780589295712502521092900",
            "7179654795269183001911849426990084952297107287660910339902947270666145459461",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let tree = SealanceMerkleTree::convert_tree_to_fields::<N>(&tree_strings).unwrap();
        let target = "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px";
        let (left, right) = SealanceMerkleTree::get_leaf_indices::<N>(&tree, target).unwrap();
        assert_eq!(
            (left, right),
            (0, 1),
            "JS vector brackets the target at 0/1"
        );

        let p1 = SealanceMerkleTree::get_sibling_path_object::<N>(&tree, left, 14).unwrap();
        let p2 = SealanceMerkleTree::get_sibling_path_object::<N>(&tree, right, 14).unwrap();
        assert_eq!(p1.leaf_index, 0);
        assert_eq!(p2.leaf_index, 1);
        assert_eq!(p1.siblings.len(), 15);
        assert_eq!(p2.siblings.len(), 15);

        let formatted =
            SealanceMerkleTree::format_merkle_proof_from_paths(&[p1.clone(), p2.clone()]);
        assert_eq!(
            formatted,
            "[{siblings: [0field, 3501665755452795161867664882580888971213780722176652848275908626939553697821field, 7162588494104628985065247846816902886874444240334527780589295712502521092900field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field], leaf_index: 0u32}, {siblings: [3501665755452795161867664882580888971213780722176652848275908626939553697821field, 0field, 7162588494104628985065247846816902886874444240334527780589295712502521092900field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field, 0field], leaf_index: 1u32}]"
        );
        // The tuple-based entry point must produce the identical string.
        assert_eq!(
            formatted,
            SealanceMerkleTree::format_merkle_proof(&[
                (p1.siblings, p1.leaf_index),
                (p2.siblings, p2.leaf_index)
            ])
        );
    }

    /// Pins **both** Poseidon recipes (see module docs). JS hashes the 4-field
    /// array-Plaintext serialization; this crate hashes the 3 field values.
    /// Neither value may drift, and they must stay different.
    #[test]
    fn test_hash_two_elements_recipes_are_both_pinned() {
        use snarkvm::prelude::{Plaintext, ToFields};
        let one = Field::<N>::one();
        let three = Field::<N>::from_str("3field").unwrap();
        let four = Field::<N>::from_str("4field").unwrap();

        let ours = SealanceMerkleTree::hash_two_elements::<N>(one, three, four).unwrap();
        assert_eq!(
            ours.to_string(),
            "1462380410393973232568205568760787070125811435977424069183384975770991170746field"
        );

        let fields =
            Plaintext::<N>::from_str("[1field,3field,4field]").unwrap().to_fields().unwrap();
        assert_eq!(
            fields.len(),
            4,
            "JS hashes the array serialization, not the three field values"
        );
        let js = N::hash_psd4(&fields).unwrap();
        assert_eq!(
            js.to_string(),
            "4560646903308595113151029585344265575242682454899063992850623350939538444867field"
        );
        assert_ne!(ours, js);
    }

    #[test]
    fn test_default_depth_convenience_methods() {
        const A: &str = "aleo1rhgdu77hgyqd3xjj8ucu3jj9r2krwz6mnzyd80gncr5fxcwlh5rsvzp9px";
        const B: &str = "aleo1s3ws5tra87fjycnjrwsjcrnw2qxr8jfqqdugnf0xzqqw29q9m5pqem2u4t";
        const TARGET: &str = "aleo1kypwp5m7qtk9mwazgcpg0tq8aal23mnrvwfvug65qgcg9xvsrqgspyjm6n";
        let addresses = vec![A.to_string(), B.to_string()];

        assert_eq!(DEFAULT_TREE_DEPTH, 15);
        assert_eq!(
            SealanceMerkleTree::generate_leaves_default::<N>(&addresses).unwrap(),
            SealanceMerkleTree::generate_leaves::<N>(&addresses, 15).unwrap()
        );
        assert_eq!(
            SealanceMerkleTree::generate_exclusion_proof_default::<N>(&addresses, TARGET).unwrap(),
            SealanceMerkleTree::generate_exclusion_proof::<N>(&addresses, TARGET, 15).unwrap()
        );
        let (left, _, _, _) =
            SealanceMerkleTree::generate_exclusion_proof_default::<N>(&addresses, TARGET).unwrap();
        assert_eq!(left.len(), 16, "depth 15 emits the on-chain [field; 16u32]");
    }
}
