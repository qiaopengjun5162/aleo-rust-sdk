use snarkvm::prelude::{Address, Field, FromStr, Network, One, Result, ToField, Zero};

/// Implements the SealanceMerkleTree protocol for generating Merkle exclusion proofs
/// for compliant stablecoin programs (USAD/USDCx) on Aleo.
///
/// The exclusion proof proves that a given address is NOT in the freeze list,
/// using a Merkle tree built from freeze list addresses with Poseidon4 hashing.
pub struct SealanceMerkleTree;

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
    /// The input is an array of decimal strings from the Provable API's merkle-tree endpoint.
    pub fn convert_tree_to_fields<N: Network>(tree: &[String]) -> Result<Vec<Field<N>>> {
        tree.iter().map(|element| Field::<N>::from_str(element)).collect()
    }

    /// Hashes two field elements using Poseidon4 with the given prefix for domain separation.
    ///
    /// JS equivalent: `SealanceMerkleTree.hashTwoElements()`.
    /// Prefix is "1field" for leaf-level hashing, "0field" for internal node hashing.
    fn hash_two_elements<N: Network>(
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
        if leaves.len() % 2 != 0 {
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
    /// Returns the sibling values needed to reconstruct the Merkle root.
    pub fn get_sibling_path<N: Network>(
        tree: &[Field<N>],
        leaf_index: usize,
        depth: u32,
    ) -> Result<Vec<Field<N>>> {
        let num_leaves = tree.len().div_ceil(2);
        let mut sibling_path: Vec<Field<N>> = Vec::with_capacity(depth as usize);
        let mut index = leaf_index;
        let mut parent_offset = num_leaves;
        let mut level = 1u32;

        // Push the leaf itself as the first element
        sibling_path.push(tree[index]);

        // Walk up through internal nodes
        while parent_offset < tree.len() {
            let sibling_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            sibling_path.push(tree[sibling_index]);

            // Calculate the next parent level
            index = parent_offset + leaf_index / (1 << level);
            parent_offset += num_leaves / (1 << level);
            level += 1;
        }

        // Pad remaining levels with zero fields
        while level < depth {
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
    /// * `depth` - Merkle tree depth (default: 15, matching Sealance)
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
        assert_eq!(path.len(), 15);
        println!(
            "Sibling path (15 levels): {:?}",
            path.iter().map(|f| format!("{}", f)).collect::<Vec<_>>()
        );
    }
}
