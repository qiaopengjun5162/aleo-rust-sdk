//! JS SDK `Hash Functions` parity.
//!
//! The JS page ships nine hashers in three families. Each one is a thin wrapper
//! over a `snarkvm` type that already exists, so this module adds no new types:
//! it pins the **default domain separators** the JS constructors choose, and
//! bridges the two places where a JS method name does not correspond to a
//! native trait.
//!
//! | JS class | Native type | `new X()` domain | Domain limit |
//! |----------|-------------|------------------|--------------|
//! | `BHP256` | `BHP256<N>` = `BHP<N, 3, 57>` | [`BHP256_DEFAULT_DOMAIN`] | 187 bits |
//! | `BHP512` | `BHP512<N>` = `BHP<N, 6, 43>` | [`BHP512_DEFAULT_DOMAIN`] | 187 bits |
//! | `BHP768` | `BHP768<N>` = `BHP<N, 15, 23>` | [`BHP768_DEFAULT_DOMAIN`] | 187 bits |
//! | `BHP1024` | `BHP1024<N>` = `BHP<N, 8, 54>` | [`BHP1024_DEFAULT_DOMAIN`] | 187 bits |
//! | `Pedersen64` | `Pedersen64<N>` = `Pedersen<N, 64>` | [`PEDERSEN64_DEFAULT_DOMAIN`] | none |
//! | `Pedersen128` | `Pedersen128<N>` = `Pedersen<N, 128>` | [`PEDERSEN128_DEFAULT_DOMAIN`] | none |
//! | `Poseidon2` | `Poseidon2<N>` = `Poseidon<N, 2>` | [`POSEIDON2_DEFAULT_DOMAIN`] | 251 bits |
//! | `Poseidon4` | `Poseidon4<N>` = `Poseidon<N, 4>` | [`POSEIDON4_DEFAULT_DOMAIN`] | 251 bits |
//! | `Poseidon8` | `Poseidon8<N>` = `Poseidon<N, 8>` | [`POSEIDON8_DEFAULT_DOMAIN`] | 251 bits |
//!
//! # Method map
//!
//! | JS method | Rust equivalent |
//! |-----------|-----------------|
//! | `new X()` | [`bhp256`] … [`bhp1024`], [`pedersen64`], [`pedersen128`], [`poseidon2`] … [`poseidon8`] |
//! | `setup(domain)` | `X::setup(domain)` — BHP and Poseidon are fallible, Pedersen is not |
//! | `hash(input)` | `Hash::hash` |
//! | `hashMany(input, n)` | `HashMany::hash_many` (Poseidon only, returns `Vec<Field>`) |
//! | `hashToScalar(input)` | `HashToScalar::hash_to_scalar` (Poseidon only) |
//! | `hashToGroup(input)` — Poseidon | `HashToGroup::hash_to_group` |
//! | `hashToGroup(input)` — BHP | [`BhpToGroup::hash_to_group`], i.e. `HashUncompressed::hash_uncompressed` |
//! | `commit(input, r)` | `Commit::commit` |
//! | `commitToGroup(input, r)` | [`BhpToGroup::commit_to_group`] / [`PedersenToGroup::commit_to_group`], i.e. `CommitUncompressed::commit_uncompressed` |
//!
//! # The compressed / uncompressed split
//!
//! `hash` and `commit` return the **x-coordinate** of the group result; the JS
//! `…ToGroup` methods return the point itself. They are the same computation:
//! `hash(input) == hashToGroup(input).to_x_coordinate()`. BHP and Pedersen do
//! **not** implement `HashToGroup` — snarkVM calls the point-valued variant
//! `HashUncompressed`, and the JS binding's `hashToGroup` maps onto it. Reaching
//! for `HashToGroup` on a BHP hasher does not compile; use [`BhpToGroup`].
//!
//! Pedersen is asymmetric on purpose: snarkVM has `HashUncompressed` for
//! `Pedersen64`/`Pedersen128` too, but the JS class exposes no `hashToGroup`
//! for them. Port code that relied on it through `HashUncompressed` directly.
//!
//! # Traps the page does not mention
//!
//! * **BHP hashes the empty input to the identity.** The input is chunked, and
//!   an empty slice produces no chunk, so `hash(&[])` returns `0field` and
//!   `hash_to_group(&[])` returns `0group` — not a hash of the empty string. Do
//!   not read "empty" as "zero bits hashed".
//! * **Poseidon's `hashToGroup` rejects an empty input** ("Input to hash to
//!   group cannot be empty"), because it maps two field elements onto the
//!   curve. `hash` and `hashMany` accept it.
//! * **Pedersen input size is a hard bound, not a chunking hint.**
//!   `Pedersen64` accepts up to 64 bits and pads shorter inputs with zeros; a
//!   65th bit is an error. BHP chunks arbitrarily long input instead.
//! * **BHP domains are capped at 187 bits** (23 ASCII characters) because 64
//!   bits of the data field are reserved for the length. Pedersen has no budget
//!   check at all; Poseidon's cap is the full data field.
//! * **Setup is not free.** BHP setup derives hundreds of curve points and
//!   Poseidon setup builds its round constants, so build a hasher once and
//!   reuse it; the constructors here are one-shot, not cached.

use anyhow::{Context, Result};
use snarkvm::console::algorithms::{
    BHP, BHP256, BHP512, BHP768, BHP1024, CommitUncompressed, HashUncompressed, Pedersen,
    Pedersen64, Pedersen128, Poseidon2, Poseidon4, Poseidon8,
};
use snarkvm::prelude::{Group, Network, Scalar};

/// Domain separator the JS `BHP256` constructor passes to `setup`.
pub const BHP256_DEFAULT_DOMAIN: &str = "AleoBHP256";
/// Domain separator the JS `BHP512` constructor passes to `setup`.
pub const BHP512_DEFAULT_DOMAIN: &str = "AleoBHP512";
/// Domain separator the JS `BHP768` constructor passes to `setup`.
pub const BHP768_DEFAULT_DOMAIN: &str = "AleoBHP768";
/// Domain separator the JS `BHP1024` constructor passes to `setup`.
pub const BHP1024_DEFAULT_DOMAIN: &str = "AleoBHP1024";
/// Domain separator the JS `Pedersen64` constructor passes to `setup`.
pub const PEDERSEN64_DEFAULT_DOMAIN: &str = "AleoPedersen64";
/// Domain separator the JS `Pedersen128` constructor passes to `setup`.
pub const PEDERSEN128_DEFAULT_DOMAIN: &str = "AleoPedersen128";
/// Domain separator the JS `Poseidon2` constructor passes to `setup`.
pub const POSEIDON2_DEFAULT_DOMAIN: &str = "AleoPoseidon2";
/// Domain separator the JS `Poseidon4` constructor passes to `setup`.
pub const POSEIDON4_DEFAULT_DOMAIN: &str = "AleoPoseidon4";
/// Domain separator the JS `Poseidon8` constructor passes to `setup`.
pub const POSEIDON8_DEFAULT_DOMAIN: &str = "AleoPoseidon8";

/// A `BHP256` hasher with the JS default domain — `new BHP256()`.
///
/// # Errors
///
/// Setup only fails if the domain exceeds the data-field budget; the literal
/// used here is fixed, so in practice this cannot fail.
pub fn bhp256<N: Network>() -> Result<BHP256<N>> {
    BHP256::<N>::setup(BHP256_DEFAULT_DOMAIN).context("Failed to set up BHP256")
}

/// A `BHP512` hasher with the JS default domain — `new BHP512()`.
///
/// # Errors
///
/// As [`bhp256`].
pub fn bhp512<N: Network>() -> Result<BHP512<N>> {
    BHP512::<N>::setup(BHP512_DEFAULT_DOMAIN).context("Failed to set up BHP512")
}

/// A `BHP768` hasher with the JS default domain — `new BHP768()`.
///
/// # Errors
///
/// As [`bhp256`].
pub fn bhp768<N: Network>() -> Result<BHP768<N>> {
    BHP768::<N>::setup(BHP768_DEFAULT_DOMAIN).context("Failed to set up BHP768")
}

/// A `BHP1024` hasher with the JS default domain — `new BHP1024()`.
///
/// # Errors
///
/// As [`bhp256`].
pub fn bhp1024<N: Network>() -> Result<BHP1024<N>> {
    BHP1024::<N>::setup(BHP1024_DEFAULT_DOMAIN).context("Failed to set up BHP1024")
}

/// A `Pedersen64` hasher with the JS default domain — `new Pedersen64()`.
///
/// Pedersen setup is infallible: it derives its base window from the domain
/// through `Blake2Xs` and has no length budget to check.
pub fn pedersen64<N: Network>() -> Pedersen64<N> {
    Pedersen64::<N>::setup(PEDERSEN64_DEFAULT_DOMAIN)
}

/// A `Pedersen128` hasher with the JS default domain — `new Pedersen128()`.
pub fn pedersen128<N: Network>() -> Pedersen128<N> {
    Pedersen128::<N>::setup(PEDERSEN128_DEFAULT_DOMAIN)
}

/// A `Poseidon2` hasher with the JS default domain — `new Poseidon2()`.
///
/// # Errors
///
/// Fails only if the domain exceeds the data-field budget.
pub fn poseidon2<N: Network>() -> Result<Poseidon2<N>> {
    Poseidon2::<N>::setup(POSEIDON2_DEFAULT_DOMAIN).context("Failed to set up Poseidon2")
}

/// A `Poseidon4` hasher with the JS default domain — `new Poseidon4()`.
///
/// # Errors
///
/// As [`poseidon2`].
pub fn poseidon4<N: Network>() -> Result<Poseidon4<N>> {
    Poseidon4::<N>::setup(POSEIDON4_DEFAULT_DOMAIN).context("Failed to set up Poseidon4")
}

/// A `Poseidon8` hasher with the JS default domain — `new Poseidon8()`.
///
/// # Errors
///
/// As [`poseidon2`].
pub fn poseidon8<N: Network>() -> Result<Poseidon8<N>> {
    Poseidon8::<N>::setup(POSEIDON8_DEFAULT_DOMAIN).context("Failed to set up Poseidon8")
}

/// The JS `hashToGroup` / `commitToGroup` methods on the BHP hashers.
///
/// Both delegate to snarkVM's *uncompressed* variants. They live on an
/// extension trait rather than on the hasher so that callers who imported
/// `HashToGroup` for Poseidon do not get an ambiguous method.
pub trait BhpToGroup<N: Network> {
    /// BHP hash as a group element — the JS `hashToGroup(input)`.
    ///
    /// # Errors
    ///
    /// Surfaces snarkVM's hashing errors; the empty input is not one of them
    /// (it hashes to the identity).
    fn hash_to_group(&self, input: &[bool]) -> Result<Group<N>>;

    /// BHP commitment as a group element — the JS `commitToGroup(input, r)`.
    ///
    /// # Errors
    ///
    /// As [`BhpToGroup::hash_to_group`].
    fn commit_to_group(&self, input: &[bool], randomizer: &Scalar<N>) -> Result<Group<N>>;
}

impl<N: Network, const NUM_WINDOWS: u8, const WINDOW_SIZE: u8> BhpToGroup<N>
    for BHP<N, NUM_WINDOWS, WINDOW_SIZE>
{
    fn hash_to_group(&self, input: &[bool]) -> Result<Group<N>> {
        HashUncompressed::hash_uncompressed(self, input)
    }

    fn commit_to_group(&self, input: &[bool], randomizer: &Scalar<N>) -> Result<Group<N>> {
        CommitUncompressed::commit_uncompressed(self, input, randomizer)
    }
}

/// The JS `commitToGroup` method on the Pedersen hashers.
///
/// There is deliberately no `hash_to_group` here: the JS `Pedersen64` /
/// `Pedersen128` classes do not expose one, even though snarkVM has
/// `HashUncompressed` for them.
pub trait PedersenToGroup<N: Network> {
    /// Pedersen commitment as a group element — the JS
    /// `commitToGroup(input, randomizer)`.
    ///
    /// # Errors
    ///
    /// Fails when the input is longer than the hasher's bit width.
    fn commit_to_group(&self, input: &[bool], randomizer: &Scalar<N>) -> Result<Group<N>>;
}

impl<N: Network, const NUM_BITS: u8> PedersenToGroup<N> for Pedersen<N, NUM_BITS> {
    fn commit_to_group(&self, input: &[bool], randomizer: &Scalar<N>) -> Result<Group<N>> {
        CommitUncompressed::commit_uncompressed(self, input, randomizer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm::prelude::{
        Commit, Field, FromStr, Hash, HashMany, HashToGroup, HashToScalar, TestnetV0, ToBits, U64,
        U128, Zero,
    };

    type N = TestnetV0;

    /// The scalar the upstream wasm tests use, so the regression pins below line
    /// up with the published vector.
    const RANDOMIZER: &str =
        "1774157567936692047646837016039369013254365378639847034769080448564598011047scalar";

    fn bits64() -> Vec<bool> {
        U64::<N>::new(0x0123_4567_89AB_CDEF).to_bits_le()
    }

    fn fields() -> Vec<Field<N>> {
        [1u64, 2, 3].into_iter().map(Field::<N>::from_u64).collect()
    }

    fn randomizer() -> Scalar<N> {
        Scalar::<N>::from_str(RANDOMIZER).unwrap()
    }

    #[test]
    fn defaults_match_the_network_hashers() {
        let bits = bits64();

        assert_eq!(
            bhp256::<N>().unwrap().hash(&bits).unwrap(),
            N::hash_bhp256(&bits).unwrap()
        );
        assert_eq!(
            bhp512::<N>().unwrap().hash(&bits).unwrap(),
            N::hash_bhp512(&bits).unwrap()
        );
        assert_eq!(
            bhp768::<N>().unwrap().hash(&bits).unwrap(),
            N::hash_bhp768(&bits).unwrap()
        );
        assert_eq!(
            bhp1024::<N>().unwrap().hash(&bits).unwrap(),
            N::hash_bhp1024(&bits).unwrap()
        );
    }

    #[test]
    fn poseidon_defaults_match_the_network_hashers() {
        let input = fields();

        assert_eq!(
            poseidon2::<N>().unwrap().hash(&input).unwrap(),
            N::hash_psd2(&input).unwrap()
        );
        assert_eq!(
            poseidon4::<N>().unwrap().hash(&input).unwrap(),
            N::hash_psd4(&input).unwrap()
        );
        assert_eq!(
            poseidon8::<N>().unwrap().hash(&input).unwrap(),
            N::hash_psd8(&input).unwrap()
        );

        assert_eq!(
            poseidon2::<N>().unwrap().hash_many(&input, 3),
            N::hash_many_psd2(&input, 3)
        );
        assert_eq!(
            poseidon4::<N>().unwrap().hash_many(&input, 3),
            N::hash_many_psd4(&input, 3)
        );
        assert_eq!(
            poseidon8::<N>().unwrap().hash_many(&input, 3),
            N::hash_many_psd8(&input, 3)
        );
    }

    /// `hash` is the compressed form of `hashToGroup`, for both families.
    #[test]
    fn compressed_and_uncompressed_agree() {
        let bits = bits64();
        let r = randomizer();

        let bhp = bhp256::<N>().unwrap();
        assert_eq!(
            bhp.hash(&bits).unwrap(),
            bhp.hash_to_group(&bits).unwrap().to_x_coordinate()
        );
        assert_eq!(
            bhp.commit(&bits, &r).unwrap(),
            bhp.commit_to_group(&bits, &r).unwrap().to_x_coordinate()
        );

        let pedersen = pedersen64::<N>();
        assert_eq!(
            pedersen.hash(&bits).unwrap(),
            HashUncompressed::hash_uncompressed(&pedersen, &bits).unwrap().to_x_coordinate()
        );
        assert_eq!(
            pedersen.commit(&bits, &r).unwrap(),
            pedersen.commit_to_group(&bits, &r).unwrap().to_x_coordinate()
        );
    }

    /// Poseidon's group hash is the sum of two `MapToGroup` images, so it is not
    /// the x-coordinate of `hash` — the two must be compared separately.
    #[test]
    fn poseidon_hash_to_group_is_not_a_compressed_hash() {
        let input = fields();
        let hasher = poseidon2::<N>().unwrap();

        let group = hasher.hash_to_group(&input).unwrap();
        assert_ne!(group.to_x_coordinate(), hasher.hash(&input).unwrap());
        // Its scalar projection is the lossy cast of the base-field hash.
        assert_eq!(
            hasher.hash_to_scalar(&input).unwrap(),
            Scalar::<N>::from_field_lossy(&hasher.hash(&input).unwrap())
        );
        assert_ne!(
            hasher.hash_to_scalar(&input).unwrap(),
            Scalar::<N>::from_field_lossy(&group.to_x_coordinate())
        );
    }

    /// The trap the page does not mention: no chunk means no hashing.
    #[test]
    fn bhp_hashes_the_empty_input_to_the_identity() {
        let empty_bits: &[bool] = &[];
        for hash in [
            bhp256::<N>().unwrap().hash(empty_bits).unwrap(),
            bhp512::<N>().unwrap().hash(empty_bits).unwrap(),
            bhp768::<N>().unwrap().hash(empty_bits).unwrap(),
            bhp1024::<N>().unwrap().hash(empty_bits).unwrap(),
        ] {
            assert!(hash.is_zero());
        }
        assert!(bhp256::<N>().unwrap().hash_to_group(empty_bits).unwrap().is_zero());
    }

    #[test]
    fn poseidon_hash_to_group_rejects_an_empty_input() {
        let empty_fields: &[Field<N>] = &[];
        let error = poseidon2::<N>().unwrap().hash_to_group(empty_fields).unwrap_err();
        assert!(error.to_string().contains("cannot be empty"), "{error}");
        // `hash` itself is fine.
        assert!(!poseidon2::<N>().unwrap().hash(empty_fields).unwrap().is_zero());
    }

    /// Pedersen pads short input and rejects anything past its width.
    #[test]
    fn pedersen_enforces_its_input_width() {
        assert!(pedersen64::<N>().hash(&bits64()).is_ok());
        assert!(pedersen128::<N>().hash(&U128::<N>::new(7).to_bits_le()).is_ok());

        let error = pedersen64::<N>().hash(&[true; 65]).unwrap_err();
        assert!(error.to_string().contains("Invalid input size"), "{error}");
        assert!(pedersen128::<N>().hash(&[true; 128]).is_ok());
        assert!(pedersen128::<N>().hash(&[true; 129]).is_err());
    }

    #[test]
    fn a_custom_domain_changes_the_hash() {
        let bits = bits64();
        let custom = BHP256::<N>::setup("AleoRustSdkTest").unwrap();
        assert_ne!(
            custom.hash(&bits).unwrap(),
            bhp256::<N>().unwrap().hash(&bits).unwrap()
        );
    }

    /// The BHP domain budget is the data field minus the 64-bit length prefix.
    #[test]
    fn bhp_rejects_an_oversized_domain() {
        assert!(BHP256::<N>::setup(&"a".repeat(23)).is_ok());
        let error = BHP256::<N>::setup(&"a".repeat(24)).unwrap_err();
        assert!(
            error.to_string().contains("Domain cannot exceed"),
            "{error}"
        );
    }

    /// Regression pins: the exact values the default domains produce, so a
    /// changed domain shows up as a failing test rather than as silently
    /// different hashes.
    #[test]
    fn default_domain_outputs_are_pinned() {
        let bits = bits64();
        let r = randomizer();
        let input = fields();

        assert_eq!(
            bhp256::<N>().unwrap().hash(&bits).unwrap().to_string(),
            "3194824410286792757902267099566195612004897031492725883476322454715525302782field"
        );
        assert_eq!(
            pedersen64::<N>().hash(&bits).unwrap().to_string(),
            "7680087407385863257448002213140359357374166807559864344142757463460174142564field"
        );
        assert_eq!(
            pedersen64::<N>().commit(&bits, &r).unwrap().to_string(),
            "1638201152822110782601963251006213092771363737227311484896351401476057114709field"
        );
        assert_eq!(
            poseidon2::<N>().unwrap().hash(&input).unwrap().to_string(),
            "7200107266741300576287128422632566638252611441475937708605571633688427921904field"
        );
        assert_eq!(
            poseidon2::<N>().unwrap().hash_to_scalar(&input).unwrap().to_string(),
            "1772353083742103915807238500350320957630580910274036269255997383317499970032scalar"
        );
    }
}
