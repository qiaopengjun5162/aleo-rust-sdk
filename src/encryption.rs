//! JS SDK `EncryptionToolkit` parity.
//!
//! The JS `EncryptionToolkit` is a static class of eight helpers for record,
//! transition, and sender decryption. Three of them already exist on
//! [`AleoAccount`](crate::account::AleoAccount); this module adds the rest.
//!
//! | JS `EncryptionToolkit` | Rust equivalent | Status |
//! |------------------------|-----------------|--------|
//! | `generateTvk(viewKey, tpk)` | `AleoAccount::generate_transition_view_key(tpk)` | existing |
//! | `generateRecordViewKey(viewKey, ct)` | `AleoAccount::generate_record_view_key(ct)` | existing |
//! | `decryptOwnedRecords(viewKey, cts)` | `AleoAccount::decrypt_records(cts)` | existing, **fail-fast** |
//! | `decryptRecordWithRVk(rvk, ct)` | [`decrypt_record_with_rvk`] | **added** |
//! | `decryptTransitionWithVk(t, tvk)` | [`decrypt_transition_with_tvk`] | **added** |
//! | `checkOwnedRecords(viewKey, cts)` | [`owned_records`] | **added** |
//! | `decryptSender(viewKey, record, ct)` | [`decrypt_sender`] | **added** |
//! | `decryptSenderWithRvk(rvk, ct)` | [`decrypt_sender_with_rvk`] | **added** |
//!
//! # What the JS class does that snarkVM already did
//!
//! The upstream binding reimplements record decryption by hand: it counts
//! randomizers, hashes them with `hash_many_psd8`, subtracts them field by
//! field, and rebuilds the record. snarkVM 4.12 exposes that as
//! [`Record::decrypt_symmetric_unchecked`], so [`decrypt_record_with_rvk`] is a
//! thin wrapper instead of a second copy of the algorithm.
//!
//! # These functions do not authenticate anything
//!
//! * [`decrypt_record_with_rvk`] is **unchecked**: it never verifies that the
//!   key belongs to the record owner. A wrong key yields garbage or a parse
//!   error, not a rejected record. Use `Record::decrypt(&view_key)` when the
//!   ownership check matters.
//! * [`decrypt_sender_with_rvk`] inverts the on-chain formula
//!   `sender_ciphertext = signer_x + hash_psd4([encryption_domain, rvk, 1])`.
//!   Any field is a valid ciphertext, so a wrong key produces some address
//!   rather than an error — compare it against an expected signer when the
//!   sender identity is security-relevant.
//! * [`decrypt_transition_with_tvk`] does not verify the transition view key,
//!   and only rewrites **private plaintext** inputs and outputs. Record inputs
//!   and record outputs carry ciphertexts, not field-level ciphertexts, so they
//!   are left alone (the JS binding behaves identically).
//!
//! # Difference from `decryptOwnedRecords`
//!
//! JS decrypts every record in parallel and silently drops the ones that fail,
//! so its output length can be shorter than its input. [`AleoAccount::decrypt_records`]
//! is fail-fast by design. To reproduce the JS behaviour exactly, filter first
//! with [`owned_records`] and then decrypt each survivor, or call
//! [`decrypt_record_with_rvk`] per item and discard the errors.
//!
//! [`AleoAccount::decrypt_records`]: crate::account::AleoAccount::decrypt_records
//! [`Record::decrypt_symmetric_unchecked`]: snarkvm::prelude::Record::decrypt_symmetric_unchecked

use anyhow::{Context, Result};
use snarkvm::console::program::compute_function_id;
use snarkvm::prelude::{
    Address, Ciphertext, Field, FromField, Input, Network, One, Output, Plaintext, Record,
    Transition, U16, ViewKey,
};

/// Decrypt a record ciphertext with a record view key — the JS
/// `decryptRecordWithRVk(record_vk, recordCiphertext)`.
///
/// The record view key is `(nonce · view_key).x`; derive it with
/// [`AleoAccount::generate_record_view_key`] so it can be shared without
/// handing over the account-wide view key.
///
/// # Errors
///
/// Fails when the ciphertext cannot be parsed with the given key. This is an
/// **unchecked** decryption — see the module docs.
///
/// [`AleoAccount::generate_record_view_key`]: crate::account::AleoAccount::generate_record_view_key
pub fn decrypt_record_with_rvk<N: Network>(
    record_view_key: &Field<N>,
    ciphertext: &Record<N, Ciphertext<N>>,
) -> Result<Record<N, Plaintext<N>>> {
    ciphertext
        .decrypt_symmetric_unchecked(record_view_key)
        .map_err(|e| anyhow::anyhow!("Record cannot be decrypted with this record view key: {e}"))
}

/// Recover the sender address from a sender ciphertext and a record view key —
/// the JS `decryptSenderWithRvk(record_view_key, sender_ciphertext)`.
///
/// The chain stores `sender_x + hash_psd4([encryption_domain, rvk, 1])`, so this
/// subtracts the same randomizer and reads the result back as a group point.
///
/// # Errors
///
/// Fails when the decrypted x-coordinate is not a valid address (i.e. the key
/// did not match the record that produced the ciphertext).
pub fn decrypt_sender_with_rvk<N: Network>(
    record_view_key: &Field<N>,
    sender_ciphertext: &Field<N>,
) -> Result<Address<N>> {
    let randomizer = N::hash_psd4(&[N::encryption_domain(), *record_view_key, Field::one()])
        .context("Failed to compute the sender ciphertext randomizer")?;
    let sender_x_coordinate = *sender_ciphertext - randomizer;
    Address::from_field(&sender_x_coordinate)
        .map_err(|e| anyhow::anyhow!("Failed to recover the sender address: {e}"))
}

/// Recover the sender address from a decrypted record and its sender ciphertext
/// — the JS `decryptSender(viewKey, record, sender_ciphertext)`.
///
/// Convenience wrapper over [`decrypt_sender_with_rvk`] that derives the record
/// view key as `(record.nonce · view_key).x`. A sender ciphertext appears on
/// every private record output, so this answers "who sent me this?" without
/// scanning the whole transaction.
///
/// # Errors
///
/// Fails when the address cannot be recovered from the ciphertext.
pub fn decrypt_sender<N: Network>(
    view_key: &ViewKey<N>,
    record: &Record<N, Plaintext<N>>,
    sender_ciphertext: &Field<N>,
) -> Result<Address<N>> {
    let record_view_key = (*record.nonce() * **view_key).to_x_coordinate();
    decrypt_sender_with_rvk(&record_view_key, sender_ciphertext)
}

/// Decrypt the private inputs and outputs of a transition with a transition view
/// key — the JS `decryptTransitionWithVk(transition, transition_vk)`.
///
/// Each private input at index `i` is encrypted under
/// `hash_psd4([function_id, tvk, i])`, and each private output at index `j` under
/// `hash_psd4([function_id, tvk, num_inputs + j])`. Decrypted values come back
/// as [`Input::Public`] / [`Output::Public`], matching the JS binding: the
/// variant says "this value is now readable", not "this was a public value on
/// chain".
///
/// The returned transition therefore has a **different ID** than the on-chain
/// one (the ID covers the function tree). Treat it as a readable view of the
/// transition, never as something to broadcast.
///
/// # Errors
///
/// Fails when a private ciphertext cannot be decrypted with the derived key, or
/// when the transition cannot be rebuilt.
pub fn decrypt_transition_with_tvk<N: Network>(
    transition: &Transition<N>,
    transition_view_key: &Field<N>,
) -> Result<Transition<N>> {
    let function_id = compute_function_id(
        &U16::new(N::ID),
        transition.program_id(),
        transition.function_name(),
    )
    .context("Failed to compute the transition function ID")?;

    let num_inputs = transition.inputs().len();
    let mut decrypted_inputs = Vec::with_capacity(num_inputs);

    for (index, input) in transition.inputs().iter().enumerate() {
        decrypted_inputs.push(match input {
            Input::Private(input_id, Some(ciphertext)) => {
                let view_key = input_view_key::<N>(&function_id, transition_view_key, index)?;
                let plaintext = ciphertext.decrypt_symmetric(view_key).map_err(|e| {
                    anyhow::anyhow!("Transition input #{index} cannot be decrypted: {e}")
                })?;
                Input::Public(*input_id, Some(plaintext))
            }
            other => other.clone(),
        });
    }

    let outputs = transition.outputs();
    let mut decrypted_outputs = Vec::with_capacity(outputs.len());

    for (index, output) in outputs.iter().enumerate() {
        decrypted_outputs.push(match output {
            Output::Private(output_id, Some(ciphertext)) => {
                // Outputs are keyed after every input, not after the previous output.
                let view_key =
                    input_view_key::<N>(&function_id, transition_view_key, num_inputs + index)?;
                let plaintext = ciphertext.decrypt_symmetric(view_key).map_err(|e| {
                    anyhow::anyhow!("Transition output #{index} cannot be decrypted: {e}")
                })?;
                Output::Public(*output_id, Some(plaintext))
            }
            other => other.clone(),
        });
    }

    Transition::new(
        *transition.program_id(),
        *transition.function_name(),
        decrypted_inputs,
        decrypted_outputs,
        *transition.tpk(),
        *transition.tcm(),
        *transition.scm(),
    )
    .context("Failed to rebuild the decrypted transition")
}

/// Per-input/output view key: `hash_psd4([function_id, tvk, index])`.
///
/// Shared by inputs and outputs because the index space is contiguous — outputs
/// start at `num_inputs`.
fn input_view_key<N: Network>(
    function_id: &Field<N>,
    transition_view_key: &Field<N>,
    index: usize,
) -> Result<Field<N>> {
    let index = u16::try_from(index).context("Transition index exceeds u16")?;
    N::hash_psd4(&[*function_id, *transition_view_key, Field::from_u16(index)])
        .context("Failed to derive the transition view key for this index")
}

/// Return the ciphertexts owned by `view_key` — the JS
/// `checkOwnedRecords(viewKey, records)`.
///
/// The check decrypts only the record owner, not the data entries, so it is
/// cheap enough to run over a whole scan result. References are returned to keep
/// the operation allocation-free.
pub fn owned_records<'a, N>(
    view_key: &ViewKey<N>,
    records: impl IntoIterator<Item = &'a Record<N, Ciphertext<N>>>,
) -> Vec<&'a Record<N, Ciphertext<N>>>
where
    N: Network + 'a,
{
    records.into_iter().filter(|record| record.is_owner(view_key)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use indexmap::IndexMap;
    use snarkvm::prelude::{
        Entry, FromStr, Identifier, Owner, Plaintext as SnarkvmPlaintext, PrivateKey, ProgramID,
        Scalar, TestRng, TestnetV0, U8, Uniform, Zero,
    };

    type N = TestnetV0;

    /// A `credits.aleo`-shaped record owned by `address`, plus the randomizer its
    /// nonce was derived from.
    ///
    /// snarkVM requires `nonce == g_scalar_multiply(randomizer)` before it will
    /// encrypt a record, so the two must be produced together.
    fn record_owned_by(
        address: Address<N>,
        rng: &mut TestRng,
    ) -> (Record<N, SnarkvmPlaintext<N>>, Scalar<N>) {
        let mut data = IndexMap::new();
        data.insert(
            Identifier::from_str("microcredits").unwrap(),
            Entry::Private(SnarkvmPlaintext::from_str("1000000u64").unwrap()),
        );
        data.insert(
            Identifier::from_str("sender").unwrap(),
            Entry::Private(SnarkvmPlaintext::from_str(&address.to_string()).unwrap()),
        );
        data.insert(
            Identifier::from_str("memo").unwrap(),
            Entry::Public(SnarkvmPlaintext::from_str("5field").unwrap()),
        );

        let randomizer = Scalar::<N>::rand(rng);
        let nonce = N::g_scalar_multiply(&randomizer);
        let record = Record::<N, SnarkvmPlaintext<N>>::from_plaintext(
            Owner::<N, SnarkvmPlaintext<N>>::Public(address),
            data,
            nonce,
            U8::new(0),
        )
        .unwrap();

        (record, randomizer)
    }

    fn signer_address(rng: &mut TestRng) -> Address<N> {
        let private_key = PrivateKey::new(rng).unwrap();
        Address::<N>::try_from(&ViewKey::try_from(&private_key).unwrap()).unwrap()
    }

    #[test]
    fn record_view_key_round_trips_both_decryption_paths() {
        let mut rng = TestRng::default();
        let private_key = PrivateKey::new(&mut rng).unwrap();
        let view_key = ViewKey::try_from(&private_key).unwrap();
        let address = Address::<N>::try_from(&view_key).unwrap();

        let (record, randomizer) = record_owned_by(address, &mut rng);
        let (ciphertext, record_view_key) = record.encrypt_symmetric(randomizer).unwrap();

        // The record view key path and the view key path must agree.
        assert_eq!(
            decrypt_record_with_rvk(&record_view_key, &ciphertext).unwrap(),
            record
        );
        assert_eq!(ciphertext.decrypt(&view_key).unwrap(), record);
    }

    #[test]
    fn record_decryption_with_a_wrong_view_key_is_not_a_record() {
        let mut rng = TestRng::default();
        let private_key = PrivateKey::new(&mut rng).unwrap();
        let view_key = ViewKey::try_from(&private_key).unwrap();

        let (record, randomizer) =
            record_owned_by(Address::<N>::try_from(&view_key).unwrap(), &mut rng);
        let (ciphertext, record_view_key) = record.encrypt_symmetric(randomizer).unwrap();

        let wrong = record_view_key + Field::<N>::one();
        // Unchecked: the failure surfaces as a parse error, not an ownership check.
        assert!(decrypt_record_with_rvk(&wrong, &ciphertext).is_err());
    }

    /// The sender ciphertext formula is the on-chain one, so snarkVM's own
    /// `Output::decrypt_sender_ciphertext` must recover the same address.
    #[test]
    fn sender_decryption_agrees_with_snarkvm() {
        let mut rng = TestRng::default();
        let owner_key = PrivateKey::new(&mut rng).unwrap();
        let owner_view_key = ViewKey::try_from(&owner_key).unwrap();

        let (record, randomizer) =
            record_owned_by(Address::<N>::try_from(&owner_view_key).unwrap(), &mut rng);
        let (record_ciphertext, record_view_key) = record.encrypt_symmetric(randomizer).unwrap();

        // Encrypt the signer address exactly as the chain does.
        let signer = signer_address(&mut rng);
        let randomizer =
            N::hash_psd4(&[N::encryption_domain(), record_view_key, Field::<N>::one()]).unwrap();
        let sender_ciphertext = signer.to_x_coordinate() + randomizer;

        assert_eq!(
            decrypt_sender_with_rvk(&record_view_key, &sender_ciphertext).unwrap(),
            signer
        );
        assert_eq!(
            decrypt_sender(&owner_view_key, &record, &sender_ciphertext).unwrap(),
            signer
        );

        // Oracle: snarkVM derives the record view key from the ciphertext + view
        // key itself and inverts the same formula.
        let output = Output::<N>::Record(
            Field::<N>::zero(),
            Field::<N>::zero(),
            Some(record_ciphertext),
            Some(sender_ciphertext),
        );
        assert_eq!(
            output.decrypt_sender_ciphertext(&owner_view_key).unwrap(),
            Some(signer)
        );
    }

    #[test]
    fn a_foreign_record_view_key_does_not_recover_the_signer() {
        let mut rng = TestRng::default();
        let owner_view_key = ViewKey::try_from(&PrivateKey::new(&mut rng).unwrap()).unwrap();

        let (record, randomizer) =
            record_owned_by(Address::<N>::try_from(&owner_view_key).unwrap(), &mut rng);
        let (_, record_view_key) = record.encrypt_symmetric(randomizer).unwrap();

        let signer = signer_address(&mut rng);
        let randomizer =
            N::hash_psd4(&[N::encryption_domain(), record_view_key, Field::one()]).unwrap();
        let sender_ciphertext = signer.to_x_coordinate() + randomizer;

        let foreign = record_view_key + Field::<N>::one();
        // Either an unrelated address comes back, or the x-coordinate is not a
        // valid address at all. Both are fine; recovering the signer is not.
        if let Ok(recovered) = decrypt_sender_with_rvk(&foreign, &sender_ciphertext) {
            assert_ne!(recovered, signer);
        }
    }

    /// Build a transition with one private input and one private output, plus a
    /// public input that must survive untouched.
    fn synthetic_transition(
        tvk: &Field<N>,
        rng: &mut TestRng,
    ) -> (Transition<N>, SnarkvmPlaintext<N>, SnarkvmPlaintext<N>) {
        let program_id = ProgramID::<N>::from_str("credits.aleo").unwrap();
        let function_name = Identifier::from_str("transfer_public").unwrap();
        let function_id =
            compute_function_id(&U16::new(N::ID), &program_id, &function_name).unwrap();

        let input_plaintext = SnarkvmPlaintext::from_str("1u64").unwrap();
        let output_plaintext = SnarkvmPlaintext::from_str("2u64").unwrap();
        let public_plaintext = SnarkvmPlaintext::from_str("3u64").unwrap();

        let input_key = input_view_key::<N>(&function_id, tvk, 0).unwrap();
        // Outputs start after every input, so this output is index 2.
        let output_key = input_view_key::<N>(&function_id, tvk, 2).unwrap();

        let inputs = vec![
            Input::Private(
                Field::<N>::zero(),
                Some(input_plaintext.encrypt_symmetric(input_key).unwrap()),
            ),
            Input::Public(Field::<N>::zero(), Some(public_plaintext)),
        ];
        let outputs = vec![Output::Private(
            Field::<N>::zero(),
            Some(output_plaintext.encrypt_symmetric(output_key).unwrap()),
        )];

        let tpk = N::g_scalar_multiply(&Scalar::<N>::rand(rng));
        let transition = Transition::new(
            program_id,
            function_name,
            inputs,
            outputs,
            tpk,
            Field::<N>::one(),
            Field::<N>::zero(),
        )
        .unwrap();

        (transition, input_plaintext, output_plaintext)
    }

    #[test]
    fn transition_decryption_rewrites_private_io_as_public() {
        let mut rng = TestRng::default();
        let tvk = N::g_scalar_multiply(&Scalar::<N>::rand(&mut rng)).to_x_coordinate();
        let (transition, input_plaintext, output_plaintext) = synthetic_transition(&tvk, &mut rng);

        let decrypted = decrypt_transition_with_tvk(&transition, &tvk).unwrap();

        assert_eq!(
            decrypted.inputs()[0],
            Input::Public(Field::<N>::zero(), Some(input_plaintext))
        );
        assert_eq!(
            decrypted.outputs()[0],
            Output::Public(Field::<N>::zero(), Some(output_plaintext))
        );
        // The public input still reads the same.
        assert!(matches!(decrypted.inputs()[1], Input::Public(_, Some(_))));
        // Only readable — the ID no longer matches the on-chain transition.
        assert_ne!(decrypted.id(), transition.id());
    }

    #[test]
    fn transition_decryption_with_a_wrong_key_fails() {
        let mut rng = TestRng::default();
        let tvk = N::g_scalar_multiply(&Scalar::<N>::rand(&mut rng)).to_x_coordinate();
        let (transition, _, _) = synthetic_transition(&tvk, &mut rng);

        let wrong = tvk + Field::<N>::one();
        assert!(decrypt_transition_with_tvk(&transition, &wrong).is_err());
    }

    #[test]
    fn owned_records_keeps_only_the_owners_ciphertexts() {
        let mut rng = TestRng::default();
        let ours = ViewKey::try_from(&PrivateKey::new(&mut rng).unwrap()).unwrap();
        let theirs = ViewKey::try_from(&PrivateKey::new(&mut rng).unwrap()).unwrap();

        let (our_record, our_randomizer) =
            record_owned_by(Address::<N>::try_from(&ours).unwrap(), &mut rng);
        let mine = our_record.encrypt_symmetric(our_randomizer).unwrap().0;

        let (their_record, their_randomizer) =
            record_owned_by(Address::<N>::try_from(&theirs).unwrap(), &mut rng);
        let other = their_record.encrypt_symmetric(their_randomizer).unwrap().0;

        let all = vec![mine.clone(), other];
        let owned = owned_records(&ours, &all);
        assert_eq!(owned.len(), 1);
        assert_eq!(owned[0], &mine);
    }
}
