// KILT Blockchain – https://botlabs.org
// Copyright (C) 2019-2021 BOTLabs GmbH

// The KILT Blockchain is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The KILT Blockchain is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// If you feel like getting in touch with us, you can do so at info@botlabs.org

use std::convert::TryFrom;

use frame_support::{assert_noop, assert_ok};
use sp_core::Pair;
use sp_std::collections::btree_set::BTreeSet;

use codec::Encode;

use crate::{self as did, mock::*};

// submit_did_create_operation

#[test]
fn check_successful_simple_ed25519_creation() {
	let auth_key = get_ed25519_authentication_key(true);
	let operation =
		generate_base_did_creation_operation(ALICE_DID, did::PublicVerificationKey::from(auth_key.public()));

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().build();

	ext.execute_with(|| {
		assert_ok!(Did::submit_did_create_operation(
			Origin::signed(DEFAULT_ACCOUNT),
			operation.clone(),
			did::DidSignature::from(signature),
		));
	});

	let stored_did = ext.execute_with(|| Did::get_did(ALICE_DID).expect("ALICE_DID should be present on chain."));
	assert_eq!(stored_did.auth_key, operation.new_auth_key);
	assert_eq!(stored_did.key_agreement_key, operation.new_key_agreement_key);
	assert_eq!(stored_did.delegation_key, operation.new_delegation_key);
	assert_eq!(stored_did.attestation_key, operation.new_attestation_key);
	assert_eq!(
		stored_did.verification_keys,
		<BTreeSet<did::PublicVerificationKey>>::new()
	);
	assert_eq!(stored_did.endpoint_url, operation.new_endpoint_url);
	assert_eq!(stored_did.last_tx_counter, 0u64);
}

#[test]
fn check_successful_simple_sr25519_creation() {
	let auth_key = get_sr25519_authentication_key(true);
	let operation =
		generate_base_did_creation_operation(ALICE_DID, did::PublicVerificationKey::from(auth_key.public()));

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().build();

	ext.execute_with(|| {
		assert_ok!(Did::submit_did_create_operation(
			Origin::signed(DEFAULT_ACCOUNT),
			operation.clone(),
			did::DidSignature::from(signature),
		));
	});

	let stored_did = ext.execute_with(|| Did::get_did(ALICE_DID).expect("ALICE_DID should be present on chain."));
	assert_eq!(stored_did.auth_key, operation.new_auth_key);
	assert_eq!(stored_did.key_agreement_key, operation.new_key_agreement_key);
	assert_eq!(stored_did.delegation_key, operation.new_delegation_key);
	assert_eq!(stored_did.attestation_key, operation.new_attestation_key);
	assert_eq!(
		stored_did.verification_keys,
		<BTreeSet<did::PublicVerificationKey>>::new()
	);
	assert_eq!(stored_did.endpoint_url, operation.new_endpoint_url);
	assert_eq!(stored_did.last_tx_counter, 0u64);
}

#[test]
fn check_successful_complete_creation() {
	let auth_key = get_sr25519_authentication_key(true);
	let del_key = get_sr25519_delegation_key(true);
	let att_key = get_ed25519_attestation_key(true);
	let new_url = did::Url::from(
		did::HttpUrl::try_from("https://new_kilt.io".as_bytes())
			.expect("https://new_kilt.io should not be considered an invalid HTTP URL."),
	);
	let mut operation =
		generate_base_did_creation_operation(ALICE_DID, did::PublicVerificationKey::from(auth_key.public()));
	operation.new_attestation_key = Some(did::PublicVerificationKey::from(att_key.public()));
	operation.new_delegation_key = Some(did::PublicVerificationKey::from(del_key.public()));
	operation.new_endpoint_url = Some(new_url);

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().build();

	ext.execute_with(|| {
		assert_ok!(Did::submit_did_create_operation(
			Origin::signed(DEFAULT_ACCOUNT),
			operation.clone(),
			did::DidSignature::from(signature),
		));
	});

	let stored_did = ext.execute_with(|| Did::get_did(ALICE_DID).expect("ALICE_DID should be present on chain."));
	assert_eq!(stored_did.auth_key, operation.new_auth_key);
	assert_eq!(stored_did.key_agreement_key, operation.new_key_agreement_key);
	assert_eq!(stored_did.delegation_key, operation.new_delegation_key);
	assert_eq!(stored_did.attestation_key, operation.new_attestation_key);
	assert_eq!(
		stored_did.verification_keys,
		<BTreeSet<did::PublicVerificationKey>>::new()
	);
	assert_eq!(stored_did.endpoint_url, operation.new_endpoint_url);
	assert_eq!(stored_did.last_tx_counter, 0u64);
}

#[test]
fn check_duplicate_did_creation() {
	let auth_key = get_sr25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation =
		generate_base_did_creation_operation(ALICE_DID, did::PublicVerificationKey::from(auth_key.public()));

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_create_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::DidAlreadyPresent
		);
	});
}

#[test]
fn check_invalid_signature_format_did_creation() {
	let auth_key = get_sr25519_authentication_key(true);
	// Using an Ed25519 key where an Sr25519 is expected
	let invalid_key = get_ed25519_authentication_key(true);
	// DID creation contains auth_key, but signature is generated using invalid_key
	let operation =
		generate_base_did_creation_operation(ALICE_DID, did::PublicVerificationKey::from(auth_key.public()));

	let signature = invalid_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_create_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidSignatureFormat
		);
	});
}

#[test]
fn check_invalid_signature_did_creation() {
	let auth_key = get_sr25519_authentication_key(true);
	let alternative_key = get_sr25519_authentication_key(false);
	let operation =
		generate_base_did_creation_operation(ALICE_DID, did::PublicVerificationKey::from(auth_key.public()));

	let signature = alternative_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_create_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidSignature
		);
	});
}

// submit_did_update_operation

#[test]
fn check_successful_complete_update() {
	let old_auth_key = get_ed25519_authentication_key(true);
	let new_auth_key = get_ed25519_authentication_key(false);
	let new_enc_key = get_x25519_encryption_key(false);
	let old_att_key = get_ed25519_attestation_key(true);
	let new_att_key = get_ed25519_attestation_key(false);
	let new_del_key = get_sr25519_attestation_key(true);
	let new_url = did::Url::from(
		did::HttpUrl::try_from("https://new_kilt.io".as_bytes())
			.expect("https://new_kilt.io should not be considered an invalid HTTP URL."),
	);

	let mut old_did_details = generate_base_did_details(did::PublicVerificationKey::from(old_auth_key.public()));
	old_did_details.attestation_key = Some(did::PublicVerificationKey::from(old_att_key.public()));

	// Update all keys, URL endpoint and tx counter. No keys are removed in this
	// test case
	let mut operation = generate_base_did_update_operation(ALICE_DID);
	operation.new_auth_key = Some(did::PublicVerificationKey::from(new_auth_key.public()));
	operation.new_key_agreement_key = Some(new_enc_key);
	operation.new_attestation_key = Some(did::PublicVerificationKey::from(new_att_key.public()));
	operation.new_delegation_key = Some(did::PublicVerificationKey::from(new_del_key.public()));
	operation.new_endpoint_url = Some(new_url);
	operation.tx_counter = old_did_details.last_tx_counter + 1u64;

	// Generate signature using the old authentication key
	let signature = old_auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, old_did_details.clone())])
		.build();

	ext.execute_with(|| {
		assert_ok!(Did::submit_did_update_operation(
			Origin::signed(DEFAULT_ACCOUNT),
			operation.clone(),
			did::DidSignature::from(signature),
		));
	});

	let new_did_details = ext.execute_with(|| Did::get_did(ALICE_DID).expect("ALICE_DID should be present on chain."));
	assert_eq!(
		new_did_details.auth_key,
		operation.new_auth_key.expect("Missing new auth key.")
	);
	assert_eq!(
		new_did_details.key_agreement_key,
		operation.new_key_agreement_key.expect("Missing new key agreement key.")
	);
	assert_eq!(new_did_details.delegation_key, operation.new_delegation_key);
	assert_eq!(new_did_details.attestation_key, operation.new_attestation_key);
	// Verification keys should contain the previous attestation key.
	assert_eq!(
		new_did_details.verification_keys,
		vec![did::PublicVerificationKey::from(old_att_key.public())]
			.into_iter()
			.collect()
	);
	assert_eq!(new_did_details.endpoint_url, operation.new_endpoint_url);
	assert_eq!(new_did_details.last_tx_counter, old_did_details.last_tx_counter + 1u64);
}

#[test]
fn check_successful_verification_keys_deletion() {
	let auth_key = get_ed25519_authentication_key(true);
	let old_verification_keys_vector = vec![
		did::PublicVerificationKey::from(get_ed25519_attestation_key(true).public()),
		did::PublicVerificationKey::from(get_ed25519_attestation_key(false).public()),
		did::PublicVerificationKey::from(get_sr25519_attestation_key(true).public()),
		did::PublicVerificationKey::from(get_sr25519_attestation_key(false).public()),
	];
	let old_verification_keys_set = old_verification_keys_vector.into_iter().collect::<BTreeSet<_>>();
	let mut old_did_details = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	old_did_details.verification_keys = old_verification_keys_set.clone();

	// Create update operation to remove all verification keys
	let mut operation = generate_base_did_update_operation(ALICE_DID);
	operation.verification_keys_to_remove = Some(old_verification_keys_set);

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, old_did_details.clone())])
		.build();

	ext.execute_with(|| {
		assert_ok!(Did::submit_did_update_operation(
			Origin::signed(DEFAULT_ACCOUNT),
			operation.clone(),
			did::DidSignature::from(signature),
		));
	});
	let new_did_details = ext.execute_with(||
		 	//All fields but verification_keys should remain unchanged
Did::get_did(ALICE_DID).expect("ALICE_DID should be present on chain."));
	assert_eq!(new_did_details.auth_key, old_did_details.auth_key);
	assert_eq!(new_did_details.key_agreement_key, old_did_details.key_agreement_key);
	assert_eq!(new_did_details.delegation_key, old_did_details.delegation_key);
	assert_eq!(new_did_details.attestation_key, old_did_details.attestation_key);
	assert_eq!(new_did_details.endpoint_url, old_did_details.endpoint_url);
	assert_eq!(new_did_details.last_tx_counter, old_did_details.last_tx_counter + 1u64);

	// Set of verification keys should be empty now
	assert_eq!(new_did_details.verification_keys, BTreeSet::new());
}

#[test]
fn check_did_not_present_update() {
	let auth_key = get_ed25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = generate_base_did_update_operation(BOB_DID);

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_update_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::DidNotPresent
		);
	});
}

#[test]
fn check_did_max_counter_update() {
	let auth_key = get_ed25519_authentication_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.last_tx_counter = u64::MAX;
	let operation = generate_base_did_update_operation(ALICE_DID);

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_update_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::MaxTxCounterValue
		);
	});
}

#[test]
fn check_smaller_tx_counter_did_update() {
	let auth_key = get_sr25519_authentication_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.last_tx_counter = 1;
	let mut operation = generate_base_did_update_operation(ALICE_DID);
	operation.tx_counter = mock_did.last_tx_counter - 1;

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_update_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidNonce
		);
	});
}

#[test]
fn check_equal_tx_counter_did_update() {
	let auth_key = get_sr25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let mut operation = generate_base_did_update_operation(ALICE_DID);
	operation.tx_counter = mock_did.last_tx_counter;

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_update_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidNonce
		);
	});
}

#[test]
fn check_too_large_tx_counter_did_update() {
	let auth_key = get_sr25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let mut operation = generate_base_did_update_operation(ALICE_DID);
	operation.tx_counter = mock_did.last_tx_counter + 2;

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_update_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidNonce
		);
	});
}

#[test]
fn check_invalid_signature_format_did_update() {
	let auth_key = get_ed25519_authentication_key(true);
	// Using an Sr25519 key where an Ed25519 is expected
	let invalid_key = get_sr25519_authentication_key(true);
	// DID update contains auth_key, but signature is generated using invalid_key
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = generate_base_did_update_operation(ALICE_DID);

	let signature = invalid_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_update_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidSignatureFormat
		);
	});
}

#[test]
fn check_invalid_signature_did_update() {
	let auth_key = get_sr25519_authentication_key(true);
	// Using an Sr25519 key as expected, but from a different seed (default = false)
	let alternative_key = get_sr25519_authentication_key(false);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = generate_base_did_update_operation(ALICE_DID);

	let signature = alternative_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_update_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidSignature
		);
	});
}

#[test]
fn check_invalid_verification_keys_deletion() {
	let auth_key = get_ed25519_authentication_key(true);
	let key1 = did::PublicVerificationKey::from(get_ed25519_attestation_key(true).public());
	let key2 = did::PublicVerificationKey::from(get_ed25519_attestation_key(false).public());
	let key3 = did::PublicVerificationKey::from(get_sr25519_attestation_key(true).public());
	let key4 = did::PublicVerificationKey::from(get_sr25519_attestation_key(false).public());
	let old_verification_keys_vector = vec![key1, key2, key3];
	let old_verification_keys_set = old_verification_keys_vector.into_iter().collect::<BTreeSet<_>>();
	let mut old_did_details = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	old_did_details.verification_keys = old_verification_keys_set;

	// Remove some verification keys including one not stored on chain (key4)
	let verification_keys_to_remove = vec![key1, key3, key4];
	let mut operation = generate_base_did_update_operation(ALICE_DID);
	operation.verification_keys_to_remove = Some(verification_keys_to_remove.into_iter().collect());

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, old_did_details)])
		.build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_update_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature)
			),
			did::Error::<Test>::VerificationKeysNotPresent
		);
	});
}

// submit_did_delete_operation

#[test]
fn check_successful_deletion() {
	let auth_key = get_ed25519_authentication_key(true);
	let did_details = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));

	// Update all keys, URL endpoint and tx counter. No keys are removed in this
	// test
	let operation = generate_base_did_delete_operation(ALICE_DID);

	// Generate signature using the old authentication key
	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, did_details)]).build();

	ext.execute_with(|| {
		assert_ok!(Did::submit_did_delete_operation(
			Origin::signed(DEFAULT_ACCOUNT),
			operation.clone(),
			did::DidSignature::from(signature),
		));
	});

	assert_eq!(ext.execute_with(|| Did::get_did(ALICE_DID)), None);

	// Re-adding the same DID identifier, which should not fail.
	let new_auth_key = get_sr25519_authentication_key(true);
	let operation =
		generate_base_did_creation_operation(ALICE_DID, did::PublicVerificationKey::from(new_auth_key.public()));

	let signature = new_auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().build();

	ext.execute_with(|| {
		assert_ok!(Did::submit_did_create_operation(
			Origin::signed(DEFAULT_ACCOUNT),
			operation.clone(),
			did::DidSignature::from(signature),
		));
	});
}

#[test]
fn check_did_not_present_deletion() {
	let auth_key = get_ed25519_authentication_key(true);

	// Update all keys, URL endpoint and tx counter. No keys are removed in this
	// test
	let operation = generate_base_did_delete_operation(ALICE_DID);

	// Generate signature using the old authentication key
	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_delete_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::DidNotPresent
		);
	});
}

#[test]
fn check_max_tx_counter_did_deletion() {
	let auth_key = get_sr25519_authentication_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.last_tx_counter = u64::MAX;
	let operation = generate_base_did_delete_operation(ALICE_DID);

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_delete_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::MaxTxCounterValue
		);
	});
}

#[test]
fn check_smaller_tx_counter_did_deletion() {
	let auth_key = get_sr25519_authentication_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.last_tx_counter = 1;
	let mut operation = generate_base_did_delete_operation(ALICE_DID);
	operation.tx_counter = mock_did.last_tx_counter - 1;

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_delete_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidNonce
		);
	});
}

#[test]
fn check_equal_tx_counter_did_deletion() {
	let auth_key = get_sr25519_authentication_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.last_tx_counter = 1;
	let mut operation = generate_base_did_delete_operation(ALICE_DID);
	operation.tx_counter = mock_did.last_tx_counter;

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_delete_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidNonce
		);
	});
}

#[test]
fn check_too_large_tx_counter_did_deletion() {
	let auth_key = get_sr25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let mut operation = generate_base_did_delete_operation(ALICE_DID);
	operation.tx_counter = mock_did.last_tx_counter + 2;

	let signature = auth_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_delete_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidNonce
		);
	});
}

#[test]
fn check_invalid_signature_format_did_deletion() {
	let auth_key = get_ed25519_authentication_key(true);
	// Using an Sr25519 key where an Ed25519 is expected
	let invalid_key = get_sr25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = generate_base_did_delete_operation(ALICE_DID);

	let signature = invalid_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_delete_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidSignatureFormat
		);
	});
}

#[test]
fn check_invalid_signature_did_deletion() {
	let auth_key = get_sr25519_authentication_key(true);
	// Using an Sr25519 key as expected, but from a different seed (default = false)
	let alternative_key = get_sr25519_authentication_key(false);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = generate_base_did_delete_operation(ALICE_DID);

	let signature = alternative_key.sign(operation.encode().as_ref());

	let mut ext = ExtBuilder::default().with_dids(vec![(ALICE_DID, mock_did)]).build();

	ext.execute_with(|| {
		assert_noop!(
			Did::submit_did_delete_operation(
				Origin::signed(DEFAULT_ACCOUNT),
				operation.clone(),
				did::DidSignature::from(signature),
			),
			did::Error::<Test>::InvalidSignature
		);
	});
}

// Internal function: verify_operation_validity_and_increase_did_nonce

#[test]
fn check_authentication_successful_operation_verification() {
	let auth_key = get_sr25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::Authentication,
		tx_counter: mock_did.last_tx_counter + 1,
	};

	let signature = auth_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_ok!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			)
		);
	});

	// Verify that the DID tx counter has increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(
		did_details.get_tx_counter_value(),
		mock_did.get_tx_counter_value() + 1u64
	);
}

#[test]
fn check_attestation_successful_operation_verification() {
	let auth_key = get_ed25519_authentication_key(true);
	let att_key = get_sr25519_attestation_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.attestation_key = Some(did::PublicVerificationKey::from(att_key.public()));
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::AssertionMethod,
		tx_counter: mock_did.last_tx_counter + 1,
	};

	let signature = att_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_ok!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			)
		);
	});

	// Verify that the DID tx counter has increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(
		did_details.get_tx_counter_value(),
		mock_did.get_tx_counter_value() + 1u64
	);
}

#[test]
fn check_delegation_successful_operation_verification() {
	let auth_key = get_ed25519_authentication_key(true);
	let del_key = get_ed25519_delegation_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.delegation_key = Some(did::PublicVerificationKey::from(del_key.public()));
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::CapabilityDelegation,
		tx_counter: mock_did.last_tx_counter + 1,
	};
	let signature = del_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_ok!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			)
		);
	});

	// Verify that the DID tx counter has increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(
		did_details.get_tx_counter_value(),
		mock_did.get_tx_counter_value() + 1u64
	);
}

#[test]
fn check_did_not_present_operation_verification() {
	let auth_key = get_ed25519_authentication_key(true);
	let del_key = get_ed25519_delegation_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.delegation_key = Some(did::PublicVerificationKey::from(del_key.public()));
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::CapabilityDelegation,
		tx_counter: mock_did.last_tx_counter + 1,
	};
	let signature = del_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default().build();

	ext.execute_with(|| {
		assert_noop!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			),
			did::DidError::StorageError(did::StorageError::DidNotPresent)
		);
	});
}

#[test]
fn check_max_tx_counter_operation_verification() {
	let auth_key = get_ed25519_authentication_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.last_tx_counter = u64::MAX;
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::Authentication,
		tx_counter: mock_did.last_tx_counter,
	};
	let signature = auth_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_noop!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			),
			did::DidError::StorageError(did::StorageError::MaxTxCounterValue)
		);
	});

	// Verify that the DID tx counter has not increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(did_details.get_tx_counter_value(), mock_did.get_tx_counter_value());
}

#[test]
fn check_smaller_counter_operation_verification() {
	let auth_key = get_ed25519_authentication_key(true);
	let mut mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	mock_did.last_tx_counter = 1;
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::Authentication,
		tx_counter: mock_did.last_tx_counter - 1,
	};
	let signature = auth_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_noop!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			),
			did::DidError::SignatureError(did::SignatureError::InvalidNonce)
		);
	});

	// Verify that the DID tx counter has not increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(did_details.get_tx_counter_value(), mock_did.get_tx_counter_value());
}

#[test]
fn check_equal_counter_operation_verification() {
	let auth_key = get_ed25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::Authentication,
		tx_counter: mock_did.last_tx_counter,
	};
	let signature = auth_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_noop!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			),
			did::DidError::SignatureError(did::SignatureError::InvalidNonce)
		);
	});

	// Verify that the DID tx counter has not increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(did_details.get_tx_counter_value(), mock_did.get_tx_counter_value());
}

#[test]
fn check_too_large_counter_operation_verification() {
	let auth_key = get_ed25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::Authentication,
		tx_counter: mock_did.last_tx_counter + 2,
	};
	let signature = auth_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_noop!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			),
			did::DidError::SignatureError(did::SignatureError::InvalidNonce)
		);
	});

	// Verify that the DID tx counter has not increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(did_details.get_tx_counter_value(), mock_did.get_tx_counter_value());
}

#[test]
fn check_verification_key_not_present_operation_verification() {
	let auth_key = get_ed25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let verification_key_required = did::DidVerificationKeyType::CapabilityInvocation;
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: verification_key_required.clone(),
		tx_counter: mock_did.last_tx_counter + 1,
	};

	let signature = auth_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_noop!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			),
			did::DidError::StorageError(did::StorageError::DidKeyNotPresent(verification_key_required.clone()))
		);
	});

	// Verify that the DID tx counter has not increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(did_details.get_tx_counter_value(), mock_did.get_tx_counter_value());
}

#[test]
fn check_invalid_signature_format_operation_verification() {
	let auth_key = get_sr25519_authentication_key(true);
	// Expected an Sr25519, given an Ed25519
	let invalid_key = get_ed25519_authentication_key(true);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::Authentication,
		tx_counter: mock_did.last_tx_counter + 1,
	};

	let signature = invalid_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_noop!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			),
			did::DidError::SignatureError(did::SignatureError::InvalidSignatureFormat)
		);
	});

	// Verify that the DID tx counter has not increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(did_details.get_tx_counter_value(), mock_did.get_tx_counter_value());
}

#[test]
fn check_invalid_signature_operation_verification() {
	let auth_key = get_sr25519_authentication_key(true);
	// Using same key type but different seed (default = false)
	let alternative_key = get_sr25519_authentication_key(false);
	let mock_did = generate_base_did_details(did::PublicVerificationKey::from(auth_key.public()));
	let operation = TestDidOperation {
		did: ALICE_DID,
		verification_key_type: did::DidVerificationKeyType::Authentication,
		tx_counter: mock_did.last_tx_counter + 1,
	};

	let signature = alternative_key.sign(&operation.encode());

	let mut ext = ExtBuilder::default()
		.with_dids(vec![(ALICE_DID, mock_did.clone())])
		.build();

	ext.execute_with(|| {
		assert_noop!(
			Did::verify_operation_validity_and_increase_did_nonce::<TestDidOperation>(
				&operation,
				&did::DidSignature::from(signature)
			),
			did::DidError::SignatureError(did::SignatureError::InvalidSignature)
		);
	});

	// Verify that the DID tx counter has not increased
	let did_details = ext.execute_with(|| Did::get_did(&operation.did).expect("DID should be present on chain."));
	assert_eq!(did_details.get_tx_counter_value(), mock_did.get_tx_counter_value());
}

// Internal function: HttpUrl try_from

#[test]
fn check_http_url() {
	assert_ok!(did::HttpUrl::try_from("http://kilt.io".as_bytes()));

	assert_ok!(did::HttpUrl::try_from("https://kilt.io".as_bytes()));

	assert_ok!(did::HttpUrl::try_from(
		"https://super.long.domain.kilt.io:12345/public/files/test.txt".as_bytes()
	));

	// All other valid ASCII characters
	assert_ok!(did::HttpUrl::try_from("http://:/?#[]@!$&'()*+,;=-._~".as_bytes()));

	assert_eq!(
		did::HttpUrl::try_from("".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);

	// Non-printable ASCII characters
	assert_eq!(
		did::HttpUrl::try_from("http://kilt.io/\x00".as_bytes()),
		Err(did::UrlError::InvalidUrlEncoding)
	);

	// Some invalid ASCII characters
	assert_eq!(
		did::HttpUrl::try_from("http://kilt.io/<tag>".as_bytes()),
		Err(did::UrlError::InvalidUrlEncoding)
	);

	// Non-ASCII characters
	assert_eq!(
		did::HttpUrl::try_from("http://¶.com".as_bytes()),
		Err(did::UrlError::InvalidUrlEncoding)
	);

	assert_eq!(
		did::HttpUrl::try_from("htt://kilt.io".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);

	assert_eq!(
		did::HttpUrl::try_from("httpss://kilt.io".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);
}

// Internal function: FtpUrl try_from

#[test]
fn check_ftp_url() {
	assert_ok!(did::FtpUrl::try_from("ftp://kilt.io".as_bytes()));

	assert_ok!(did::FtpUrl::try_from("ftps://kilt.io".as_bytes()));

	assert_ok!(did::FtpUrl::try_from(
		"ftps://user@super.long.domain.kilt.io:12345/public/files/test.txt".as_bytes()
	));

	// All other valid ASCII characters
	assert_ok!(did::FtpUrl::try_from("ftps://:/?#[]@%!$&'()*+,;=-._~".as_bytes()));

	assert_eq!(
		did::FtpUrl::try_from("".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);

	// Non-printable ASCII characters
	assert_eq!(
		did::HttpUrl::try_from("http://kilt.io/\x00".as_bytes()),
		Err(did::UrlError::InvalidUrlEncoding)
	);

	// Some invalid ASCII characters
	assert_eq!(
		did::FtpUrl::try_from("ftp://kilt.io/<tag>".as_bytes()),
		Err(did::UrlError::InvalidUrlEncoding)
	);

	// Non-ASCII characters
	assert_eq!(
		did::FtpUrl::try_from("ftps://¶.com".as_bytes()),
		Err(did::UrlError::InvalidUrlEncoding)
	);

	assert_eq!(
		did::FtpUrl::try_from("ft://kilt.io".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);

	assert_eq!(
		did::HttpUrl::try_from("ftpss://kilt.io".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);
}

// Internal function: IpfsUrl try_from

#[test]
fn check_ipfs_url() {
	// Base58 address
	assert_ok!(did::IpfsUrl::try_from(
		"ipfs://QmdQ1rHHHTbgbGorfuMMYDQQ36q4sxvYcB4GDEHREuJQkL".as_bytes()
	));

	// Base32 address (at the moment, padding characters can appear anywhere in the
	// string)
	assert_ok!(did::IpfsUrl::try_from(
		"ipfs://OQQHHHTGMMYDQQ364YB4GDE=HREJQL==".as_bytes()
	));

	assert_eq!(
		did::IpfsUrl::try_from("".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);

	assert_eq!(
		did::IpfsUrl::try_from("ipfs://¶QmdQ1rHHHTbgbGorfuMMYDQQ36q4sxvYcB4GDEHREuJQkL".as_bytes()),
		Err(did::UrlError::InvalidUrlEncoding)
	);

	assert_eq!(
		did::IpfsUrl::try_from("ipf://QmdQ1rHHHTbgbGorfuMMYDQQ36q4sxvYcB4GDEHREuJQkL".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);

	assert_eq!(
		did::IpfsUrl::try_from("ipfss://QmdQ1rHHHTbgbGorfuMMYDQQ36q4sxvYcB4GDEHREuJQkL".as_bytes()),
		Err(did::UrlError::InvalidUrlScheme)
	);
}
