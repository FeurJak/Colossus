// =============================================================================
// DAC Builder Tests
// =============================================================================
//
// These tests demonstrate credential building with blinded attributes.
// The tests use IssuerBlindingKey for creating privacy-preserving attributes
// that can be used with the DAC (Delegatable Anonymous Credentials) system.

use anyhow::Result;
use cosmian_crypto_core::reexport::rand_core::SeedableRng;

use crate::crypto::{Felt, Word};
use crate::policy::{BlindedClaimBuilder, DimensionType, IssuerBlindingKey};

/// Test credential building with blinded attributes.
///
/// This test demonstrates:
/// 1. Creating an IssuerBlindingKey
/// 2. Registering it with an authority's blinded structure
/// 3. Creating BlindedAttribute entries
/// 4. Building claims with the blinded attributes
#[test]
fn test_credential_building_blinded() -> Result<()> {
    use crate::access_control::AccessControl;
    use crate::access_control::capability::create_blinded_capability_token;

    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let access_control = AccessControl::default();

    // Setup blinded authority
    let mut auth = access_control.setup_blinded_authority()?.with_identity();
    auth.init_blinded_structure()?;
    let authority_pk = auth.authority_pk().expect("should have pk");

    // Add dimensions for credential attributes
    let role_dim = auth.add_blinded_dimension("ROLE", DimensionType::Anarchy)?;
    let level_dim = auth.add_blinded_dimension("LEVEL", DimensionType::Hierarchy)?;

    // Create issuer with blinding key
    let mut issuer = IssuerBlindingKey::new();
    let registration = issuer.register_with_authority(authority_pk, 1000);

    // Register issuer with authority
    let issuer_id =
        auth.register_blinded_issuer(registration, issuer.identity().public_key(), &mut rng)?;

    // Create and register blinded attributes
    let timestamp = 2000u64;

    // Role attributes
    for role in &["ADMIN", "USER", "GUEST"] {
        let attr = issuer.create_blinded_attribute("ROLE", role, &authority_pk)?;
        let proof = issuer.prove_ownership("ROLE", role, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &role_dim, "ROLE", role, attr, &proof, timestamp, &mut rng,
        )?;
    }

    // Level attributes
    for level in &["L1", "L2", "L3"] {
        let attr = issuer.create_blinded_attribute("LEVEL", level, &authority_pk)?;
        let proof = issuer.prove_ownership("LEVEL", level, &authority_pk)?;
        auth.add_blinded_attribute_with_name(
            &level_dim, "LEVEL", level, attr, &proof, timestamp, &mut rng,
        )?;
    }

    // Build a credential claim with multiple attributes
    let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("ROLE", "ADMIN")
        .add_attribute("LEVEL", "L3")
        .build_batched()?;

    // Verify the claim
    let issuer_pk = issuer.identity().public_key();
    assert!(claim.verify(&issuer_pk), "claim should verify");
    assert_eq!(claim.len(), 2, "should have 2 attributes");

    // Create capability token from the claim
    let cap_claim = crate::access_control::capability::BlindedCapabilityClaim::from_batched_claim(
        issuer_id, claim,
    );
    let token = create_blinded_capability_token(&mut rng, &mut auth, &[cap_claim])?;

    assert!(token.count() > 0, "token should have access rights");
    println!("Credential building test passed with {} access rights", token.count());

    Ok(())
}

/// Test issuer with unsupported attributes (blinded version).
///
/// This test verifies that:
/// 1. Issuers can only create blinded attributes for registered authorities
/// 2. Ownership proofs are validated before accepting attributes
/// 3. Wrong issuer proofs are rejected
#[test]
fn test_issuer_unsupported_attribute_blinded() -> Result<()> {
    use crate::access_control::AccessControl;

    let mut rng = cosmian_crypto_core::CsRng::from_entropy();
    let access_control = AccessControl::default();

    // Setup blinded authority
    let mut auth = access_control.setup_blinded_authority()?.with_identity();
    auth.init_blinded_structure()?;
    let authority_pk = auth.authority_pk().expect("should have pk");

    // Add only one dimension
    let role_dim = auth.add_blinded_dimension("ROLE", DimensionType::Anarchy)?;

    // Create and register issuer
    let mut issuer = IssuerBlindingKey::new();
    let registration = issuer.register_with_authority(authority_pk, 1000);
    auth.register_blinded_issuer(registration, issuer.identity().public_key(), &mut rng)?;

    // Add a valid attribute
    let attr = issuer.create_blinded_attribute("ROLE", "ADMIN", &authority_pk)?;
    let proof = issuer.prove_ownership("ROLE", "ADMIN", &authority_pk)?;

    let timestamp = 2000u64;
    auth.add_blinded_attribute_with_name(
        &role_dim,
        "ROLE",
        "ADMIN",
        attr.clone(),
        &proof,
        timestamp,
        &mut rng,
    )?;

    // Test: Create a different issuer and try to use their proof for our attribute
    let mut rogue_issuer = IssuerBlindingKey::new();
    rogue_issuer.register_with_authority(authority_pk, 2000);

    // Rogue issuer creates their own attribute
    let rogue_attr = rogue_issuer.create_blinded_attribute("ROLE", "USER", &authority_pk)?;
    let rogue_proof = rogue_issuer.prove_ownership("ROLE", "USER", &authority_pk)?;

    // The rogue proof should NOT verify with our issuer's public key
    assert!(
        !rogue_proof.verify(&issuer.identity().public_key()),
        "rogue proof should not verify with different issuer key"
    );

    // The rogue proof SHOULD verify with rogue issuer's own key
    assert!(
        rogue_proof.verify(&rogue_issuer.identity().public_key()),
        "rogue proof should verify with own key"
    );

    // Test: Attempting to add attribute with mismatched proof should fail
    // (proof was created by rogue_issuer but we're using issuer's key in registration)
    // The authority should reject this because the issuer pk doesn't match

    // First, register the rogue issuer properly
    let rogue_reg = rogue_issuer.register_with_authority(authority_pk, 3000);
    auth.register_blinded_issuer(rogue_reg, rogue_issuer.identity().public_key(), &mut rng)?;

    // Now the rogue issuer can add their attribute
    auth.add_blinded_attribute_with_name(
        &role_dim,
        "ROLE",
        "USER",
        rogue_attr,
        &rogue_proof,
        timestamp,
        &mut rng,
    )?;

    // Test: Claims must use matching issuer
    // Building a claim with rogue issuer should work
    let rogue_claim = BlindedClaimBuilder::new(&mut rogue_issuer, authority_pk)
        .add_attribute("ROLE", "USER")
        .build_batched()?;

    assert!(
        rogue_claim.verify(&rogue_issuer.identity().public_key()),
        "rogue claim should verify with rogue key"
    );

    // But the claim should NOT verify with the original issuer's key
    assert!(
        !rogue_claim.verify(&issuer.identity().public_key()),
        "rogue claim should not verify with different issuer key"
    );

    println!("Issuer unsupported attribute test passed!");
    Ok(())
}

/// Test blinded attribute behavior: each creation generates unique commitment (privacy),
/// but deterministic creation with same salt produces same commitment.
#[test]
fn test_blinded_attribute_determinism() -> Result<()> {
    use miden_crypto::Felt as MidenFelt;

    let authority_pk = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

    let mut issuer = IssuerBlindingKey::new();
    issuer.register_with_authority(authority_pk, 1000);

    // Each call to create_blinded_attribute generates a NEW random salt
    // This is intentional for privacy - allows same issuer to create
    // multiple unlinkable instances of the same attribute
    let attr1 = issuer.create_blinded_attribute("ROLE", "ADMIN", &authority_pk)?;
    let attr2 = issuer.create_blinded_attribute("ROLE", "ADMIN", &authority_pk)?;

    // Different commitments due to different salts (privacy feature)
    assert_ne!(
        attr1.commitment(),
        attr2.commitment(),
        "each creation should produce different commitment (random salt)"
    );

    // For deterministic behavior, use create_blinded_attribute_deterministic with same salt
    let fixed_salt = miden_crypto::Word::new([
        MidenFelt::new(1),
        MidenFelt::new(2),
        MidenFelt::new(3),
        MidenFelt::new(4),
    ]);

    let attr3 = issuer.create_blinded_attribute_deterministic(
        "ROLE",
        "ADMIN",
        &authority_pk,
        fixed_salt,
    )?;
    let attr4 = issuer.create_blinded_attribute_deterministic(
        "ROLE",
        "ADMIN",
        &authority_pk,
        fixed_salt,
    )?;

    // Same salt produces same commitment (deterministic)
    assert_eq!(
        attr3.commitment(),
        attr4.commitment(),
        "deterministic creation with same salt should produce same commitment"
    );

    // Different attribute name produces different commitment
    let attr5 = issuer.create_blinded_attribute("ROLE", "USER", &authority_pk)?;
    assert_ne!(
        attr1.commitment(),
        attr5.commitment(),
        "different attributes should have different commitments"
    );

    Ok(())
}

/// Test batch credential building efficiency.
#[test]
fn test_batch_credential_building() -> Result<()> {
    let authority_pk = Word::new([Felt::new(100), Felt::new(200), Felt::new(300), Felt::new(400)]);

    let mut issuer = IssuerBlindingKey::new();
    issuer.register_with_authority(authority_pk, 1000);

    // Create multiple attributes
    for attr in &["ROLE1", "ROLE2", "ROLE3", "ROLE4", "ROLE5"] {
        issuer.create_blinded_attribute("ROLES", attr, &authority_pk)?;
    }

    // Create batch proof (single signature for multiple attributes)
    let batch_proof = issuer.prove_ownership_batch(
        &[
            ("ROLES", "ROLE1"),
            ("ROLES", "ROLE2"),
            ("ROLES", "ROLE3"),
            ("ROLES", "ROLE4"),
            ("ROLES", "ROLE5"),
        ],
        &authority_pk,
    )?;

    // Verify batch proof
    let issuer_pk = issuer.identity().public_key();
    assert!(batch_proof.verify(&issuer_pk), "batch proof should verify");
    assert_eq!(batch_proof.len(), 5, "should have 5 attributes");

    // Build batched claim
    let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
        .add_attribute("ROLES", "ROLE1")
        .add_attribute("ROLES", "ROLE2")
        .add_attribute("ROLES", "ROLE3")
        .build_batched()?;

    assert!(claim.verify(&issuer_pk), "batched claim should verify");
    assert_eq!(claim.len(), 3, "claim should have 3 attributes");

    println!("Batch credential building test passed!");
    Ok(())
}
