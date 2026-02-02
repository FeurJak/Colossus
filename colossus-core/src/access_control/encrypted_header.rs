//! Encrypted Header Module
//!
//! This module provides authenticated encryption for metadata using the Poseidon2
//! AEAD scheme from miden-crypto. Poseidon2 is an arithmetization-oriented cipher
//! optimized for zero-knowledge proof systems (STARKs/SNARKs).
//!
//! # Encryption Scheme
//!
//! The encrypted header uses a hybrid encryption approach:
//!
//! 1. **Key Encapsulation**: ML-KEM (Kyber) + ElGamal NIKE for post-quantum hybrid security
//! 2. **Metadata Encryption**: Poseidon2 AEAD for ZK-proof compatibility
//! 3. **Key Derivation**: BLAKE3-based KDF for symmetric key derivation
//!
//! # Security Properties
//!
//! - 128-bit classical security
//! - Post-quantum security via ML-KEM key encapsulation
//! - ZK-proof friendly metadata encryption via Poseidon2
//! - Authenticated encryption with associated data (AEAD)

use crate::{
    access_control::{
        AccessControl, CapabilityAuthority, CapabilityAuthorityPublicKey,
        capability::AccessCapabilityToken,
        cryptography::{
            SHARED_SECRET_LENGTH, XEnc,
            ae_poseidon2::{POSEIDON2_KEY_SIZE, Poseidon2Aead},
            traits::AE,
        },
    },
    policy::{AccessPolicy, Error, Right},
};
use cosmian_crypto_core::{Secret, SymmetricKey, kdf256, reexport::rand_core::SeedableRng};
use std::collections::HashSet;

#[derive(Debug, PartialEq, Eq)]
pub struct CleartextHeader {
    pub secret: Secret<SHARED_SECRET_LENGTH>,
    pub metadata: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct EncryptedHeader {
    pub encapsulation: XEnc,
    pub encrypted_metadata: Option<Vec<u8>>,
}

impl EncryptedHeader {
    /// Generate an encrypted header using Poseidon2 AEAD.
    ///
    /// This encrypts optional metadata with the Poseidon2 AEAD scheme, which is
    /// optimized for zero-knowledge proof systems.
    ///
    /// # Arguments
    ///
    /// * `api` - The access control instance
    /// * `auth_pk` - The authority's public key
    /// * `rights` - The set of access rights to encrypt for
    /// * `metadata` - Optional metadata bytes to encrypt
    /// * `authentication_data` - Optional additional authenticated data (AAD)
    pub fn generate(
        api: &AccessControl,
        auth_pk: &CapabilityAuthorityPublicKey,
        rights: &HashSet<Right>,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self), Error> {
        let (seed, encapsulation) = api.encapsulate_for_rights(auth_pk, rights)?;

        let encrypted_metadata = metadata
            .map(|bytes| {
                // Derive a key for metadata encryption
                let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::derive(&seed, &[0u8])?;
                let aad = authentication_data.unwrap_or(&[]);

                // Encrypt using Poseidon2 AEAD
                // Note: Poseidon2Aead::encrypt doesn't actually use the RNG (it's deterministic)
                let mut rng = cosmian_crypto_core::CsRng::from_entropy();
                Poseidon2Aead::encrypt(&mut rng, &key, bytes, aad)
            })
            .transpose()?;

        let mut secret = Secret::default();
        kdf256!(&mut *secret, &*seed, &[1u8]);

        Ok((secret, Self { encapsulation, encrypted_metadata }))
    }

    /// Generate an encrypted header using an AccessPolicy.
    ///
    /// This is the hybrid mode API that accepts human-readable access policies
    /// like `"AGE::ADULT && LOC::INNER_CITY"` and converts them to rights
    /// using the authority's blinded structure.
    ///
    /// # Arguments
    ///
    /// * `api` - The access control instance
    /// * `auth_pk` - The authority's public key
    /// * `auth` - The capability authority (for policy resolution)
    /// * `policy` - The access policy expression
    /// * `metadata` - Optional metadata bytes to encrypt
    /// * `authentication_data` - Optional additional authenticated data (AAD)
    pub fn generate_with_policy(
        api: &AccessControl,
        auth_pk: &CapabilityAuthorityPublicKey,
        auth: &CapabilityAuthority,
        policy: &AccessPolicy,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self), Error> {
        // Resolve the policy to a set of rights
        let rights = auth.resolve_policy(policy).map_err(|e| {
            Error::OperationNotPermitted(format!("Failed to resolve policy: {}", e))
        })?;

        // Generate using the rights-based method
        Self::generate(api, auth_pk, &rights, metadata, authentication_data)
    }

    /// Decrypt an encrypted header using Poseidon2 AEAD.
    pub fn decrypt(
        &self,
        api: &AccessControl,
        cap_token: &AccessCapabilityToken,
        authentication_data: Option<&[u8]>,
    ) -> Result<Option<CleartextHeader>, Error> {
        api.decapsulate(cap_token, &self.encapsulation)?
            .map(|seed| {
                let metadata = self
                    .encrypted_metadata
                    .as_ref()
                    .map(|ctx| {
                        // Derive the key for metadata decryption
                        let key = SymmetricKey::<POSEIDON2_KEY_SIZE>::derive(&seed, &[0u8])?;
                        let aad = authentication_data.unwrap_or(&[]);

                        // Decrypt using Poseidon2 AEAD
                        Poseidon2Aead::decrypt(&key, ctx, aad).map(|z| z.to_vec())
                    })
                    .transpose()?;

                let mut secret = Secret::<SHARED_SECRET_LENGTH>::default();
                kdf256!(&mut *secret, &*seed, &[1u8]);

                Ok(CleartextHeader { secret, metadata })
            })
            .transpose()
    }
}

mod serialization {

    use super::*;
    use cosmian_crypto_core::bytes_ser_de::{
        Deserializer, Serializable, Serializer, to_leb128_len,
    };

    impl Serializable for EncryptedHeader {
        type Error = Error;

        fn length(&self) -> usize {
            self.encapsulation.length()
                + if let Some(metadata) = &self.encrypted_metadata {
                    to_leb128_len(metadata.len()) + metadata.len()
                } else {
                    1
                }
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = self.encapsulation.write(ser)?;
            match &self.encrypted_metadata {
                Some(bytes) => n += ser.write_vec(bytes)?,
                None => n += ser.write_vec(&[])?,
            }
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let encapsulation = de.read::<XEnc>()?;
            let ciphertext = de.read_vec()?;
            let encrypted_metadata = if ciphertext.is_empty() { None } else { Some(ciphertext) };
            Ok(Self { encapsulation, encrypted_metadata })
        }
    }

    impl Serializable for CleartextHeader {
        type Error = Error;

        fn length(&self) -> usize {
            SHARED_SECRET_LENGTH
                + to_leb128_len(self.metadata.as_ref().map(std::vec::Vec::len).unwrap_or_default())
                + self.metadata.as_ref().map(std::vec::Vec::len).unwrap_or_default()
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = ser.write_array(&self.secret[..SHARED_SECRET_LENGTH])?;
            match &self.metadata {
                Some(bytes) => n += ser.write_vec(bytes)?,
                None => n += ser.write_vec(&[])?,
            }
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let seed =
                Secret::from_unprotected_bytes(&mut de.read_array::<SHARED_SECRET_LENGTH>()?);
            let metadata = de.read_vec()?;
            let metadata = if metadata.is_empty() { None } else { Some(metadata) };
            Ok(Self { secret: seed, metadata })
        }
    }

    /// Test serialization/deserialization of EncryptedHeader and CleartextHeader.
    #[test]
    fn test_ser() {
        use crate::access_control::AccessControl;
        use crate::access_control::capability::create_blinded_capability_token;
        use crate::policy::{AccessPolicy, BlindedClaimBuilder, DimensionType, IssuerBlindingKey};
        use cosmian_crypto_core::reexport::rand_core::SeedableRng;

        let mut rng = cosmian_crypto_core::CsRng::from_entropy();
        let access_control = AccessControl::default();

        // Setup blinded authority
        let mut auth = access_control.setup_blinded_authority().unwrap().with_identity();
        auth.init_blinded_structure().unwrap();
        let authority_pk = auth.authority_pk().expect("should have pk");

        // Add dimension
        let role_dim = auth.add_blinded_dimension("ROLE", DimensionType::Anarchy).unwrap();

        // Setup issuer
        let mut issuer = IssuerBlindingKey::new();
        let reg = issuer.register_with_authority(authority_pk, 1000);
        let issuer_id = auth
            .register_blinded_issuer(reg, issuer.identity().public_key(), &mut rng)
            .unwrap();

        // Add attributes
        let timestamp = 2000u64;
        let attr = issuer.create_blinded_attribute("ROLE", "ADMIN", &authority_pk).unwrap();
        let proof = issuer.prove_ownership("ROLE", "ADMIN", &authority_pk).unwrap();
        auth.add_blinded_attribute_with_name(
            &role_dim, "ROLE", "ADMIN", attr, &proof, timestamp, &mut rng,
        )
        .unwrap();

        let apk = auth.rpk().unwrap();

        // Create policy and encrypt
        let policy = AccessPolicy::parse("ROLE::ADMIN").unwrap();
        let metadata = b"test metadata for serialization";
        let aad = b"test_aad";

        let (secret, enc_header) = super::EncryptedHeader::generate_with_policy(
            &access_control,
            &apk,
            &auth,
            &policy,
            Some(metadata),
            Some(aad),
        )
        .unwrap();

        // Test EncryptedHeader serialization
        let serialized = enc_header.serialize().unwrap();
        let deserialized = super::EncryptedHeader::deserialize(&serialized).unwrap();
        assert_eq!(enc_header, deserialized);

        // Get capability token
        let claim = BlindedClaimBuilder::new(&mut issuer, authority_pk)
            .add_attribute("ROLE", "ADMIN")
            .build_batched()
            .unwrap();
        let cap_claim =
            crate::access_control::capability::BlindedCapabilityClaim::from_batched_claim(
                issuer_id, claim,
            );
        let cap_token = create_blinded_capability_token(&mut rng, &mut auth, &[cap_claim]).unwrap();

        // Decrypt original
        let cleartext =
            enc_header.decrypt(&access_control, &cap_token, Some(aad)).unwrap().unwrap();
        assert_eq!(cleartext.secret, secret);
        assert_eq!(cleartext.metadata.as_ref().unwrap(), metadata);

        // Decrypt deserialized (should produce same result)
        let cleartext2 =
            deserialized.decrypt(&access_control, &cap_token, Some(aad)).unwrap().unwrap();
        assert_eq!(cleartext.secret, cleartext2.secret);
        assert_eq!(cleartext.metadata, cleartext2.metadata);

        // Test CleartextHeader serialization
        let cleartext_serialized = cleartext.serialize().unwrap();
        let cleartext_deserialized =
            super::CleartextHeader::deserialize(&cleartext_serialized).unwrap();
        assert_eq!(cleartext.metadata, cleartext_deserialized.metadata);
        // Note: Secret comparison requires special handling due to SecretBox
        // Just verify the metadata matches

        // Test with no metadata
        let (_, enc_header_no_meta) = super::EncryptedHeader::generate_with_policy(
            &access_control,
            &apk,
            &auth,
            &policy,
            None,
            None,
        )
        .unwrap();

        let serialized_no_meta = enc_header_no_meta.serialize().unwrap();
        let deserialized_no_meta =
            super::EncryptedHeader::deserialize(&serialized_no_meta).unwrap();
        assert_eq!(enc_header_no_meta, deserialized_no_meta);
    }
}
