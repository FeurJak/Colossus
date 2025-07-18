use crate::{
    access_control::{UserId, keys::rights::RightSecretKey},
    policy::{RevisionVec, Right},
};

/// Covercrypt User Secret Key (USK).
///
/// It is composed of:
/// - a user ID (pair of scalars);
/// - the keys of the rights derived from the user decryption policy;
/// - a signature from the MSK that guarantees its integrity.
#[derive(Clone, Debug, PartialEq)]
pub struct UserSecretKey {
    id: UserId,
    ps: Vec<<ElGamal as Nike>::PublicKey>,
    secrets: RevisionVec<Right, RightSecretKey>,
    signature: Option<KmacSignature>,
}

impl UserSecretKey {
    /// Returns the tracing level of this user secret key.
    pub fn tracing_level(&self) -> usize {
        self.id.tracing_level()
    }

    pub fn count(&self) -> usize {
        self.secrets.len()
    }

    fn set_traps(&self, r: &<ElGamal as Nike>::SecretKey) -> Vec<<ElGamal as Nike>::PublicKey> {
        self.ps.iter().map(|Pi| Pi * r).collect()
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Encapsulations {
    HEncs(Vec<(<MlKem as Kem>::Encapsulation, [u8; SHARED_SECRET_LENGTH])>),
    CEncs(Vec<[u8; SHARED_SECRET_LENGTH]>),
}
