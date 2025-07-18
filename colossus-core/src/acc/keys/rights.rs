/// The Covercrypt subkeys hold the DH secret key associated to a right.
/// Subkeys can be hybridized, in which case they also hold a PQ-KEM secret key.
#[derive(Clone, Debug, PartialEq)]
pub enum RightSecretKey {
    Hybridized {
        sk: <ElGamal as Nike>::SecretKey,
        dk: <MlKem as Kem>::DecapsulationKey,
    },
    Classic {
        sk: <ElGamal as Nike>::SecretKey,
    },
}

impl RightSecretKey {
    /// Generates a new random right secret key cryptographically bound to the Covercrypt binding
    /// point `h`.
    fn random(rng: &mut impl CryptoRngCore, hybridize: bool) -> Result<Self, Error> {
        let sk = <ElGamal as Nike>::SecretKey::random(rng);
        if hybridize {
            let (dk, _) = MlKem::keygen(rng)?;
            Ok(Self::Hybridized { sk, dk })
        } else {
            Ok(Self::Classic { sk })
        }
    }

    /// Generates the associated right public key.
    #[must_use]
    fn cpk(&self, h: &<ElGamal as Nike>::PublicKey) -> RightPublicKey {
        match self {
            Self::Hybridized { sk, dk } => RightPublicKey::Hybridized { H: h * sk, ek: dk.ek() },
            Self::Classic { sk } => RightPublicKey::Classic { H: h * sk },
        }
    }

    /// Returns true if this right secret key is hybridized.
    fn is_hybridized(&self) -> bool {
        match self {
            Self::Hybridized { .. } => true,
            Self::Classic { .. } => false,
        }
    }

    fn drop_hybridization(&self) -> Self {
        match self {
            Self::Hybridized { sk: x_i, .. } => Self::Classic { sk: x_i.clone() },
            Self::Classic { .. } => self.clone(),
        }
    }
}

/// The Covercrypt public keys hold the DH secret public key associated to a right.
/// Subkeys can be hybridized, in which case they also hold a PQ-KEM public key.
#[derive(Clone, Debug, PartialEq)]
enum RightPublicKey {
    Hybridized {
        H: <ElGamal as Nike>::PublicKey,
        ek: <MlKem as Kem>::EncapsulationKey,
    },
    Classic {
        H: <ElGamal as Nike>::PublicKey,
    },
}

impl RightPublicKey {
    pub fn is_hybridized(&self) -> bool {
        match self {
            Self::Hybridized { .. } => true,
            Self::Classic { .. } => false,
        }
    }
}
