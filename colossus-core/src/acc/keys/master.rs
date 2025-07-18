use super::{
    AccessStructure, RevisionMap, Right, SIGNING_KEY_LENGTH, rights::RightSecretKey,
    tracing::TracingSecretKey,
};

use crate::{keys::rights::RightPublicKey, policy::Error};

/// The Covercrypt Master Secret Key (MSK).
///
/// It is composed of:
/// - the scalar `s` used to bind tracing and right secrets;
/// - the tracing secret key used to produce challenges to trace user keys;
/// - the secret associated to the each right in Omega;
/// - an optional key for symmetric USK-signing;
/// - the access structure.
#[derive(Debug, PartialEq)]
pub struct MasterSecretKey {
    tsk: TracingSecretKey,
    secrets: RevisionMap<Right, (bool, RightSecretKey)>,
    signing_key: Option<SymmetricKey<SIGNING_KEY_LENGTH>>,
    pub access_structure: AccessStructure,
}

impl MasterSecretKey {
    /// Returns the most recent secret key associated to each given right.
    ///
    /// # Error
    ///
    /// Returns an error if some right is missing from the MSK.
    fn get_latest_right_sk<'a>(
        &'a self,
        rs: impl Iterator<Item = Right> + 'a,
    ) -> impl Iterator<Item = Result<(Right, RightSecretKey), Error>> + 'a {
        rs.map(|r| {
            self.secrets
                .get_latest(&r)
                .ok_or(Error::KeyError(format!("MSK has no key for right {r:?}")))
                .cloned()
                .map(|(_, key)| (r, key))
        })
    }

    /// Generates a new MPK holding the latest public information of each right in Omega.
    pub fn mpk(&self) -> Result<MasterPublicKey, Error> {
        let h = self.tsk.binding_point();
        Ok(MasterPublicKey {
            tpk: self.tsk.tpk(),
            encryption_keys: self
                .secrets
                .iter()
                .filter_map(|(r, secrets)| {
                    secrets.front().and_then(|(is_activated, csk)| {
                        if *is_activated {
                            Some((r.clone(), csk.cpk(&h)))
                        } else {
                            None
                        }
                    })
                })
                .collect(),
            access_structure: self.access_structure.clone(),
        })
    }
}

/// Covercrypt Public Key (PK).
///
/// It is composed of:
/// - the tracing public key;
/// - the public keys for each right in Omega;
/// - the access structure.
#[derive(Debug, PartialEq)]
pub struct MasterPublicKey {
    tpk: TracingPublicKey,
    encryption_keys: HashMap<Right, RightPublicKey>,
    pub access_structure: AccessStructure,
}

impl MasterPublicKey {
    /// Returns the tracing level of this MPK.
    #[inline(always)]
    pub fn tracing_level(&self) -> usize {
        self.tpk.tracing_level()
    }

    /// Generates traps for the given scalar.
    // TODO: find a better concept.
    fn set_traps(&self, r: &<ElGamal as Nike>::SecretKey) -> Vec<<ElGamal as Nike>::PublicKey> {
        self.tpk.0.iter().map(|Pi| Pi * r).collect()
    }

    /// Returns the subkeys associated with the given rights in this public key,
    /// alongside a boolean value that is true if all of them are hybridized.
    fn select_subkeys(
        &self,
        targets: &HashSet<Right>,
    ) -> Result<(bool, Vec<&RightPublicKey>), Error> {
        // This mutable variable is set to false if at least one sub-key is not
        // hybridized.
        let mut is_hybridized = true;

        let subkeys = targets
            .iter()
            .map(|r| {
                let subkey = self
                    .encryption_keys
                    .get(r)
                    .ok_or_else(|| Error::KeyError(format!("no public key for right '{r:#?}'")))?;
                if !subkey.is_hybridized() {
                    is_hybridized = false;
                }
                Ok(subkey)
            })
            .collect::<Result<_, Error>>()?;

        Ok((is_hybridized, subkeys))
    }
}
