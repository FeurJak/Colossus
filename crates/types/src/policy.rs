//! This module defines the models for representing access policie & access structures
mod access_policy;
mod access_structure;
mod dimension;
mod rights;

use super::CryptographyError as Error;
use super::data_struct::Dict;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Debug,
    hash::Hash,
    ops::{BitAnd, BitOr, Deref},
};

type Name = String;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    V1,
}

/// An access policy is a boolean expression of qualified attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessPolicy {
    Broadcast,
    Term(QualifiedAttribute),
    Conjunction(Box<AccessPolicy>, Box<AccessPolicy>),
    Disjunction(Box<AccessPolicy>, Box<AccessPolicy>),
}

impl BitAnd for AccessPolicy {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        if self == Self::Broadcast {
            rhs
        } else if rhs == Self::Broadcast {
            self
        } else {
            Self::Conjunction(Box::new(self), Box::new(rhs))
        }
    }
}

impl BitOr for AccessPolicy {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::Broadcast {
            self
        } else if rhs == Self::Broadcast {
            rhs
        } else {
            Self::Disjunction(Box::new(self), Box::new(rhs))
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccessStructure {
    version: Version,
    // Use a hash-map to efficiently find dimensions by name.
    dimensions: HashMap<String, Dimension>,
}

impl Default for AccessStructure {
    fn default() -> Self {
        Self {
            version: Version::V1,
            dimensions: HashMap::new(),
        }
    }
}

impl AccessStructure {
    pub fn new() -> Self {
        Self {
            version: Version::V1,
            dimensions: HashMap::new(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Attribute {
    pub(crate) id: usize,
    pub(crate) encryption_hint: EncryptionHint,
    pub(crate) write_status: AttributeStatus,
}

impl Attribute {
    pub fn new(encryption_hint: EncryptionHint, id: usize) -> Self {
        Self {
            id,
            encryption_hint,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_encryption_hint(&self) -> EncryptionHint {
        self.encryption_hint
    }

    pub fn get_status(&self) -> AttributeStatus {
        self.write_status
    }
}

/// A dimension is an object that contains attributes. It can be ordered or unordered.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum Dimension {
    Anarchy(HashMap<Name, Attribute>),
    Hierarchy(Dict<Name, Attribute>),
}

impl Default for Dimension {
    fn default() -> Self {
        Self::Anarchy(Default::default())
    }
}

impl Dimension {
    pub fn nb_attributes(&self) -> usize {
        match self {
            Self::Anarchy(attributes) => attributes.len(),
            Self::Hierarchy(attributes) => attributes.len(),
        }
    }

    pub fn is_ordered(&self) -> bool {
        match self {
            Self::Anarchy(_) => false,
            Self::Hierarchy(_) => true,
        }
    }

    /// Returns an iterator over the attributes name.
    ///
    /// If the dimension is ordered, the names are returned in this order, otherwise they are
    /// returned in arbitrary order.
    pub fn get_attributes_name(&self) -> Box<dyn '_ + Iterator<Item = &Name>> {
        match self {
            Self::Anarchy(attributes) => Box::new(attributes.keys()),
            Self::Hierarchy(attributes) => Box::new(attributes.keys()),
        }
    }

    pub fn get_attribute(&self, attr_name: &Name) -> Option<&Attribute> {
        match self {
            Self::Anarchy(attributes) => attributes.get(attr_name),
            Self::Hierarchy(attributes) => attributes.get(attr_name),
        }
    }
}

/// A right is a combination of the IDs of its associated attributes.
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct Right(pub(crate) Vec<u8>);

impl Deref for Right {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for Right {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for Right {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

/// Hint the user about which kind of encryption to use.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionHint {
    /// Hybridized encryption should be used.
    Hybridized,
    /// Classic encryption should be used.
    Classic,
}

impl BitOr for EncryptionHint {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::Hybridized || rhs == Self::Hybridized {
            Self::Hybridized
        } else {
            Self::Classic
        }
    }
}

impl EncryptionHint {
    #[must_use]
    pub fn new(is_hybridized: bool) -> Self {
        if is_hybridized { Self::Hybridized } else { Self::Classic }
    }
}

impl From<EncryptionHint> for bool {
    fn from(val: EncryptionHint) -> Self {
        val == EncryptionHint::Hybridized
    }
}

/// Whether to provide an encryption key in the master public key for this
/// attribute.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttributeStatus {
    EncryptDecrypt,
    DecryptOnly,
}

impl BitOr for AttributeStatus {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        if self == Self::DecryptOnly || rhs == Self::DecryptOnly {
            Self::DecryptOnly
        } else {
            Self::EncryptDecrypt
        }
    }
}

impl From<AttributeStatus> for bool {
    fn from(val: AttributeStatus) -> Self {
        val == AttributeStatus::EncryptDecrypt
    }
}

/// A qualified attribute is composed of a dimension an attribute name.
#[derive(Hash, PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "&str", into = "String")]
pub struct QualifiedAttribute {
    pub dimension: String,
    pub name: String,
}

impl QualifiedAttribute {
    /// Creates a qualified attribute with the given dimension and attribute names.
    #[must_use]
    pub fn new(dimension: &str, name: &str) -> Self {
        Self {
            dimension: dimension.to_owned(),
            name: name.to_owned(),
        }
    }
}

impl Debug for QualifiedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}::{}", &self.dimension, &self.name))
    }
}

impl std::fmt::Display for QualifiedAttribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.dimension, self.name)
    }
}

impl From<QualifiedAttribute> for String {
    fn from(attr: QualifiedAttribute) -> Self {
        attr.to_string()
    }
}

impl From<(&str, &str)> for QualifiedAttribute {
    fn from(input: (&str, &str)) -> Self {
        Self {
            dimension: input.0.to_owned(),
            name: input.1.to_owned(),
        }
    }
}

impl From<(String, String)> for QualifiedAttribute {
    fn from(input: (String, String)) -> Self {
        Self { dimension: input.0, name: input.1 }
    }
}

impl TryFrom<&str> for QualifiedAttribute {
    type Error = crate::CryptographyError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (dimension, component) = s.split_once("::").ok_or_else(|| {
            crate::CryptographyError::InvalidAttribute(format!(
                "at least one separator '::' expected in {s}"
            ))
        })?;

        if component.contains("::") {
            return Err(crate::CryptographyError::InvalidAttribute(format!(
                "separator '::' expected only once in {s}"
            )));
        }

        if dimension.is_empty() || component.is_empty() {
            return Err(crate::CryptographyError::InvalidAttribute(format!(
                "empty dimension or empty name in {s}"
            )));
        }

        Ok(Self::new(dimension.trim(), component.trim()))
    }
}

pub fn gen_test_structure(policy: &mut AccessStructure, complete: bool) -> Result<(), Error> {
    policy.add_hierarchy("SEC".to_string())?;

    policy.add_attribute(
        QualifiedAttribute {
            dimension: "SEC".to_string(),
            name: "LOW".to_string(),
        },
        EncryptionHint::Classic,
        None,
    )?;
    policy.add_attribute(
        QualifiedAttribute {
            dimension: "SEC".to_string(),
            name: "TOP".to_string(),
        },
        EncryptionHint::Hybridized,
        Some("LOW"),
    )?;

    policy.add_anarchy("DPT".to_string())?;
    [
        ("RD", EncryptionHint::Classic),
        ("HR", EncryptionHint::Classic),
        ("MKG", EncryptionHint::Classic),
        ("FIN", EncryptionHint::Classic),
        ("DEV", EncryptionHint::Classic),
    ]
    .into_iter()
    .try_for_each(|(attribute, hint)| {
        policy.add_attribute(
            QualifiedAttribute {
                dimension: "DPT".to_string(),
                name: attribute.to_string(),
            },
            hint,
            None,
        )
    })?;

    if complete {
        policy.add_anarchy("CTR".to_string())?;
        [
            ("EN", EncryptionHint::Classic),
            ("DE", EncryptionHint::Classic),
            ("IT", EncryptionHint::Classic),
            ("FR", EncryptionHint::Classic),
            ("SP", EncryptionHint::Classic),
        ]
        .into_iter()
        .try_for_each(|(attribute, hint)| {
            policy.add_attribute(
                QualifiedAttribute {
                    dimension: "CTR".to_string(),
                    name: attribute.to_string(),
                },
                hint,
                None,
            )
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_edit_anarchic_attributes() {
        use super::QualifiedAttribute;

        let mut structure = AccessStructure::new();
        gen_test_structure(&mut structure, false).unwrap();

        assert_eq!(structure.attributes().count(), 7);

        // Try renaming Research to already used name MKG
        assert!(
            structure
                .rename_attribute(&QualifiedAttribute::new("DPT", "RD"), "MKG".to_string(),)
                .is_err()
        );

        // Rename RD to Research
        assert!(
            structure
                .rename_attribute(&QualifiedAttribute::new("DPT", "RD"), "Research".to_string(),)
                .is_ok()
        );

        let order: Vec<_> = structure
            .attributes()
            .filter(|a| a.dimension.as_str() == "SEC")
            .map(|a| a.name)
            .collect();

        assert!(order.len() == 2);

        // Add new attribute Sales
        let new_attr = QualifiedAttribute::new("DPT", "Sales");
        assert!(structure.add_attribute(new_attr.clone(), EncryptionHint::Classic, None).is_ok());
        assert_eq!(structure.attributes().count(), 8);

        // Try adding already existing attribute HR
        let duplicate_attr = QualifiedAttribute::new("DPT", "HR");
        assert!(structure.add_attribute(duplicate_attr, EncryptionHint::Classic, None).is_err());

        // Try adding attribute to non existing dimension
        let missing_dimension = QualifiedAttribute::new("Missing", "dimension");
        assert!(
            structure
                .add_attribute(missing_dimension.clone(), EncryptionHint::Classic, None)
                .is_err()
        );

        // Remove research attribute
        let delete_attr = QualifiedAttribute::new("DPT", "Research");
        structure.del_attribute(&delete_attr).unwrap();
        assert_eq!(structure.attributes().count(), 7);

        // Duplicate remove
        assert!(structure.del_attribute(&delete_attr).is_err());

        // Missing dimension remove
        assert!(structure.del_attribute(&missing_dimension).is_err());

        // Remove all attributes from a dimension
        structure.del_attribute(&new_attr).unwrap();
        structure.del_attribute(&QualifiedAttribute::new("DPT", "HR")).unwrap();
        structure.del_attribute(&QualifiedAttribute::new("DPT", "MKG")).unwrap();

        structure.del_dimension("DPT").unwrap();

        assert_eq!(structure.dimensions().count(), 1);

        // Add new dimension
        structure.add_anarchy("DimensionTest".to_string()).unwrap();
        structure
            .add_attribute(
                QualifiedAttribute::new("DimensionTest", "Attr1"),
                EncryptionHint::Classic,
                None,
            )
            .unwrap();
        structure
            .add_attribute(
                QualifiedAttribute::new("DimensionTest", "Attr2"),
                EncryptionHint::Classic,
                None,
            )
            .unwrap();
        assert_eq!(structure.dimensions().count(), 2);

        //// Remove the new dimension
        structure.del_dimension("DimensionTest").unwrap();
        assert_eq!(structure.dimensions().count(), 1);

        //// Try removing non existing dimension
        assert!(structure.del_dimension("MissingDim").is_err());
    }

    #[test]
    fn test_edit_hierarchic_attributes() {
        use super::QualifiedAttribute;

        let mut structure = AccessStructure::new();
        gen_test_structure(&mut structure, false).unwrap();

        assert_eq!(
            structure.attributes().filter(|a| a.dimension == "SEC").collect::<Vec<_>>(),
            vec![
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                },
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                },
            ]
        );

        // Rename ordered dimension
        assert!(
            structure
                .rename_attribute(&QualifiedAttribute::new("SEC", "LOW"), "WOL".to_string(),)
                .is_ok()
        );

        let order = structure.attributes().map(|q| q.name).collect::<Vec<_>>();
        assert!(order.contains(&"WOL".to_string()));
        assert!(!order.contains(&"LOW".to_string()));

        //// Try modifying hierarchical dimension
        structure.del_attribute(&QualifiedAttribute::new("SEC", "WOL")).unwrap();

        structure
            .add_attribute(QualifiedAttribute::new("SEC", "MID"), EncryptionHint::Classic, None)
            .unwrap();

        assert_eq!(
            structure.attributes().filter(|a| a.dimension == "SEC").collect::<Vec<_>>(),
            vec![
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "MID".to_string(),
                },
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                },
            ]
        );

        structure
            .add_attribute(QualifiedAttribute::new("SEC", "LOW"), EncryptionHint::Classic, None)
            .unwrap();

        assert_eq!(
            structure.attributes().filter(|a| a.dimension == "SEC").collect::<Vec<_>>(),
            vec![
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                },
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "MID".to_string(),
                },
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                },
            ]
        );

        structure.del_attribute(&QualifiedAttribute::new("SEC", "MID")).unwrap();

        structure
            .add_attribute(
                QualifiedAttribute::new("SEC", "MID"),
                EncryptionHint::Classic,
                Some("LOW"),
            )
            .unwrap();

        assert_eq!(
            structure.attributes().filter(|a| a.dimension == "SEC").collect::<Vec<_>>(),
            vec![
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                },
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "MID".to_string(),
                },
                QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                },
            ]
        );

        //// Removing a hierarchical dimension is permitted
        structure.del_dimension("SEC").unwrap();
    }
}
