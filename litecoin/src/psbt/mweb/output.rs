// SPDX-License-Identifier: CC0-1.0

use crate::prelude::*;
use crate::psbt::raw;
use crate::psbt::mweb::types::*;

/// MWEB fields for one PSBT output.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct MwebOutput {
    /// Stealth address bytes (66 bytes: scan pubkey || spend pubkey).
    pub stealth_address: Option<Vec<u8>>,
    /// Commitment.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::serde_utils::hex_array_opt::n33")
    )]
    pub commit: Option<[u8; 33]>,
    /// Features.
    pub features: Option<u8>,
    /// Sender pubkey.
    pub sender_pubkey: Option<Vec<u8>>,
    /// Output pubkey.
    pub output_pubkey: Option<Vec<u8>>,
    /// Standard fields blob.
    pub standard_fields: Option<Vec<u8>>,
    /// Range proof.
    pub range_proof: Option<Vec<u8>>,
    /// Signature.
    pub signature: Option<Vec<u8>>,
    /// Extra data.
    pub extra_data: Option<Vec<u8>>,
}

impl MwebOutput {
    /// Encode as PSBT key-value pairs (`0x90+`, empty key).
    pub fn to_pairs(&self) -> Vec<(u8, Vec<u8>)> {
        let mut pairs = Vec::new();
        if let Some(ref a) = self.stealth_address {
            pairs.push((MWEB_STEALTH_ADDRESS_OUTPUT_TYPE, a.clone()));
        }
        if let Some(c) = self.commit {
            pairs.push((MWEB_COMMIT_OUTPUT_TYPE, c.to_vec()));
        }
        if let Some(f) = self.features {
            pairs.push((MWEB_FEATURES_OUTPUT_TYPE, vec![f]));
        }
        if let Some(ref p) = self.sender_pubkey {
            pairs.push((MWEB_SENDER_PUBKEY_OUTPUT_TYPE, p.clone()));
        }
        if let Some(ref p) = self.output_pubkey {
            pairs.push((MWEB_OUTPUT_PUBKEY_OUTPUT_TYPE, p.clone()));
        }
        if let Some(ref s) = self.standard_fields {
            pairs.push((MWEB_STANDARD_FIELDS_OUTPUT_TYPE, s.clone()));
        }
        if let Some(ref r) = self.range_proof {
            pairs.push((MWEB_RANGE_PROOF_OUTPUT_TYPE, r.clone()));
        }
        if let Some(ref s) = self.signature {
            pairs.push((MWEB_SIGNATURE_OUTPUT_TYPE, s.clone()));
        }
        if let Some(ref e) = self.extra_data {
            pairs.push((MWEB_EXTRA_DATA_OUTPUT_TYPE, e.clone()));
        }
        pairs
    }

    /// Apply one typed output field.
    pub fn apply_field(&mut self, field_ty: u8, value: &[u8]) {
        match field_ty {
            MWEB_STEALTH_ADDRESS_OUTPUT_TYPE => self.stealth_address = Some(value.to_vec()),
            MWEB_COMMIT_OUTPUT_TYPE if value.len() == 33 => {
                let mut c = [0u8; 33];
                c.copy_from_slice(value);
                self.commit = Some(c);
            }
            MWEB_FEATURES_OUTPUT_TYPE if !value.is_empty() => self.features = Some(value[0]),
            MWEB_SENDER_PUBKEY_OUTPUT_TYPE => self.sender_pubkey = Some(value.to_vec()),
            MWEB_OUTPUT_PUBKEY_OUTPUT_TYPE => self.output_pubkey = Some(value.to_vec()),
            MWEB_STANDARD_FIELDS_OUTPUT_TYPE => self.standard_fields = Some(value.to_vec()),
            MWEB_RANGE_PROOF_OUTPUT_TYPE => self.range_proof = Some(value.to_vec()),
            MWEB_SIGNATURE_OUTPUT_TYPE => self.signature = Some(value.to_vec()),
            MWEB_EXTRA_DATA_OUTPUT_TYPE => self.extra_data = Some(value.to_vec()),
            _ => {}
        }
    }

    /// Build from an iterator of `(field_ty, value)` pairs.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (u8, Vec<u8>)>) -> Self {
        let mut out = Self::default();
        for (ty, val) in pairs {
            out.apply_field(ty, &val);
        }
        out
    }

    /// Parse from a PSBT output `unknown` map (MWEB `0x90+` keys with empty key only).
    pub fn from_unknown_map(unknown: &BTreeMap<raw::Key, Vec<u8>>) -> Self {
        let mut out = Self::default();
        for (k, v) in unknown {
            if !k.key.is_empty() {
                continue;
            }
            if (MWEB_OUTPUT_FIELD_MIN..=MWEB_OUTPUT_FIELD_MAX).contains(&k.type_value) {
                out.apply_field(k.type_value, v);
            }
        }
        out
    }

    /// Merge `other` into `self`, keeping existing values when set.
    pub fn combine(&mut self, other: Self) {
        if self.stealth_address.is_none() {
            self.stealth_address = other.stealth_address;
        }
        if self.commit.is_none() {
            self.commit = other.commit;
        }
        if self.features.is_none() {
            self.features = other.features;
        }
        if self.sender_pubkey.is_none() {
            self.sender_pubkey = other.sender_pubkey;
        }
        if self.output_pubkey.is_none() {
            self.output_pubkey = other.output_pubkey;
        }
        if self.standard_fields.is_none() {
            self.standard_fields = other.standard_fields;
        }
        if self.range_proof.is_none() {
            self.range_proof = other.range_proof;
        }
        if self.signature.is_none() {
            self.signature = other.signature;
        }
        if self.extra_data.is_none() {
            self.extra_data = other.extra_data;
        }
    }
}
