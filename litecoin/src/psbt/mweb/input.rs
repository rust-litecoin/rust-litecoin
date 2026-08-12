// SPDX-License-Identifier: CC0-1.0

use crate::bip32::KeySource;
use crate::prelude::*;
use crate::psbt::mweb::types::*;
use crate::psbt::raw;
use crate::psbt::serialize::{Deserialize as PsbtDeserialize, Serialize as PsbtSerialize};
use crate::psbt::Error;

/// MWEB fields for one PSBT input (ltcd `PInput` MWEB subset).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct MwebInput {
    /// Spent output id.
    pub output_id: Option<[u8; 32]>,
    /// Spent commitment (33 bytes).
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::serde_utils::hex_array_opt::n33")
    )]
    pub commit: Option<[u8; 33]>,
    /// Output pubkey.
    pub output_pubkey: Option<Vec<u8>>,
    /// Input pubkey.
    pub input_pubkey: Option<Vec<u8>>,
    /// Feature bits.
    pub features: Option<u8>,
    /// Input signature.
    pub signature: Option<Vec<u8>>,
    /// Address index.
    pub address_index: Option<u32>,
    /// Amount litoshis.
    pub amount: Option<u64>,
    /// Shared secret.
    pub shared_secret: Option<[u8; 32]>,
    /// Key exchange pubkey.
    pub key_exchange_pubkey: Option<Vec<u8>>,
    /// Master scan key origin (ltcd `MwebMasterScanKey`: pubkey key + BIP32 KeySource value).
    pub master_scan_key_origin: Option<(secp256k1::PublicKey, KeySource)>,
    /// Master spend key origin (ltcd `MwebMasterSpendKey`: pubkey key + BIP32 KeySource value).
    pub master_spend_key_origin: Option<(secp256k1::PublicKey, KeySource)>,
    /// Extra data.
    pub extra_data: Option<Vec<u8>>,
}

impl MwebInput {
    /// Encode as PSBT `(type, key_data, value)` triples.
    ///
    /// Most MWEB fields use empty `key_data`. Origins `0x9A`/`0x9B` use compressed pubkey
    /// as key data and BIP174 KeySource bytes as value (ltcd `partial_input.go`).
    pub fn to_kv_pairs(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut pairs = Vec::new();
        if let Some(id) = self.output_id {
            pairs.push((MWEB_SPENT_OUTPUT_ID_TYPE, Vec::new(), id.to_vec()));
        }
        if let Some(c) = self.commit {
            pairs.push((MWEB_SPENT_OUTPUT_COMMIT_TYPE, Vec::new(), c.to_vec()));
        }
        if let Some(ref p) = self.output_pubkey {
            pairs.push((MWEB_SPENT_OUTPUT_PUBKEY_TYPE, Vec::new(), p.clone()));
        }
        if let Some(ref p) = self.input_pubkey {
            pairs.push((MWEB_INPUT_PUBKEY_TYPE, Vec::new(), p.clone()));
        }
        if let Some(f) = self.features {
            pairs.push((MWEB_INPUT_FEATURES_TYPE, Vec::new(), vec![f]));
        }
        if let Some(ref s) = self.signature {
            pairs.push((MWEB_INPUT_SIGNATURE_TYPE, Vec::new(), s.clone()));
        }
        if let Some(i) = self.address_index {
            pairs.push((MWEB_ADDRESS_INDEX_TYPE, Vec::new(), i.to_le_bytes().to_vec()));
        }
        if let Some(a) = self.amount {
            pairs.push((MWEB_INPUT_AMOUNT_TYPE, Vec::new(), a.to_le_bytes().to_vec()));
        }
        if let Some(ss) = self.shared_secret {
            pairs.push((MWEB_SHARED_SECRET_TYPE, Vec::new(), ss.to_vec()));
        }
        if let Some(ref p) = self.key_exchange_pubkey {
            pairs.push((MWEB_KEY_EXCHANGE_PUBKEY_TYPE, Vec::new(), p.clone()));
        }
        if let Some((ref pk, ref ks)) = self.master_scan_key_origin {
            pairs.push((
                MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE,
                pk.serialize().to_vec(),
                PsbtSerialize::serialize(ks),
            ));
        }
        if let Some((ref pk, ref ks)) = self.master_spend_key_origin {
            pairs.push((
                MWEB_MASTER_SPEND_KEY_ORIGIN_TYPE,
                pk.serialize().to_vec(),
                PsbtSerialize::serialize(ks),
            ));
        }
        if let Some(ref e) = self.extra_data {
            pairs.push((MWEB_INPUT_EXTRA_DATA_TYPE, Vec::new(), e.clone()));
        }
        pairs
    }

    /// Encode as `(type, value)` with empty keys (legacy helper for non-origin fields).
    ///
    /// Origins are included only when their pubkey key-data is empty (never for valid
    /// ltcd-shaped origins). Prefer [`Self::to_kv_pairs`].
    pub fn to_pairs(&self) -> Vec<(u8, Vec<u8>)> {
        self.to_kv_pairs()
            .into_iter()
            .filter(|(_, key, _)| key.is_empty())
            .map(|(ty, _, val)| (ty, val))
            .collect()
    }

    /// Apply one typed field from wire `(field_ty, key_data, value)`.
    pub fn apply_kv_field(&mut self, field_ty: u8, key_data: &[u8], value: &[u8]) {
        match field_ty {
            MWEB_SPENT_OUTPUT_ID_TYPE if key_data.is_empty() && value.len() == 32 => {
                let mut id = [0u8; 32];
                id.copy_from_slice(value);
                self.output_id = Some(id);
            }
            MWEB_SPENT_OUTPUT_COMMIT_TYPE if key_data.is_empty() && value.len() == 33 => {
                let mut c = [0u8; 33];
                c.copy_from_slice(value);
                self.commit = Some(c);
            }
            MWEB_SPENT_OUTPUT_PUBKEY_TYPE if key_data.is_empty() => {
                self.output_pubkey = Some(value.to_vec())
            }
            MWEB_INPUT_PUBKEY_TYPE if key_data.is_empty() => {
                self.input_pubkey = Some(value.to_vec())
            }
            MWEB_INPUT_FEATURES_TYPE if key_data.is_empty() && !value.is_empty() => {
                self.features = Some(value[0])
            }
            MWEB_INPUT_SIGNATURE_TYPE if key_data.is_empty() => {
                self.signature = Some(value.to_vec())
            }
            MWEB_ADDRESS_INDEX_TYPE if key_data.is_empty() && value.len() == 4 => {
                self.address_index = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
            }
            MWEB_INPUT_AMOUNT_TYPE if key_data.is_empty() && value.len() == 8 => {
                self.amount = Some(u64::from_le_bytes(value[..8].try_into().unwrap()));
            }
            MWEB_SHARED_SECRET_TYPE if key_data.is_empty() && value.len() == 32 => {
                let mut ss = [0u8; 32];
                ss.copy_from_slice(value);
                self.shared_secret = Some(ss);
            }
            MWEB_KEY_EXCHANGE_PUBKEY_TYPE if key_data.is_empty() => {
                self.key_exchange_pubkey = Some(value.to_vec())
            }
            MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE => {
                if let Ok(pk) = secp256k1::PublicKey::from_slice(key_data) {
                    if let Ok(ks) = <KeySource as PsbtDeserialize>::deserialize(value) {
                        self.master_scan_key_origin = Some((pk, ks));
                    }
                }
            }
            MWEB_MASTER_SPEND_KEY_ORIGIN_TYPE => {
                if let Ok(pk) = secp256k1::PublicKey::from_slice(key_data) {
                    if let Ok(ks) = <KeySource as PsbtDeserialize>::deserialize(value) {
                        self.master_spend_key_origin = Some((pk, ks));
                    }
                }
            }
            MWEB_INPUT_EXTRA_DATA_TYPE if key_data.is_empty() => {
                self.extra_data = Some(value.to_vec())
            }
            _ => {}
        }
    }

    /// Apply one typed field with empty key data (non-origin fields).
    pub fn apply_field(&mut self, field_ty: u8, value: &[u8]) {
        self.apply_kv_field(field_ty, &[], value);
    }

    /// Build from an iterator of `(field_ty, value)` pairs (empty keys).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (u8, Vec<u8>)>) -> Self {
        let mut out = Self::default();
        for (ty, val) in pairs {
            out.apply_field(ty, &val);
        }
        out
    }

    /// Build from `(field_ty, key_data, value)` triples.
    pub fn from_kv_pairs(pairs: impl IntoIterator<Item = (u8, Vec<u8>, Vec<u8>)>) -> Self {
        let mut out = Self::default();
        for (ty, key, val) in pairs {
            out.apply_kv_field(ty, &key, &val);
        }
        out
    }

    /// Parse from a PSBT input `unknown` map (MWEB `0x90+` keys).
    pub fn from_unknown_map(unknown: &BTreeMap<raw::Key, Vec<u8>>) -> Self {
        let mut out = Self::default();
        for (k, v) in unknown {
            if (MWEB_INPUT_FIELD_MIN..=MWEB_INPUT_FIELD_MAX).contains(&k.type_value) {
                out.apply_kv_field(k.type_value, &k.key, v);
            }
        }
        out
    }

    /// Merge `other` into `self`, keeping existing values when set (BIP-174 combine semantics).
    pub fn combine(&mut self, other: Self) {
        if self.output_id.is_none() {
            self.output_id = other.output_id;
        }
        if self.commit.is_none() {
            self.commit = other.commit;
        }
        if self.output_pubkey.is_none() {
            self.output_pubkey = other.output_pubkey;
        }
        if self.input_pubkey.is_none() {
            self.input_pubkey = other.input_pubkey;
        }
        if self.features.is_none() {
            self.features = other.features;
        }
        if self.signature.is_none() {
            self.signature = other.signature;
        }
        if self.address_index.is_none() {
            self.address_index = other.address_index;
        }
        if self.amount.is_none() {
            self.amount = other.amount;
        }
        if self.shared_secret.is_none() {
            self.shared_secret = other.shared_secret;
        }
        if self.key_exchange_pubkey.is_none() {
            self.key_exchange_pubkey = other.key_exchange_pubkey;
        }
        if self.master_scan_key_origin.is_none() {
            self.master_scan_key_origin = other.master_scan_key_origin;
        }
        if self.master_spend_key_origin.is_none() {
            self.master_spend_key_origin = other.master_spend_key_origin;
        }
        if self.extra_data.is_none() {
            self.extra_data = other.extra_data;
        }
    }

    /// Validate that origin fields are either all absent or fully populated (ltcwallet shape).
    pub fn validate_key_origins(&self) -> Result<(), Error> {
        let has_scan = self.master_scan_key_origin.is_some();
        let has_spend = self.master_spend_key_origin.is_some();
        let has_idx = self.address_index.is_some();
        if has_scan && has_spend && has_idx {
            return Ok(());
        }
        if !has_scan && !has_spend && !has_idx {
            return Ok(());
        }
        Err(Error::IncompleteMwebMaps(
            "incomplete MWEB key origins (need scan, spend, and address index)",
        ))
    }
}
