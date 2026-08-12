// SPDX-License-Identifier: CC0-1.0

use io::Cursor;

use crate::consensus::encode::{self, deserialize, serialize, Decodable};
use crate::prelude::*;
use crate::psbt::mweb::types::*;
use crate::psbt::raw;
use crate::psbt::{serialize as psbt_ser, Error};

/// One MWEB kernel PSBT map (ltcd `PKernel`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct MwebKernel {
    /// Excess commitment.
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::serde_utils::hex_array_opt::n33")
    )]
    pub excess_commit: Option<[u8; 33]>,
    /// Stealth excess (33-byte compressed pubkey).
    pub stealth_commit: Option<Vec<u8>>,
    /// Fee (litoshis).
    pub fee: Option<u64>,
    /// Peg-in amount.
    pub pegin_amount: Option<u64>,
    /// Peg-out PSBT values (ltcd: repeated type-`4` KVs; each value is TxOut wire:
    /// 8-byte LE amount || script).
    pub pegouts: Vec<Vec<u8>>,
    /// Lock height.
    pub lock_height: Option<u32>,
    /// Features.
    pub features: Option<u8>,
    /// Extra data.
    pub extra_data: Option<Vec<u8>>,
    /// Signature (64 bytes).
    #[cfg_attr(
        feature = "serde",
        serde(default, with = "crate::serde_utils::hex_array_opt::n64")
    )]
    pub signature: Option<[u8; 64]>,
    /// Unknown / proprietary pairs preserved for ltcd map round-trips
    /// (`key` = type byte || keydata).
    pub unknowns: Vec<(Vec<u8>, Vec<u8>)>,
}

impl MwebKernel {
    /// Encode kernel map as typed `(field_ty, key_suffix, value)` pairs.
    ///
    /// Peg-outs use `key_suffix = [pegout_index]` (ltcd-shaped). Other fields use an empty
    /// suffix.
    pub fn to_kv_pairs(&self) -> Vec<(u8, Vec<u8>, Vec<u8>)> {
        let mut pairs = Vec::new();
        if let Some(c) = self.excess_commit {
            pairs.push((MWEB_KERNEL_EXCESS_COMMIT_TYPE, Vec::new(), c.to_vec()));
        }
        if let Some(ref c) = self.stealth_commit {
            pairs.push((MWEB_KERNEL_STEALTH_COMMIT_TYPE, Vec::new(), c.clone()));
        }
        if let Some(f) = self.fee {
            pairs.push((MWEB_KERNEL_FEE_TYPE, Vec::new(), f.to_le_bytes().to_vec()));
        }
        if let Some(a) = self.pegin_amount {
            pairs.push((
                MWEB_KERNEL_PEGIN_AMOUNT_TYPE,
                Vec::new(),
                a.to_le_bytes().to_vec(),
            ));
        }
        for (i, p) in self.pegouts.iter().enumerate() {
            pairs.push((MWEB_KERNEL_PEGOUT_TYPE, vec![i as u8], p.clone()));
        }
        if let Some(h) = self.lock_height {
            pairs.push((
                MWEB_KERNEL_LOCK_HEIGHT_TYPE,
                Vec::new(),
                h.to_le_bytes().to_vec(),
            ));
        }
        if let Some(f) = self.features {
            pairs.push((MWEB_KERNEL_FEATURES_TYPE, Vec::new(), vec![f]));
        }
        if let Some(ref e) = self.extra_data {
            pairs.push((MWEB_KERNEL_EXTRA_DATA_TYPE, Vec::new(), e.clone()));
        }
        if let Some(s) = self.signature {
            pairs.push((MWEB_KERNEL_SIGNATURE_TYPE, Vec::new(), s.to_vec()));
        }
        pairs
    }

    /// Encode as `(field_ty, value)` pairs (peg-out index is not preserved; use
    /// [`Self::to_kv_pairs`] for full fidelity).
    pub fn to_pairs(&self) -> Vec<(u8, Vec<u8>)> {
        self.to_kv_pairs()
            .into_iter()
            .map(|(ty, _, val)| (ty, val))
            .collect()
    }

    /// Apply one kernel field from wire `(field_ty, key_data, value)`.
    ///
    /// For peg-outs, `key_data` is the pegout index (ltcd); empty `key_data` appends.
    pub fn apply_field(&mut self, field_ty: u8, key_data: &[u8], value: &[u8]) {
        match field_ty {
            MWEB_KERNEL_EXCESS_COMMIT_TYPE if value.len() == 33 => {
                let mut c = [0u8; 33];
                c.copy_from_slice(value);
                self.excess_commit = Some(c);
            }
            MWEB_KERNEL_STEALTH_COMMIT_TYPE => self.stealth_commit = Some(value.to_vec()),
            MWEB_KERNEL_FEE_TYPE if value.len() == 8 => {
                self.fee = Some(u64::from_le_bytes(value[..8].try_into().unwrap()));
            }
            MWEB_KERNEL_PEGIN_AMOUNT_TYPE if value.len() == 8 => {
                self.pegin_amount = Some(u64::from_le_bytes(value[..8].try_into().unwrap()));
            }
            MWEB_KERNEL_PEGOUT_TYPE => {
                let idx = if key_data.is_empty() {
                    self.pegouts.len()
                } else {
                    key_data[0] as usize
                };
                while self.pegouts.len() <= idx {
                    self.pegouts.push(Vec::new());
                }
                self.pegouts[idx] = value.to_vec();
            }
            MWEB_KERNEL_LOCK_HEIGHT_TYPE if value.len() == 4 => {
                self.lock_height = Some(u32::from_le_bytes(value[..4].try_into().unwrap()));
            }
            MWEB_KERNEL_FEATURES_TYPE if !value.is_empty() => self.features = Some(value[0]),
            MWEB_KERNEL_EXTRA_DATA_TYPE => self.extra_data = Some(value.to_vec()),
            MWEB_KERNEL_SIGNATURE_TYPE if value.len() == 64 => {
                let mut s = [0u8; 64];
                s.copy_from_slice(value);
                self.signature = Some(s);
            }
            _ => {}
        }
    }

    /// Build from an iterator of `(field_ty, value)` pairs (peg-outs append in order).
    pub fn from_pairs(pairs: impl IntoIterator<Item = (u8, Vec<u8>)>) -> Self {
        let mut out = Self::default();
        for (ty, val) in pairs {
            out.apply_field(ty, &[], &val);
        }
        out
    }

    /// Merge `other` into `self`, keeping existing values when set.
    pub fn combine(&mut self, other: Self) {
        if self.excess_commit.is_none() {
            self.excess_commit = other.excess_commit;
        }
        if self.stealth_commit.is_none() {
            self.stealth_commit = other.stealth_commit;
        }
        if self.fee.is_none() {
            self.fee = other.fee;
        }
        if self.pegin_amount.is_none() {
            self.pegin_amount = other.pegin_amount;
        }
        if self.pegouts.is_empty() {
            self.pegouts = other.pegouts;
        }
        if self.lock_height.is_none() {
            self.lock_height = other.lock_height;
        }
        if self.features.is_none() {
            self.features = other.features;
        }
        if self.extra_data.is_none() {
            self.extra_data = other.extra_data;
        }
        if self.signature.is_none() {
            self.signature = other.signature;
        }
        if self.unknowns.is_empty() {
            self.unknowns = other.unknowns;
        }
    }

    /// Deserialize an ltcd-style standalone kernel PSBT map (pairs + `0x00` separator).
    pub fn deserialize_ltcd_map(data: &[u8]) -> Result<Self, Error> {
        let mut decoder = Cursor::new(data);
        let mut out = Self::default();
        loop {
            match raw::Pair::decode(&mut decoder) {
                Ok(pair) => {
                    if pair.key.type_value <= MWEB_KERNEL_SIGNATURE_TYPE {
                        out.apply_field(pair.key.type_value, &pair.key.key, &pair.value);
                    } else {
                        let mut full_key = vec![pair.key.type_value];
                        full_key.extend_from_slice(&pair.key.key);
                        out.unknowns.push((full_key, pair.value));
                    }
                }
                Err(Error::NoMorePairs) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }

    /// Serialize as an ltcd-style standalone kernel PSBT map (pairs + `0x00` separator).
    pub fn serialize_ltcd_map(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for (field_ty, key_suffix, value) in self.to_kv_pairs() {
            let pair = raw::Pair {
                key: raw::Key {
                    type_value: field_ty,
                    key: key_suffix,
                },
                value,
            };
            buf.extend(psbt_ser::Serialize::serialize(&pair));
        }
        for (full_key, value) in &self.unknowns {
            if full_key.is_empty() {
                continue;
            }
            let pair = raw::Pair {
                key: raw::Key {
                    type_value: full_key[0],
                    key: full_key[1..].to_vec(),
                },
                value: value.clone(),
            };
            buf.extend(psbt_ser::Serialize::serialize(&pair));
        }
        buf.push(0x00); // map separator
        buf
    }
}

/// Decode one PSBT peg-out value (ltcd TxOut wire: 8-byte LE amount || script).
pub fn pegout_coin_from_psbt_value(raw: &[u8]) -> Result<crate::blockdata::mimblewimble::PegOutCoin, Error> {
    if raw.len() < 8 {
        return Err(Error::IncompleteMwebMaps("kernel pegout value too short"));
    }
    let amount = i64::from_le_bytes(raw[..8].try_into().unwrap());
    let script_pub_key = deserialize(&raw[8..]).map_err(Error::ConsensusEncoding)?;
    Ok(crate::blockdata::mimblewimble::PegOutCoin {
        amount,
        script_pub_key,
    })
}

/// Encode one [`PegOutCoin`](crate::blockdata::mimblewimble::PegOutCoin) as a PSBT peg-out value.
pub fn pegout_psbt_value(coin: &crate::blockdata::mimblewimble::PegOutCoin) -> Vec<u8> {
    let mut v = (coin.amount as u64).to_le_bytes().to_vec();
    v.extend(serialize(&coin.script_pub_key));
    v
}

// Silence unused-import warning when serde is off and encode helpers are only used above.
#[allow(dead_code)]
fn _encode_unused_guard() -> Result<(), encode::Error> {
    let _: u8 = Decodable::consensus_decode(&mut Cursor::new([0u8].as_slice()))?;
    Ok(())
}
