// SPDX-License-Identifier: CC0-1.0

//! Litecoin MimbleWimble (MWEB) transaction types.
//!
//! Implements the subset of MWEB needed to parse and serialize transactions, kernels, inputs and
//! outputs as they appear inside a Litecoin block. The cryptographic verification (range proofs,
//! kernel signatures, Pedersen commitment balancing) is out of scope; this module only covers the
//! wire format.

#![allow(missing_docs)]

use io::{Read, Write};
use secp256k1::PublicKey;

use crate::blockdata::script::ScriptBuf;
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::prelude::*;
use crate::VarInt;

// NOTE: MWEB types intentionally do not derive `serde::{Serialize, Deserialize}`. They contain
// large fixed-size byte arrays (`[u8; 64]` signatures, `[u8; 675]` range proofs) that serde does
// not auto-derive for, and the consensus encoding is the canonical wire format. Use
// `consensus::serialize` / `consensus::deserialize` to round-trip them.

/// Kernel feature bits.
pub enum KernelFeatures {
    FeeFeatureBit = 0x01,
    PeginFeatureBit = 0x02,
    PegoutFeatureBit = 0x04,
    HeightLockFeatureBit = 0x08,
    StealthExcessFeatureBit = 0x10,
    ExtraDataFeatureBit = 0x20,
}

/// Output feature bits.
pub enum OutputFeatures {
    StandardFieldsFeatureBit = 0x01,
    ExtraDataFeatureBit = 0x02,
}

/// Standard "encrypted" fields embedded in an [`OutputMessage`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct OutputMessageStandardFields {
    pub key_exchange_pubkey: PublicKey,
    pub view_tag: u8,
    pub masked_value: u64,
    pub masked_nonce: [u8; 16],
}

/// Encrypted/embedded payload of an MWEB [`Output`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct OutputMessage {
    pub features: u8,
    pub standard_fields: Option<OutputMessageStandardFields>,
    pub extra_data: Vec<u8>,
}

/// An MWEB output.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Output {
    pub commitment: [u8; 33],
    pub sender_public_key: PublicKey,
    pub receiver_public_key: PublicKey,
    pub message: OutputMessage,
    pub range_proof: [u8; 675],
    pub signature: [u8; 64],
}

/// An MWEB input (spending a previously-created [`Output`]).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Input {
    pub features: u8,
    pub output_id: [u8; 32],
    pub commitment: [u8; 33],
    pub input_public_key: Option<PublicKey>,
    pub output_public_key: PublicKey,
    pub extra_data: Vec<u8>,
    pub signature: [u8; 64],
}

/// Peg-out coin: a destination on the regular Litecoin UTXO set funded by an MWEB kernel.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct PegOutCoin {
    pub amount: i64,
    pub script_pub_key: ScriptBuf,
}

/// An MWEB kernel: signs the offset/excess that proves balance for a transaction.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Kernel {
    pub features: u8,
    pub fee: Option<i64>,
    pub pegin: Option<i64>,
    pub pegouts: Vec<PegOutCoin>,
    pub lock_height: Option<u32>,
    pub stealth_excess: Option<PublicKey>,
    pub extra_data: Vec<u8>,
    /// Remainder of the sum of all transaction commitments. If the transaction is well-formed,
    /// the amount components sum to zero and the excess is hence a valid public key.
    pub excess: [u8; 33],
    /// Signature proving the excess is a valid public key; signs the kernel commitments.
    pub signature: [u8; 64],
}

/// The body of an MWEB transaction (or extension block): inputs, outputs, and kernels.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct TxBody {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub kernels: Vec<Kernel>,
}

/// A full MWEB transaction as embedded inside a regular Litecoin transaction with segwit flag 9
/// (or, with flag 8, as a peg-in container with no MW body).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Transaction {
    pub kernel_offset: [u8; 32],
    pub stealth_offset: [u8; 32],
    pub body: TxBody,
}

// ----- Helpers -----------------------------------------------------------------------------------

/// Decode the LTC Core "CompactSize"-style varint used for MWEB amounts (kernel fee, pegin,
/// pegout, height-lock). This is the same encoding `WriteVarInt` produces in litecoind
/// (`src/serialize.h`). Overflow is rejected the same way Litecoin Core does it: if shifting
/// `n << 7` would lose set bits, the encoding is malformed.
pub(crate) fn read_amount<R: Read + ?Sized>(reader: &mut R) -> Result<i64, encode::Error> {
    let mut n: i64 = 0;
    loop {
        let ch_data = u8::consensus_decode(reader)?;
        // Reject overlong / out-of-range encodings before shifting (mirrors LTC Core's
        // `(n > (std::numeric_limits<I>::max() >> 7))` check).
        if n > (i64::MAX >> 7) {
            return Err(encode::Error::ParseFailed("MWEB varint overflow"));
        }
        n = (n << 7) | ((ch_data & 0x7f) as i64);
        if (ch_data & 0x80) != 0 {
            n = n.checked_add(1).ok_or(encode::Error::ParseFailed("MWEB varint overflow"))?;
        } else {
            return Ok(n);
        }
    }
}

/// Encode an `i64` in LTC Core's MWEB CompactSize varint format.
pub(crate) fn write_amount<W: Write + ?Sized>(
    amount: i64,
    writer: &mut W,
) -> Result<usize, io::Error> {
    let mut n = amount;
    const SIZE: usize = 10;
    let mut tmp = [0u8; SIZE];
    let mut len = 0;
    loop {
        let a = (n & 0x7f) as u8;
        let b = if len != 0 { 0x80 } else { 0x00 };
        tmp[len] = a | b;
        if n <= 0x7f {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    len += 1;
    for i in (0..len).rev() {
        u8::consensus_encode(&tmp[i], writer)?;
    }
    Ok(len)
}

/// Read a CompactSize-style varint as a `u64`. Used for inline length fields in MWEB block
/// headers (`output_mmr_size`, `kernel_mmr_size`) and the height field. This is **not** the same
/// as Bitcoin's `VarInt`; it matches litecoind's `WriteVarInt` in `serialize.h`.
pub(crate) fn read_compact_varint<R: Read + ?Sized>(reader: &mut R) -> Result<u64, encode::Error> {
    let mut n: u64 = 0;
    loop {
        let ch_data = u8::consensus_decode(reader)?;
        // Mirror LTC Core's pre-shift overflow check.
        if n > (u64::MAX >> 7) {
            return Err(encode::Error::ParseFailed("MWEB varint overflow"));
        }
        n = (n << 7) | ((ch_data & 0x7f) as u64);
        if (ch_data & 0x80) != 0 {
            n = n.checked_add(1).ok_or(encode::Error::ParseFailed("MWEB varint overflow"))?;
        } else {
            return Ok(n);
        }
    }
}

/// Encode a `u64` in MWEB CompactSize varint format.
pub(crate) fn write_compact_varint<W: Write + ?Sized>(
    value: u64,
    writer: &mut W,
) -> Result<usize, io::Error> {
    let mut n = value;
    const SIZE: usize = 10;
    let mut tmp = [0u8; SIZE];
    let mut len = 0;
    loop {
        let a = (n & 0x7f) as u8;
        let b = if len != 0 { 0x80 } else { 0x00 };
        tmp[len] = a | b;
        if n <= 0x7f {
            break;
        }
        n = (n >> 7) - 1;
        len += 1;
    }
    len += 1;
    for i in (0..len).rev() {
        u8::consensus_encode(&tmp[i], writer)?;
    }
    Ok(len)
}

fn read_array_len<R: Read + ?Sized>(reader: &mut R) -> Result<u64, encode::Error> {
    Ok(VarInt::consensus_decode(reader)?.0)
}

// ----- Encodable / Decodable impls --------------------------------------------------------------

impl Decodable for PegOutCoin {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let amount = read_amount(r)?;
        let script_pub_key = ScriptBuf::consensus_decode_from_finite_reader(r)?;
        // Mirror Litecoin Core PegOutCoin Unserialize: empty destinations are invalid on the wire.
        if script_pub_key.is_empty() {
            return Err(encode::Error::ParseFailed("Pegout scriptPubKey must not be empty"));
        }
        Ok(PegOutCoin { amount, script_pub_key })
    }
}

impl Encodable for PegOutCoin {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += write_amount(self.amount, w)?;
        len += self.script_pub_key.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for Kernel {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(r)?;
        let fee = if features & KernelFeatures::FeeFeatureBit as u8 != 0 {
            Some(read_amount(r)?)
        } else {
            None
        };
        let pegin = if features & KernelFeatures::PeginFeatureBit as u8 != 0 {
            Some(read_amount(r)?)
        } else {
            None
        };
        let mut pegouts = Vec::<PegOutCoin>::new();
        if features & KernelFeatures::PegoutFeatureBit as u8 != 0 {
            let n = read_array_len(r)?;
            // Do NOT `reserve(n as usize)` — `n` is attacker-controlled. Each PegOutCoin
            // decode pulls bytes from the (finite) reader, so unreachable elements naturally
            // fail with `Error::Io` instead of triggering a 16 GiB up-front allocation.
            for _ in 0..n {
                pegouts.push(PegOutCoin::consensus_decode_from_finite_reader(r)?);
            }
        }
        let lock_height = if features & KernelFeatures::HeightLockFeatureBit as u8 != 0 {
            // LTC Core stores lock_height as a varint; truncating to i32 would silently lose
            // any value above ~2.1 billion. Reject those as malformed.
            let raw = read_amount(r)?;
            if raw < 0 || raw > u32::MAX as i64 {
                return Err(encode::Error::ParseFailed(
                    "Kernel lock_height out of range",
                ));
            }
            Some(raw as u32)
        } else {
            None
        };
        let stealth_excess = if features & KernelFeatures::StealthExcessFeatureBit as u8 != 0 {
            let bytes: [u8; 33] = Decodable::consensus_decode(r)?;
            Some(
                PublicKey::from_slice(&bytes)
                    .map_err(|_| encode::Error::ParseFailed("invalid kernel stealth excess"))?,
            )
        } else {
            None
        };
        let extra_data = if features & KernelFeatures::ExtraDataFeatureBit as u8 != 0 {
            Vec::<u8>::consensus_decode_from_finite_reader(r)?
        } else {
            Vec::new()
        };
        let excess: [u8; 33] = Decodable::consensus_decode(r)?;
        let signature: [u8; 64] = Decodable::consensus_decode(r)?;
        Ok(Kernel {
            features,
            fee,
            pegin,
            pegouts,
            lock_height,
            stealth_excess,
            extra_data,
            excess,
            signature,
        })
    }
}

impl Encodable for Kernel {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        fn missing(what: &'static str) -> io::Error {
            io::Error::new(io::ErrorKind::Other, what)
        }
        let mut len = 0;
        len += self.features.consensus_encode(w)?;
        if self.features & KernelFeatures::FeeFeatureBit as u8 != 0 {
            let fee = self.fee.ok_or_else(|| missing("Kernel.fee bit set but None"))?;
            len += write_amount(fee, w)?;
        }
        if self.features & KernelFeatures::PeginFeatureBit as u8 != 0 {
            let pegin = self.pegin.ok_or_else(|| missing("Kernel.pegin bit set but None"))?;
            len += write_amount(pegin, w)?;
        }
        if self.features & KernelFeatures::PegoutFeatureBit as u8 != 0 {
            len += VarInt(self.pegouts.len() as u64).consensus_encode(w)?;
            for p in &self.pegouts {
                len += p.consensus_encode(w)?;
            }
        }
        if self.features & KernelFeatures::HeightLockFeatureBit as u8 != 0 {
            let lh = self
                .lock_height
                .ok_or_else(|| missing("Kernel.lock_height bit set but None"))?;
            len += write_amount(lh as i64, w)?;
        }
        if self.features & KernelFeatures::StealthExcessFeatureBit as u8 != 0 {
            let excess = self
                .stealth_excess
                .ok_or_else(|| missing("Kernel.stealth_excess bit set but None"))?;
            len += excess.serialize().consensus_encode(w)?;
        }
        if self.features & KernelFeatures::ExtraDataFeatureBit as u8 != 0 {
            len += self.extra_data.consensus_encode(w)?;
        }
        len += self.excess.consensus_encode(w)?;
        len += self.signature.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for Input {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(r)?;
        let output_id: [u8; 32] = Decodable::consensus_decode(r)?;
        let commitment: [u8; 33] = Decodable::consensus_decode(r)?;
        let output_pubkey_bytes: [u8; 33] = Decodable::consensus_decode(r)?;
        let output_public_key = PublicKey::from_slice(&output_pubkey_bytes)
            .map_err(|_| encode::Error::ParseFailed("invalid input output_public_key"))?;
        let input_public_key = if features & 1 != 0 {
            let bytes: [u8; 33] = Decodable::consensus_decode(r)?;
            Some(
                PublicKey::from_slice(&bytes)
                    .map_err(|_| encode::Error::ParseFailed("invalid input input_public_key"))?,
            )
        } else {
            None
        };
        let extra_data = if features & 2 != 0 {
            Vec::<u8>::consensus_decode_from_finite_reader(r)?
        } else {
            Vec::new()
        };
        let signature: [u8; 64] = Decodable::consensus_decode(r)?;
        Ok(Input {
            features,
            output_id,
            commitment,
            input_public_key,
            output_public_key,
            extra_data,
            signature,
        })
    }
}

impl Encodable for Input {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(w)?;
        len += self.output_id.consensus_encode(w)?;
        len += self.commitment.consensus_encode(w)?;
        len += self.output_public_key.serialize().consensus_encode(w)?;
        if self.features & 1 != 0 {
            let ipk = self.input_public_key.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "Input.input_public_key bit set but None",
                )
            })?;
            len += ipk.serialize().consensus_encode(w)?;
        }
        if self.features & 2 != 0 {
            len += self.extra_data.consensus_encode(w)?;
        }
        len += self.signature.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for Output {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let commitment: [u8; 33] = Decodable::consensus_decode(r)?;
        let sender_bytes: [u8; 33] = Decodable::consensus_decode(r)?;
        let sender_public_key = PublicKey::from_slice(&sender_bytes)
            .map_err(|_| encode::Error::ParseFailed("invalid output sender_public_key"))?;
        let receiver_bytes: [u8; 33] = Decodable::consensus_decode(r)?;
        let receiver_public_key = PublicKey::from_slice(&receiver_bytes)
            .map_err(|_| encode::Error::ParseFailed("invalid output receiver_public_key"))?;
        let message = OutputMessage::consensus_decode_from_finite_reader(r)?;
        let range_proof: [u8; 675] = Decodable::consensus_decode(r)?;
        let signature: [u8; 64] = Decodable::consensus_decode(r)?;
        Ok(Output {
            commitment,
            sender_public_key,
            receiver_public_key,
            message,
            range_proof,
            signature,
        })
    }
}

impl Encodable for Output {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.commitment.consensus_encode(w)?;
        len += self.sender_public_key.serialize().consensus_encode(w)?;
        len += self.receiver_public_key.serialize().consensus_encode(w)?;
        len += self.message.consensus_encode(w)?;
        len += self.range_proof.consensus_encode(w)?;
        len += self.signature.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for OutputMessage {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let features = u8::consensus_decode(r)?;
        let standard_fields = if features & OutputFeatures::StandardFieldsFeatureBit as u8 != 0 {
            let bytes: [u8; 33] = Decodable::consensus_decode(r)?;
            let key_exchange_pubkey = PublicKey::from_slice(&bytes)
                .map_err(|_| encode::Error::ParseFailed("invalid output key_exchange_pubkey"))?;
            let view_tag = u8::consensus_decode(r)?;
            let masked_value = u64::consensus_decode(r)?;
            let masked_nonce: [u8; 16] = Decodable::consensus_decode(r)?;
            Some(OutputMessageStandardFields {
                key_exchange_pubkey,
                view_tag,
                masked_value,
                masked_nonce,
            })
        } else {
            None
        };
        let extra_data = if features & OutputFeatures::ExtraDataFeatureBit as u8 != 0 {
            Vec::<u8>::consensus_decode_from_finite_reader(r)?
        } else {
            Vec::new()
        };
        Ok(OutputMessage { features, standard_fields, extra_data })
    }
}

impl Encodable for OutputMessage {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.features.consensus_encode(w)?;
        if let Some(fields) = &self.standard_fields {
            len += fields.key_exchange_pubkey.serialize().consensus_encode(w)?;
            len += fields.view_tag.consensus_encode(w)?;
            len += fields.masked_value.consensus_encode(w)?;
            len += fields.masked_nonce.consensus_encode(w)?;
        }
        if self.features & OutputFeatures::ExtraDataFeatureBit as u8 != 0 {
            len += self.extra_data.consensus_encode(w)?;
        }
        Ok(len)
    }
}

impl Decodable for TxBody {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let inputs = Vec::<Input>::consensus_decode_from_finite_reader(r)?;
        let outputs = Vec::<Output>::consensus_decode_from_finite_reader(r)?;
        let kernels = Vec::<Kernel>::consensus_decode_from_finite_reader(r)?;
        Ok(TxBody { inputs, outputs, kernels })
    }
}

impl Encodable for TxBody {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.inputs.consensus_encode(w)?;
        len += self.outputs.consensus_encode(w)?;
        len += self.kernels.consensus_encode(w)?;
        Ok(len)
    }
}

impl Decodable for Transaction {
    fn consensus_decode_from_finite_reader<R: Read + ?Sized>(
        r: &mut R,
    ) -> Result<Self, encode::Error> {
        let kernel_offset: [u8; 32] = Decodable::consensus_decode(r)?;
        let stealth_offset: [u8; 32] = Decodable::consensus_decode(r)?;
        let body = TxBody::consensus_decode_from_finite_reader(r)?;
        // Litecoin Core asserts an MWEB transaction has at least one kernel
        // (libmw `Transaction::FromUnsignedTx` / `mw::Transaction::Validate`).
        if body.kernels.is_empty() {
            return Err(encode::Error::ParseFailed(
                "MWEB transaction must contain at least one kernel",
            ));
        }
        Ok(Transaction { kernel_offset, stealth_offset, body })
    }
}

impl Encodable for Transaction {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.kernel_offset.consensus_encode(w)?;
        len += self.stealth_offset.consensus_encode(w)?;
        len += self.body.consensus_encode(w)?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{deserialize, serialize};

    #[test]
    fn amount_roundtrip() {
        for amount in [
            0i64,
            1,
            127,
            128,
            255,
            256,
            1000,
            1_000_000,
            100_000_000,            // 1 LTC
            8_400_000_000_000_000,  // 84M LTC supply cap
            i64::MAX,
        ] {
            let mut buf = Vec::new();
            let n = write_amount(amount, &mut buf).unwrap();
            assert_eq!(n, buf.len(), "len mismatch for {amount}");
            let decoded = read_amount(&mut &buf[..]).unwrap();
            assert_eq!(decoded, amount, "decode mismatch for {amount}");
        }
    }

    #[test]
    fn compact_varint_roundtrip() {
        for v in [0u64, 1, 127, 128, 255, 256, 1000, 1 << 32, u64::MAX - 1] {
            let mut buf = Vec::new();
            write_compact_varint(v, &mut buf).unwrap();
            let decoded = read_compact_varint(&mut &buf[..]).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn pegout_coin_roundtrip() {
        let coin = PegOutCoin {
            amount: 100_000_000,
            script_pub_key: ScriptBuf::from_hex(
                "76a91413c60d8e68d7349f5b4ca362c3954b15045061b188ac",
            )
            .unwrap(),
        };
        let encoded = serialize(&coin);
        let decoded: PegOutCoin = deserialize(&encoded).unwrap();
        assert_eq!(coin, decoded);
    }

    #[test]
    fn pegout_coin_empty_script_rejected() {
        // amount varint=1, then Bitcoin CompactSize script length 0 (Core rejects on read).
        let buf = vec![0x01, 0x00];
        match deserialize::<PegOutCoin>(&buf) {
            Err(encode::Error::ParseFailed(msg)) => {
                assert_eq!(msg, "Pegout scriptPubKey must not be empty")
            }
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }

    #[test]
    fn kernel_minimal_features_roundtrip() {
        let kernel = Kernel {
            features: KernelFeatures::FeeFeatureBit as u8,
            fee: Some(1000),
            pegin: None,
            pegouts: vec![],
            lock_height: None,
            stealth_excess: None,
            extra_data: vec![],
            excess: [1u8; 33],
            signature: [2u8; 64],
        };
        let encoded = serialize(&kernel);
        let decoded: Kernel = deserialize(&encoded).unwrap();
        assert_eq!(kernel, decoded);
    }

    #[test]
    fn kernel_height_lock_roundtrip() {
        let kernel = Kernel {
            features: KernelFeatures::HeightLockFeatureBit as u8,
            fee: None,
            pegin: None,
            pegouts: vec![],
            lock_height: Some(2_257_920), // approximate MWEB activation height on mainnet
            stealth_excess: None,
            extra_data: vec![],
            excess: [0u8; 33],
            signature: [0u8; 64],
        };
        let encoded = serialize(&kernel);
        let decoded: Kernel = deserialize(&encoded).unwrap();
        assert_eq!(decoded.lock_height, kernel.lock_height);
        assert_eq!(decoded, kernel);
    }

    #[test]
    fn lock_height_above_u32_max_rejected() {
        // Wire: features = HeightLockFeatureBit, then a height-lock varint encoding 2^32
        // (one above u32::MAX). Decoder must reject without panicking or wrapping.
        let mut buf = Vec::new();
        (KernelFeatures::HeightLockFeatureBit as u8).consensus_encode(&mut buf).unwrap();
        write_amount(1i64 << 32, &mut buf).unwrap();
        match deserialize::<Kernel>(&buf) {
            Err(encode::Error::ParseFailed(msg)) => assert_eq!(msg, "Kernel lock_height out of range"),
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }

    #[test]
    fn kernel_encoder_rejects_inconsistent_feature_bits() {
        // FeeFeatureBit set but fee is None — encoder must return an error, not panic.
        let kernel = Kernel {
            features: KernelFeatures::FeeFeatureBit as u8,
            fee: None,
            pegin: None,
            pegouts: vec![],
            lock_height: None,
            stealth_excess: None,
            extra_data: vec![],
            excess: [0u8; 33],
            signature: [0u8; 64],
        };
        let mut buf = Vec::new();
        let err = kernel.consensus_encode(&mut buf).expect_err("must error");
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn invalid_stealth_excess_returns_parse_error() {
        let mut buf = Vec::new();
        (KernelFeatures::StealthExcessFeatureBit as u8).consensus_encode(&mut buf).unwrap();
        [0u8; 33].consensus_encode(&mut buf).unwrap(); // all-zero pubkey is invalid
        [0u8; 33].consensus_encode(&mut buf).unwrap();
        [0u8; 64].consensus_encode(&mut buf).unwrap();
        match deserialize::<Kernel>(&buf) {
            Err(encode::Error::ParseFailed(msg)) => assert_eq!(msg, "invalid kernel stealth excess"),
            other => panic!("expected ParseFailed, got {other:?}"),
        }
    }
}
