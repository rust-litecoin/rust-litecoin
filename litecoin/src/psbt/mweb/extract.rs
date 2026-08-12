// SPDX-License-Identifier: CC0-1.0

use secp256k1::PublicKey;

use crate::blockdata::mimblewimble::{
    self, Input, Kernel, Output, OutputMessage, OutputMessageStandardFields,
    Transaction as MwebTransaction,
};
use crate::prelude::*;
use crate::psbt::Error;
use crate::psbt::mweb::{MwebInput, MwebKernel, MwebOutput};

/// Assemble a wire [`mimblewimble::Transaction`] from typed PSBT MWEB maps.
///
/// Cryptographic validity (range proofs, kernel signatures, balance) is not checked.
pub fn assemble_mw_tx(
    kernel_offset: [u8; 32],
    stealth_offset: [u8; 32],
    inputs: &[MwebInput],
    outputs: &[MwebOutput],
    kernels: &[MwebKernel],
) -> Result<MwebTransaction, Error> {
    let mut wire_inputs = Vec::with_capacity(inputs.len());
    for inp in inputs {
        wire_inputs.push(wire_input_from_map(inp)?);
    }
    let mut wire_outputs = Vec::with_capacity(outputs.len());
    for out in outputs {
        wire_outputs.push(wire_output_from_map(out)?);
    }
    let mut wire_kernels = Vec::with_capacity(kernels.len());
    for k in kernels {
        wire_kernels.push(wire_kernel_from_map(k)?);
    }
    Ok(MwebTransaction {
        kernel_offset,
        stealth_offset,
        body: mimblewimble::TxBody {
            inputs: wire_inputs,
            outputs: wire_outputs,
            kernels: wire_kernels,
        },
    })
}

pub(crate) fn wire_input_from_map(inp: &MwebInput) -> Result<Input, Error> {
    let output_id = inp
        .output_id
        .ok_or(Error::IncompleteMwebMaps("input map missing output_id"))?;
    let commitment = inp
        .commit
        .ok_or(Error::IncompleteMwebMaps("input map missing commit"))?;
    let features = inp.features.unwrap_or(0);
    let output_public_key = PublicKey::from_slice(
        inp.output_pubkey
            .as_ref()
            .ok_or(Error::IncompleteMwebMaps("input map missing output_pubkey"))?,
    )
    .map_err(|_| Error::InvalidSecp256k1PublicKey(secp256k1::Error::InvalidPublicKey))?;
    let input_public_key = match &inp.input_pubkey {
        Some(b) => Some(
            PublicKey::from_slice(b)
                .map_err(|_| Error::InvalidSecp256k1PublicKey(secp256k1::Error::InvalidPublicKey))?,
        ),
        None => None,
    };
    let mut signature = [0u8; 64];
    let sig = inp
        .signature
        .as_ref()
        .ok_or(Error::IncompleteMwebMaps("input map missing signature"))?;
    if sig.len() != 64 {
        return Err(Error::IncompleteMwebMaps("input signature must be 64 bytes"));
    }
    signature.copy_from_slice(sig);
    Ok(Input {
        features,
        output_id,
        commitment,
        input_public_key,
        output_public_key,
        extra_data: inp.extra_data.clone().unwrap_or_default(),
        signature,
    })
}

pub(crate) fn wire_output_from_map(out: &MwebOutput) -> Result<Output, Error> {
    let commitment = out
        .commit
        .ok_or(Error::IncompleteMwebMaps("output map missing commit"))?;
    let sender_public_key = PublicKey::from_slice(
        out.sender_pubkey
            .as_ref()
            .ok_or(Error::IncompleteMwebMaps("output map missing sender_pubkey"))?,
    )
    .map_err(|_| Error::InvalidSecp256k1PublicKey(secp256k1::Error::InvalidPublicKey))?;
    let receiver_public_key = PublicKey::from_slice(
        out.output_pubkey
            .as_ref()
            .ok_or(Error::IncompleteMwebMaps("output map missing output_pubkey"))?,
    )
    .map_err(|_| Error::InvalidSecp256k1PublicKey(secp256k1::Error::InvalidPublicKey))?;
    let features = out.features.unwrap_or(0);
    let standard_fields = match &out.standard_fields {
        Some(blob) if blob.len() >= 33 + 1 + 8 + 16 => {
            let ke = PublicKey::from_slice(&blob[..33]).map_err(|_| {
                Error::InvalidSecp256k1PublicKey(secp256k1::Error::InvalidPublicKey)
            })?;
            let view_tag = blob[33];
            let masked_value = u64::from_le_bytes(blob[34..42].try_into().unwrap());
            let mut masked_nonce = [0u8; 16];
            masked_nonce.copy_from_slice(&blob[42..58]);
            Some(OutputMessageStandardFields {
                key_exchange_pubkey: ke,
                view_tag,
                masked_value,
                masked_nonce,
            })
        }
        _ => None,
    };
    let mut range_proof = [0u8; 675];
    let rp = out
        .range_proof
        .as_ref()
        .ok_or(Error::IncompleteMwebMaps("output map missing range_proof"))?;
    if rp.len() != 675 {
        return Err(Error::IncompleteMwebMaps("range_proof must be 675 bytes"));
    }
    range_proof.copy_from_slice(rp);
    let mut signature = [0u8; 64];
    let sig = out
        .signature
        .as_ref()
        .ok_or(Error::IncompleteMwebMaps("output map missing signature"))?;
    if sig.len() != 64 {
        return Err(Error::IncompleteMwebMaps("output signature must be 64 bytes"));
    }
    signature.copy_from_slice(sig);
    Ok(Output {
        commitment,
        sender_public_key,
        receiver_public_key,
        message: OutputMessage {
            features,
            standard_fields,
            extra_data: out.extra_data.clone().unwrap_or_default(),
        },
        range_proof,
        signature,
    })
}

pub(crate) fn wire_kernel_from_map(k: &MwebKernel) -> Result<Kernel, Error> {
    let excess = k
        .excess_commit
        .ok_or(Error::IncompleteMwebMaps("kernel map missing excess"))?;
    let signature = k
        .signature
        .ok_or(Error::IncompleteMwebMaps("kernel map missing signature"))?;
    let mut pegouts = Vec::with_capacity(k.pegouts.len());
    for raw in &k.pegouts {
        pegouts.push(crate::psbt::mweb::kernel::pegout_coin_from_psbt_value(raw)?);
    }
    let stealth_excess = match &k.stealth_commit {
        Some(b) => Some(
            PublicKey::from_slice(b)
                .map_err(|_| Error::InvalidSecp256k1PublicKey(secp256k1::Error::InvalidPublicKey))?,
        ),
        None => None,
    };
    Ok(Kernel {
        features: k.features.unwrap_or(0),
        fee: k.fee.map(|f| f as i64),
        pegin: k.pegin_amount.map(|a| a as i64),
        pegouts,
        lock_height: k.lock_height,
        stealth_excess,
        extra_data: k.extra_data.clone().unwrap_or_default(),
        excess,
        signature,
    })
}
