// SPDX-License-Identifier: CC0-1.0

//! MWEB PSBT key type constants (ltcsuite / ltcd compatible).

// --- Global ---

/// `MwebTxOffsetType`
pub const MWEB_TX_OFFSET_TYPE: u8 = 0x90;
/// `MwebTxStealthOffsetType`
pub const MWEB_TX_STEALTH_OFFSET_TYPE: u8 = 0x91;
/// `MwebKernelCountType`
pub const MWEB_KERNEL_COUNT_TYPE: u8 = 0x92;
/// Global MWEB kernel field (`type_value=0x93`, key =
/// `[kernel_index: u32 LE][field_ty: u8]` plus optional pegout index for type 4).
pub const MWEB_GLOBAL_KERNEL_FIELD_TYPE: u8 = 0x93;
/// Global MWEB output field (`type_value=0x94`, key = `[output_index: u32 LE][field_ty: u8]`).
pub const MWEB_GLOBAL_OUTPUT_FIELD_TYPE: u8 = 0x94;

// --- Input ---

/// `MwebSpentOutputIdType`
pub const MWEB_SPENT_OUTPUT_ID_TYPE: u8 = 0x90;
/// `MwebSpentOutputCommitType`
pub const MWEB_SPENT_OUTPUT_COMMIT_TYPE: u8 = 0x91;
/// `MwebSpentOutputPubKeyType`
pub const MWEB_SPENT_OUTPUT_PUBKEY_TYPE: u8 = 0x92;
/// `MwebInputPubKeyType`
pub const MWEB_INPUT_PUBKEY_TYPE: u8 = 0x93;
/// `MwebInputFeaturesType`
pub const MWEB_INPUT_FEATURES_TYPE: u8 = 0x94;
/// `MwebInputSignatureType`
pub const MWEB_INPUT_SIGNATURE_TYPE: u8 = 0x95;
/// `MwebAddressIndexType`
pub const MWEB_ADDRESS_INDEX_TYPE: u8 = 0x96;
/// `MwebInputAmountType`
pub const MWEB_INPUT_AMOUNT_TYPE: u8 = 0x97;
/// `MwebSharedSecretType`
pub const MWEB_SHARED_SECRET_TYPE: u8 = 0x98;
/// `MwebKeyExchangePubKeyType`
pub const MWEB_KEY_EXCHANGE_PUBKEY_TYPE: u8 = 0x99;
/// `MwebMasterScanKeyOriginType`
pub const MWEB_MASTER_SCAN_KEY_ORIGIN_TYPE: u8 = 0x9A;
/// `MwebMasterSpendKeyOriginType`
pub const MWEB_MASTER_SPEND_KEY_ORIGIN_TYPE: u8 = 0x9B;
/// `MwebInputExtraDataType`
pub const MWEB_INPUT_EXTRA_DATA_TYPE: u8 = 0x9C;

/// Inclusive range of PSBT input MWEB field type bytes.
pub const MWEB_INPUT_FIELD_MIN: u8 = MWEB_SPENT_OUTPUT_ID_TYPE;
/// Inclusive range of PSBT input MWEB field type bytes.
pub const MWEB_INPUT_FIELD_MAX: u8 = MWEB_INPUT_EXTRA_DATA_TYPE;

// --- Output ---

/// `MwebStealthAddressOutputType`
pub const MWEB_STEALTH_ADDRESS_OUTPUT_TYPE: u8 = 0x90;
/// `MwebCommitOutputType`
pub const MWEB_COMMIT_OUTPUT_TYPE: u8 = 0x91;
/// `MwebFeaturesOutputType`
pub const MWEB_FEATURES_OUTPUT_TYPE: u8 = 0x92;
/// `MwebSenderPubKeyOutputType`
pub const MWEB_SENDER_PUBKEY_OUTPUT_TYPE: u8 = 0x93;
/// `MwebOutputPubKeyOutputType`
pub const MWEB_OUTPUT_PUBKEY_OUTPUT_TYPE: u8 = 0x94;
/// `MwebStandardFieldsOutputType`
pub const MWEB_STANDARD_FIELDS_OUTPUT_TYPE: u8 = 0x95;
/// `MwebRangeProofOutputType`
pub const MWEB_RANGE_PROOF_OUTPUT_TYPE: u8 = 0x96;
/// `MwebSignatureOutputType`
pub const MWEB_SIGNATURE_OUTPUT_TYPE: u8 = 0x97;
/// `MwebExtraDataOutputType`
pub const MWEB_EXTRA_DATA_OUTPUT_TYPE: u8 = 0x98;

/// Inclusive range of PSBT output MWEB field type bytes.
pub const MWEB_OUTPUT_FIELD_MIN: u8 = MWEB_STEALTH_ADDRESS_OUTPUT_TYPE;
/// Inclusive range of PSBT output MWEB field type bytes.
pub const MWEB_OUTPUT_FIELD_MAX: u8 = MWEB_EXTRA_DATA_OUTPUT_TYPE;

// --- Kernel (field type in global `0x93` key suffix) ---

/// `MwebKernelExcessCommitType`
pub const MWEB_KERNEL_EXCESS_COMMIT_TYPE: u8 = 0;
/// `MwebKernelStealthCommitType`
pub const MWEB_KERNEL_STEALTH_COMMIT_TYPE: u8 = 1;
/// `MwebKernelFeeType`
pub const MWEB_KERNEL_FEE_TYPE: u8 = 2;
/// `MwebKernelPeginAmountType`
pub const MWEB_KERNEL_PEGIN_AMOUNT_TYPE: u8 = 3;
/// `MwebKernelPegoutType`
pub const MWEB_KERNEL_PEGOUT_TYPE: u8 = 4;
/// `MwebKernelLockHeightType`
pub const MWEB_KERNEL_LOCK_HEIGHT_TYPE: u8 = 5;
/// `MwebKernelFeaturesType`
pub const MWEB_KERNEL_FEATURES_TYPE: u8 = 6;
/// `MwebKernelExtraDataType`
pub const MWEB_KERNEL_EXTRA_DATA_TYPE: u8 = 7;
/// `MwebKernelSignatureType`
pub const MWEB_KERNEL_SIGNATURE_TYPE: u8 = 8;
