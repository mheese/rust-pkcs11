// Copyright 2017 Marcus Heese
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![allow(non_camel_case_types, non_snake_case)]

use types::*;

pub type C_Initialize = extern "C" fn(CK_C_INITIALIZE_ARGS_PTR) -> CK_RV;
pub type C_Finalize = extern "C" fn(CK_VOID_PTR) -> CK_RV;
pub type C_GetInfo = extern "C" fn(CK_INFO_PTR) -> CK_RV;
pub type C_GetFunctionList = extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;
pub type C_GetSlotList = extern "C" fn(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) -> CK_RV;
pub type C_GetSlotInfo = extern "C" fn(CK_SLOT_ID, CK_SLOT_INFO_PTR) -> CK_RV;
pub type C_GetTokenInfo = extern "C" fn(CK_SLOT_ID, CK_TOKEN_INFO_PTR) -> CK_RV;
pub type C_GetMechanismList = extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type C_GetMechanismInfo = extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR) -> CK_RV;
pub type C_InitToken = extern "C" fn(CK_SLOT_ID, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR) -> CK_RV;
pub type C_InitPIN = extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;
pub type C_SetPIN = extern "C" fn(CK_SESSION_HANDLE, CK_UTF8CHAR_PTR, CK_ULONG, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;
pub type C_OpenSession = extern "C" fn(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY, CK_SESSION_HANDLE_PTR) -> CK_RV;
pub type C_CloseSession = extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type C_CloseAllSessions = extern "C" fn(CK_SLOT_ID) -> CK_RV;
pub type C_GetSessionInfo = extern "C" fn(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR) -> CK_RV;
pub type C_GetOperationState = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR) -> CK_RV;
pub type C_SetOperationState = extern "C" fn(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type C_Login = extern "C" fn(CK_SESSION_HANDLE, CK_USER_TYPE, CK_UTF8CHAR_PTR, CK_ULONG) -> CK_RV;
pub type C_Logout = extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;
pub type C_CreateObject = extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV;
pub type C_CopyObject = extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR) -> CK_RV;
pub type C_DestroyObject = extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV;
pub type C_GetObjectSize = extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR) -> CK_RV;
pub type C_GetAttributeValue = extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV;
pub type C_SetAttributeValue = extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV;
pub type C_FindObjectsInit = extern "C" fn(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG) -> CK_RV;
pub type C_FindObjects = extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG, CK_ULONG_PTR) -> CK_RV;
pub type C_FindObjectsFinal = extern "C" fn(CK_SESSION_HANDLE) -> CK_RV;

/// `C_EncryptInit` initializes an encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the encryption mechanism
/// * `hKey`: handle of encryption key
///
pub type C_EncryptInit = extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) -> CK_RV;

/// `C_Encrypt` encrypts single-part data.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pData`: the plaintext data
/// * `ulDataLen`: bytes of plaintext
/// * `pEncryptedData`: gets ciphertext
/// * `pulEncryptedDataLen`: gets c-text size
///
pub type C_Encrypt = extern "C" fn(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pEncryptedData: CK_BYTE_PTR, pulEncryptedDataLen: CK_ULONG_PTR) -> CK_RV;

/// `C_EncryptUpdate` continues a multiple-part encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext data len
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text size
///
pub type C_EncryptUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR) -> CK_RV;

/// `C_EncryptFinal` finishes a multiple-part encryption operation
///
/// # Function Parameters
///
/// * `hSession`: session handle
/// * `pLastEncryptedPart` last c-text
/// * `pulLastEncryptedPartLen`: gets last size
///
pub type C_EncryptFinal = extern "C" fn(hSession: CK_SESSION_HANDLE, pLastEncryptedPart: CK_BYTE_PTR, pulLastEncryptedPartLen: CK_ULONG_PTR) -> CK_RV;

/// `C_DecryptInit` initializes a decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the decryption mechanism
/// * `hKey`: handle of decryption key
///
pub type C_DecryptInit = extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) -> CK_RV;

/// `C_Decrypt` decrypts encrypted data in a single part.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedData`: ciphertext
/// * `ulEncryptedDataLen`: ciphertext length
/// * `pData`: gets plaintext
/// * `pulDataLen`: gets p-text size
///
pub type C_Decrypt = extern "C" fn(hSession: CK_SESSION_HANDLE, pEncryptedData: CK_BYTE_PTR, ulEncryptedDataLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR) -> CK_RV;

/// `C_DecryptUpdate` continues a multiple-part decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: encrypted data
/// * `ulEncryptedPartLen`: input length
/// * `pPart`: gets plaintext
/// * `pulPartLen`: p-text size
///
pub type C_DecryptUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR) -> CK_RV;

/// `C_DecryptFinal` finishes a multiple-part decryption operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pLastPart`: gets plaintext
/// * `pulLastPartLen`: p-text size
///
pub type C_DecryptFinal = extern "C" fn(hSession: CK_SESSION_HANDLE, pLastPart: CK_BYTE_PTR, pulLastPartLen: CK_ULONG_PTR) -> CK_RV;

/// `C_DigestInit` initializes a message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the digesting mechanism
///
pub type C_DigestInit = extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR) -> CK_RV;

/// `C_Digest` digests data in a single part.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: data to be digested
/// * `ulDataLen`: bytes of data to digest
/// * `pDigest`: gets the message digest
/// * `pulDigestLen`: gets digest length
///
pub type C_Digest = extern "C" fn(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR) -> CK_RV;

/// `C_DigestUpdate` continues a multiple-part message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: data to be digested
/// * `ulPartLen`: bytes of data to be digested
///
pub type C_DigestUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) -> CK_RV;

/// `C_DigestKey` continues a multi-part message-digesting operation, by digesting the value of a secret key as part of the data already digested.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `hKey`: secret key to digest
pub type C_DigestKey = extern "C" fn(hSession: CK_SESSION_HANDLE, hKey: CK_OBJECT_HANDLE) -> CK_RV;

/// `C_DigestFinal` finishes a multiple-part message-digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pDigest`: gets the message digest
/// * `pulDigestLen`: gets byte count of digest
///
pub type C_DigestFinal = extern "C" fn(hSession: CK_SESSION_HANDLE, pDigest: CK_BYTE_PTR, pulDigestLen: CK_ULONG_PTR) -> CK_RV;

/// `C_SignInit` initializes a signature (private key encryption) operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the signature mechanism
/// * `hKey`: handle of signature key
///
pub type C_SignInit = extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) -> CK_RV;

/// `C_Sign` signs (encrypts with private key) data in a single part, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: the data to sign
/// * `ulDataLen`: count of bytes to sign
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub type C_Sign = extern "C" fn(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR) -> CK_RV;

/// `C_SignUpdate` continues a multiple-part signature operation, where the signature is (will be) an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: the data to sign
/// * `ulPartLen`: count of bytes to sign
///
pub type C_SignUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) -> CK_RV;

/// `C_SignFinal` finishes a multiple-part signature operation, returning the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub type C_SignFinal = extern "C" fn(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR) -> CK_RV;

/// `C_SignRecoverInit` initializes a signature operation, where the data can be recovered from the signature.
/// `hSession`: the session's handle
/// `pMechanism`: the signature mechanism
/// `hKey`: handle of the signature key
pub type C_SignRecoverInit = extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) -> CK_RV;

/// `C_SignRecover` signs data in a single operation, where the data can be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: the data to sign
/// * `ulDataLen`: count of bytes to sign
/// * `pSignature`: gets the signature
/// * `pulSignatureLen`: gets signature length
///
pub type C_SignRecover = extern "C" fn(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, pulSignatureLen: CK_ULONG_PTR) -> CK_RV;

/// `C_VerifyInit` initializes a verification operation, where the signature is an appendix to the data, and plaintext cannot cannot be recovered from the signature (e.g. DSA).
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the verification mechanism
/// * `hKey`: verification key
///
pub type C_VerifyInit = extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) -> CK_RV;

/// `C_Verify` verifies a signature in a single-part operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pData`: signed data
/// * `ulDataLen`: length of signed data
/// * `pSignature`: signature
/// * `ulSignatureLen`: signature length
///
pub type C_Verify = extern "C" fn(hSession: CK_SESSION_HANDLE, pData: CK_BYTE_PTR, ulDataLen: CK_ULONG, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG) -> CK_RV;

/// `C_VerifyUpdate` continues a multiple-part verification operation, where the signature is an appendix to the data, and plaintext cannot be recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pPart`: signed data
/// * `ulPartLen`: length of signed data
///
pub type C_VerifyUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG) -> CK_RV;

/// `C_VerifyFinal` finishes a multiple-part verification operation, checking the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: signature to verify
/// * `ulSignatureLen`: signature length
///
pub type C_VerifyFinal = extern "C" fn(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG) -> CK_RV;

/// `C_VerifyRecoverInit` initializes a signature verification operation, where the data is recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the verification mechanism
/// * `hKey`: verification key
///
pub type C_VerifyRecoverInit = extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, hKey: CK_OBJECT_HANDLE) -> CK_RV;

/// `C_VerifyRecover` verifies a signature in a single-part operation, where the data is recovered from the signature.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSignature`: signature to verify
/// * `ulSignatureLen`: signature length
/// * `pData`: gets signed data
/// * `pulDataLen`: gets signed data len
///
pub type C_VerifyRecover = extern "C" fn(hSession: CK_SESSION_HANDLE, pSignature: CK_BYTE_PTR, ulSignatureLen: CK_ULONG, pData: CK_BYTE_PTR, pulDataLen: CK_ULONG_PTR) -> CK_RV;

/// `C_DigestEncryptUpdate` continues a multiple-part digesting and encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext length
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text length
///
pub type C_DigestEncryptUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR) -> CK_RV;

/// `C_DecryptDigestUpdate` continues a multiple-part decryption and digesting operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: ciphertext
/// * `ulEncryptedPartLen`: ciphertext length
/// * `pPart:`: gets plaintext
/// * `pulPartLen`: gets plaintext len
///
pub type C_DecryptDigestUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR) -> CK_RV;

/// `C_SignEncryptUpdate` continues a multiple-part signing and encryption operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pPart`: the plaintext data
/// * `ulPartLen`: plaintext length
/// * `pEncryptedPart`: gets ciphertext
/// * `pulEncryptedPartLen`: gets c-text length
///
pub type C_SignEncryptUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pPart: CK_BYTE_PTR, ulPartLen: CK_ULONG, pEncryptedPart: CK_BYTE_PTR, pulEncryptedPartLen: CK_ULONG_PTR) -> CK_RV;

/// `C_DecryptVerifyUpdate` continues a multiple-part decryption and verify operation.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pEncryptedPart`: ciphertext
/// * `ulEncryptedPartLen`: ciphertext length
/// * `pPart`: gets plaintext
/// * `pulPartLen`: gets p-text length
///
pub type C_DecryptVerifyUpdate = extern "C" fn(hSession: CK_SESSION_HANDLE, pEncryptedPart: CK_BYTE_PTR, ulEncryptedPartLen: CK_ULONG, pPart: CK_BYTE_PTR, pulPartLen: CK_ULONG_PTR) -> CK_RV;

/// `C_GenerateKey` generates a secret key, creating a new key object.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: key generation mech.
/// * `pTemplate`: template for new key
/// * `ulCount`: # of attrs in template
/// * `phKey`: gets handle of new key
///
pub type C_GenerateKey = extern "C" fn(hSession: CK_SESSION_HANDLE, pMechanism: CK_MECHANISM_PTR, pTemplate: CK_ATTRIBUTE_PTR, ulCount: CK_ULONG, phKey: CK_OBJECT_HANDLE_PTR) -> CK_RV;

/// `C_GenerateKeyPair` generates a public-key/private-key pair, creating new key objects.
///
/// # Function Parameters
///
/// * `hSession`: session handle
/// * `pMechanism`: key-gen mech.
/// * `pPublicKeyTemplate`: template for pub. key
/// * `ulPublicKeyAttributeCount`: # pub. attrs.
/// * `pPrivateKeyTemplate`: template for priv. key
/// * `ulPrivateKeyAttributeCount`: # priv.  attrs.
/// * `phPublicKey`: gets pub. key handle
/// * `phPrivateKey`: gets priv. key handle
///
pub type C_GenerateKeyPair = extern "C" fn(
  hSession: CK_SESSION_HANDLE,
  pMechanism: CK_MECHANISM_PTR,
  pPublicKeyTemplate: CK_ATTRIBUTE_PTR,
  ulPublicKeyAttributeCount: CK_ULONG,
  pPrivateKeyTemplate: CK_ATTRIBUTE_PTR,
  ulPrivateKeyAttributeCount: CK_ULONG,
  phPublicKey: CK_OBJECT_HANDLE_PTR,
  phPrivateKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

/// `C_WrapKey` wraps (i.e., encrypts) a key.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pMechanism`: the wrapping mechanism
/// * `hWrappingKey`: wrapping key
/// * `hKey`: key to be wrapped
/// * `pWrappedKey`: gets wrapped key
/// * `pulWrappedKeyLen`: gets wrapped key size
///
pub type C_WrapKey = extern "C" fn(
  hSession: CK_SESSION_HANDLE,
  pMechanism: CK_MECHANISM_PTR,
  hWrappingKey: CK_OBJECT_HANDLE,
  hKey: CK_OBJECT_HANDLE,
  pWrappedKey: CK_BYTE_PTR,
  pulWrappedKeyLen: CK_ULONG_PTR,
) -> CK_RV;

/// `C_UnwrapKey` unwraps (decrypts) a wrapped key, creating a new key object.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pMechanism`: unwrapping mech.
/// * `hUnwrappingKey`: unwrapping key
/// * `pWrappedKey`: the wrapped key
/// * `ulWrappedKeyLen`: wrapped key len
/// * `pTemplate`: new key template
/// * `ulAttributeCount`: template length
/// * `phKey`: gets new handle
///
pub type C_UnwrapKey = extern "C" fn(
  hSession: CK_SESSION_HANDLE,
  pMechanism: CK_MECHANISM_PTR,
  hUnwrappingKey: CK_OBJECT_HANDLE,
  pWrappedKey: CK_BYTE_PTR,
  ulWrappedKeyLen: CK_ULONG,
  pTemplate: CK_ATTRIBUTE_PTR,
  ulAttributeCount: CK_ULONG,
  phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

/// `C_DeriveKey` derives a key from a base key, creating a new key object.
///
/// # Function Parameters
///
/// * `hSession`: session's handle
/// * `pMechanism`: key deriv. mech.
/// * `hBaseKey`: base key
/// * `pTemplate`: new key template
/// * `ulAttributeCount`: template length
/// * `phKey`: gets new handle
///
pub type C_DeriveKey = extern "C" fn(
  hSession: CK_SESSION_HANDLE,
  pMechanism: CK_MECHANISM_PTR,
  hBaseKey: CK_OBJECT_HANDLE,
  pTemplate: CK_ATTRIBUTE_PTR,
  ulAttributeCount: CK_ULONG,
  phKey: CK_OBJECT_HANDLE_PTR,
) -> CK_RV;

/// `C_SeedRandom` mixes additional seed material into the token's random number generator.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `pSeed`: the seed material
/// * `ulSeedLen`: length of seed material
///
pub type C_SeedRandom = extern "C" fn(hSession: CK_SESSION_HANDLE, pSeed: CK_BYTE_PTR, ulSeedLen: CK_ULONG) -> CK_RV;

/// `C_GenerateRandom` generates random data.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
/// * `RandomData`: receives the random data
/// * `ulRandomLen`: # of bytes to generate
///
pub type C_GenerateRandom = extern "C" fn(hSession: CK_SESSION_HANDLE, RandomData: CK_BYTE_PTR, ulRandomLen: CK_ULONG) -> CK_RV;

/// `C_GetFunctionStatus` is a legacy function; it obtains an updated status of a function running in parallel with an application.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub type C_GetFunctionStatus = extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;

/// `C_CancelFunction` is a legacy function; it cancels a function running in parallel.
///
/// # Function Parameters
///
/// * `hSession`: the session's handle
///
pub type C_CancelFunction = extern "C" fn(hSession: CK_SESSION_HANDLE) -> CK_RV;

/// `C_WaitForSlotEvent` waits for a slot event (token insertion, removal, etc.) to occur.
///
/// # Function Parameters
///
/// * `flags`: blocking/nonblocking flag
/// * `pSlot`: location that receives the slot ID
/// * `pRserved`: reserved.  Should be NULL_PTR
///
pub type C_WaitForSlotEvent = extern "C" fn(flags: CK_FLAGS, pSlot: CK_SLOT_ID_PTR, pRserved: CK_VOID_PTR) -> CK_RV;
