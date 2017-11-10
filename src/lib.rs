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
extern crate libloading;
extern crate num_traits;
extern crate num_bigint;

use std::mem;
use std::slice;
use std::ptr;
use std::ffi::{CString};
use num_bigint::BigUint;
//use num_traits::Num;
//use libc::c_uchar;

pub const CK_TRUE: CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;

//// an unsigned 8-bit value
pub type CK_BYTE = u8;
pub type CK_BYTE_PTR = *const CK_BYTE;

/// an unsigned 8-bit character
pub type CK_CHAR = CK_BYTE;
pub type CK_CHAR_PTR = *const CK_CHAR;

/// an 8-bit UTF-8 character
pub type CK_UTF8CHAR = CK_BYTE;
pub type CK_UTF8CHAR_PTR = *const CK_UTF8CHAR;

/// a BYTE-sized Boolean flag
pub type CK_BBOOL = CK_BYTE;

/// an unsigned value, at least 32 bits long
pub type CK_ULONG = usize;
pub type CK_ULONG_PTR = *const CK_ULONG;

/// a signed value, the same size as a CK_ULONG
pub type CK_LONG = isize;

/// at least 32 bits; each bit is a Boolean flag
pub type CK_FLAGS = CK_ULONG;

/* some special values for certain CK_ULONG variables */
pub const CK_UNAVAILABLE_INFORMATION: CK_ULONG =      0xffffffffffffffff;
pub const CK_EFFECTIVELY_INFINITE: CK_ULONG =         0;

#[derive(Debug)]
#[repr(u8)]
pub enum CK_VOID {
    #[doc(hidden)]
    __Variant1,
    #[doc(hidden)]
    __Variant2,
}
pub type CK_VOID_PTR = *const CK_VOID;

/// Pointer to a CK_VOID_PTR-- i.e., pointer to pointer to void
pub type CK_VOID_PTR_PTR = *const CK_VOID_PTR;

/// The following value is always invalid if used as a session
/// handle or object handle
pub const CK_INVALID_HANDLE: CK_ULONG = 0;

#[derive(Debug,Clone,Default)]
#[repr(C)]
pub struct CK_VERSION {
  pub major: CK_BYTE,  /* integer portion of version number */
  pub minor: CK_BYTE,   /* 1/100ths portion of version number */
}

#[derive(Debug,Clone,Default)]
#[repr(C)]
pub struct CK_INFO {
  /* manufacturerID and libraryDecription have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  pub cryptokiVersion: CK_VERSION,              /* Cryptoki interface ver */
  pub manufacturerID: [CK_UTF8CHAR; 32],        /* blank padded */
  pub flags: CK_FLAGS,                          /* must be zero */
  pub libraryDescription: [CK_UTF8CHAR; 32],    /* blank padded */
  pub libraryVersion: CK_VERSION,               /* version of library */
}

impl CK_INFO {
    pub fn new() -> CK_INFO {
        CK_INFO {
            cryptokiVersion: Default::default(),
            manufacturerID: [32; 32],
            flags: 0,
            libraryDescription: [32; 32],
            libraryVersion: Default::default(),
        }
    }
}

pub type CK_INFO_PTR = *const CK_INFO;

/// CK_NOTIFICATION enumerates the types of notifications that
/// Cryptoki provides to an application
pub type CK_NOTIFICATION = CK_ULONG;

pub const CKN_SURRENDER          : CK_NOTIFICATION = 0;
pub const CKN_OTP_CHANGED        : CK_NOTIFICATION = 1;

pub type CK_SLOT_ID = CK_ULONG;
pub type CK_SLOT_ID_PTR = *const CK_SLOT_ID;

/// CK_SLOT_INFO provides information about a slot
#[repr(C)]
pub struct CK_SLOT_INFO {
    /// slotDescription and manufacturerID have been changed from
    /// CK_CHAR to CK_UTF8CHAR for v2.10
    pub slotDescription: [CK_UTF8CHAR; 64],    /* blank padded */
    pub manufacturerID: [CK_UTF8CHAR; 32],     /* blank padded */
    pub flags: CK_FLAGS,

    /// version of hardware
    pub hardwareVersion: CK_VERSION,  /* version of hardware */
    /// version of firmware
    pub firmwareVersion: CK_VERSION,  /* version of firmware */
}

impl Default for CK_SLOT_INFO {
    fn default() -> CK_SLOT_INFO {
        CK_SLOT_INFO {
            slotDescription: [32; 64],
            manufacturerID: [32; 32],
            flags: 0,
            hardwareVersion: Default::default(),
            firmwareVersion: Default::default(),
        }
    }
}

impl std::fmt::Debug for CK_SLOT_INFO {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        let sd = self.slotDescription.to_vec();
        fmt.debug_struct("CK_SLOT_INFO")
            .field("slotDescription", &sd)
            .field("manufacturerID", &self.manufacturerID)
            .field("flags", &self.flags)
            .field("hardwareVersion", &self.hardwareVersion)
            .field("firmwareVersion", &self.firmwareVersion)
            .finish()
    }
}

/// a token is there
pub const CKF_TOKEN_PRESENT    : CK_FLAGS = 0x00000001;
/// removable devices
pub const CKF_REMOVABLE_DEVICE : CK_FLAGS = 0x00000002;
/// hardware slot
pub const CKF_HW_SLOT          : CK_FLAGS = 0x00000004;

pub type CK_SLOT_INFO_PTR = *const CK_SLOT_INFO;

#[derive(Debug)]
#[repr(C)]
pub struct CK_TOKEN_INFO {
  /* label, manufacturerID, and model have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  pub label: [CK_UTF8CHAR; 32],           /* blank padded */
  pub manufacturerID: [CK_UTF8CHAR; 32],  /* blank padded */
  pub model: [CK_UTF8CHAR; 16],           /* blank padded */
  pub serialNumber: [CK_CHAR; 16],        /* blank padded */
  pub flags: CK_FLAGS,                    /* see below */
  pub ulMaxSessionCount: CK_ULONG,     /* max open sessions */
  pub ulSessionCount: CK_ULONG,        /* sess. now open */
  pub ulMaxRwSessionCount: CK_ULONG,   /* max R/W sessions */
  pub ulRwSessionCount: CK_ULONG,      /* R/W sess. now open */
  pub ulMaxPinLen: CK_ULONG,           /* in bytes */
  pub ulMinPinLen: CK_ULONG,           /* in bytes */
  pub ulTotalPublicMemory: CK_ULONG,   /* in bytes */
  pub ulFreePublicMemory: CK_ULONG,    /* in bytes */
  pub ulTotalPrivateMemory: CK_ULONG,  /* in bytes */
  pub ulFreePrivateMemory: CK_ULONG,   /* in bytes */
  pub hardwareVersion: CK_VERSION,     /* version of hardware */
  pub firmwareVersion: CK_VERSION,     /* version of firmware */
  pub utcTime: [CK_CHAR; 16],          /* time */
}

impl Default for CK_TOKEN_INFO {
    fn default() -> CK_TOKEN_INFO {
        CK_TOKEN_INFO {
            label: [32; 32],
            manufacturerID: [32; 32],
            model: [32; 16],
            serialNumber: [32; 16],
            flags: 0,
            ulMaxSessionCount: 0,
            ulSessionCount: 0,
            ulMaxRwSessionCount: 0,
            ulRwSessionCount: 0,
            ulMaxPinLen: 0,
            ulMinPinLen: 0,
            ulTotalPublicMemory: 0,
            ulFreePublicMemory: 0,
            ulTotalPrivateMemory: 0,
            ulFreePrivateMemory: 0,
            hardwareVersion: Default::default(),
            firmwareVersion: Default::default(),
            utcTime: [0; 16],
        }
    }
}

/// has random # generator
pub const CKF_RNG                    : CK_FLAGS = 0x00000001;

/// token is write-protected
pub const CKF_WRITE_PROTECTED        : CK_FLAGS = 0x00000002;

/// user must login
pub const CKF_LOGIN_REQUIRED         : CK_FLAGS = 0x00000004;

/// normal user's PIN is set
pub const CKF_USER_PIN_INITIALIZED   : CK_FLAGS = 0x00000008;

/// CKF_RESTORE_KEY_NOT_NEEDED.  If it is set,
/// that means that *every* time the state of cryptographic
/// operations of a session is successfully saved, all keys
/// needed to continue those operations are stored in the state
pub const CKF_RESTORE_KEY_NOT_NEEDED : CK_FLAGS = 0x00000020;

/// CKF_CLOCK_ON_TOKEN.  If it is set, that means
/// that the token has some sort of clock.  The time on that
/// clock is returned in the token info structure
pub const CKF_CLOCK_ON_TOKEN         : CK_FLAGS = 0x00000040;

/// CKF_PROTECTED_AUTHENTICATION_PATH.  If it is
/// set, that means that there is some way for the user to login
/// without sending a PIN through the Cryptoki library itself
pub const CKF_PROTECTED_AUTHENTICATION_PATH : CK_FLAGS = 0x00000100;

/// CKF_DUAL_CRYPTO_OPERATIONS.  If it is true,
/// that means that a single session with the token can perform
/// dual simultaneous cryptographic operations (digest and
/// encrypt; decrypt and digest; sign and encrypt; and decrypt
/// and sign)
pub const CKF_DUAL_CRYPTO_OPERATIONS : CK_FLAGS = 0x00000200;

/// CKF_TOKEN_INITIALIZED. If it is true, the
/// token has been initialized using C_InitializeToken or an
/// equivalent mechanism outside the scope of PKCS #11.
/// Calling C_InitializeToken when this flag is set will cause
/// the token to be reinitialized.
pub const CKF_TOKEN_INITIALIZED      : CK_FLAGS = 0x00000400;

/// CKF_SECONDARY_AUTHENTICATION. If it is
/// true, the token supports secondary authentication for
/// private key objects.
pub const CKF_SECONDARY_AUTHENTICATION : CK_FLAGS = 0x00000800;

/// CKF_USER_PIN_COUNT_LOW. If it is true, an
/// incorrect user login PIN has been entered at least once
/// since the last successful authentication.
pub const CKF_USER_PIN_COUNT_LOW      : CK_FLAGS = 0x00010000;

/// CKF_USER_PIN_FINAL_TRY. If it is true,
/// supplying an incorrect user PIN will it to become locked.
pub const CKF_USER_PIN_FINAL_TRY      : CK_FLAGS = 0x00020000;

/// CKF_USER_PIN_LOCKED. If it is true, the
/// user PIN has been locked. User login to the token is not
/// possible.
pub const CKF_USER_PIN_LOCKED         : CK_FLAGS = 0x00040000;

/// CKF_USER_PIN_TO_BE_CHANGED. If it is true,
/// the user PIN value is the default value set by token
/// initialization or manufacturing, or the PIN has been
/// expired by the card.
pub const CKF_USER_PIN_TO_BE_CHANGED  : CK_FLAGS = 0x00080000;

/// CKF_SO_PIN_COUNT_LOW. If it is true, an
/// incorrect SO login PIN has been entered at least once since
/// the last successful authentication.
pub const CKF_SO_PIN_COUNT_LOW        : CK_FLAGS = 0x00100000;

/// CKF_SO_PIN_FINAL_TRY. If it is true,
/// supplying an incorrect SO PIN will it to become locked.
pub const CKF_SO_PIN_FINAL_TRY        : CK_FLAGS = 0x00200000;

/// CKF_SO_PIN_LOCKED. If it is true, the SO
/// PIN has been locked. SO login to the token is not possible.
pub const CKF_SO_PIN_LOCKED           : CK_FLAGS = 0x00400000;

/// CKF_SO_PIN_TO_BE_CHANGED. If it is true,
/// the SO PIN value is the default value set by token
/// initialization or manufacturing, or the PIN has been
/// expired by the card.
pub const CKF_SO_PIN_TO_BE_CHANGED    : CK_FLAGS = 0x00800000;

pub const CKF_ERROR_STATE             : CK_FLAGS = 0x01000000;

pub type CK_TOKEN_INFO_PTR = *const CK_TOKEN_INFO;

/// CK_SESSION_HANDLE is a Cryptoki-assigned value that
/// identifies a session
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_SESSION_HANDLE_PTR = *const CK_SESSION_HANDLE;

/// CK_USER_TYPE enumerates the types of Cryptoki users
pub type CK_USER_TYPE = CK_ULONG;

/// Security Officer
pub const CKU_SO: CK_USER_TYPE = 0;
/// Normal user
pub const CKU_USER: CK_USER_TYPE = 1;
/// Context specific
pub const CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2;

/// CK_STATE enumerates the session states
type CK_STATE = CK_ULONG;
pub const CKS_RO_PUBLIC_SESSION  : CK_STATE = 0;
pub const CKS_RO_USER_FUNCTIONS  : CK_STATE = 1;
pub const CKS_RW_PUBLIC_SESSION  : CK_STATE = 2;
pub const CKS_RW_USER_FUNCTIONS  : CK_STATE = 3;
pub const CKS_RW_SO_FUNCTIONS    : CK_STATE = 4;

#[derive(Debug,Default,Clone)]
#[repr(C)]
pub struct CK_SESSION_INFO {
  pub slotID: CK_SLOT_ID,
  pub state: CK_STATE,
  pub flags: CK_FLAGS,
  /// device-dependent error code
  pub ulDeviceError: CK_ULONG,
}

/// session is r/w
pub const CKF_RW_SESSION: CK_FLAGS = 0x00000002;
/// no parallel
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004;

pub type CK_SESSION_INFO_PTR = *const CK_SESSION_INFO;

/// CK_OBJECT_HANDLE is a token-specific identifier for an
/// object
pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE_PTR = *const CK_OBJECT_HANDLE;

/// CK_OBJECT_CLASS is a value that identifies the classes (or
/// types) of objects that Cryptoki recognizes.  It is defined
/// as follows:
pub type CK_OBJECT_CLASS = CK_ULONG;

/// The following classes of objects are defined:
pub const CKO_DATA              : CK_OBJECT_CLASS = 0x00000000;
pub const CKO_CERTIFICATE       : CK_OBJECT_CLASS = 0x00000001;
pub const CKO_PUBLIC_KEY        : CK_OBJECT_CLASS = 0x00000002;
pub const CKO_PRIVATE_KEY       : CK_OBJECT_CLASS = 0x00000003;
pub const CKO_SECRET_KEY        : CK_OBJECT_CLASS = 0x00000004;
pub const CKO_HW_FEATURE        : CK_OBJECT_CLASS = 0x00000005;
pub const CKO_DOMAIN_PARAMETERS : CK_OBJECT_CLASS = 0x00000006;
pub const CKO_MECHANISM         : CK_OBJECT_CLASS = 0x00000007;
pub const CKO_OTP_KEY           : CK_OBJECT_CLASS = 0x00000008;
pub const CKO_VENDOR_DEFINED    : CK_OBJECT_CLASS = 0x80000000;

pub type CK_OBJECT_CLASS_PTR = *const CK_OBJECT_CLASS;

/// CK_HW_FEATURE_TYPE is a value that identifies the hardware feature type
/// of an object with CK_OBJECT_CLASS equal to CKO_HW_FEATURE.
pub type CK_HW_FEATURE_TYPE = CK_ULONG;

/// The following hardware feature types are defined
pub const CKH_MONOTONIC_COUNTER : CK_HW_FEATURE_TYPE = 0x00000001;
pub const CKH_CLOCK             : CK_HW_FEATURE_TYPE = 0x00000002;
pub const CKH_USER_INTERFACE    : CK_HW_FEATURE_TYPE = 0x00000003;
pub const CKH_VENDOR_DEFINED    : CK_HW_FEATURE_TYPE = 0x80000000;

/// CK_KEY_TYPE is a value that identifies a key type
pub type CK_KEY_TYPE = CK_ULONG;

/// the following key types are defined:
pub const CKK_RSA                : CK_KEY_TYPE = 0x00000000;
pub const CKK_DSA                : CK_KEY_TYPE = 0x00000001;
pub const CKK_DH                 : CK_KEY_TYPE = 0x00000002;
pub const CKK_ECDSA              : CK_KEY_TYPE = CKK_EC;
pub const CKK_EC                 : CK_KEY_TYPE = 0x00000003;
pub const CKK_X9_42_DH           : CK_KEY_TYPE = 0x00000004;
pub const CKK_KEA                : CK_KEY_TYPE = 0x00000005;
pub const CKK_GENERIC_SECRET     : CK_KEY_TYPE = 0x00000010;
pub const CKK_RC2                : CK_KEY_TYPE = 0x00000011;
pub const CKK_RC4                : CK_KEY_TYPE = 0x00000012;
pub const CKK_DES                : CK_KEY_TYPE = 0x00000013;
pub const CKK_DES2               : CK_KEY_TYPE = 0x00000014;
pub const CKK_DES3               : CK_KEY_TYPE = 0x00000015;
pub const CKK_CAST               : CK_KEY_TYPE = 0x00000016;
pub const CKK_CAST3              : CK_KEY_TYPE = 0x00000017;
pub const CKK_CAST5              : CK_KEY_TYPE = CKK_CAST128;
pub const CKK_CAST128            : CK_KEY_TYPE = 0x00000018;
pub const CKK_RC5                : CK_KEY_TYPE = 0x00000019;
pub const CKK_IDEA               : CK_KEY_TYPE = 0x0000001A;
pub const CKK_SKIPJACK           : CK_KEY_TYPE = 0x0000001B;
pub const CKK_BATON              : CK_KEY_TYPE = 0x0000001C;
pub const CKK_JUNIPER            : CK_KEY_TYPE = 0x0000001D;
pub const CKK_CDMF               : CK_KEY_TYPE = 0x0000001E;
pub const CKK_AES                : CK_KEY_TYPE = 0x0000001F;
pub const CKK_BLOWFISH           : CK_KEY_TYPE = 0x00000020;
pub const CKK_TWOFISH            : CK_KEY_TYPE = 0x00000021;
pub const CKK_SECURID            : CK_KEY_TYPE = 0x00000022;
pub const CKK_HOTP               : CK_KEY_TYPE = 0x00000023;
pub const CKK_ACTI               : CK_KEY_TYPE = 0x00000024;
pub const CKK_CAMELLIA           : CK_KEY_TYPE = 0x00000025;
pub const CKK_ARIA               : CK_KEY_TYPE = 0x00000026;
pub const CKK_MD5_HMAC           : CK_KEY_TYPE = 0x00000027;
pub const CKK_SHA_1_HMAC         : CK_KEY_TYPE = 0x00000028;
pub const CKK_RIPEMD128_HMAC     : CK_KEY_TYPE = 0x00000029;
pub const CKK_RIPEMD160_HMAC     : CK_KEY_TYPE = 0x0000002A;
pub const CKK_SHA256_HMAC        : CK_KEY_TYPE = 0x0000002B;
pub const CKK_SHA384_HMAC        : CK_KEY_TYPE = 0x0000002C;
pub const CKK_SHA512_HMAC        : CK_KEY_TYPE = 0x0000002D;
pub const CKK_SHA224_HMAC        : CK_KEY_TYPE = 0x0000002E;
pub const CKK_SEED               : CK_KEY_TYPE = 0x0000002F;
pub const CKK_GOSTR3410          : CK_KEY_TYPE = 0x00000030;
pub const CKK_GOSTR3411          : CK_KEY_TYPE = 0x00000031;
pub const CKK_GOST28147          : CK_KEY_TYPE = 0x00000032;
pub const CKK_VENDOR_DEFINED     : CK_KEY_TYPE = 0x80000000;

/// CK_CERTIFICATE_TYPE is a value that identifies a certificate
/// type
pub type CK_CERTIFICATE_TYPE = CK_ULONG;

pub const CK_CERTIFICATE_CATEGORY_UNSPECIFIED    : CK_ULONG = 0;
pub const CK_CERTIFICATE_CATEGORY_TOKEN_USER     : CK_ULONG = 1;
pub const CK_CERTIFICATE_CATEGORY_AUTHORITY      : CK_ULONG = 2;
pub const CK_CERTIFICATE_CATEGORY_OTHER_ENTITY   : CK_ULONG = 3;

pub const CK_SECURITY_DOMAIN_UNSPECIFIED    : CK_ULONG = 0;
pub const CK_SECURITY_DOMAIN_MANUFACTURER   : CK_ULONG = 1;
pub const CK_SECURITY_DOMAIN_OPERATOR       : CK_ULONG = 2;
pub const CK_SECURITY_DOMAIN_THIRD_PARTY    : CK_ULONG = 3;

/// The following certificate types are defined:
pub const CKC_X_509              : CK_CERTIFICATE_TYPE = 0x00000000;
pub const CKC_X_509_ATTR_CERT    : CK_CERTIFICATE_TYPE = 0x00000001;
pub const CKC_WTLS               : CK_CERTIFICATE_TYPE = 0x00000002;
pub const CKC_VENDOR_DEFINED     : CK_CERTIFICATE_TYPE = 0x80000000;

/// CK_ATTRIBUTE_TYPE is a value that identifies an attribute
/// type
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;

/// The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
/// consists of an array of values.
pub const CKF_ARRAY_ATTRIBUTE: CK_FLAGS = 0x40000000;

/// The following OTP-related defines relate to the CKA_OTP_FORMAT attribute
pub const CK_OTP_FORMAT_DECIMAL         : CK_ULONG = 0;
pub const CK_OTP_FORMAT_HEXADECIMAL     : CK_ULONG = 1;
pub const CK_OTP_FORMAT_ALPHANUMERIC    : CK_ULONG = 2;
pub const CK_OTP_FORMAT_BINARY          : CK_ULONG = 3;

/// The following OTP-related defines relate to the CKA_OTP_..._REQUIREMENT
/// attributes
pub const CK_OTP_PARAM_IGNORED          : CK_ULONG = 0;
pub const CK_OTP_PARAM_OPTIONAL         : CK_ULONG = 1;
pub const CK_OTP_PARAM_MANDATORY        : CK_ULONG = 2;

/// The following attribute types are defined:
pub const CKA_CLASS            : CK_ATTRIBUTE_TYPE = 0x00000000;
pub const CKA_TOKEN            : CK_ATTRIBUTE_TYPE = 0x00000001;
pub const CKA_PRIVATE          : CK_ATTRIBUTE_TYPE = 0x00000002;
pub const CKA_LABEL            : CK_ATTRIBUTE_TYPE = 0x00000003;
pub const CKA_APPLICATION      : CK_ATTRIBUTE_TYPE = 0x00000010;
pub const CKA_VALUE            : CK_ATTRIBUTE_TYPE = 0x00000011;
pub const CKA_OBJECT_ID        : CK_ATTRIBUTE_TYPE = 0x00000012;
pub const CKA_CERTIFICATE_TYPE : CK_ATTRIBUTE_TYPE = 0x00000080;
pub const CKA_ISSUER           : CK_ATTRIBUTE_TYPE = 0x00000081;
pub const CKA_SERIAL_NUMBER    : CK_ATTRIBUTE_TYPE = 0x00000082;
pub const CKA_AC_ISSUER        : CK_ATTRIBUTE_TYPE = 0x00000083;
pub const CKA_OWNER            : CK_ATTRIBUTE_TYPE = 0x00000084;
pub const CKA_ATTR_TYPES       : CK_ATTRIBUTE_TYPE = 0x00000085;
pub const CKA_TRUSTED          : CK_ATTRIBUTE_TYPE = 0x00000086;
pub const CKA_CERTIFICATE_CATEGORY        : CK_ATTRIBUTE_TYPE = 0x00000087;
pub const CKA_JAVA_MIDP_SECURITY_DOMAIN   : CK_ATTRIBUTE_TYPE = 0x00000088;
pub const CKA_URL                         : CK_ATTRIBUTE_TYPE = 0x00000089;
pub const CKA_HASH_OF_SUBJECT_PUBLIC_KEY  : CK_ATTRIBUTE_TYPE = 0x0000008A;
pub const CKA_HASH_OF_ISSUER_PUBLIC_KEY   : CK_ATTRIBUTE_TYPE = 0x0000008B;
pub const CKA_NAME_HASH_ALGORITHM         : CK_ATTRIBUTE_TYPE = 0x0000008C;
pub const CKA_CHECK_VALUE                 : CK_ATTRIBUTE_TYPE = 0x00000090;

pub const CKA_KEY_TYPE           : CK_ATTRIBUTE_TYPE = 0x00000100;
pub const CKA_SUBJECT            : CK_ATTRIBUTE_TYPE = 0x00000101;
pub const CKA_ID                 : CK_ATTRIBUTE_TYPE = 0x00000102;
pub const CKA_SENSITIVE          : CK_ATTRIBUTE_TYPE = 0x00000103;
pub const CKA_ENCRYPT            : CK_ATTRIBUTE_TYPE = 0x00000104;
pub const CKA_DECRYPT            : CK_ATTRIBUTE_TYPE = 0x00000105;
pub const CKA_WRAP               : CK_ATTRIBUTE_TYPE = 0x00000106;
pub const CKA_UNWRAP             : CK_ATTRIBUTE_TYPE = 0x00000107;
pub const CKA_SIGN               : CK_ATTRIBUTE_TYPE = 0x00000108;
pub const CKA_SIGN_RECOVER       : CK_ATTRIBUTE_TYPE = 0x00000109;
pub const CKA_VERIFY             : CK_ATTRIBUTE_TYPE = 0x0000010A;
pub const CKA_VERIFY_RECOVER     : CK_ATTRIBUTE_TYPE = 0x0000010B;
pub const CKA_DERIVE             : CK_ATTRIBUTE_TYPE = 0x0000010C;
pub const CKA_START_DATE         : CK_ATTRIBUTE_TYPE = 0x00000110;
pub const CKA_END_DATE           : CK_ATTRIBUTE_TYPE = 0x00000111;
pub const CKA_MODULUS            : CK_ATTRIBUTE_TYPE = 0x00000120;
pub const CKA_MODULUS_BITS       : CK_ATTRIBUTE_TYPE = 0x00000121;
pub const CKA_PUBLIC_EXPONENT    : CK_ATTRIBUTE_TYPE = 0x00000122;
pub const CKA_PRIVATE_EXPONENT   : CK_ATTRIBUTE_TYPE = 0x00000123;
pub const CKA_PRIME_1            : CK_ATTRIBUTE_TYPE = 0x00000124;
pub const CKA_PRIME_2            : CK_ATTRIBUTE_TYPE = 0x00000125;
pub const CKA_EXPONENT_1         : CK_ATTRIBUTE_TYPE = 0x00000126;
pub const CKA_EXPONENT_2         : CK_ATTRIBUTE_TYPE = 0x00000127;
pub const CKA_COEFFICIENT        : CK_ATTRIBUTE_TYPE = 0x00000128;
pub const CKA_PUBLIC_KEY_INFO    : CK_ATTRIBUTE_TYPE = 0x00000129;
pub const CKA_PRIME              : CK_ATTRIBUTE_TYPE = 0x00000130;
pub const CKA_SUBPRIME           : CK_ATTRIBUTE_TYPE = 0x00000131;
pub const CKA_BASE               : CK_ATTRIBUTE_TYPE = 0x00000132;

pub const CKA_PRIME_BITS         : CK_ATTRIBUTE_TYPE = 0x00000133;
pub const CKA_SUBPRIME_BITS      : CK_ATTRIBUTE_TYPE = 0x00000134;
pub const CKA_SUB_PRIME_BITS     : CK_ATTRIBUTE_TYPE = CKA_SUBPRIME_BITS;

pub const CKA_VALUE_BITS         : CK_ATTRIBUTE_TYPE = 0x00000160;
pub const CKA_VALUE_LEN          : CK_ATTRIBUTE_TYPE = 0x00000161;
pub const CKA_EXTRACTABLE        : CK_ATTRIBUTE_TYPE = 0x00000162;
pub const CKA_LOCAL              : CK_ATTRIBUTE_TYPE = 0x00000163;
pub const CKA_NEVER_EXTRACTABLE  : CK_ATTRIBUTE_TYPE = 0x00000164;
pub const CKA_ALWAYS_SENSITIVE   : CK_ATTRIBUTE_TYPE = 0x00000165;
pub const CKA_KEY_GEN_MECHANISM  : CK_ATTRIBUTE_TYPE = 0x00000166;

pub const CKA_MODIFIABLE         : CK_ATTRIBUTE_TYPE = 0x00000170;
pub const CKA_COPYABLE           : CK_ATTRIBUTE_TYPE = 0x00000171;

pub const CKA_DESTROYABLE          : CK_ATTRIBUTE_TYPE = 0x00000172;

pub const CKA_ECDSA_PARAMS      : CK_ATTRIBUTE_TYPE = CKA_EC_PARAMS;
pub const CKA_EC_PARAMS         : CK_ATTRIBUTE_TYPE = 0x00000180;

pub const CKA_EC_POINT          : CK_ATTRIBUTE_TYPE = 0x00000181;

pub const CKA_SECONDARY_AUTH    : CK_ATTRIBUTE_TYPE = 0x00000200; /* Deprecated */
pub const CKA_AUTH_PIN_FLAGS    : CK_ATTRIBUTE_TYPE = 0x00000201; /* Deprecated */

pub const CKA_ALWAYS_AUTHENTICATE : CK_ATTRIBUTE_TYPE = 0x00000202;

pub const CKA_WRAP_WITH_TRUSTED   : CK_ATTRIBUTE_TYPE = 0x00000210;
pub const CKA_WRAP_TEMPLATE       : CK_ATTRIBUTE_TYPE = (CKF_ARRAY_ATTRIBUTE|0x00000211);
pub const CKA_UNWRAP_TEMPLATE     : CK_ATTRIBUTE_TYPE = (CKF_ARRAY_ATTRIBUTE|0x00000212);
pub const CKA_DERIVE_TEMPLATE     : CK_ATTRIBUTE_TYPE = (CKF_ARRAY_ATTRIBUTE|0x00000213);

pub const CKA_OTP_FORMAT                : CK_ATTRIBUTE_TYPE = 0x00000220;
pub const CKA_OTP_LENGTH                : CK_ATTRIBUTE_TYPE = 0x00000221;
pub const CKA_OTP_TIME_INTERVAL         : CK_ATTRIBUTE_TYPE = 0x00000222;
pub const CKA_OTP_USER_FRIENDLY_MODE    : CK_ATTRIBUTE_TYPE = 0x00000223;
pub const CKA_OTP_CHALLENGE_REQUIREMENT : CK_ATTRIBUTE_TYPE = 0x00000224;
pub const CKA_OTP_TIME_REQUIREMENT      : CK_ATTRIBUTE_TYPE = 0x00000225;
pub const CKA_OTP_COUNTER_REQUIREMENT   : CK_ATTRIBUTE_TYPE = 0x00000226;
pub const CKA_OTP_PIN_REQUIREMENT       : CK_ATTRIBUTE_TYPE = 0x00000227;
pub const CKA_OTP_COUNTER               : CK_ATTRIBUTE_TYPE = 0x0000022E;
pub const CKA_OTP_TIME                  : CK_ATTRIBUTE_TYPE = 0x0000022F;
pub const CKA_OTP_USER_IDENTIFIER       : CK_ATTRIBUTE_TYPE = 0x0000022A;
pub const CKA_OTP_SERVICE_IDENTIFIER    : CK_ATTRIBUTE_TYPE = 0x0000022B;
pub const CKA_OTP_SERVICE_LOGO          : CK_ATTRIBUTE_TYPE = 0x0000022C;
pub const CKA_OTP_SERVICE_LOGO_TYPE     : CK_ATTRIBUTE_TYPE = 0x0000022D;

pub const CKA_GOSTR3410_PARAMS          : CK_ATTRIBUTE_TYPE = 0x00000250;
pub const CKA_GOSTR3411_PARAMS          : CK_ATTRIBUTE_TYPE = 0x00000251;
pub const CKA_GOST28147_PARAMS          : CK_ATTRIBUTE_TYPE = 0x00000252;

pub const CKA_HW_FEATURE_TYPE           : CK_ATTRIBUTE_TYPE = 0x00000300;
pub const CKA_RESET_ON_INIT             : CK_ATTRIBUTE_TYPE = 0x00000301;
pub const CKA_HAS_RESET                 : CK_ATTRIBUTE_TYPE = 0x00000302;

pub const CKA_PIXEL_X                     : CK_ATTRIBUTE_TYPE = 0x00000400;
pub const CKA_PIXEL_Y                     : CK_ATTRIBUTE_TYPE = 0x00000401;
pub const CKA_RESOLUTION                  : CK_ATTRIBUTE_TYPE = 0x00000402;
pub const CKA_CHAR_ROWS                   : CK_ATTRIBUTE_TYPE = 0x00000403;
pub const CKA_CHAR_COLUMNS                : CK_ATTRIBUTE_TYPE = 0x00000404;
pub const CKA_COLOR                       : CK_ATTRIBUTE_TYPE = 0x00000405;
pub const CKA_BITS_PER_PIXEL              : CK_ATTRIBUTE_TYPE = 0x00000406;
pub const CKA_CHAR_SETS                   : CK_ATTRIBUTE_TYPE = 0x00000480;
pub const CKA_ENCODING_METHODS            : CK_ATTRIBUTE_TYPE = 0x00000481;
pub const CKA_MIME_TYPES                  : CK_ATTRIBUTE_TYPE = 0x00000482;
pub const CKA_MECHANISM_TYPE              : CK_ATTRIBUTE_TYPE = 0x00000500;
pub const CKA_REQUIRED_CMS_ATTRIBUTES     : CK_ATTRIBUTE_TYPE = 0x00000501;
pub const CKA_DEFAULT_CMS_ATTRIBUTES      : CK_ATTRIBUTE_TYPE = 0x00000502;
pub const CKA_SUPPORTED_CMS_ATTRIBUTES    : CK_ATTRIBUTE_TYPE = 0x00000503;
pub const CKA_ALLOWED_MECHANISMS          : CK_ATTRIBUTE_TYPE = (CKF_ARRAY_ATTRIBUTE|0x00000600);

pub const CKA_VENDOR_DEFINED              : CK_ATTRIBUTE_TYPE = 0x80000000;

/// CK_ATTRIBUTE is a structure that includes the type, length
/// and value of an attribute
#[derive(Clone)]
#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub attrType: CK_ATTRIBUTE_TYPE,
    pub pValue: CK_VOID_PTR,
    /// in bytes
    pub ulValueLen: CK_ULONG,
}

pub type CK_ATTRIBUTE_PTR = *const CK_ATTRIBUTE;

impl Default for CK_ATTRIBUTE {
    fn default() -> Self {
        Self {
            attrType: CKA_VENDOR_DEFINED,
            pValue: ptr::null(),
            ulValueLen: 0,
        }
    }
}

impl std::fmt::Debug for CK_ATTRIBUTE {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        let attrType = format!("0x{:x}", self.attrType);
        let data = unsafe { slice::from_raw_parts(self.pValue as *const u8, self.ulValueLen) };
        fmt.debug_struct("CK_ATTRIBUTE")
            .field("attrType", &attrType)
            .field("pValue", &data)
            .field("ulValueLen", &self.ulValueLen)
            .finish()
    }
}

impl CK_ATTRIBUTE {
    pub fn new(attrType: CK_ATTRIBUTE_TYPE) -> Self {
        Self {
            attrType: attrType,
            pValue: ptr::null(),
            ulValueLen: 0,
        }
    }

    pub fn set_bool(mut self, b: &CK_BBOOL) -> Self {
        self.pValue = b as *const CK_BBOOL as CK_VOID_PTR;
        self.ulValueLen = 1;
        self
    }

    pub fn get_bool(&self) -> bool {
        let data: CK_BBOOL = unsafe { mem::transmute_copy(&*self.pValue) };
        CkFrom::from(data)
    }

    pub fn set_ck_ulong(mut self, val: &CK_ULONG) -> Self {
        self.pValue = val as *const _ as CK_VOID_PTR;
        self.ulValueLen = std::mem::size_of::<CK_ULONG>();
        self
    }

    pub fn get_ck_ulong(&self) -> CK_ULONG {
        unsafe { mem::transmute_copy(&*self.pValue) }
    }

    pub fn set_ck_long(mut self, val: &CK_LONG) -> Self {
        self.pValue = val as *const _ as CK_VOID_PTR;
        self.ulValueLen = std::mem::size_of::<CK_LONG>();
        self
    }

    pub fn get_ck_long(&self) -> CK_LONG {
        unsafe { mem::transmute_copy(&*self.pValue) }
    }

    pub fn set_biginteger(mut self, val: &Vec<u8>) -> Self {
        self.pValue = val.as_slice().as_ptr() as CK_VOID_PTR;
        self.ulValueLen = val.len();
        self
    }

    pub fn get_biginteger(&self) -> BigUint {
        let slice = unsafe { slice::from_raw_parts(self.pValue as CK_BYTE_PTR, self.ulValueLen) };
        BigUint::from_bytes_le(slice)
    }

    pub fn set_bytes(mut self, val: &[CK_BYTE]) -> Self {
        self.pValue = val.as_ptr() as CK_VOID_PTR;
        self.ulValueLen = val.len();
        self
    }

    pub fn get_bytes(&self) -> Vec<CK_BYTE> {
        let slice = unsafe { slice::from_raw_parts(self.pValue as CK_BYTE_PTR, self.ulValueLen) };
        Vec::from(slice).clone()
    }

    pub fn set_string(mut self, str: &String) -> Self {
        self.pValue = str.as_ptr() as CK_VOID_PTR;
        self.ulValueLen = str.len();
        self
    }

    pub fn get_string(&self) -> String {
        let slice = unsafe { slice::from_raw_parts(self.pValue as CK_BYTE_PTR, self.ulValueLen) };
        String::from_utf8_lossy(slice).into_owned().clone()
    }

    pub fn set_date(mut self, date: &CK_DATE) -> Self {
        self.pValue = (date as *const CK_DATE) as CK_VOID_PTR;
        self.ulValueLen = mem::size_of::<CK_DATE>();
        self
    }

    pub fn get_date(&self) -> CK_DATE {
        unsafe { mem::transmute_copy(&*self.pValue) }
    }
}

//trait CkAttributeFrom<T> {
//    fn from_ck(T, CK_ATTRIBUTE_TYPE) -> Self;
//}
//
//trait CkAttributeInto<T> {
//    fn into_attribute(self, CK_ATTRIBUTE_TYPE) -> CK_ATTRIBUTE;
//}
//
//impl<T> CkAttributeInto<T> for T where CK_ATTRIBUTE: CkAttributeFrom<T> {
//    fn into_attribute(self, attrType: CK_ATTRIBUTE_TYPE) -> CK_ATTRIBUTE {
//        CkAttributeFrom::from_ck(self, attrType)
//    }
//}
//
//impl CkAttributeFrom<bool> for CK_ATTRIBUTE {
//    fn from_ck(b: bool, attrType: CK_ATTRIBUTE_TYPE) -> CK_ATTRIBUTE {
//        let val: CK_BBOOL = if b { 1 } else { 0 };
//        let ret = Self {
//            attrType: attrType,
//            pValue: &val as *const u8 as *const CK_VOID,
//            ulValueLen: 1,
//        };
//        println!("{:?}", ret);
//        ret
//    }
//}

/// CK_DATE is a structure that defines a date
#[derive(Debug,Default,Clone)]
#[repr(C)]
pub struct CK_DATE{
    /// the year ("1900" - "9999")
    pub year: [CK_CHAR; 4],
    /// the month ("01" - "12")
    pub month: [CK_CHAR; 2],
    /// the day   ("01" - "31")
    pub day: [CK_CHAR; 2],
}

/// CK_MECHANISM_TYPE is a value that identifies a mechanism
/// type
pub type CK_MECHANISM_TYPE = CK_ULONG;

/// the following mechanism types are defined:
pub const CKM_RSA_PKCS_KEY_PAIR_GEN      : CK_MECHANISM_TYPE = 0x00000000;
pub const CKM_RSA_PKCS                   : CK_MECHANISM_TYPE = 0x00000001;
pub const CKM_RSA_9796                   : CK_MECHANISM_TYPE = 0x00000002;
pub const CKM_RSA_X_509                  : CK_MECHANISM_TYPE = 0x00000003;

pub const CKM_MD2_RSA_PKCS               : CK_MECHANISM_TYPE = 0x00000004;
pub const CKM_MD5_RSA_PKCS               : CK_MECHANISM_TYPE = 0x00000005;
pub const CKM_SHA1_RSA_PKCS              : CK_MECHANISM_TYPE = 0x00000006;

pub const CKM_RIPEMD128_RSA_PKCS         : CK_MECHANISM_TYPE = 0x00000007;
pub const CKM_RIPEMD160_RSA_PKCS         : CK_MECHANISM_TYPE = 0x00000008;
pub const CKM_RSA_PKCS_OAEP              : CK_MECHANISM_TYPE = 0x00000009;

pub const CKM_RSA_X9_31_KEY_PAIR_GEN     : CK_MECHANISM_TYPE = 0x0000000A;
pub const CKM_RSA_X9_31                  : CK_MECHANISM_TYPE = 0x0000000B;
pub const CKM_SHA1_RSA_X9_31             : CK_MECHANISM_TYPE = 0x0000000C;
pub const CKM_RSA_PKCS_PSS               : CK_MECHANISM_TYPE = 0x0000000D;
pub const CKM_SHA1_RSA_PKCS_PSS          : CK_MECHANISM_TYPE = 0x0000000E;

pub const CKM_DSA_KEY_PAIR_GEN           : CK_MECHANISM_TYPE = 0x00000010;
pub const CKM_DSA                        : CK_MECHANISM_TYPE = 0x00000011;
pub const CKM_DSA_SHA1                   : CK_MECHANISM_TYPE = 0x00000012;
pub const CKM_DSA_SHA224                 : CK_MECHANISM_TYPE = 0x00000013;
pub const CKM_DSA_SHA256                 : CK_MECHANISM_TYPE = 0x00000014;
pub const CKM_DSA_SHA384                 : CK_MECHANISM_TYPE = 0x00000015;
pub const CKM_DSA_SHA512                 : CK_MECHANISM_TYPE = 0x00000016;

pub const CKM_DH_PKCS_KEY_PAIR_GEN       : CK_MECHANISM_TYPE = 0x00000020;
pub const CKM_DH_PKCS_DERIVE             : CK_MECHANISM_TYPE = 0x00000021;

pub const CKM_X9_42_DH_KEY_PAIR_GEN      : CK_MECHANISM_TYPE = 0x00000030;
pub const CKM_X9_42_DH_DERIVE            : CK_MECHANISM_TYPE = 0x00000031;
pub const CKM_X9_42_DH_HYBRID_DERIVE     : CK_MECHANISM_TYPE = 0x00000032;
pub const CKM_X9_42_MQV_DERIVE           : CK_MECHANISM_TYPE = 0x00000033;

pub const CKM_SHA256_RSA_PKCS            : CK_MECHANISM_TYPE = 0x00000040;
pub const CKM_SHA384_RSA_PKCS            : CK_MECHANISM_TYPE = 0x00000041;
pub const CKM_SHA512_RSA_PKCS            : CK_MECHANISM_TYPE = 0x00000042;
pub const CKM_SHA256_RSA_PKCS_PSS        : CK_MECHANISM_TYPE = 0x00000043;
pub const CKM_SHA384_RSA_PKCS_PSS        : CK_MECHANISM_TYPE = 0x00000044;
pub const CKM_SHA512_RSA_PKCS_PSS        : CK_MECHANISM_TYPE = 0x00000045;

pub const CKM_SHA224_RSA_PKCS            : CK_MECHANISM_TYPE = 0x00000046;
pub const CKM_SHA224_RSA_PKCS_PSS        : CK_MECHANISM_TYPE = 0x00000047;

pub const CKM_SHA512_224                 : CK_MECHANISM_TYPE = 0x00000048;
pub const CKM_SHA512_224_HMAC            : CK_MECHANISM_TYPE = 0x00000049;
pub const CKM_SHA512_224_HMAC_GENERAL    : CK_MECHANISM_TYPE = 0x0000004A;
pub const CKM_SHA512_224_KEY_DERIVATION  : CK_MECHANISM_TYPE = 0x0000004B;
pub const CKM_SHA512_256                 : CK_MECHANISM_TYPE = 0x0000004C;
pub const CKM_SHA512_256_HMAC            : CK_MECHANISM_TYPE = 0x0000004D;
pub const CKM_SHA512_256_HMAC_GENERAL    : CK_MECHANISM_TYPE = 0x0000004E;
pub const CKM_SHA512_256_KEY_DERIVATION  : CK_MECHANISM_TYPE = 0x0000004F;

pub const CKM_SHA512_T                   : CK_MECHANISM_TYPE = 0x00000050;
pub const CKM_SHA512_T_HMAC              : CK_MECHANISM_TYPE = 0x00000051;
pub const CKM_SHA512_T_HMAC_GENERAL      : CK_MECHANISM_TYPE = 0x00000052;
pub const CKM_SHA512_T_KEY_DERIVATION    : CK_MECHANISM_TYPE = 0x00000053;

pub const CKM_RC2_KEY_GEN                : CK_MECHANISM_TYPE = 0x00000100;
pub const CKM_RC2_ECB                    : CK_MECHANISM_TYPE = 0x00000101;
pub const CKM_RC2_CBC                    : CK_MECHANISM_TYPE = 0x00000102;
pub const CKM_RC2_MAC                    : CK_MECHANISM_TYPE = 0x00000103;

pub const CKM_RC2_MAC_GENERAL            : CK_MECHANISM_TYPE = 0x00000104;
pub const CKM_RC2_CBC_PAD                : CK_MECHANISM_TYPE = 0x00000105;

pub const CKM_RC4_KEY_GEN                : CK_MECHANISM_TYPE = 0x00000110;
pub const CKM_RC4                        : CK_MECHANISM_TYPE = 0x00000111;
pub const CKM_DES_KEY_GEN                : CK_MECHANISM_TYPE = 0x00000120;
pub const CKM_DES_ECB                    : CK_MECHANISM_TYPE = 0x00000121;
pub const CKM_DES_CBC                    : CK_MECHANISM_TYPE = 0x00000122;
pub const CKM_DES_MAC                    : CK_MECHANISM_TYPE = 0x00000123;

pub const CKM_DES_MAC_GENERAL            : CK_MECHANISM_TYPE = 0x00000124;
pub const CKM_DES_CBC_PAD                : CK_MECHANISM_TYPE = 0x00000125;

pub const CKM_DES2_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000130;
pub const CKM_DES3_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000131;
pub const CKM_DES3_ECB                   : CK_MECHANISM_TYPE = 0x00000132;
pub const CKM_DES3_CBC                   : CK_MECHANISM_TYPE = 0x00000133;
pub const CKM_DES3_MAC                   : CK_MECHANISM_TYPE = 0x00000134;

pub const CKM_DES3_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000135;
pub const CKM_DES3_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000136;
pub const CKM_DES3_CMAC_GENERAL          : CK_MECHANISM_TYPE = 0x00000137;
pub const CKM_DES3_CMAC                  : CK_MECHANISM_TYPE = 0x00000138;
pub const CKM_CDMF_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000140;
pub const CKM_CDMF_ECB                   : CK_MECHANISM_TYPE = 0x00000141;
pub const CKM_CDMF_CBC                   : CK_MECHANISM_TYPE = 0x00000142;
pub const CKM_CDMF_MAC                   : CK_MECHANISM_TYPE = 0x00000143;
pub const CKM_CDMF_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000144;
pub const CKM_CDMF_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000145;

pub const CKM_DES_OFB64                  : CK_MECHANISM_TYPE = 0x00000150;
pub const CKM_DES_OFB8                   : CK_MECHANISM_TYPE = 0x00000151;
pub const CKM_DES_CFB64                  : CK_MECHANISM_TYPE = 0x00000152;
pub const CKM_DES_CFB8                   : CK_MECHANISM_TYPE = 0x00000153;

pub const CKM_MD2                        : CK_MECHANISM_TYPE = 0x00000200;

pub const CKM_MD2_HMAC                   : CK_MECHANISM_TYPE = 0x00000201;
pub const CKM_MD2_HMAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000202;

pub const CKM_MD5                        : CK_MECHANISM_TYPE = 0x00000210;

pub const CKM_MD5_HMAC                   : CK_MECHANISM_TYPE = 0x00000211;
pub const CKM_MD5_HMAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000212;

pub const CKM_SHA_1                      : CK_MECHANISM_TYPE = 0x00000220;

pub const CKM_SHA_1_HMAC                 : CK_MECHANISM_TYPE = 0x00000221;
pub const CKM_SHA_1_HMAC_GENERAL         : CK_MECHANISM_TYPE = 0x00000222;

pub const CKM_RIPEMD128                  : CK_MECHANISM_TYPE = 0x00000230;
pub const CKM_RIPEMD128_HMAC             : CK_MECHANISM_TYPE = 0x00000231;
pub const CKM_RIPEMD128_HMAC_GENERAL     : CK_MECHANISM_TYPE = 0x00000232;
pub const CKM_RIPEMD160                  : CK_MECHANISM_TYPE = 0x00000240;
pub const CKM_RIPEMD160_HMAC             : CK_MECHANISM_TYPE = 0x00000241;
pub const CKM_RIPEMD160_HMAC_GENERAL     : CK_MECHANISM_TYPE = 0x00000242;

pub const CKM_SHA256                     : CK_MECHANISM_TYPE = 0x00000250;
pub const CKM_SHA256_HMAC                : CK_MECHANISM_TYPE = 0x00000251;
pub const CKM_SHA256_HMAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000252;
pub const CKM_SHA224                     : CK_MECHANISM_TYPE = 0x00000255;
pub const CKM_SHA224_HMAC                : CK_MECHANISM_TYPE = 0x00000256;
pub const CKM_SHA224_HMAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000257;
pub const CKM_SHA384                     : CK_MECHANISM_TYPE = 0x00000260;
pub const CKM_SHA384_HMAC                : CK_MECHANISM_TYPE = 0x00000261;
pub const CKM_SHA384_HMAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000262;
pub const CKM_SHA512                     : CK_MECHANISM_TYPE = 0x00000270;
pub const CKM_SHA512_HMAC                : CK_MECHANISM_TYPE = 0x00000271;
pub const CKM_SHA512_HMAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000272;
pub const CKM_SECURID_KEY_GEN            : CK_MECHANISM_TYPE = 0x00000280;
pub const CKM_SECURID                    : CK_MECHANISM_TYPE = 0x00000282;
pub const CKM_HOTP_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000290;
pub const CKM_HOTP                       : CK_MECHANISM_TYPE = 0x00000291;
pub const CKM_ACTI                       : CK_MECHANISM_TYPE = 0x000002A0;
pub const CKM_ACTI_KEY_GEN               : CK_MECHANISM_TYPE = 0x000002A1;

pub const CKM_CAST_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000300;
pub const CKM_CAST_ECB                   : CK_MECHANISM_TYPE = 0x00000301;
pub const CKM_CAST_CBC                   : CK_MECHANISM_TYPE = 0x00000302;
pub const CKM_CAST_MAC                   : CK_MECHANISM_TYPE = 0x00000303;
pub const CKM_CAST_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000304;
pub const CKM_CAST_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000305;
pub const CKM_CAST3_KEY_GEN              : CK_MECHANISM_TYPE = 0x00000310;
pub const CKM_CAST3_ECB                  : CK_MECHANISM_TYPE = 0x00000311;
pub const CKM_CAST3_CBC                  : CK_MECHANISM_TYPE = 0x00000312;
pub const CKM_CAST3_MAC                  : CK_MECHANISM_TYPE = 0x00000313;
pub const CKM_CAST3_MAC_GENERAL          : CK_MECHANISM_TYPE = 0x00000314;
pub const CKM_CAST3_CBC_PAD              : CK_MECHANISM_TYPE = 0x00000315;
/// Note that CAST128 and CAST5 are the same algorithm
pub const CKM_CAST5_KEY_GEN              : CK_MECHANISM_TYPE = 0x00000320;
pub const CKM_CAST128_KEY_GEN            : CK_MECHANISM_TYPE = 0x00000320;
pub const CKM_CAST5_ECB                  : CK_MECHANISM_TYPE = 0x00000321;
pub const CKM_CAST128_ECB                : CK_MECHANISM_TYPE = 0x00000321;
pub const CKM_CAST5_CBC                  : CK_MECHANISM_TYPE = CKM_CAST128_CBC;
pub const CKM_CAST128_CBC                : CK_MECHANISM_TYPE = 0x00000322;
pub const CKM_CAST5_MAC                  : CK_MECHANISM_TYPE = CKM_CAST128_MAC;
pub const CKM_CAST128_MAC                : CK_MECHANISM_TYPE = 0x00000323;
pub const CKM_CAST5_MAC_GENERAL          : CK_MECHANISM_TYPE = CKM_CAST128_MAC_GENERAL;
pub const CKM_CAST128_MAC_GENERAL        : CK_MECHANISM_TYPE = 0x00000324;
pub const CKM_CAST5_CBC_PAD              : CK_MECHANISM_TYPE = CKM_CAST128_CBC_PAD;
pub const CKM_CAST128_CBC_PAD            : CK_MECHANISM_TYPE = 0x00000325;
pub const CKM_RC5_KEY_GEN                : CK_MECHANISM_TYPE = 0x00000330;
pub const CKM_RC5_ECB                    : CK_MECHANISM_TYPE = 0x00000331;
pub const CKM_RC5_CBC                    : CK_MECHANISM_TYPE = 0x00000332;
pub const CKM_RC5_MAC                    : CK_MECHANISM_TYPE = 0x00000333;
pub const CKM_RC5_MAC_GENERAL            : CK_MECHANISM_TYPE = 0x00000334;
pub const CKM_RC5_CBC_PAD                : CK_MECHANISM_TYPE = 0x00000335;
pub const CKM_IDEA_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000340;
pub const CKM_IDEA_ECB                   : CK_MECHANISM_TYPE = 0x00000341;
pub const CKM_IDEA_CBC                   : CK_MECHANISM_TYPE = 0x00000342;
pub const CKM_IDEA_MAC                   : CK_MECHANISM_TYPE = 0x00000343;
pub const CKM_IDEA_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000344;
pub const CKM_IDEA_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000345;
pub const CKM_GENERIC_SECRET_KEY_GEN     : CK_MECHANISM_TYPE = 0x00000350;
pub const CKM_CONCATENATE_BASE_AND_KEY   : CK_MECHANISM_TYPE = 0x00000360;
pub const CKM_CONCATENATE_BASE_AND_DATA  : CK_MECHANISM_TYPE = 0x00000362;
pub const CKM_CONCATENATE_DATA_AND_BASE  : CK_MECHANISM_TYPE = 0x00000363;
pub const CKM_XOR_BASE_AND_DATA          : CK_MECHANISM_TYPE = 0x00000364;
pub const CKM_EXTRACT_KEY_FROM_KEY       : CK_MECHANISM_TYPE = 0x00000365;
pub const CKM_SSL3_PRE_MASTER_KEY_GEN    : CK_MECHANISM_TYPE = 0x00000370;
pub const CKM_SSL3_MASTER_KEY_DERIVE     : CK_MECHANISM_TYPE = 0x00000371;
pub const CKM_SSL3_KEY_AND_MAC_DERIVE    : CK_MECHANISM_TYPE = 0x00000372;

pub const CKM_SSL3_MASTER_KEY_DERIVE_DH  : CK_MECHANISM_TYPE = 0x00000373;
pub const CKM_TLS_PRE_MASTER_KEY_GEN     : CK_MECHANISM_TYPE = 0x00000374;
pub const CKM_TLS_MASTER_KEY_DERIVE      : CK_MECHANISM_TYPE = 0x00000375;
pub const CKM_TLS_KEY_AND_MAC_DERIVE     : CK_MECHANISM_TYPE = 0x00000376;
pub const CKM_TLS_MASTER_KEY_DERIVE_DH   : CK_MECHANISM_TYPE = 0x00000377;

pub const CKM_TLS_PRF                    : CK_MECHANISM_TYPE = 0x00000378;

pub const CKM_SSL3_MD5_MAC               : CK_MECHANISM_TYPE = 0x00000380;
pub const CKM_SSL3_SHA1_MAC              : CK_MECHANISM_TYPE = 0x00000381;
pub const CKM_MD5_KEY_DERIVATION         : CK_MECHANISM_TYPE = 0x00000390;
pub const CKM_MD2_KEY_DERIVATION         : CK_MECHANISM_TYPE = 0x00000391;
pub const CKM_SHA1_KEY_DERIVATION        : CK_MECHANISM_TYPE = 0x00000392;

pub const CKM_SHA256_KEY_DERIVATION      : CK_MECHANISM_TYPE = 0x00000393;
pub const CKM_SHA384_KEY_DERIVATION      : CK_MECHANISM_TYPE = 0x00000394;
pub const CKM_SHA512_KEY_DERIVATION      : CK_MECHANISM_TYPE = 0x00000395;
pub const CKM_SHA224_KEY_DERIVATION      : CK_MECHANISM_TYPE = 0x00000396;

pub const CKM_PBE_MD2_DES_CBC            : CK_MECHANISM_TYPE = 0x000003A0;
pub const CKM_PBE_MD5_DES_CBC            : CK_MECHANISM_TYPE = 0x000003A1;
pub const CKM_PBE_MD5_CAST_CBC           : CK_MECHANISM_TYPE = 0x000003A2;
pub const CKM_PBE_MD5_CAST3_CBC          : CK_MECHANISM_TYPE = 0x000003A3;
pub const CKM_PBE_MD5_CAST5_CBC          : CK_MECHANISM_TYPE = CKM_PBE_MD5_CAST128_CBC;
pub const CKM_PBE_MD5_CAST128_CBC        : CK_MECHANISM_TYPE = 0x000003A4;
pub const CKM_PBE_SHA1_CAST5_CBC         : CK_MECHANISM_TYPE = CKM_PBE_SHA1_CAST128_CBC;
pub const CKM_PBE_SHA1_CAST128_CBC       : CK_MECHANISM_TYPE = 0x000003A5;
pub const CKM_PBE_SHA1_RC4_128           : CK_MECHANISM_TYPE = 0x000003A6;
pub const CKM_PBE_SHA1_RC4_40            : CK_MECHANISM_TYPE = 0x000003A7;
pub const CKM_PBE_SHA1_DES3_EDE_CBC      : CK_MECHANISM_TYPE = 0x000003A8;
pub const CKM_PBE_SHA1_DES2_EDE_CBC      : CK_MECHANISM_TYPE = 0x000003A9;
pub const CKM_PBE_SHA1_RC2_128_CBC       : CK_MECHANISM_TYPE = 0x000003AA;
pub const CKM_PBE_SHA1_RC2_40_CBC        : CK_MECHANISM_TYPE = 0x000003AB;

pub const CKM_PKCS5_PBKD2                : CK_MECHANISM_TYPE = 0x000003B0;

pub const CKM_PBA_SHA1_WITH_SHA1_HMAC    : CK_MECHANISM_TYPE = 0x000003C0;

pub const CKM_WTLS_PRE_MASTER_KEY_GEN         : CK_MECHANISM_TYPE = 0x000003D0;
pub const CKM_WTLS_MASTER_KEY_DERIVE          : CK_MECHANISM_TYPE = 0x000003D1;
pub const CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   : CK_MECHANISM_TYPE = 0x000003D2;
pub const CKM_WTLS_PRF                        : CK_MECHANISM_TYPE = 0x000003D3;
pub const CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  : CK_MECHANISM_TYPE = 0x000003D4;
pub const CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  : CK_MECHANISM_TYPE = 0x000003D5;

pub const CKM_TLS10_MAC_SERVER                : CK_MECHANISM_TYPE = 0x000003D6;
pub const CKM_TLS10_MAC_CLIENT                : CK_MECHANISM_TYPE = 0x000003D7;
pub const CKM_TLS12_MAC                       : CK_MECHANISM_TYPE = 0x000003D8;
pub const CKM_TLS12_KDF                       : CK_MECHANISM_TYPE = 0x000003D9;
pub const CKM_TLS12_MASTER_KEY_DERIVE         : CK_MECHANISM_TYPE = 0x000003E0;
pub const CKM_TLS12_KEY_AND_MAC_DERIVE        : CK_MECHANISM_TYPE = 0x000003E1;
pub const CKM_TLS12_MASTER_KEY_DERIVE_DH      : CK_MECHANISM_TYPE = 0x000003E2;
pub const CKM_TLS12_KEY_SAFE_DERIVE           : CK_MECHANISM_TYPE = 0x000003E3;
pub const CKM_TLS_MAC                         : CK_MECHANISM_TYPE = 0x000003E4;
pub const CKM_TLS_KDF                         : CK_MECHANISM_TYPE = 0x000003E5;

pub const CKM_KEY_WRAP_LYNKS             : CK_MECHANISM_TYPE = 0x00000400;
pub const CKM_KEY_WRAP_SET_OAEP          : CK_MECHANISM_TYPE = 0x00000401;

pub const CKM_CMS_SIG                    : CK_MECHANISM_TYPE = 0x00000500;
pub const CKM_KIP_DERIVE                 : CK_MECHANISM_TYPE = 0x00000510;
pub const CKM_KIP_WRAP                   : CK_MECHANISM_TYPE = 0x00000511;
pub const CKM_KIP_MAC                    : CK_MECHANISM_TYPE = 0x00000512;

pub const CKM_CAMELLIA_KEY_GEN           : CK_MECHANISM_TYPE = 0x00000550;
pub const CKM_CAMELLIA_ECB               : CK_MECHANISM_TYPE = 0x00000551;
pub const CKM_CAMELLIA_CBC               : CK_MECHANISM_TYPE = 0x00000552;
pub const CKM_CAMELLIA_MAC               : CK_MECHANISM_TYPE = 0x00000553;
pub const CKM_CAMELLIA_MAC_GENERAL       : CK_MECHANISM_TYPE = 0x00000554;
pub const CKM_CAMELLIA_CBC_PAD           : CK_MECHANISM_TYPE = 0x00000555;
pub const CKM_CAMELLIA_ECB_ENCRYPT_DATA  : CK_MECHANISM_TYPE = 0x00000556;
pub const CKM_CAMELLIA_CBC_ENCRYPT_DATA  : CK_MECHANISM_TYPE = 0x00000557;
pub const CKM_CAMELLIA_CTR               : CK_MECHANISM_TYPE = 0x00000558;

pub const CKM_ARIA_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000560;
pub const CKM_ARIA_ECB                   : CK_MECHANISM_TYPE = 0x00000561;
pub const CKM_ARIA_CBC                   : CK_MECHANISM_TYPE = 0x00000562;
pub const CKM_ARIA_MAC                   : CK_MECHANISM_TYPE = 0x00000563;
pub const CKM_ARIA_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000564;
pub const CKM_ARIA_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000565;
pub const CKM_ARIA_ECB_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00000566;
pub const CKM_ARIA_CBC_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00000567;

pub const CKM_SEED_KEY_GEN               : CK_MECHANISM_TYPE = 0x00000650;
pub const CKM_SEED_ECB                   : CK_MECHANISM_TYPE = 0x00000651;
pub const CKM_SEED_CBC                   : CK_MECHANISM_TYPE = 0x00000652;
pub const CKM_SEED_MAC                   : CK_MECHANISM_TYPE = 0x00000653;
pub const CKM_SEED_MAC_GENERAL           : CK_MECHANISM_TYPE = 0x00000654;
pub const CKM_SEED_CBC_PAD               : CK_MECHANISM_TYPE = 0x00000655;
pub const CKM_SEED_ECB_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00000656;
pub const CKM_SEED_CBC_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00000657;

pub const CKM_SKIPJACK_KEY_GEN           : CK_MECHANISM_TYPE = 0x00001000;
pub const CKM_SKIPJACK_ECB64             : CK_MECHANISM_TYPE = 0x00001001;
pub const CKM_SKIPJACK_CBC64             : CK_MECHANISM_TYPE = 0x00001002;
pub const CKM_SKIPJACK_OFB64             : CK_MECHANISM_TYPE = 0x00001003;
pub const CKM_SKIPJACK_CFB64             : CK_MECHANISM_TYPE = 0x00001004;
pub const CKM_SKIPJACK_CFB32             : CK_MECHANISM_TYPE = 0x00001005;
pub const CKM_SKIPJACK_CFB16             : CK_MECHANISM_TYPE = 0x00001006;
pub const CKM_SKIPJACK_CFB8              : CK_MECHANISM_TYPE = 0x00001007;
pub const CKM_SKIPJACK_WRAP              : CK_MECHANISM_TYPE = 0x00001008;
pub const CKM_SKIPJACK_PRIVATE_WRAP      : CK_MECHANISM_TYPE = 0x00001009;
pub const CKM_SKIPJACK_RELAYX            : CK_MECHANISM_TYPE = 0x0000100a;
pub const CKM_KEA_KEY_PAIR_GEN           : CK_MECHANISM_TYPE = 0x00001010;
pub const CKM_KEA_KEY_DERIVE             : CK_MECHANISM_TYPE = 0x00001011;
pub const CKM_KEA_DERIVE                 : CK_MECHANISM_TYPE = 0x00001012;
pub const CKM_FORTEZZA_TIMESTAMP         : CK_MECHANISM_TYPE = 0x00001020;
pub const CKM_BATON_KEY_GEN              : CK_MECHANISM_TYPE = 0x00001030;
pub const CKM_BATON_ECB128               : CK_MECHANISM_TYPE = 0x00001031;
pub const CKM_BATON_ECB96                : CK_MECHANISM_TYPE = 0x00001032;
pub const CKM_BATON_CBC128               : CK_MECHANISM_TYPE = 0x00001033;
pub const CKM_BATON_COUNTER              : CK_MECHANISM_TYPE = 0x00001034;
pub const CKM_BATON_SHUFFLE              : CK_MECHANISM_TYPE = 0x00001035;
pub const CKM_BATON_WRAP                 : CK_MECHANISM_TYPE = 0x00001036;

pub const CKM_ECDSA_KEY_PAIR_GEN         : CK_MECHANISM_TYPE = CKM_EC_KEY_PAIR_GEN;
pub const CKM_EC_KEY_PAIR_GEN            : CK_MECHANISM_TYPE = 0x00001040;

pub const CKM_ECDSA                      : CK_MECHANISM_TYPE = 0x00001041;
pub const CKM_ECDSA_SHA1                 : CK_MECHANISM_TYPE = 0x00001042;
pub const CKM_ECDSA_SHA224               : CK_MECHANISM_TYPE = 0x00001043;
pub const CKM_ECDSA_SHA256               : CK_MECHANISM_TYPE = 0x00001044;
pub const CKM_ECDSA_SHA384               : CK_MECHANISM_TYPE = 0x00001045;
pub const CKM_ECDSA_SHA512               : CK_MECHANISM_TYPE = 0x00001046;

pub const CKM_ECDH1_DERIVE               : CK_MECHANISM_TYPE = 0x00001050;
pub const CKM_ECDH1_COFACTOR_DERIVE      : CK_MECHANISM_TYPE = 0x00001051;
pub const CKM_ECMQV_DERIVE               : CK_MECHANISM_TYPE = 0x00001052;

pub const CKM_ECDH_AES_KEY_WRAP          : CK_MECHANISM_TYPE = 0x00001053;
pub const CKM_RSA_AES_KEY_WRAP           : CK_MECHANISM_TYPE = 0x00001054;

pub const CKM_JUNIPER_KEY_GEN            : CK_MECHANISM_TYPE = 0x00001060;
pub const CKM_JUNIPER_ECB128             : CK_MECHANISM_TYPE = 0x00001061;
pub const CKM_JUNIPER_CBC128             : CK_MECHANISM_TYPE = 0x00001062;
pub const CKM_JUNIPER_COUNTER            : CK_MECHANISM_TYPE = 0x00001063;
pub const CKM_JUNIPER_SHUFFLE            : CK_MECHANISM_TYPE = 0x00001064;
pub const CKM_JUNIPER_WRAP               : CK_MECHANISM_TYPE = 0x00001065;
pub const CKM_FASTHASH                   : CK_MECHANISM_TYPE = 0x00001070;

pub const CKM_AES_KEY_GEN                : CK_MECHANISM_TYPE = 0x00001080;
pub const CKM_AES_ECB                    : CK_MECHANISM_TYPE = 0x00001081;
pub const CKM_AES_CBC                    : CK_MECHANISM_TYPE = 0x00001082;
pub const CKM_AES_MAC                    : CK_MECHANISM_TYPE = 0x00001083;
pub const CKM_AES_MAC_GENERAL            : CK_MECHANISM_TYPE = 0x00001084;
pub const CKM_AES_CBC_PAD                : CK_MECHANISM_TYPE = 0x00001085;
pub const CKM_AES_CTR                    : CK_MECHANISM_TYPE = 0x00001086;
pub const CKM_AES_GCM                    : CK_MECHANISM_TYPE = 0x00001087;
pub const CKM_AES_CCM                    : CK_MECHANISM_TYPE = 0x00001088;
pub const CKM_AES_CTS                    : CK_MECHANISM_TYPE = 0x00001089;
pub const CKM_AES_CMAC                   : CK_MECHANISM_TYPE = 0x0000108A;
pub const CKM_AES_CMAC_GENERAL           : CK_MECHANISM_TYPE = 0x0000108B;

pub const CKM_AES_XCBC_MAC               : CK_MECHANISM_TYPE = 0x0000108C;
pub const CKM_AES_XCBC_MAC_96            : CK_MECHANISM_TYPE = 0x0000108D;
pub const CKM_AES_GMAC                   : CK_MECHANISM_TYPE = 0x0000108E;

pub const CKM_BLOWFISH_KEY_GEN           : CK_MECHANISM_TYPE = 0x00001090;
pub const CKM_BLOWFISH_CBC               : CK_MECHANISM_TYPE = 0x00001091;
pub const CKM_TWOFISH_KEY_GEN            : CK_MECHANISM_TYPE = 0x00001092;
pub const CKM_TWOFISH_CBC                : CK_MECHANISM_TYPE = 0x00001093;
pub const CKM_BLOWFISH_CBC_PAD           : CK_MECHANISM_TYPE = 0x00001094;
pub const CKM_TWOFISH_CBC_PAD            : CK_MECHANISM_TYPE = 0x00001095;

pub const CKM_DES_ECB_ENCRYPT_DATA       : CK_MECHANISM_TYPE = 0x00001100;
pub const CKM_DES_CBC_ENCRYPT_DATA       : CK_MECHANISM_TYPE = 0x00001101;
pub const CKM_DES3_ECB_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00001102;
pub const CKM_DES3_CBC_ENCRYPT_DATA      : CK_MECHANISM_TYPE = 0x00001103;
pub const CKM_AES_ECB_ENCRYPT_DATA       : CK_MECHANISM_TYPE = 0x00001104;
pub const CKM_AES_CBC_ENCRYPT_DATA       : CK_MECHANISM_TYPE = 0x00001105;

pub const CKM_GOSTR3410_KEY_PAIR_GEN     : CK_MECHANISM_TYPE = 0x00001200;
pub const CKM_GOSTR3410                  : CK_MECHANISM_TYPE = 0x00001201;
pub const CKM_GOSTR3410_WITH_GOSTR3411   : CK_MECHANISM_TYPE = 0x00001202;
pub const CKM_GOSTR3410_KEY_WRAP         : CK_MECHANISM_TYPE = 0x00001203;
pub const CKM_GOSTR3410_DERIVE           : CK_MECHANISM_TYPE = 0x00001204;
pub const CKM_GOSTR3411                  : CK_MECHANISM_TYPE = 0x00001210;
pub const CKM_GOSTR3411_HMAC             : CK_MECHANISM_TYPE = 0x00001211;
pub const CKM_GOST28147_KEY_GEN          : CK_MECHANISM_TYPE = 0x00001220;
pub const CKM_GOST28147_ECB              : CK_MECHANISM_TYPE = 0x00001221;
pub const CKM_GOST28147                  : CK_MECHANISM_TYPE = 0x00001222;
pub const CKM_GOST28147_MAC              : CK_MECHANISM_TYPE = 0x00001223;
pub const CKM_GOST28147_KEY_WRAP         : CK_MECHANISM_TYPE = 0x00001224;

pub const CKM_DSA_PARAMETER_GEN          : CK_MECHANISM_TYPE = 0x00002000;
pub const CKM_DH_PKCS_PARAMETER_GEN      : CK_MECHANISM_TYPE = 0x00002001;
pub const CKM_X9_42_DH_PARAMETER_GEN     : CK_MECHANISM_TYPE = 0x00002002;
pub const CKM_DSA_PROBABLISTIC_PARAMETER_GEN   : CK_MECHANISM_TYPE = 0x00002003;
pub const CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN   : CK_MECHANISM_TYPE = 0x00002004;

pub const CKM_AES_OFB                   : CK_MECHANISM_TYPE = 0x00002104;
pub const CKM_AES_CFB64                 : CK_MECHANISM_TYPE = 0x00002105;
pub const CKM_AES_CFB8                  : CK_MECHANISM_TYPE = 0x00002106;
pub const CKM_AES_CFB128                : CK_MECHANISM_TYPE = 0x00002107;

pub const CKM_AES_CFB1                  : CK_MECHANISM_TYPE = 0x00002108;
/// WAS: 0x00001090
pub const CKM_AES_KEY_WRAP              : CK_MECHANISM_TYPE = 0x00002109;
/// WAS: 0x00001091
pub const CKM_AES_KEY_WRAP_PAD          : CK_MECHANISM_TYPE = 0x0000210A;

pub const CKM_RSA_PKCS_TPM_1_1          : CK_MECHANISM_TYPE = 0x00004001;
pub const CKM_RSA_PKCS_OAEP_TPM_1_1     : CK_MECHANISM_TYPE = 0x00004002;

pub const CKM_VENDOR_DEFINED            : CK_MECHANISM_TYPE = 0x80000000;

pub type CK_MECHANISM_TYPE_PTR = *const CK_MECHANISM_TYPE;


/// CK_MECHANISM is a structure that specifies a particular
/// mechanism
#[derive(Debug,Clone)]
#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub pParameter: CK_VOID_PTR,
    /// in bytes
    pub ulParameterLen: CK_ULONG,
}

pub type CK_MECHANISM_PTR = *const CK_MECHANISM;

/// CK_MECHANISM_INFO provides information about a particular
/// mechanism
#[derive(Debug,Default,Clone)]
#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub ulMinKeySize: CK_ULONG,
    pub ulMaxKeySize: CK_ULONG,
    pub flags: CK_FLAGS,
}

/// The flags are defined as follows:
pub const CKF_HW                : CK_FLAGS = 0x00000001;  /* performed by HW */

/// Specify whether or not a mechanism can be used for a particular task
pub const CKF_ENCRYPT            : CK_FLAGS = 0x00000100;
pub const CKF_DECRYPT            : CK_FLAGS = 0x00000200;
pub const CKF_DIGEST             : CK_FLAGS = 0x00000400;
pub const CKF_SIGN               : CK_FLAGS = 0x00000800;
pub const CKF_SIGN_RECOVER       : CK_FLAGS = 0x00001000;
pub const CKF_VERIFY             : CK_FLAGS = 0x00002000;
pub const CKF_VERIFY_RECOVER     : CK_FLAGS = 0x00004000;
pub const CKF_GENERATE           : CK_FLAGS = 0x00008000;
pub const CKF_GENERATE_KEY_PAIR  : CK_FLAGS = 0x00010000;
pub const CKF_WRAP               : CK_FLAGS = 0x00020000;
pub const CKF_UNWRAP             : CK_FLAGS = 0x00040000;
pub const CKF_DERIVE             : CK_FLAGS = 0x00080000;

/// Describe a token's EC capabilities not available in mechanism
/// information.
pub const CKF_EC_F_P             : CK_FLAGS = 0x00100000;
pub const CKF_EC_F_2M            : CK_FLAGS = 0x00200000;
pub const CKF_EC_ECPARAMETERS    : CK_FLAGS = 0x00400000;
pub const CKF_EC_NAMEDCURVE      : CK_FLAGS = 0x00800000;
pub const CKF_EC_UNCOMPRESS      : CK_FLAGS = 0x01000000;
pub const CKF_EC_COMPRESS        : CK_FLAGS = 0x02000000;

pub const CKF_EXTENSION          : CK_FLAGS = 0x80000000;

pub type CK_MECHANISM_INFO_PTR = *const CK_MECHANISM_INFO;

/// CK_RV is a value that identifies the return value of a
/// Cryptoki function
pub type CK_RV = CK_ULONG;
pub const CKR_OK                               : CK_RV = 0x00000000;
pub const CKR_CANCEL                           : CK_RV = 0x00000001;
pub const CKR_HOST_MEMORY                      : CK_RV = 0x00000002;
pub const CKR_SLOT_ID_INVALID                  : CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR                    : CK_RV = 0x00000005;
pub const CKR_FUNCTION_FAILED                  : CK_RV = 0x00000006;
pub const CKR_ARGUMENTS_BAD                    : CK_RV = 0x00000007;
pub const CKR_NO_EVENT                         : CK_RV = 0x00000008;
pub const CKR_NEED_TO_CREATE_THREADS           : CK_RV = 0x00000009;
pub const CKR_CANT_LOCK                        : CK_RV = 0x0000000A;
pub const CKR_ATTRIBUTE_READ_ONLY              : CK_RV = 0x00000010;
pub const CKR_ATTRIBUTE_SENSITIVE              : CK_RV = 0x00000011;
pub const CKR_ATTRIBUTE_TYPE_INVALID           : CK_RV = 0x00000012;
pub const CKR_ATTRIBUTE_VALUE_INVALID          : CK_RV = 0x00000013;
pub const CKR_ACTION_PROHIBITED                : CK_RV = 0x0000001B;
pub const CKR_DATA_INVALID                     : CK_RV = 0x00000020;
pub const CKR_DATA_LEN_RANGE                   : CK_RV = 0x00000021;
pub const CKR_DEVICE_ERROR                     : CK_RV = 0x00000030;
pub const CKR_DEVICE_MEMORY                    : CK_RV = 0x00000031;
pub const CKR_DEVICE_REMOVED                   : CK_RV = 0x00000032;
pub const CKR_ENCRYPTED_DATA_INVALID           : CK_RV = 0x00000040;
pub const CKR_ENCRYPTED_DATA_LEN_RANGE         : CK_RV = 0x00000041;
pub const CKR_FUNCTION_CANCELED                : CK_RV = 0x00000050;
pub const CKR_FUNCTION_NOT_PARALLEL            : CK_RV = 0x00000051;
pub const CKR_FUNCTION_NOT_SUPPORTED           : CK_RV = 0x00000054;
pub const CKR_KEY_HANDLE_INVALID               : CK_RV = 0x00000060;
pub const CKR_KEY_SIZE_RANGE                   : CK_RV = 0x00000062;
pub const CKR_KEY_TYPE_INCONSISTENT            : CK_RV = 0x00000063;
pub const CKR_KEY_NOT_NEEDED                   : CK_RV = 0x00000064;
pub const CKR_KEY_CHANGED                      : CK_RV = 0x00000065;
pub const CKR_KEY_NEEDED                       : CK_RV = 0x00000066;
pub const CKR_KEY_INDIGESTIBLE                 : CK_RV = 0x00000067;
pub const CKR_KEY_FUNCTION_NOT_PERMITTED       : CK_RV = 0x00000068;
pub const CKR_KEY_NOT_WRAPPABLE                : CK_RV = 0x00000069;
pub const CKR_KEY_UNEXTRACTABLE                : CK_RV = 0x0000006A;
pub const CKR_MECHANISM_INVALID                : CK_RV = 0x00000070;
pub const CKR_MECHANISM_PARAM_INVALID          : CK_RV = 0x00000071;
pub const CKR_OBJECT_HANDLE_INVALID            : CK_RV = 0x00000082;
pub const CKR_OPERATION_ACTIVE                 : CK_RV = 0x00000090;
pub const CKR_OPERATION_NOT_INITIALIZED        : CK_RV = 0x00000091;
pub const CKR_PIN_INCORRECT                    : CK_RV = 0x000000A0;
pub const CKR_PIN_INVALID                      : CK_RV = 0x000000A1;
pub const CKR_PIN_LEN_RANGE                    : CK_RV = 0x000000A2;
pub const CKR_PIN_EXPIRED                      : CK_RV = 0x000000A3;
pub const CKR_PIN_LOCKED                       : CK_RV = 0x000000A4;
pub const CKR_SESSION_CLOSED                   : CK_RV = 0x000000B0;
pub const CKR_SESSION_COUNT                    : CK_RV = 0x000000B1;
pub const CKR_SESSION_HANDLE_INVALID           : CK_RV = 0x000000B3;
pub const CKR_SESSION_PARALLEL_NOT_SUPPORTED   : CK_RV = 0x000000B4;
pub const CKR_SESSION_READ_ONLY                : CK_RV = 0x000000B5;
pub const CKR_SESSION_EXISTS                   : CK_RV = 0x000000B6;
pub const CKR_SESSION_READ_ONLY_EXISTS         : CK_RV = 0x000000B7;
pub const CKR_SESSION_READ_WRITE_SO_EXISTS     : CK_RV = 0x000000B8;
pub const CKR_SIGNATURE_INVALID                : CK_RV = 0x000000C0;
pub const CKR_SIGNATURE_LEN_RANGE              : CK_RV = 0x000000C1;
pub const CKR_TEMPLATE_INCOMPLETE              : CK_RV = 0x000000D0;
pub const CKR_TEMPLATE_INCONSISTENT            : CK_RV = 0x000000D1;
pub const CKR_TOKEN_NOT_PRESENT                : CK_RV = 0x000000E0;
pub const CKR_TOKEN_NOT_RECOGNIZED             : CK_RV = 0x000000E1;
pub const CKR_TOKEN_WRITE_PROTECTED            : CK_RV = 0x000000E2;
pub const CKR_UNWRAPPING_KEY_HANDLE_INVALID    : CK_RV = 0x000000F0;
pub const CKR_UNWRAPPING_KEY_SIZE_RANGE        : CK_RV = 0x000000F1;
pub const CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT : CK_RV = 0x000000F2;
pub const CKR_USER_ALREADY_LOGGED_IN           : CK_RV = 0x00000100;
pub const CKR_USER_NOT_LOGGED_IN               : CK_RV = 0x00000101;
pub const CKR_USER_PIN_NOT_INITIALIZED         : CK_RV = 0x00000102;
pub const CKR_USER_TYPE_INVALID                : CK_RV = 0x00000103;
pub const CKR_USER_ANOTHER_ALREADY_LOGGED_IN   : CK_RV = 0x00000104;
pub const CKR_USER_TOO_MANY_TYPES              : CK_RV = 0x00000105;
pub const CKR_WRAPPED_KEY_INVALID              : CK_RV = 0x00000110;
pub const CKR_WRAPPED_KEY_LEN_RANGE            : CK_RV = 0x00000112;
pub const CKR_WRAPPING_KEY_HANDLE_INVALID      : CK_RV = 0x00000113;
pub const CKR_WRAPPING_KEY_SIZE_RANGE          : CK_RV = 0x00000114;
pub const CKR_WRAPPING_KEY_TYPE_INCONSISTENT   : CK_RV = 0x00000115;
pub const CKR_RANDOM_SEED_NOT_SUPPORTED        : CK_RV = 0x00000120;
pub const CKR_RANDOM_NO_RNG                    : CK_RV = 0x00000121;
pub const CKR_DOMAIN_PARAMS_INVALID            : CK_RV = 0x00000130;
pub const CKR_CURVE_NOT_SUPPORTED              : CK_RV = 0x00000140;
pub const CKR_BUFFER_TOO_SMALL                 : CK_RV = 0x00000150;
pub const CKR_SAVED_STATE_INVALID              : CK_RV = 0x00000160;
pub const CKR_INFORMATION_SENSITIVE            : CK_RV = 0x00000170;
pub const CKR_STATE_UNSAVEABLE                 : CK_RV = 0x00000180;
pub const CKR_CRYPTOKI_NOT_INITIALIZED         : CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED     : CK_RV = 0x00000191;
pub const CKR_MUTEX_BAD                        : CK_RV = 0x000001A0;
pub const CKR_MUTEX_NOT_LOCKED                 : CK_RV = 0x000001A1;
pub const CKR_NEW_PIN_MODE                     : CK_RV = 0x000001B0;
pub const CKR_NEXT_OTP                         : CK_RV = 0x000001B1;
pub const CKR_EXCEEDED_MAX_ITERATIONS          : CK_RV = 0x000001B5;
pub const CKR_FIPS_SELF_TEST_FAILED            : CK_RV = 0x000001B6;
pub const CKR_LIBRARY_LOAD_FAILED              : CK_RV = 0x000001B7;
pub const CKR_PIN_TOO_WEAK                     : CK_RV = 0x000001B8;
pub const CKR_PUBLIC_KEY_INVALID               : CK_RV = 0x000001B9;
pub const CKR_FUNCTION_REJECTED                : CK_RV = 0x00000200;
pub const CKR_VENDOR_DEFINED                   : CK_RV = 0x80000000;

/// CK_NOTIFY is an application callback that processes events
pub type CK_NOTIFY = Option<extern "C" fn(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) -> CK_RV>;

/// CK_FUNCTION_LIST is a structure holding a Cryptoki spec
/// version and pointers of appropriate types to all the
/// Cryptoki functions
#[derive(Debug,Clone)]
#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub C_Initialize: Option<C_Initialize>,
    pub C_Finalize: Option<C_Finalize>,
    pub C_GetInfo: Option<C_GetInfo>,
    pub C_GetFunctionList: Option<C_GetFunctionList>,
    pub C_GetSlotList: Option<C_GetSlotList>,
    pub C_GetSlotInfo: Option<C_GetSlotInfo>,
    pub C_GetTokenInfo: Option<C_GetTokenInfo>,
    pub C_GetMechanismList: Option<C_GetMechanismList>,
    pub C_GetMechanismInfo: Option<C_GetMechanismInfo>,
    pub C_InitToken: Option<C_InitToken>,
    pub C_InitPIN: Option<C_InitPIN>,
    pub C_SetPIN: Option<C_SetPIN>,
    pub C_OpenSession: Option<C_OpenSession>,
    pub C_CloseSession: Option<C_CloseSession>,
    pub C_CloseAllSessions: Option<C_CloseAllSessions>,
    pub C_GetSessionInfo: Option<C_GetSessionInfo>,
    pub C_GetOperationState: Option<C_GetOperationState>,
    pub C_SetOperationState: Option<C_SetOperationState>,
    pub C_Login: Option<C_Login>,
    pub C_Logout: Option<C_Logout>,
    pub C_CreateObject: Option<C_CreateObject>,
    pub C_CopyObject: Option<C_CopyObject>,
    pub C_DestroyObject: Option<C_DestroyObject>,
    pub C_GetObjectSize: Option<C_GetObjectSize>,
    pub C_GetAttributeValue: Option<C_GetAttributeValue>,
    pub C_SetAttributeValue: Option<C_SetAttributeValue>,
    pub C_FindObjectsInit: Option<C_FindObjectsInit>,
    pub C_FindObjects: Option<C_FindObjects>,
    pub C_FindObjectsFinal: Option<C_FindObjectsFinal>,
}
pub type CK_FUNCTION_LIST_PTR = *const CK_FUNCTION_LIST;
pub type CK_FUNCTION_LIST_PTR_PTR = *const CK_FUNCTION_LIST_PTR;

/// CK_CREATEMUTEX is an application callback for creating a
/// mutex object
pub type CK_CREATEMUTEX = Option<extern "C" fn(CK_VOID_PTR_PTR) -> CK_RV>;
/// CK_DESTROYMUTEX is an application callback for destroying a
/// mutex object
pub type CK_DESTROYMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;
/// CK_LOCKMUTEX is an application callback for locking a mutex
pub type CK_LOCKMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;
/// CK_UNLOCKMUTEX is an application callback for unlocking a
/// mutex
pub type CK_UNLOCKMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;

/// CK_C_INITIALIZE_ARGS provides the optional arguments to
/// C_Initialize
#[derive(Debug)]
#[repr(C)]
pub struct CK_C_INITIALIZE_ARGS {
  pub CreateMutex: CK_CREATEMUTEX,
  pub DestroyMutex: CK_DESTROYMUTEX,
  pub LockMutex: CK_LOCKMUTEX,
  pub UnlockMutex: CK_UNLOCKMUTEX,
  pub flags: CK_FLAGS,
  pub pReserved: CK_VOID_PTR,
}

// TODO: we need to make this the default and implement a new
// function
impl CK_C_INITIALIZE_ARGS {
    pub fn new() -> CK_C_INITIALIZE_ARGS {
        CK_C_INITIALIZE_ARGS {
            flags: CKF_OS_LOCKING_OK,
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            pReserved: ptr::null(),
        }
    }
}

pub const CKF_LIBRARY_CANT_CREATE_OS_THREADS: CK_FLAGS = 0x00000001;
pub const CKF_OS_LOCKING_OK: CK_FLAGS                  = 0x00000002;

pub type CK_C_INITIALIZE_ARGS_PTR = *const CK_C_INITIALIZE_ARGS;

/// CKF_DONT_BLOCK is for the function C_WaitForSlotEvent
pub const CKF_DONT_BLOCK    : CK_FLAGS = 1;

/// CK_RSA_PKCS_MGF_TYPE  is used to indicate the Message
/// Generation Function (MGF) applied to a message block when
/// formatting a message block for the PKCS #1 OAEP encryption
/// scheme.
pub type CK_RSA_PKCS_MGF_TYPE = CK_ULONG;

pub type CK_RSA_PKCS_MGF_TYPE_PTR = *const CK_RSA_PKCS_MGF_TYPE;

/// The following MGFs are defined
pub const CKG_MGF1_SHA1         : CK_RSA_PKCS_MGF_TYPE = 0x00000001;
pub const CKG_MGF1_SHA256       : CK_RSA_PKCS_MGF_TYPE = 0x00000002;
pub const CKG_MGF1_SHA384       : CK_RSA_PKCS_MGF_TYPE = 0x00000003;
pub const CKG_MGF1_SHA512       : CK_RSA_PKCS_MGF_TYPE = 0x00000004;
pub const CKG_MGF1_SHA224       : CK_RSA_PKCS_MGF_TYPE = 0x00000005;



trait CkFrom<T> {
    fn from(T) -> Self;
}

impl CkFrom<bool> for CK_BBOOL {
    fn from(b: bool) -> Self {
        match b {
            true => 1,
            false => 0,
        }
    }
}

impl CkFrom<CK_BBOOL> for bool {
    fn from(b: CK_BBOOL) -> bool {
        match b {
            0 => false,
            _ => true,
        }
    }
}

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

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Module(&'static str),
    InvalidInput(&'static str),
    Pkcs11(CK_RV),
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::Io(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::Io(ref err) => write!(f, "IO error: {}", err),
            Error::Module(ref err) => write!(f, "PKCS#11 Module error: {}", err),
            Error::InvalidInput(ref err) => write!(f, "Invalid Input for PKCS#11: {}", err),
            Error::Pkcs11(ref err) => write!(f, "PKCS#11 error: 0x{:x}", err),
        }
    }
}

fn label_from_str(label: &str) -> [CK_UTF8CHAR; 32] {
    // initialize a fixed-size array with whitespace characters
    let mut lab: [CK_UTF8CHAR; 32] = [32; 32];
    let mut i = 0;
    for c in label.chars() {
        if i + c.len_utf8() <= 32 {
            let mut buf = [0; 4];
            let bytes = c.encode_utf8(&mut buf).as_bytes();
            for b in bytes {
                lab[i] = b.clone();
                i += 1;
            }
        } else {
            break
        }
    }
    lab
}

#[derive(Debug)]
pub struct Ctx {
  lib: libloading::Library,
  _is_initialized: bool,
  C_Initialize: C_Initialize,
  C_Finalize: C_Finalize,
  C_GetInfo: C_GetInfo,
  C_GetFunctionList: C_GetFunctionList,
  C_GetSlotList: C_GetSlotList,
  C_GetSlotInfo: C_GetSlotInfo,
  C_GetTokenInfo: C_GetTokenInfo,
  C_GetMechanismList: C_GetMechanismList,
  C_GetMechanismInfo: C_GetMechanismInfo,
  C_InitToken: C_InitToken,
  C_InitPIN: C_InitPIN,
  C_SetPIN: C_SetPIN,
  C_OpenSession: C_OpenSession,
  C_CloseSession: C_CloseSession,
  C_CloseAllSessions: C_CloseAllSessions,
  C_GetSessionInfo: C_GetSessionInfo,
  C_GetOperationState: C_GetOperationState,
  C_SetOperationState: C_SetOperationState,
  C_Login: C_Login,
  C_Logout: C_Logout,
  C_CreateObject: C_CreateObject,
  C_CopyObject: C_CopyObject,
  C_DestroyObject: C_DestroyObject,
  C_GetObjectSize: C_GetObjectSize,
  C_GetAttributeValue: C_GetAttributeValue,
  C_SetAttributeValue: C_SetAttributeValue,
  C_FindObjectsInit: C_FindObjectsInit,
  C_FindObjects: C_FindObjects,
  C_FindObjectsFinal: C_FindObjectsFinal,
}

impl Ctx {
    pub fn new(filename: &'static str) -> Result<Ctx, Error> {
        unsafe {
            let lib = libloading::Library::new(filename)?;
            let mut list: CK_FUNCTION_LIST_PTR = mem::uninitialized();
            {
                let func: libloading::Symbol<unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib.get(b"C_GetFunctionList")?;
                match func(&mut list) {
                    CKR_OK => (),
                    err => return Err(Error::Pkcs11(err)),
                }
            }

            Ok(Ctx {
                lib: lib,
                _is_initialized: false,
                C_Initialize: (*list).C_Initialize.ok_or(Error::Module("C_Initialize function not found"))?,
                C_Finalize: (*list).C_Finalize.ok_or(Error::Module("C_Finalize function not found"))?,
                C_GetInfo: (*list).C_GetInfo.ok_or(Error::Module("C_GetInfo function not found"))?,
                C_GetFunctionList: (*list).C_GetFunctionList.ok_or(Error::Module("C_GetFunctionList function not found"))?,
                C_GetSlotList: (*list).C_GetSlotList.ok_or(Error::Module("C_GetSlotList function not found"))?,
                C_GetSlotInfo: (*list).C_GetSlotInfo.ok_or(Error::Module("C_GetSlotInfo function not found"))?,
                C_GetTokenInfo: (*list).C_GetTokenInfo.ok_or(Error::Module("C_GetTokenInfo function not found"))?,
                C_GetMechanismList: (*list).C_GetMechanismList.ok_or(Error::Module("C_GetMechanismList function not found"))?,
                C_GetMechanismInfo: (*list).C_GetMechanismInfo.ok_or(Error::Module("C_GetMechanismInfo function not found"))?,
                C_InitToken: (*list).C_InitToken.ok_or(Error::Module("C_InitToken function not found"))?,
                C_InitPIN: (*list).C_InitPIN.ok_or(Error::Module("C_InitPIN function not found"))?,
                C_SetPIN: (*list).C_SetPIN.ok_or(Error::Module("C_SetPIN function not found"))?,
                C_OpenSession: (*list).C_OpenSession.ok_or(Error::Module("C_OpenSession function not found"))?,
                C_CloseSession: (*list).C_CloseSession.ok_or(Error::Module("C_CloseSession function not found"))?,
                C_CloseAllSessions: (*list).C_CloseAllSessions.ok_or(Error::Module("C_CloseAllSessions function not found"))?,
                C_GetSessionInfo: (*list).C_GetSessionInfo.ok_or(Error::Module("C_GetSessionInfo function not found"))?,
                C_GetOperationState: (*list).C_GetOperationState.ok_or(Error::Module("C_GetOperationState function not found"))?,
                C_SetOperationState: (*list).C_SetOperationState.ok_or(Error::Module("C_SetOperationState function not found"))?,
                C_Login: (*list).C_Login.ok_or(Error::Module("C_Login function not found"))?,
                C_Logout: (*list).C_Logout.ok_or(Error::Module("C_Logout function not found"))?,
                C_CreateObject: (*list).C_CreateObject.ok_or(Error::Module("C_CreateObject function not found"))?,
                C_CopyObject: (*list).C_CopyObject.ok_or(Error::Module("C_CopyObject function not found"))?,
                C_DestroyObject: (*list).C_DestroyObject.ok_or(Error::Module("C_DestroyObject function not found"))?,
                C_GetObjectSize: (*list).C_GetObjectSize.ok_or(Error::Module("C_GetObjectSize function not found"))?,
                C_GetAttributeValue: (*list).C_GetAttributeValue.ok_or(Error::Module("C_GetAttributeValue function not found"))?,
                C_SetAttributeValue: (*list).C_SetAttributeValue.ok_or(Error::Module("C_SetAttributeValue function not found"))?,
                C_FindObjectsInit: (*list).C_FindObjectsInit.ok_or(Error::Module("C_FindObjectsInit function not found"))?,
                C_FindObjects: (*list).C_FindObjects.ok_or(Error::Module("C_FindObjects function not found"))?,
                C_FindObjectsFinal: (*list).C_FindObjectsFinal.ok_or(Error::Module("C_FindObjectsFinal function not found"))?,
            })
        }
    }

    pub fn new_and_initialize(filename: &'static str) -> Result<Ctx, Error> {
        let mut ctx = Ctx::new(filename)?;
        ctx.initialize(None)?;
        Ok(ctx)
    }

    pub fn is_initialized(&self) -> bool {
        self._is_initialized
    }

    fn initialized(&self) -> Result<(),Error> {
        if !self._is_initialized {
            Err(Error::Module("module not initialized"))
        } else {
            Ok(())
        }
    }

    fn not_initialized(&self) -> Result<(),Error> {
        if self._is_initialized {
            Err(Error::Module("module already initialized"))
        } else {
            Ok(())
        }
    }

    pub fn initialize(&mut self, init_args: Option<CK_C_INITIALIZE_ARGS>) -> Result<(), Error> {
        self.not_initialized()?;
        match (self.C_Initialize)(&init_args.unwrap_or(CK_C_INITIALIZE_ARGS::new())) {
            CKR_OK => {
                self._is_initialized = true;
                Ok(())
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        self.initialized()?;
        match (self.C_Finalize)(ptr::null()) {
            CKR_OK => {
                self._is_initialized = false;
                Ok(())
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_info(&self) -> Result<CK_INFO, Error> {
        self.initialized()?;
        let info = CK_INFO::new();
        match (self.C_GetInfo)(&info) {
            CKR_OK => {
                Ok(info)
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_function_list(&self) -> Result<CK_FUNCTION_LIST, Error> {
        let list: CK_FUNCTION_LIST_PTR = unsafe { mem::uninitialized() };
        match (self.C_GetFunctionList)(&list) {
            CKR_OK => {
                unsafe { Ok((*list).clone()) }
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_slot_list(&self, token_present: bool) -> Result<Vec<CK_SLOT_ID>, Error> {
        self.initialized()?;
        let mut slots_len: CK_ULONG = 0;
        match (self.C_GetSlotList)(CkFrom::from(token_present), ptr::null(), &mut slots_len) {
            CKR_OK => {
                // now slots_len contains the number of slots,
                // and we can generate a vector with the right capacity
                // important is to pass slots_len **again** because in
                // the 2nd call it is used to tell C how big the memory
                // in slots is.
                let mut slots = Vec::<CK_SLOT_ID>::with_capacity(slots_len);
                let slots_ptr = slots.as_mut_ptr();
                match (self.C_GetSlotList)(CkFrom::from(token_present), slots_ptr, &slots_len) {
                    CKR_OK => {
                        unsafe { 
                            slots.set_len(slots_len);
                        }
                        Ok(slots)
                    },
                    err => Err(Error::Pkcs11(err)),
                }
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_slot_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_SLOT_INFO, Error> {
        self.initialized()?;
        let info: CK_SLOT_INFO = Default::default();
        match (self.C_GetSlotInfo)(slot_id, &info) {
            CKR_OK => {
                Ok(info)
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_token_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_TOKEN_INFO, Error> {
        self.initialized()?;
        let info: CK_TOKEN_INFO = Default::default();
        match (self.C_GetTokenInfo)(slot_id, &info) {
            CKR_OK => {
                Ok(info)
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_mechanism_list(&self, slot_id: CK_SLOT_ID) -> Result<Vec<CK_MECHANISM_TYPE>, Error> {
        self.initialized()?;
        let mut count: CK_ULONG = 0;
        match (self.C_GetMechanismList)(slot_id, ptr::null(), &mut count) {
            CKR_OK => {
                // see get_slot_list() for an explanation - it works the same way 
                let mut list = Vec::<CK_MECHANISM_TYPE>::with_capacity(count);
                let list_ptr = list.as_mut_ptr();
                match (self.C_GetMechanismList)(slot_id, list_ptr, &count) {
                    CKR_OK => {
                        unsafe {
                            list.set_len(count);
                        }
                        Ok(list)
                    },
                    err => Err(Error::Pkcs11(err))
                }
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_mechanism_info(&self, slot_id: CK_SLOT_ID, mechanism_type: CK_MECHANISM_TYPE) -> Result<CK_MECHANISM_INFO, Error> {
        self.initialized()?;
        let info: CK_MECHANISM_INFO = Default::default();
        match (self.C_GetMechanismInfo)(slot_id, mechanism_type, &info) {
            CKR_OK => {
                Ok(info)
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn init_token<'a, 'b>(&self, slot_id: CK_SLOT_ID, pin: Option<&'a str>, label: &'b str) -> Result<(), Error> {
        self.initialized()?;
        let formatted_label = label_from_str(label).to_vec().as_ptr();
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let cpin_bytes = cpin.into_bytes();
                    match (self.C_InitToken)(slot_id, cpin_bytes.as_ptr(), cpin_bytes.len(), formatted_label) {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            },
            None => {
                // CKF_PROTECTED_AUTHENTICATION_PATH requires a NULL pointer
                match (self.C_InitToken)(slot_id, ptr::null(), 0, formatted_label) {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
        }
    }

    pub fn init_pin<'a>(&self, session: CK_SESSION_HANDLE, pin: Option<&'a str>) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let cpin_bytes = cpin.into_bytes();
                    match (self.C_InitPIN)(session, cpin_bytes.as_ptr(), cpin_bytes.len()) {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            },
            None => {
                match (self.C_InitPIN)(session, ptr::null(), 0) {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
        }
    }

    pub fn set_pin<'a, 'b>(&self, session: CK_SESSION_HANDLE, old_pin: Option<&'a str>, new_pin: Option<&'b str>) -> Result<(), Error> {
        self.initialized()?;
        if old_pin.is_none() && new_pin.is_none() {
            match (self.C_SetPIN)(session, ptr::null(), 0, ptr::null(), 0) {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            }
        } else if old_pin.is_some() && new_pin.is_some() {
            let old_cpin_res = CString::new(old_pin.unwrap());
            let new_cpin_res = CString::new(new_pin.unwrap());
            if old_cpin_res.is_err() {
                return Err(Error::InvalidInput("Old PIN contains a nul byte"));
            }
            if new_cpin_res.is_err() {
                return Err(Error::InvalidInput("New PIN contains a nul byte"));
            }
            let old_cpin = old_cpin_res.unwrap().into_bytes();
            let new_cpin = new_cpin_res.unwrap().into_bytes();
            match (self.C_SetPIN)(session, old_cpin.as_ptr(), old_cpin.len(), new_cpin.as_ptr(), new_cpin.len()) {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            }
        } else {
            Err(Error::InvalidInput("both PINs must be either set or unset"))
        }
    }

    pub fn open_session(&self, slot_id: CK_SLOT_ID, flags: CK_FLAGS, application: Option<CK_VOID_PTR>, notify: CK_NOTIFY) -> Result<CK_SESSION_HANDLE, Error> {
        self.initialized()?;
        let mut session: CK_SESSION_HANDLE = 0;
        match (self.C_OpenSession)(slot_id, flags, application.unwrap_or(ptr::null()), notify, &mut session) {
            CKR_OK => Ok(session),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn close_session(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match (self.C_CloseSession)(session) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn close_all_sessions(&self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        self.initialized()?;
        match (self.C_CloseAllSessions)(slot_id) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_session_info(&self, session: CK_SESSION_HANDLE) -> Result<CK_SESSION_INFO, Error> {
        self.initialized()?;
        let info: CK_SESSION_INFO = Default::default();
        match (self.C_GetSessionInfo)(session, &info) {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_operation_state(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut state_length: CK_ULONG = 0;
        match (self.C_GetOperationState)(session, ptr::null(), &mut state_length) {
            CKR_OK => {
                let mut state: Vec<CK_BYTE> = Vec::with_capacity(state_length);
                let state_ptr = state.as_mut_ptr();
                match (self.C_GetOperationState)(session, state_ptr, &state_length) {
                    CKR_OK => {
                        unsafe {
                            state.set_len(state_length);
                        }
                        Ok(state)
                    },
                    err => Err(Error::Pkcs11(err)),
                }
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn set_operation_state(&self, session: CK_SESSION_HANDLE, operation_state: Vec<CK_BYTE>, encryption_key: Option<CK_OBJECT_HANDLE>, authentication_key: Option<CK_OBJECT_HANDLE>) -> Result<(), Error> {
        self.initialized()?;
        match (self.C_SetOperationState)(session, operation_state.as_ptr(), operation_state.len(), encryption_key.unwrap_or(0), authentication_key.unwrap_or(0)) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)), 
        }
    }

    pub fn login<'a>(&self, session: CK_SESSION_HANDLE, user_type: CK_USER_TYPE, pin: Option<&'a str>) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let cpin_bytes = cpin.into_bytes();
                    match (self.C_Login)(session, user_type, cpin_bytes.as_ptr(), cpin_bytes.len()) {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            },
            None => {
                match (self.C_Login)(session, user_type, ptr::null(), 0) {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
        }
    }

    pub fn logout(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match (self.C_Logout)(session) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn create_object(&self, session: CK_SESSION_HANDLE, template: Vec<CK_ATTRIBUTE>) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn copy_object(&self, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, template: Vec<CK_ATTRIBUTE>) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn destroy_object(&self, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn get_object_size(&self, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> Result<CK_ULONG, Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn get_attribute_value(&self, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, template: Vec<CK_ATTRIBUTE>) -> Result<Vec<CK_ATTRIBUTE>, Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn set_attribute_value(&self, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, template: Vec<CK_ATTRIBUTE>) -> Result<(), Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn find_objects_init(&self, session: CK_SESSION_HANDLE, template: Vec<CK_ATTRIBUTE>) -> Result<(), Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn find_objects(&self, session: CK_SESSION_HANDLE, max_object_count: CK_ULONG) -> Result<Vec<CK_OBJECT_HANDLE>, Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn find_objects_final(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        unimplemented!()
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if self.is_initialized() {
            if let Err(err) = self.finalize() {
                println!("ERROR: {}", err);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Tests need to be run with `RUST_TEST_THREADS=1` currently to pass.

    use super::*;

    const PKCS11_MODULE_FILENAME: &'static str = "/usr/local/lib/softhsm/libsofthsm2.so";

    #[test]
    fn test_label_from_str() {
        let s30 = "Löwe 老虎 Léopar虎d虎aaa";
        let s32 = "Löwe 老虎 Léopar虎d虎aaaö";
        let s33 = "Löwe 老虎 Léopar虎d虎aaa虎";
        let s34 = "Löwe 老虎 Léopar虎d虎aaab虎";
        let l30 = label_from_str(s30);
        let l32 = label_from_str(s32);
        let l33 = label_from_str(s33);
        let l34 = label_from_str(s34);
        println!("Label l30: {:?}", l30);
        println!("Label l32: {:?}", l32);
        println!("Label l33: {:?}", l33);
        println!("Label l34: {:?}", l34);
        // now the assertions:
        // - l30 must have the last 2 as byte 32
        // - l32 must not have any byte 32 at the end
        // - l33 must have the last 2 as byte 32 because the trailing '虎' is three bytes
        // - l34 must have hte last 1 as byte 32
        assert_ne!(l30[29], 32);
        assert_eq!(l30[30], 32);
        assert_eq!(l30[31], 32);
        assert_ne!(l32[31], 32);
        assert_ne!(l33[29], 32);
        assert_eq!(l33[30], 32);
        assert_eq!(l33[31], 32);
        assert_ne!(l34[30], 32);
        assert_eq!(l34[31], 32);
    }
    #[test]
    fn ctx_new() {
        let res = Ctx::new(PKCS11_MODULE_FILENAME);
        assert!(res.is_ok(), "failed to create new context: {}", res.unwrap_err());
    }

    #[test]
    fn ctx_initialize() {
        let mut ctx = Ctx::new(PKCS11_MODULE_FILENAME).unwrap();
        let res = ctx.initialize(None);
        assert!(res.is_ok(), "failed to initialize context: {}", res.unwrap_err());
        assert!(ctx.is_initialized(), "internal state is not initialized");
    }

    #[test]
    fn ctx_new_and_initialize() {
        
        let res = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME);
        assert!(res.is_ok(), "failed to create or initialize new context: {}", res.unwrap_err());
    }

    #[test]
    fn ctx_finalize() {
        let mut ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let res = ctx.finalize();
        assert!(res.is_ok(), "failed to finalize context: {}", res.unwrap_err());
    }

    #[test]
    fn ctx_get_info() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let res = ctx.get_info();
        assert!(res.is_ok(), "failed to call C_GetInfo: {}", res.unwrap_err());
        let info = res.unwrap();
        println!("{:?}", info);
    }

    #[test]
    fn ctx_get_function_list() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let res = ctx.get_function_list();
        assert!(res.is_ok(), "failed to call C_GetFunctionList: {}", res.unwrap_err());
        let list = res.unwrap();
        println!("{:?}", list);
    }

    #[test]
    fn ctx_get_slot_list() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let res = ctx.get_slot_list(false);
        assert!(res.is_ok(), "failed to call C_GetSlotList: {}", res.unwrap_err());
        let slots = res.unwrap();
        println!("Slots: {:?}", slots);
    }

    #[test]
    fn ctx_get_slot_infos() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            let res = ctx.get_slot_info(slot);
            assert!(res.is_ok(), "failed to call C_GetSlotInfo({}): {}", slot, res.unwrap_err());
            let info = res.unwrap();
            println!("Slot {} {:?}", slot, info);
        }
    }

    #[test]
    fn ctx_get_token_infos() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            let res = ctx.get_token_info(slot);
            assert!(res.is_ok(), "failed to call C_GetTokenInfo({}): {}", slot, res.unwrap_err());
            let info = res.unwrap();
            println!("Slot {} {:?}", slot, info);
        }
    }

    #[test]
    fn ctx_get_mechanism_lists() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            let res = ctx.get_mechanism_list(slot);
            assert!(res.is_ok(), "failed to call C_GetMechanismList({}): {}", slot, res.unwrap_err());
            let mechs = res.unwrap();
            println!("Slot {} Mechanisms: {:?}", slot, mechs);
        }
    }

    #[test]
    fn ctx_get_mechanism_infos() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            let mechanisms = ctx.get_mechanism_list(slot).unwrap();
            for mechanism in mechanisms {
                let res = ctx.get_mechanism_info(slot, mechanism);
                assert!(res.is_ok(), "failed to call C_GetMechanismInfo({}, {}): {}", slot, mechanism, res.unwrap_err());
                let info = res.unwrap();
                println!("Slot {} Mechanism {}: {:?}", slot, mechanism, info);
            }
        }
    }

    #[test]
    fn ctx_init_token() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            let res = ctx.init_token(slot, pin, LABEL);
            assert!(res.is_ok(), "failed to call C_InitToken({}, {}, {}): {}", slot, pin.unwrap(), LABEL, res.unwrap_err());
            println!("Slot {} C_InitToken successful, PIN: {}", slot, pin.unwrap());
        }
    }

    #[test]
    fn ctx_init_pin() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            ctx.init_token(slot, pin, LABEL).unwrap();
            let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None).unwrap();
            ctx.login(sh, CKU_SO, pin).unwrap();
            let res = ctx.init_pin(sh, pin);
            assert!(res.is_ok(), "failed to call C_InitPIN({}, {}): {}", sh, pin.unwrap(), res.unwrap_err());
            println!("InitPIN successful");
        }
    }

    #[test]
    fn ctx_set_pin() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        let new_pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            ctx.init_token(slot, pin, LABEL).unwrap();
            let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None).unwrap();
            ctx.login(sh, CKU_SO, pin).unwrap();
            let res = ctx.set_pin(sh, pin, new_pin);
            assert!(res.is_ok(), "failed to call C_SetPIN({}, {}, {}): {}", sh, pin.unwrap(), new_pin.unwrap(), res.unwrap_err());
            println!("SetPIN successful");
        }
    }

    #[test]
    fn ctx_open_session() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            ctx.init_token(slot, pin, LABEL).unwrap();
            let res = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None);
            assert!(res.is_ok(), "failed to call C_OpenSession({}, CKF_SERIAL_SESSION, None, None): {}", slot, res.unwrap_err());
            let sh = res.unwrap();
            println!("Opened Session on Slot {}: CK_SESSION_HANDLE {}", slot, sh);
        }
    }

    #[test]
    fn ctx_close_session() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            ctx.init_token(slot, pin, LABEL).unwrap();
            let sh = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None).unwrap();
            let res = ctx.close_session(sh);
            assert!(res.is_ok(), "failed to call C_CloseSession({}): {}", sh, res.unwrap_err());
            println!("Closed Session with CK_SESSION_HANDLE {}", sh);
        } 
    }

    #[test]
    fn ctx_close_all_sessions() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            ctx.init_token(slot, pin, LABEL).unwrap();
            ctx.open_session(slot, CKF_SERIAL_SESSION, None, None).unwrap();
            let res = ctx.close_all_sessions(slot);
            assert!(res.is_ok(), "failed to call C_CloseAllSessions({}): {}", slot, res.unwrap_err());
            println!("Closed All Sessions on Slot {}", slot);
        } 
    }

    #[test]
    fn ctx_get_session_info() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            ctx.init_token(slot, pin, LABEL).unwrap();
            let sh = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None).unwrap();
            let res = ctx.get_session_info(sh);
            assert!(res.is_ok(), "failed to call C_GetSessionInfo({}): {}", sh, res.unwrap_err());
            let info = res.unwrap();
            println!("{:?}", info);
        }
    }

    #[test]
    fn ctx_login() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            ctx.init_token(slot, pin, LABEL).unwrap();
            let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None).unwrap();
            let res = ctx.login(sh, CKU_SO, pin);
            assert!(res.is_ok(), "failed to call C_Login({}, CKU_SO, {}): {}", sh, pin.unwrap(), res.unwrap_err());
            println!("Login successful");
        }
    }

    #[test]
    fn ctx_logout() {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        for slot in slots[..1].into_iter() {
            let slot = *slot;
            ctx.init_token(slot, pin, LABEL).unwrap();
            let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None).unwrap();
            ctx.login(sh, CKU_SO, pin).unwrap();
            let res = ctx.logout(sh);
            assert!(res.is_ok(), "failed to call C_Logout({}): {}", sh, res.unwrap_err());
            println!("Logout successful");
        }
    }

    #[test]
    fn attr_bool() {
        let b: CK_BBOOL = CK_FALSE;
        let attr = CK_ATTRIBUTE::new(CKA_OTP_USER_IDENTIFIER).set_bool(&b);
        println!("{:?}", attr);
        let ret: bool = attr.get_bool();
        println!("{}", ret);
        assert_eq!(false, ret, "attr.get_bool() should have been false");

        let b: CK_BBOOL = CK_TRUE;
        let attr = CK_ATTRIBUTE::new(CKA_OTP_USER_IDENTIFIER).set_bool(&b);
        println!("{:?}", attr);
        let ret: bool = attr.get_bool();
        println!("{}", ret);
        assert_eq!(true, ret, "attr.get_bool() should have been true");
    }

    #[test]
    fn attr_ck_ulong() {
        let val: CK_ULONG = 42;
        let attr = CK_ATTRIBUTE::new(CKA_RESOLUTION).set_ck_ulong(&val);
        println!("{:?}", attr);
        let ret: CK_ULONG = attr.get_ck_ulong();
        println!("{}", ret);
        assert_eq!(val, ret, "attr.get_ck_ulong() shouls have been {}", val);
    }

    #[test]
    fn attr_ck_long() {
        let val: CK_LONG = -42;
        let attr = CK_ATTRIBUTE::new(CKA_RESOLUTION).set_ck_long(&val);
        println!("{:?}", attr);
        let ret: CK_LONG = attr.get_ck_long();
        println!("{}", ret);
        assert_eq!(val, ret, "attr.get_ck_long() shouls have been {}", val);
    }

    #[test]
    fn attr_bytes() {
        let val = vec![0,1,2,3,3,4,5];
        let attr = CK_ATTRIBUTE::new(CKA_VALUE).set_bytes(val.as_slice());
        println!("{:?}", attr);
        let ret: Vec<CK_BYTE> = attr.get_bytes();
        println!("{:?}", ret);
        assert_eq!(val, ret.as_slice(), "attr.get_bytes() shouls have been {:?}", val);
    }

    #[test]
    fn attr_string() {
        let val = String::from("Löwe 老虎");
        let attr = CK_ATTRIBUTE::new(CKA_LABEL).set_string(&val);
        println!("{:?}", attr);
        let ret = attr.get_string();
        println!("{:?}", ret);
        assert_eq!(val, ret, "attr.get_string() shouls have been {}", val);
    }

    #[test]
    fn attr_date() {
        let val: CK_DATE = Default::default();
        let attr = CK_ATTRIBUTE::new(CKA_LABEL).set_date(&val);
        println!("{:?}", attr);
        let ret = attr.get_date();
        println!("{:?}", ret);
        assert_eq!(val.day, ret.day, "attr.get_date() should have been {:?}", val);
        assert_eq!(val.month, ret.month, "attr.get_date() should have been {:?}", val);
        assert_eq!(val.year, ret.year, "attr.get_date() should have been {:?}", val);
    }

    #[test]
    fn attr_biginteger() {
        let num_str = "12345678901234567890123456789012345678901234567890123456789012345678901234567890";
        let val = BigUint::from_str_radix(num_str, 10).unwrap();
        let slice = val.to_bytes_le();
        let attr = CK_ATTRIBUTE::new(CKA_LABEL).set_biginteger(&slice);
        println!("{:?}", attr);
        let ret = attr.get_biginteger();
        println!("{:?}", ret);
        assert_eq!(ret, val, "attr.get_biginteger() should have been {:?}", val);
        assert_eq!(ret.to_str_radix(10), num_str, "attr.get_biginteger() should have been {:?}", num_str);
    }

    /// This will create and initialize a context, set a SO and USER PIN, and login as the USER.
    /// This is the starting point for all tests that are acting on the token.
    /// If you look at the tests here in a "serial" manner, if all the tests are working up until
    /// here, this will always succeed.
    fn fixture_token() -> Result<(Ctx, CK_SESSION_HANDLE), Error> {
        let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
        let slots = ctx.get_slot_list(false).unwrap();
        let pin = Some("1234");
        const LABEL: &str = "rust-unit-test";
        let slot = *slots.first().ok_or(Error::Module("no slot available"))?;
        ctx.init_token(slot, pin, LABEL)?;
        let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)?;
        ctx.login(sh, CKU_SO, pin)?;
        ctx.init_pin(sh, pin)?;
        ctx.logout(sh)?;
        ctx.login(sh, CKU_USER, pin)?;
        Ok((ctx, sh))
    }

    #[test]
    fn ctx_create_object() {
        /*
        CKA_CLASS       ck_type  object_class:CKO_DATA
        CKA_TOKEN       bool      true
        CKA_PRIVATE     bool      true
        CKA_MODIFIABLE  bool      true
        CKA_COPYABLE    bool      true
        CKA_LABEL       string    e4-example
        CKA_VALUE       bytes     SGVsbG8gV29ybGQh
        */
        //let (ctx, sh) = fixture_token().unwrap();
        //let b = (true).into_ck(CKA_CLASS);
        //let template = vec![
        //    CK_ATTRIBUTE { ulType: CKA_CLASS, },
        //];
        //let res = ctx.create_object(sh, template);
        //assert!(res.is_ok(), "failed to call C_CreateObject({}, {:?}): {}", sh, template, res.is_err());
    }

    #[test]
    fn ctx_copy_object() {
        unimplemented!()
    }

    #[test]
    fn ctx_destroy_object() {
        unimplemented!()
    }

    #[test]
    fn ctx_get_object_size() {
        unimplemented!()
    }

    #[test]
    fn ctx_get_attribute_value() {
        unimplemented!()
    }

    #[test]
    fn ctx_set_attribute_value() {
        unimplemented!()
    }

    #[test]
    fn ctx_find_objects_init() {
        unimplemented!()
    }

    #[test]
    fn ctx_find_objects() {
        unimplemented!()
    }

    #[test]
    fn ctx_find_objects_final() {
        unimplemented!()
    }
}
