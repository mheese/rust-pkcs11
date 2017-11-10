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
use num_traits::Num;
//use libc::c_uchar;

pub type CK_BYTE = u8;
pub type CK_BYTE_PTR = *const CK_BYTE;
pub type CK_CHAR = CK_BYTE;
pub type CK_UTF8CHAR = CK_BYTE;
pub type CK_UTF8CHAR_PTR = *const CK_UTF8CHAR;
pub type CK_BBOOL = CK_BYTE;
pub type CK_ULONG = usize;
pub type CK_ULONG_PTR = *const CK_ULONG;
pub type CK_LONG = isize;
pub type CK_FLAGS = CK_ULONG;
pub type CK_RV = CK_ULONG;
pub type CK_SLOT_ID = CK_ULONG;
pub type CK_SLOT_ID_PTR = *const CK_SLOT_ID;
pub type CK_SESSION_HANDLE = CK_ULONG;
pub type CK_SESSION_HANDLE_PTR = *const CK_SESSION_HANDLE;
pub type CK_NOTIFICATION = CK_ULONG;
pub type CK_USER_TYPE = CK_ULONG;

pub const CK_TRUE: CK_BBOOL = 1;
pub const CK_FALSE: CK_BBOOL = 0;

pub const CKU_SO: CK_USER_TYPE = 0;
/* Normal user */
pub const CKU_USER: CK_USER_TYPE = 1;
/* Context specific */
pub const CKU_CONTEXT_SPECIFIC: CK_USER_TYPE = 2;

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

#[derive(Debug)]
#[repr(u8)]
pub enum CK_VOID {
    #[doc(hidden)]
    __Variant1,
    #[doc(hidden)]
    __Variant2,
}


pub type CK_VOID_PTR = *const CK_VOID;
pub type CK_VOID_PTR_PTR = *const CK_VOID_PTR;

#[derive(Debug,Clone)]
#[repr(C)]
pub struct CK_VERSION {
  pub major: CK_BYTE,  /* integer portion of version number */
  pub minor: CK_BYTE,   /* 1/100ths portion of version number */
}

impl CK_VERSION {
    pub fn new() -> CK_VERSION {
        CK_VERSION {
            major: 0,
            minor: 0,
        }
    }
}

pub type CK_CREATEMUTEX = Option<extern "C" fn(CK_VOID_PTR_PTR) -> CK_RV>;
pub type CK_DESTROYMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_LOCKMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;
pub type CK_UNLOCKMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;

pub type CK_NOTIFY = Option<extern "C" fn(CK_SESSION_HANDLE, CK_NOTIFICATION, CK_VOID_PTR) -> CK_RV>;

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

#[derive(Debug)]
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
            cryptokiVersion: CK_VERSION::new(),
            manufacturerID: [0; 32],
            flags: 0,
            libraryDescription: [0; 32],
            libraryVersion: CK_VERSION::new(),
        }
    }
}

pub type CK_INFO_PTR = *const CK_INFO;

#[repr(C)]
pub struct CK_SLOT_INFO {
  /* slotDescription and manufacturerID have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  pub slotDescription: [CK_UTF8CHAR; 64],    /* blank padded */
  pub manufacturerID: [CK_UTF8CHAR; 32],     /* blank padded */
  pub flags: CK_FLAGS,

  pub hardwareVersion: CK_VERSION,  /* version of hardware */
  pub firmwareVersion: CK_VERSION,  /* version of firmware */
}

impl CK_SLOT_INFO {
    pub fn new() -> CK_SLOT_INFO {
        CK_SLOT_INFO {
            slotDescription: [0; 64],
            manufacturerID: [0; 32],
            flags: 0,
            hardwareVersion: CK_VERSION::new(),
            firmwareVersion: CK_VERSION::new(),
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

impl CK_TOKEN_INFO {
    pub fn new() -> CK_TOKEN_INFO {
        CK_TOKEN_INFO {
            label: [0; 32],
            manufacturerID: [0; 32],
            model: [0; 16],
            serialNumber: [0; 16],
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
            hardwareVersion: CK_VERSION::new(),
            firmwareVersion: CK_VERSION::new(),
            utcTime: [0; 16],
        }
    }
}

pub type CK_TOKEN_INFO_PTR = *const CK_TOKEN_INFO;

pub type CK_MECHANISM_TYPE = CK_ULONG;
pub type CK_MECHANISM_TYPE_PTR = *const CK_MECHANISM_TYPE;

#[derive(Debug,Default,Clone)]
#[repr(C)]
pub struct CK_MECHANISM_INFO {
    pub ulMinKeySize: CK_ULONG,
    pub ulMaxKeySize: CK_ULONG,
    pub flags: CK_FLAGS,
}

pub type CK_MECHANISM_INFO_PTR = *const CK_MECHANISM_INFO;

pub type CK_STATE = CK_ULONG;

#[derive(Debug,Default,Clone)]
#[repr(C)]
pub struct CK_SESSION_INFO {
  pub slotID: CK_SLOT_ID,
  pub state: CK_STATE,
  pub flags: CK_FLAGS,
  pub ulDeviceError: CK_ULONG,  /* device-dependent error code */
}

pub type CK_SESSION_INFO_PTR = *const CK_SESSION_INFO;

pub const CKF_RW_SESSION: CK_FLAGS = 0x00000002; /* session is r/w */
pub const CKF_SERIAL_SESSION: CK_FLAGS = 0x00000004; /* no parallel    */

pub type CK_OBJECT_HANDLE = CK_ULONG;
pub type CK_OBJECT_HANDLE_PTR = *const CK_OBJECT_HANDLE;

/* CK_ATTRIBUTE_TYPE is a value that identifies an attribute
 * type
 */
pub type CK_ATTRIBUTE_TYPE = CK_ULONG;

/* The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
 * consists of an array of values.
 */
pub const CKF_ARRAY_ATTRIBUTE: CK_FLAGS = 0x40000000;

/* The following OTP-related defines relate to the CKA_OTP_FORMAT attribute */
pub const CK_OTP_FORMAT_DECIMAL         : CK_ULONG = 0;
pub const CK_OTP_FORMAT_HEXADECIMAL     : CK_ULONG = 1;
pub const CK_OTP_FORMAT_ALPHANUMERIC    : CK_ULONG = 2;
pub const CK_OTP_FORMAT_BINARY          : CK_ULONG = 3;

/* The following OTP-related defines relate to the CKA_OTP_..._REQUIREMENT
 * attributes
 */
pub const CK_OTP_PARAM_IGNORED          : CK_ULONG = 0;
pub const CK_OTP_PARAM_OPTIONAL         : CK_ULONG = 1;
pub const CK_OTP_PARAM_MANDATORY        : CK_ULONG = 2;

/* The following attribute types are defined: */
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

pub const CKA_ECDSA_PARAMS      : CK_ATTRIBUTE_TYPE = 0x00000180; /* Deprecated */
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

/* CK_ATTRIBUTE is a structure that includes the type, length
 * and value of an attribute
 */
#[derive(Clone)]
#[repr(C)]
pub struct CK_ATTRIBUTE {
  pub attrType: CK_ATTRIBUTE_TYPE,
  pub pValue: CK_VOID_PTR,
  pub ulValueLen: CK_ULONG,  /* in bytes */
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

/* CK_DATE is a structure that defines a date */
#[derive(Debug,Default,Clone)]
#[repr(C)]
pub struct CK_DATE{
  pub year: [CK_CHAR; 4],   /* the year ("1900" - "9999") */
  pub month: [CK_CHAR; 2],  /* the month ("01" - "12") */
  pub day: [CK_CHAR; 2],    /* the day   ("01" - "31") */
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
        let info = CK_SLOT_INFO::new();
        match (self.C_GetSlotInfo)(slot_id, &info) {
            CKR_OK => {
                Ok(info)
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_token_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_TOKEN_INFO, Error> {
        self.initialized()?;
        let info = CK_TOKEN_INFO::new();
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

    //#[test]
    //fn ctx_create_object() {
    //    let (ctx, sh) = fixture_token().unwrap();
    //    let b = (true).into_ck(CKA_CLASS);
    //    let template = vec![
    //        CK_ATTRIBUTE { ulType: CKA_CLASS, },
    //    ];
    //    let res = ctx.create_object(sh, template);
    //    assert!(res.is_ok(), "failed to call C_CreateObject({}, {:?}): {}", sh, template, res.is_err());
    //}

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
