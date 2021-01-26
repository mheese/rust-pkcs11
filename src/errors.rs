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

use crate::types::*;

#[derive(Debug)]
pub enum Error {
    /// Any error that happens during library loading of the PKCS#11 module is encompassed under
    /// this error. It is a direct forward of the underlying error from libloading.
    LibraryLoading { err: libloading::Error },

    /// If a PKCS11 library is not a compliant module, this error will be reporting on the details
    /// of the problem.
    Module(&'static str),

    /// This error is specific to all PIN-related functions: whenever a PKCS11 function has a PIN input,
    /// and the PIN is invalid (for example contains a nul byte), this error will be returned.
    InvalidInput(&'static str),

    /// All PKCS#11 functions that return non-zero translate to this error. Note though that only true
    /// errors will be returned as such. Some functions that return non-zero values that are not errors
    /// will not be returned as errors. The affected functions are:
    /// `get_attribute_value`, `get_function_status`, `cancel_function` and `wait_for_slot_event`
    Pkcs11(CK_RV),

    /// This error happens when trying to get an attribute's value which is unavailable, because the
    /// constant `CK_UNAVAILABLE_INFORMATION` is set in the `ulValueLen` attribute field.
    /// Note that this error can only be returned if `get_attribute_value` was previously called,
    /// and one tries to return the value of a `types::CK_ATTRIBUTE` with one of its associated
    /// getter method (e.g. `get_bytes`).
    UnavailableInformation,

    /// This error happens when trying to use the function which is not supported in the PKCS#11 API.
    UnavailableFunction(&'static str),
}

impl From<libloading::Error> for Error {
    fn from(err: libloading::Error) -> Error {
        Error::LibraryLoading { err }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::LibraryLoading { ref err } => write!(f, "PKCS#11 Library Loading: {}", err),
            Error::Module(ref err) => write!(f, "PKCS#11 Module: {}", err),
            Error::InvalidInput(ref err) => write!(f, "PKCS#11 Invalid Input: {}", err),
            Error::Pkcs11(ref err) => write!(f, "PKCS#11: {} (0x{:x})", strerror(*err), err),
            Error::UnavailableInformation => write!(f, "Attribute value is unavailable"),
            Error::UnavailableFunction(ref name) => write!(f, "Function not available: {}", name),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Error::LibraryLoading { ref err } = self {
            Some(err)
        } else {
            None
        }
    }
}

fn strerror(err: CK_RV) -> &'static str {
    match err {
        CKR_OK => "CKR_OK",
        CKR_CANCEL => "CKR_CANCEL",
        CKR_HOST_MEMORY => "CKR_HOST_MEMORY",
        CKR_SLOT_ID_INVALID => "CKR_SLOT_ID_INVALID",
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        CKR_ARGUMENTS_BAD => "CKR_ARGUMENTS_BAD",
        CKR_NO_EVENT => "CKR_NO_EVENT",
        CKR_NEED_TO_CREATE_THREADS => "CKR_NEED_TO_CREATE_THREADS",
        CKR_CANT_LOCK => "CKR_CANT_LOCK",
        CKR_ATTRIBUTE_READ_ONLY => "CKR_ATTRIBUTE_READ_ONLY",
        CKR_ATTRIBUTE_SENSITIVE => "CKR_ATTRIBUTE_SENSITIVE",
        CKR_ATTRIBUTE_TYPE_INVALID => "CKR_ATTRIBUTE_TYPE_INVALID",
        CKR_ATTRIBUTE_VALUE_INVALID => "CKR_ATTRIBUTE_VALUE_INVALID",
        CKR_ACTION_PROHIBITED => "CKR_ACTION_PROHIBITED",
        CKR_DATA_INVALID => "CKR_DATA_INVALID",
        CKR_DATA_LEN_RANGE => "CKR_DATA_LEN_RANGE",
        CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        CKR_DEVICE_MEMORY => "CKR_DEVICE_MEMORY",
        CKR_DEVICE_REMOVED => "CKR_DEVICE_REMOVED",
        CKR_ENCRYPTED_DATA_INVALID => "CKR_ENCRYPTED_DATA_INVALID",
        CKR_ENCRYPTED_DATA_LEN_RANGE => "CKR_ENCRYPTED_DATA_LEN_RANGE",
        CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
        CKR_FUNCTION_NOT_PARALLEL => "CKR_FUNCTION_NOT_PARALLEL",
        CKR_FUNCTION_NOT_SUPPORTED => "CKR_FUNCTION_NOT_SUPPORTED",
        CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        CKR_KEY_SIZE_RANGE => "CKR_KEY_SIZE_RANGE",
        CKR_KEY_TYPE_INCONSISTENT => "CKR_KEY_TYPE_INCONSISTENT",
        CKR_KEY_NOT_NEEDED => "CKR_KEY_NOT_NEEDED",
        CKR_KEY_CHANGED => "CKR_KEY_CHANGED",
        CKR_KEY_NEEDED => "CKR_KEY_NEEDED",
        CKR_KEY_INDIGESTIBLE => "CKR_KEY_INDIGESTIBLE",
        CKR_KEY_FUNCTION_NOT_PERMITTED => "CKR_KEY_FUNCTION_NOT_PERMITTED",
        CKR_KEY_NOT_WRAPPABLE => "CKR_KEY_NOT_WRAPPABLE",
        CKR_KEY_UNEXTRACTABLE => "CKR_KEY_UNEXTRACTABLE",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        CKR_MECHANISM_PARAM_INVALID => "CKR_MECHANISM_PARAM_INVALID",
        CKR_OBJECT_HANDLE_INVALID => "CKR_OBJECT_HANDLE_INVALID",
        CKR_OPERATION_ACTIVE => "CKR_OPERATION_ACTIVE",
        CKR_OPERATION_NOT_INITIALIZED => "CKR_OPERATION_NOT_INITIALIZED",
        CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        CKR_PIN_INVALID => "CKR_PIN_INVALID",
        CKR_PIN_LEN_RANGE => "CKR_PIN_LEN_RANGE",
        CKR_PIN_EXPIRED => "CKR_PIN_EXPIRED",
        CKR_PIN_LOCKED => "CKR_PIN_LOCKED",
        CKR_SESSION_CLOSED => "CKR_SESSION_CLOSED",
        CKR_SESSION_COUNT => "CKR_SESSION_COUNT",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_SESSION_PARALLEL_NOT_SUPPORTED => "CKR_SESSION_PARALLEL_NOT_SUPPORTED",
        CKR_SESSION_READ_ONLY => "CKR_SESSION_READ_ONLY",
        CKR_SESSION_EXISTS => "CKR_SESSION_EXISTS",
        CKR_SESSION_READ_ONLY_EXISTS => "CKR_SESSION_READ_ONLY_EXISTS",
        CKR_SESSION_READ_WRITE_SO_EXISTS => "CKR_SESSION_READ_WRITE_SO_EXISTS",
        CKR_SIGNATURE_INVALID => "CKR_SIGNATURE_INVALID",
        CKR_SIGNATURE_LEN_RANGE => "CKR_SIGNATURE_LEN_RANGE",
        CKR_TEMPLATE_INCOMPLETE => "CKR_TEMPLATE_INCOMPLETE",
        CKR_TEMPLATE_INCONSISTENT => "CKR_TEMPLATE_INCONSISTENT",
        CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
        CKR_TOKEN_NOT_RECOGNIZED => "CKR_TOKEN_NOT_RECOGNIZED",
        CKR_TOKEN_WRITE_PROTECTED => "CKR_TOKEN_WRITE_PROTECTED",
        CKR_UNWRAPPING_KEY_HANDLE_INVALID => "CKR_UNWRAPPING_KEY_HANDLE_INVALID",
        CKR_UNWRAPPING_KEY_SIZE_RANGE => "CKR_UNWRAPPING_KEY_SIZE_RANGE",
        CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT => "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT",
        CKR_USER_ALREADY_LOGGED_IN => "CKR_USER_ALREADY_LOGGED_IN",
        CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        CKR_USER_PIN_NOT_INITIALIZED => "CKR_USER_PIN_NOT_INITIALIZED",
        CKR_USER_TYPE_INVALID => "CKR_USER_TYPE_INVALID",
        CKR_USER_ANOTHER_ALREADY_LOGGED_IN => "CKR_USER_ANOTHER_ALREADY_LOGGED_IN",
        CKR_USER_TOO_MANY_TYPES => "CKR_USER_TOO_MANY_TYPES",
        CKR_WRAPPED_KEY_INVALID => "CKR_WRAPPED_KEY_INVALID",
        CKR_WRAPPED_KEY_LEN_RANGE => "CKR_WRAPPED_KEY_LEN_RANGE",
        CKR_WRAPPING_KEY_HANDLE_INVALID => "CKR_WRAPPING_KEY_HANDLE_INVALID",
        CKR_WRAPPING_KEY_SIZE_RANGE => "CKR_WRAPPING_KEY_SIZE_RANGE",
        CKR_WRAPPING_KEY_TYPE_INCONSISTENT => "CKR_WRAPPING_KEY_TYPE_INCONSISTENT",
        CKR_RANDOM_SEED_NOT_SUPPORTED => "CKR_RANDOM_SEED_NOT_SUPPORTED",
        CKR_RANDOM_NO_RNG => "CKR_RANDOM_NO_RNG",
        CKR_DOMAIN_PARAMS_INVALID => "CKR_DOMAIN_PARAMS_INVALID",
        CKR_CURVE_NOT_SUPPORTED => "CKR_CURVE_NOT_SUPPORTED",
        CKR_BUFFER_TOO_SMALL => "CKR_BUFFER_TOO_SMALL",
        CKR_SAVED_STATE_INVALID => "CKR_SAVED_STATE_INVALID",
        CKR_INFORMATION_SENSITIVE => "CKR_INFORMATION_SENSITIVE",
        CKR_STATE_UNSAVEABLE => "CKR_STATE_UNSAVEABLE",
        CKR_CRYPTOKI_NOT_INITIALIZED => "CKR_CRYPTOKI_NOT_INITIALIZED",
        CKR_CRYPTOKI_ALREADY_INITIALIZED => "CKR_CRYPTOKI_ALREADY_INITIALIZED",
        CKR_MUTEX_BAD => "CKR_MUTEX_BAD",
        CKR_MUTEX_NOT_LOCKED => "CKR_MUTEX_NOT_LOCKED",
        CKR_NEW_PIN_MODE => "CKR_NEW_PIN_MODE",
        CKR_NEXT_OTP => "CKR_NEXT_OTP",
        CKR_EXCEEDED_MAX_ITERATIONS => "CKR_EXCEEDED_MAX_ITERATIONS",
        CKR_FIPS_SELF_TEST_FAILED => "CKR_FIPS_SELF_TEST_FAILED",
        CKR_LIBRARY_LOAD_FAILED => "CKR_LIBRARY_LOAD_FAILED",
        CKR_PIN_TOO_WEAK => "CKR_PIN_TOO_WEAK",
        CKR_PUBLIC_KEY_INVALID => "CKR_PUBLIC_KEY_INVALID",
        CKR_FUNCTION_REJECTED => "CKR_FUNCTION_REJECTED",
        CKR_VENDOR_DEFINED => "CKR_VENDOR_DEFINED",
        _ => {
            if err > CKR_VENDOR_DEFINED {
                "CKR_VENDOR_DEFINED"
            } else {
                "unknown"
            }
        }
    }
}
