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
#![allow(non_camel_case_types, non_snake_case, clippy::unreadable_literal)]

extern crate libloading;
extern crate num_bigint;

#[cfg(test)]
#[macro_use]
extern crate serial_test_derive;

#[cfg(test)]
mod tests;

/// The error types are defined here - they are used throughout the crate.
pub mod errors;
/// This module is basically a full conversion of the `pkcs11f.h` C header file.
pub mod functions;
/// This module is basically a full conversion of the `pkcs11t.h` C header file.
pub mod types;

use errors::Error;
use functions::*;
use types::*;

use std::ffi::CString;
use std::mem;
use std::path::Path;
use std::ptr;

macro_rules! req {
    ($ctx: ident, $f: ident) => {
        $ctx.$f.ok_or(Error::UnavailableFunction(stringify!($f)))
    };
}

trait CkFrom<T> {
    fn from(_: T) -> Self;
}

impl CkFrom<bool> for CK_BBOOL {
    fn from(b: bool) -> Self {
        if b {
            1
        } else {
            0
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

fn str_from_blank_padded(field: &[CK_UTF8CHAR]) -> String {
    let decoded_str = String::from_utf8_lossy(field);
    decoded_str.trim_end_matches(' ').to_string()
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
                lab[i] = *b;
                i += 1;
            }
        } else {
            break;
        }
    }
    lab
}

#[derive(Debug)]
pub struct Ctx {
    lib: libloading::Library,
    _is_initialized: bool,
    version: CK_VERSION,
    C_Initialize: Option<C_Initialize>,
    C_Finalize: Option<C_Finalize>,
    C_GetInfo: Option<C_GetInfo>,
    C_GetFunctionList: Option<C_GetFunctionList>,
    C_GetSlotList: Option<C_GetSlotList>,
    C_GetSlotInfo: Option<C_GetSlotInfo>,
    C_GetTokenInfo: Option<C_GetTokenInfo>,
    C_GetMechanismList: Option<C_GetMechanismList>,
    C_GetMechanismInfo: Option<C_GetMechanismInfo>,
    C_InitToken: Option<C_InitToken>,
    C_InitPIN: Option<C_InitPIN>,
    C_SetPIN: Option<C_SetPIN>,
    C_OpenSession: Option<C_OpenSession>,
    C_CloseSession: Option<C_CloseSession>,
    C_CloseAllSessions: Option<C_CloseAllSessions>,
    C_GetSessionInfo: Option<C_GetSessionInfo>,
    C_GetOperationState: Option<C_GetOperationState>,
    C_SetOperationState: Option<C_SetOperationState>,
    C_Login: Option<C_Login>,
    C_Logout: Option<C_Logout>,
    C_CreateObject: Option<C_CreateObject>,
    C_CopyObject: Option<C_CopyObject>,
    C_DestroyObject: Option<C_DestroyObject>,
    C_GetObjectSize: Option<C_GetObjectSize>,
    C_GetAttributeValue: Option<C_GetAttributeValue>,
    C_SetAttributeValue: Option<C_SetAttributeValue>,
    C_FindObjectsInit: Option<C_FindObjectsInit>,
    C_FindObjects: Option<C_FindObjects>,
    C_FindObjectsFinal: Option<C_FindObjectsFinal>,
    C_EncryptInit: Option<C_EncryptInit>,
    C_Encrypt: Option<C_Encrypt>,
    C_EncryptUpdate: Option<C_EncryptUpdate>,
    C_EncryptFinal: Option<C_EncryptFinal>,
    C_DecryptInit: Option<C_DecryptInit>,
    C_Decrypt: Option<C_Decrypt>,
    C_DecryptUpdate: Option<C_DecryptUpdate>,
    C_DecryptFinal: Option<C_DecryptFinal>,
    C_DigestInit: Option<C_DigestInit>,
    C_Digest: Option<C_Digest>,
    C_DigestUpdate: Option<C_DigestUpdate>,
    C_DigestKey: Option<C_DigestKey>,
    C_DigestFinal: Option<C_DigestFinal>,
    C_SignInit: Option<C_SignInit>,
    C_Sign: Option<C_Sign>,
    C_SignUpdate: Option<C_SignUpdate>,
    C_SignFinal: Option<C_SignFinal>,
    C_SignRecoverInit: Option<C_SignRecoverInit>,
    C_SignRecover: Option<C_SignRecover>,
    C_VerifyInit: Option<C_VerifyInit>,
    C_Verify: Option<C_Verify>,
    C_VerifyUpdate: Option<C_VerifyUpdate>,
    C_VerifyFinal: Option<C_VerifyFinal>,
    C_VerifyRecoverInit: Option<C_VerifyRecoverInit>,
    C_VerifyRecover: Option<C_VerifyRecover>,
    C_DigestEncryptUpdate: Option<C_DigestEncryptUpdate>,
    C_DecryptDigestUpdate: Option<C_DecryptDigestUpdate>,
    C_SignEncryptUpdate: Option<C_SignEncryptUpdate>,
    C_DecryptVerifyUpdate: Option<C_DecryptVerifyUpdate>,
    C_GenerateKey: Option<C_GenerateKey>,
    C_GenerateKeyPair: Option<C_GenerateKeyPair>,
    C_WrapKey: Option<C_WrapKey>,
    C_UnwrapKey: Option<C_UnwrapKey>,
    C_DeriveKey: Option<C_DeriveKey>,
    C_SeedRandom: Option<C_SeedRandom>,
    C_GenerateRandom: Option<C_GenerateRandom>,
    C_GetFunctionStatus: Option<C_GetFunctionStatus>,
    C_CancelFunction: Option<C_CancelFunction>,
    // Functions added in for Cryptoki Version 2.01 or later
    C_WaitForSlotEvent: Option<C_WaitForSlotEvent>,
}

impl Ctx {
    pub fn new<P>(filename: P) -> Result<Ctx, Error>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let lib = libloading::Library::new(filename.as_ref())?;
            let mut list = mem::MaybeUninit::uninit();
            {
                let func: libloading::Symbol<
                    unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV,
                > = lib.get(b"C_GetFunctionList")?;
                match func(list.as_mut_ptr()) {
                    CKR_OK => (),
                    err => return Err(Error::Pkcs11(err)),
                }
            }

            let list_ptr = *list.as_ptr();

            Ok(Ctx {
                lib,
                _is_initialized: false,
                version: (*list_ptr).version,
                C_Initialize: (*list_ptr).C_Initialize,
                C_Finalize: (*list_ptr).C_Finalize,
                C_GetInfo: (*list_ptr).C_GetInfo,
                C_GetFunctionList: (*list_ptr).C_GetFunctionList,
                C_GetSlotList: (*list_ptr).C_GetSlotList,
                C_GetSlotInfo: (*list_ptr).C_GetSlotInfo,
                C_GetTokenInfo: (*list_ptr).C_GetTokenInfo,
                C_GetMechanismList: (*list_ptr).C_GetMechanismList,
                C_GetMechanismInfo: (*list_ptr).C_GetMechanismInfo,
                C_InitToken: (*list_ptr).C_InitToken,
                C_InitPIN: (*list_ptr).C_InitPIN,
                C_SetPIN: (*list_ptr).C_SetPIN,
                C_OpenSession: (*list_ptr).C_OpenSession,
                C_CloseSession: (*list_ptr).C_CloseSession,
                C_CloseAllSessions: (*list_ptr).C_CloseAllSessions,
                C_GetSessionInfo: (*list_ptr).C_GetSessionInfo,
                C_GetOperationState: (*list_ptr).C_GetOperationState,
                C_SetOperationState: (*list_ptr).C_SetOperationState,
                C_Login: (*list_ptr).C_Login,
                C_Logout: (*list_ptr).C_Logout,
                C_CreateObject: (*list_ptr).C_CreateObject,
                C_CopyObject: (*list_ptr).C_CopyObject,
                C_DestroyObject: (*list_ptr).C_DestroyObject,
                C_GetObjectSize: (*list_ptr).C_GetObjectSize,
                C_GetAttributeValue: (*list_ptr).C_GetAttributeValue,
                C_SetAttributeValue: (*list_ptr).C_SetAttributeValue,
                C_FindObjectsInit: (*list_ptr).C_FindObjectsInit,
                C_FindObjects: (*list_ptr).C_FindObjects,
                C_FindObjectsFinal: (*list_ptr).C_FindObjectsFinal,
                C_EncryptInit: (*list_ptr).C_EncryptInit,
                C_Encrypt: (*list_ptr).C_Encrypt,
                C_EncryptUpdate: (*list_ptr).C_EncryptUpdate,
                C_EncryptFinal: (*list_ptr).C_EncryptFinal,
                C_DecryptInit: (*list_ptr).C_DecryptInit,
                C_Decrypt: (*list_ptr).C_Decrypt,
                C_DecryptUpdate: (*list_ptr).C_DecryptUpdate,
                C_DecryptFinal: (*list_ptr).C_DecryptFinal,
                C_DigestInit: (*list_ptr).C_DigestInit,
                C_Digest: (*list_ptr).C_Digest,
                C_DigestUpdate: (*list_ptr).C_DigestUpdate,
                C_DigestKey: (*list_ptr).C_DigestKey,
                C_DigestFinal: (*list_ptr).C_DigestFinal,
                C_SignInit: (*list_ptr).C_SignInit,
                C_Sign: (*list_ptr).C_Sign,
                C_SignUpdate: (*list_ptr).C_SignUpdate,
                C_SignFinal: (*list_ptr).C_SignFinal,
                C_SignRecoverInit: (*list_ptr).C_SignRecoverInit,
                C_SignRecover: (*list_ptr).C_SignRecover,
                C_VerifyInit: (*list_ptr).C_VerifyInit,
                C_Verify: (*list_ptr).C_Verify,
                C_VerifyUpdate: (*list_ptr).C_VerifyUpdate,
                C_VerifyFinal: (*list_ptr).C_VerifyFinal,
                C_VerifyRecoverInit: (*list_ptr).C_VerifyRecoverInit,
                C_VerifyRecover: (*list_ptr).C_VerifyRecover,
                C_DigestEncryptUpdate: (*list_ptr).C_DigestEncryptUpdate,
                C_DecryptDigestUpdate: (*list_ptr).C_DecryptDigestUpdate,
                C_SignEncryptUpdate: (*list_ptr).C_SignEncryptUpdate,
                C_DecryptVerifyUpdate: (*list_ptr).C_DecryptVerifyUpdate,
                C_GenerateKey: (*list_ptr).C_GenerateKey,
                C_GenerateKeyPair: (*list_ptr).C_GenerateKeyPair,
                C_WrapKey: (*list_ptr).C_WrapKey,
                C_UnwrapKey: (*list_ptr).C_UnwrapKey,
                C_DeriveKey: (*list_ptr).C_DeriveKey,
                C_SeedRandom: (*list_ptr).C_SeedRandom,
                C_GenerateRandom: (*list_ptr).C_GenerateRandom,
                C_GetFunctionStatus: (*list_ptr).C_GetFunctionStatus,
                C_CancelFunction: (*list_ptr).C_CancelFunction,
                // Functions added in for Cryptoki Version 2.01 or later:
                // to be compatible with PKCS#11 2.00 we do not fail during initialization
                // but when the function will be called.
                C_WaitForSlotEvent: (*list_ptr).C_WaitForSlotEvent,
            })
        }
    }

    pub fn new_and_initialize<P>(filename: P) -> Result<Ctx, Error>
    where
        P: AsRef<Path>,
    {
        let mut ctx = Ctx::new(filename)?;
        ctx.initialize(None)?;
        Ok(ctx)
    }

    pub fn is_initialized(&self) -> bool {
        self._is_initialized
    }

    fn initialized(&self) -> Result<(), Error> {
        if !self._is_initialized {
            Err(Error::Module("module not initialized"))
        } else {
            Ok(())
        }
    }

    fn not_initialized(&self) -> Result<(), Error> {
        if self._is_initialized {
            Err(Error::Module("module already initialized"))
        } else {
            Ok(())
        }
    }

    pub fn initialize(&mut self, init_args: Option<CK_C_INITIALIZE_ARGS>) -> Result<(), Error> {
        self.not_initialized()?;
        // if no args are specified, library expects NULL
        let init_args = match init_args {
            Some(mut args) => &mut args,
            None => ptr::null_mut(),
        };
        match (req!(self, C_Initialize)?)(init_args) {
            CKR_OK => {
                self._is_initialized = true;
                Ok(())
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        self.initialized()?;
        match (req!(self, C_Finalize)?)(ptr::null_mut()) {
            CKR_OK => {
                self._is_initialized = false;
                Ok(())
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_info(&self) -> Result<CK_INFO, Error> {
        self.initialized()?;
        let mut info = CK_INFO::new();
        match (req!(self, C_GetInfo)?)(&mut info) {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_function_list(&self) -> Result<CK_FUNCTION_LIST, Error> {
        let mut list = mem::MaybeUninit::uninit();
        match (req!(self, C_GetFunctionList)?)(&mut list.as_mut_ptr()) {
            CKR_OK => unsafe { Ok(*list.as_ptr()) },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_slot_list(&self, token_present: bool) -> Result<Vec<CK_SLOT_ID>, Error> {
        self.initialized()?;
        let mut slots_len: CK_ULONG = 0;
        match (req!(self, C_GetSlotList)?)(
            CkFrom::from(token_present),
            ptr::null_mut(),
            &mut slots_len,
        ) {
            CKR_OK => {
                // now slots_len contains the number of slots,
                // and we can generate a vector with the right capacity
                // important is to pass slots_len **again** because in
                // the 2nd call it is used to tell C how big the memory
                // in slots is.
                let mut slots = Vec::<CK_SLOT_ID>::with_capacity(slots_len as usize);
                let slots_ptr = slots.as_mut_ptr();
                match (req!(self, C_GetSlotList)?)(
                    CkFrom::from(token_present),
                    slots_ptr,
                    &mut slots_len,
                ) {
                    CKR_OK => {
                        unsafe {
                            slots.set_len(slots_len as usize);
                        }
                        Ok(slots)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_slot_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_SLOT_INFO, Error> {
        self.initialized()?;
        let mut info: CK_SLOT_INFO = Default::default();
        match (req!(self, C_GetSlotInfo)?)(slot_id, &mut info) {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_token_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_TOKEN_INFO, Error> {
        self.initialized()?;
        let mut info: CK_TOKEN_INFO = Default::default();
        match (req!(self, C_GetTokenInfo)?)(slot_id, &mut info) {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_mechanism_list(&self, slot_id: CK_SLOT_ID) -> Result<Vec<CK_MECHANISM_TYPE>, Error> {
        self.initialized()?;
        let mut count: CK_ULONG = 0;
        match (req!(self, C_GetMechanismList)?)(slot_id, ptr::null_mut(), &mut count) {
            CKR_OK => {
                // see get_slot_list() for an explanation - it works the same way
                let mut list = Vec::<CK_MECHANISM_TYPE>::with_capacity(count as usize);
                let list_ptr = list.as_mut_ptr();
                match (req!(self, C_GetMechanismList)?)(slot_id, list_ptr, &mut count) {
                    CKR_OK => {
                        unsafe {
                            list.set_len(count as usize);
                        }
                        Ok(list)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_mechanism_info(
        &self,
        slot_id: CK_SLOT_ID,
        mechanism_type: CK_MECHANISM_TYPE,
    ) -> Result<CK_MECHANISM_INFO, Error> {
        self.initialized()?;
        let mut info: CK_MECHANISM_INFO = Default::default();
        match (req!(self, C_GetMechanismInfo)?)(slot_id, mechanism_type, &mut info) {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn init_token<'a, 'b>(
        &self,
        slot_id: CK_SLOT_ID,
        pin: Option<&'a str>,
        label: &'b str,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut formatted_label = label_from_str(label).to_vec();
        let formatted_label_ptr = formatted_label.as_mut_ptr();
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let mut cpin_bytes = cpin.into_bytes();
                    match (req!(self, C_InitToken)?)(
                        slot_id,
                        cpin_bytes.as_mut_ptr(),
                        cpin_bytes.len() as CK_ULONG,
                        formatted_label_ptr,
                    ) {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            }
            None => {
                // CKF_PROTECTED_AUTHENTICATION_PATH requires a NULL pointer
                match (req!(self, C_InitToken)?)(slot_id, ptr::null_mut(), 0, formatted_label_ptr) {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
        }
    }

    pub fn init_pin<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        pin: Option<&'a str>,
    ) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let mut cpin_bytes = cpin.into_bytes();
                    match (req!(self, C_InitPIN)?)(
                        session,
                        cpin_bytes.as_mut_ptr(),
                        cpin_bytes.len() as CK_ULONG,
                    ) {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            }
            None => match (req!(self, C_InitPIN)?)(session, ptr::null_mut(), 0) {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            },
        }
    }

    pub fn set_pin<'a, 'b>(
        &self,
        session: CK_SESSION_HANDLE,
        old_pin: Option<&'a str>,
        new_pin: Option<&'b str>,
    ) -> Result<(), Error> {
        self.initialized()?;
        if old_pin.is_none() && new_pin.is_none() {
            match (req!(self, C_SetPIN)?)(session, ptr::null_mut(), 0, ptr::null_mut(), 0) {
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
            let mut old_cpin = old_cpin_res.unwrap().into_bytes();
            let mut new_cpin = new_cpin_res.unwrap().into_bytes();
            match (req!(self, C_SetPIN)?)(
                session,
                old_cpin.as_mut_ptr(),
                old_cpin.len() as CK_ULONG,
                new_cpin.as_mut_ptr(),
                new_cpin.len() as CK_ULONG,
            ) {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            }
        } else {
            Err(Error::InvalidInput("both PINs must be either set or unset"))
        }
    }

    pub fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        application: Option<CK_VOID_PTR>,
        notify: CK_NOTIFY,
    ) -> Result<CK_SESSION_HANDLE, Error> {
        self.initialized()?;
        let mut session: CK_SESSION_HANDLE = 0;
        match (req!(self, C_OpenSession)?)(
            slot_id,
            flags,
            application.unwrap_or(ptr::null_mut()),
            notify,
            &mut session,
        ) {
            CKR_OK => Ok(session),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn close_session(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match (req!(self, C_CloseSession)?)(session) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn close_all_sessions(&self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        self.initialized()?;
        match (req!(self, C_CloseAllSessions)?)(slot_id) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_session_info(&self, session: CK_SESSION_HANDLE) -> Result<CK_SESSION_INFO, Error> {
        self.initialized()?;
        let mut info: CK_SESSION_INFO = Default::default();
        match (req!(self, C_GetSessionInfo)?)(session, &mut info) {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_operation_state(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut state_length: CK_ULONG = 0;
        match (req!(self, C_GetOperationState)?)(session, ptr::null_mut(), &mut state_length) {
            CKR_OK => {
                let mut state: Vec<CK_BYTE> = Vec::with_capacity(state_length as usize);
                let state_ptr = state.as_mut_ptr();
                match (req!(self, C_GetOperationState)?)(session, state_ptr, &mut state_length) {
                    CKR_OK => {
                        unsafe {
                            state.set_len(state_length as usize);
                        }
                        Ok(state)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn set_operation_state(
        &self,
        session: CK_SESSION_HANDLE,
        operation_state: Vec<CK_BYTE>,
        encryption_key: Option<CK_OBJECT_HANDLE>,
        authentication_key: Option<CK_OBJECT_HANDLE>,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut operation_state = operation_state;
        match (req!(self, C_SetOperationState)?)(
            session,
            operation_state.as_mut_ptr(),
            operation_state.len() as CK_ULONG,
            encryption_key.unwrap_or(0),
            authentication_key.unwrap_or(0),
        ) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn login<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: Option<&'a str>,
    ) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let mut cpin_bytes = cpin.into_bytes();
                    match (req!(self, C_Login)?)(
                        session,
                        user_type,
                        cpin_bytes.as_mut_ptr(),
                        cpin_bytes.len() as CK_ULONG,
                    ) {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            }
            None => match (req!(self, C_Login)?)(session, user_type, ptr::null_mut(), 0) {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            },
        }
    }

    /// Some dongle drivers (such as Safenet) allow NUL bytes in PINs, and fail
    /// login if a NUL containing PIN is truncated. Combined with poor PIN gen
    /// algorithms which insert NULs into the PIN, you might need a way to supply
    /// raw bytes for a PIN, instead of converting from a UTF8 string as per spec
    pub fn login_with_raw(
        &self,
        session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: Option<&[CK_BYTE]>,
    ) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => {
                let mut pin = pin.to_vec();
                match (req!(self, C_Login)?)(
                    session,
                    user_type,
                    pin.as_mut_ptr(),
                    pin.len() as CK_ULONG,
                ) {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
            None => match (req!(self, C_Login)?)(session, user_type, ptr::null_mut(), 0) {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            },
        }
    }

    pub fn logout(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match (req!(self, C_Logout)?)(session) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn create_object(
        &self,
        session: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut template = template.to_vec();
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match (req!(self, C_CreateObject)?)(
            session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut oh,
        ) {
            CKR_OK => Ok(oh),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn copy_object(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut template = template.to_vec();
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match (req!(self, C_CopyObject)?)(
            session,
            object,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut oh,
        ) {
            CKR_OK => Ok(oh),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn destroy_object(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        match (req!(self, C_DestroyObject)?)(session, object) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_object_size(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
    ) -> Result<CK_ULONG, Error> {
        self.initialized()?;
        let mut size: CK_ULONG = 0;
        match (req!(self, C_GetObjectSize)?)(session, object, &mut size) {
            CKR_OK => Ok(size),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_attribute_value<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: &'a mut Vec<CK_ATTRIBUTE>,
    ) -> Result<(CK_RV, &'a Vec<CK_ATTRIBUTE>), Error> {
        self.initialized()?;
        /*
          Note that the error codes CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL
          do not denote true errors for C_GetAttributeValue.  If a call to C_GetAttributeValue returns any of these three
          values, then the call MUST nonetheless have processed every attribute in the template supplied to
          C_GetAttributeValue.  Each attribute in the template whose value can be returned by the call to
          C_GetAttributeValue will be returned by the call to C_GetAttributeValue.
        */
        match (req!(self, C_GetAttributeValue)?)(
            session,
            object,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        ) {
            CKR_OK => Ok((CKR_OK, template)),
            CKR_ATTRIBUTE_SENSITIVE => Ok((CKR_ATTRIBUTE_SENSITIVE, template)),
            CKR_ATTRIBUTE_TYPE_INVALID => Ok((CKR_ATTRIBUTE_TYPE_INVALID, template)),
            CKR_BUFFER_TOO_SMALL => Ok((CKR_BUFFER_TOO_SMALL, template)),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn set_attribute_value(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut template = template.to_vec();
        match (req!(self, C_SetAttributeValue)?)(
            session,
            object,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        ) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn find_objects_init(
        &self,
        session: CK_SESSION_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut template = template.to_vec();
        match (req!(self, C_FindObjectsInit)?)(
            session,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
        ) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn find_objects(
        &self,
        session: CK_SESSION_HANDLE,
        max_object_count: CK_ULONG,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Error> {
        self.initialized()?;
        let mut list: Vec<CK_OBJECT_HANDLE> = Vec::with_capacity(max_object_count as usize);
        let mut count: CK_ULONG = 0;
        match (req!(self, C_FindObjects)?)(session, list.as_mut_ptr(), max_object_count, &mut count)
        {
            CKR_OK => {
                unsafe {
                    list.set_len(count as usize);
                }
                Ok(list)
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn find_objects_final(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match (req!(self, C_FindObjectsFinal)?)(session) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn encrypt_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match (req!(self, C_EncryptInit)?)(session, &mut mechanism, key) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn encrypt(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut encryptedDataLen: CK_ULONG = 0;
        match (req!(self, C_Encrypt)?)(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut encryptedDataLen,
        ) {
            CKR_OK => {
                let mut encryptedData: Vec<CK_BYTE> = Vec::with_capacity(encryptedDataLen as usize);
                match (req!(self, C_Encrypt)?)(
                    session,
                    data.as_mut_ptr(),
                    data.len() as CK_ULONG,
                    encryptedData.as_mut_ptr(),
                    &mut encryptedDataLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            encryptedData.set_len(encryptedDataLen as usize);
                        }
                        Ok(encryptedData)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn encrypt_update(
        &self,
        session: CK_SESSION_HANDLE,
        part: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        let mut encryptedPartLen: CK_ULONG = 0;
        match (req!(self, C_EncryptUpdate)?)(
            session,
            part.as_mut_ptr(),
            part.len() as CK_ULONG,
            ptr::null_mut(),
            &mut encryptedPartLen,
        ) {
            CKR_OK => {
                let mut encryptedPart: Vec<CK_BYTE> = Vec::with_capacity(encryptedPartLen as usize);
                match (req!(self, C_EncryptUpdate)?)(
                    session,
                    part.as_mut_ptr(),
                    part.len() as CK_ULONG,
                    encryptedPart.as_mut_ptr(),
                    &mut encryptedPartLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            encryptedPart.set_len(encryptedPartLen as usize);
                        }
                        Ok(encryptedPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn encrypt_final(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut lastEncryptedPartLen: CK_ULONG = 0;
        match (req!(self, C_EncryptFinal)?)(session, ptr::null_mut(), &mut lastEncryptedPartLen) {
            CKR_OK => {
                let mut lastEncryptedPart: Vec<CK_BYTE> =
                    Vec::with_capacity(lastEncryptedPartLen as usize);
                match (req!(self, C_EncryptFinal)?)(
                    session,
                    lastEncryptedPart.as_mut_ptr(),
                    &mut lastEncryptedPartLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            lastEncryptedPart.set_len(lastEncryptedPartLen as usize);
                        }
                        Ok(lastEncryptedPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match (req!(self, C_DecryptInit)?)(session, &mut mechanism, key) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt(
        &self,
        session: CK_SESSION_HANDLE,
        encryptedData: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut encrypted_data = encryptedData.to_vec();
        let mut dataLen: CK_ULONG = 0;
        match (req!(self, C_Decrypt)?)(
            session,
            encrypted_data.as_mut_ptr(),
            encrypted_data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut dataLen,
        ) {
            CKR_OK => {
                let mut data: Vec<CK_BYTE> = Vec::with_capacity(dataLen as usize);
                match (req!(self, C_Decrypt)?)(
                    session,
                    encrypted_data.as_mut_ptr(),
                    encrypted_data.len() as CK_ULONG,
                    data.as_mut_ptr(),
                    &mut dataLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            data.set_len(dataLen as usize);
                        }
                        Ok(data)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_update(
        &self,
        session: CK_SESSION_HANDLE,
        encryptedPart: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut encrypted_part = encryptedPart.to_vec();
        let mut partLen: CK_ULONG = 0;
        match (req!(self, C_DecryptUpdate)?)(
            session,
            encrypted_part.as_mut_ptr(),
            encrypted_part.len() as CK_ULONG,
            ptr::null_mut(),
            &mut partLen,
        ) {
            CKR_OK => {
                let mut part: Vec<CK_BYTE> = Vec::with_capacity(partLen as usize);
                match (req!(self, C_DecryptUpdate)?)(
                    session,
                    encrypted_part.as_mut_ptr(),
                    encrypted_part.len() as CK_ULONG,
                    part.as_mut_ptr(),
                    &mut partLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            part.set_len(partLen as usize);
                        }
                        Ok(part)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_final(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut lastPartLen: CK_ULONG = 0;
        match (req!(self, C_DecryptFinal)?)(session, ptr::null_mut(), &mut lastPartLen) {
            CKR_OK => {
                let mut lastPart: Vec<CK_BYTE> = Vec::with_capacity(lastPartLen as usize);
                match (req!(self, C_DecryptFinal)?)(
                    session,
                    lastPart.as_mut_ptr(),
                    &mut lastPartLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            lastPart.set_len(lastPartLen as usize);
                        }
                        Ok(lastPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match (req!(self, C_DigestInit)?)(session, &mut mechanism) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut digestLen: CK_ULONG = 0;
        match (req!(self, C_Digest)?)(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut digestLen,
        ) {
            CKR_OK => {
                let mut digest: Vec<CK_BYTE> = Vec::with_capacity(digestLen as usize);
                match (req!(self, C_Digest)?)(
                    session,
                    data.as_mut_ptr(),
                    data.len() as CK_ULONG,
                    digest.as_mut_ptr(),
                    &mut digestLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            digest.set_len(digestLen as usize);
                        }
                        Ok(digest)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_update(&self, session: CK_SESSION_HANDLE, part: &[CK_BYTE]) -> Result<(), Error> {
        let mut part = part.to_vec();
        match (req!(self, C_DigestUpdate)?)(session, part.as_mut_ptr(), part.len() as CK_ULONG) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_key(
        &self,
        session: CK_SESSION_HANDLE,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        match (req!(self, C_DigestKey)?)(session, key) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_final(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut digestLen: CK_ULONG = 0;
        match (req!(self, C_DigestFinal)?)(session, ptr::null_mut(), &mut digestLen) {
            CKR_OK => {
                let mut digest: Vec<CK_BYTE> = Vec::with_capacity(digestLen as usize);
                match (req!(self, C_DigestFinal)?)(session, digest.as_mut_ptr(), &mut digestLen) {
                    CKR_OK => {
                        unsafe {
                            digest.set_len(digestLen as usize);
                        }
                        Ok(digest)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match (req!(self, C_SignInit)?)(session, &mut mechanism, key) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut signatureLen: CK_ULONG = 0;
        match (req!(self, C_Sign)?)(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut signatureLen,
        ) {
            CKR_OK => {
                let mut signature: Vec<CK_BYTE> = Vec::with_capacity(signatureLen as usize);
                match (req!(self, C_Sign)?)(
                    session,
                    data.as_mut_ptr(),
                    data.len() as CK_ULONG,
                    signature.as_mut_ptr(),
                    &mut signatureLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            signature.set_len(signatureLen as usize);
                        }
                        Ok(signature)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_update(&self, session: CK_SESSION_HANDLE, part: &[CK_BYTE]) -> Result<(), Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        match (req!(self, C_SignUpdate)?)(session, part.as_mut_ptr(), part.len() as CK_ULONG) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_final(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut signatureLen: CK_ULONG = 0;
        match (req!(self, C_SignFinal)?)(session, ptr::null_mut(), &mut signatureLen) {
            CKR_OK => {
                let mut signature: Vec<CK_BYTE> = Vec::with_capacity(signatureLen as usize);
                match (req!(self, C_SignFinal)?)(session, signature.as_mut_ptr(), &mut signatureLen)
                {
                    CKR_OK => {
                        unsafe {
                            signature.set_len(signatureLen as usize);
                        }
                        Ok(signature)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_recover_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match (req!(self, C_SignRecoverInit)?)(session, &mut mechanism, key) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_recover(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut signatureLen: CK_ULONG = 0;
        match (req!(self, C_SignRecover)?)(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            ptr::null_mut(),
            &mut signatureLen,
        ) {
            CKR_OK => {
                let mut signature: Vec<CK_BYTE> = Vec::with_capacity(signatureLen as usize);
                match (req!(self, C_SignRecover)?)(
                    session,
                    data.as_mut_ptr(),
                    data.len() as CK_ULONG,
                    signature.as_mut_ptr(),
                    &mut signatureLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            signature.set_len(signatureLen as usize);
                        }
                        Ok(signature)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match (req!(self, C_VerifyInit)?)(session, &mut mechanism, key) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
        signature: &[CK_BYTE],
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut signature = signature.to_vec();
        match (req!(self, C_Verify)?)(
            session,
            data.as_mut_ptr(),
            data.len() as CK_ULONG,
            signature.as_mut_ptr(),
            signature.len() as CK_ULONG,
        ) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_update(&self, session: CK_SESSION_HANDLE, part: &[CK_BYTE]) -> Result<(), Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        match (req!(self, C_VerifyUpdate)?)(session, part.as_mut_ptr(), part.len() as CK_ULONG) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_final(
        &self,
        session: CK_SESSION_HANDLE,
        signature: &[CK_BYTE],
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut signature = signature.to_vec();
        match (req!(self, C_VerifyFinal)?)(
            session,
            signature.as_mut_ptr(),
            signature.len() as CK_ULONG,
        ) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_recover_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match (req!(self, C_VerifyRecoverInit)?)(session, &mut mechanism, key) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_recover(
        &self,
        session: CK_SESSION_HANDLE,
        signature: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut signature = signature.to_vec();
        let mut dataLen: CK_ULONG = 0;
        match (req!(self, C_VerifyRecover)?)(
            session,
            signature.as_mut_ptr(),
            signature.len() as CK_ULONG,
            ptr::null_mut(),
            &mut dataLen,
        ) {
            CKR_OK => {
                let mut data: Vec<CK_BYTE> = Vec::with_capacity(dataLen as usize);
                match (req!(self, C_VerifyRecover)?)(
                    session,
                    signature.as_mut_ptr(),
                    signature.len() as CK_ULONG,
                    data.as_mut_ptr(),
                    &mut dataLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            data.set_len(dataLen as usize);
                        }
                        Ok(data)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_encrypt_update(
        &self,
        session: CK_SESSION_HANDLE,
        part: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        let mut encryptedPartLen: CK_ULONG = 0;
        match (req!(self, C_DigestEncryptUpdate)?)(
            session,
            part.as_mut_ptr(),
            part.len() as CK_ULONG,
            ptr::null_mut(),
            &mut encryptedPartLen,
        ) {
            CKR_OK => {
                let mut encryptedPart: Vec<CK_BYTE> = Vec::with_capacity(encryptedPartLen as usize);
                match (req!(self, C_DigestEncryptUpdate)?)(
                    session,
                    part.as_mut_ptr(),
                    part.len() as CK_ULONG,
                    encryptedPart.as_mut_ptr(),
                    &mut encryptedPartLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            encryptedPart.set_len(encryptedPartLen as usize);
                        }
                        Ok(encryptedPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_digest_update(
        &self,
        session: CK_SESSION_HANDLE,
        encryptedPart: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut encrypted_part = encryptedPart.to_vec();
        let mut partLen: CK_ULONG = 0;
        match (req!(self, C_DecryptDigestUpdate)?)(
            session,
            encrypted_part.as_mut_ptr(),
            encrypted_part.len() as CK_ULONG,
            ptr::null_mut(),
            &mut partLen,
        ) {
            CKR_OK => {
                let mut part: Vec<CK_BYTE> = Vec::with_capacity(partLen as usize);
                match (req!(self, C_DecryptDigestUpdate)?)(
                    session,
                    encrypted_part.as_mut_ptr(),
                    encrypted_part.len() as CK_ULONG,
                    part.as_mut_ptr(),
                    &mut partLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            part.set_len(partLen as usize);
                        }
                        Ok(part)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_encrypt_update(
        &self,
        session: CK_SESSION_HANDLE,
        part: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        let mut encryptedPartLen: CK_ULONG = 0;
        match (req!(self, C_SignEncryptUpdate)?)(
            session,
            part.as_mut_ptr(),
            part.len() as CK_ULONG,
            ptr::null_mut(),
            &mut encryptedPartLen,
        ) {
            CKR_OK => {
                let mut encryptedPart: Vec<CK_BYTE> = Vec::with_capacity(encryptedPartLen as usize);
                match (req!(self, C_SignEncryptUpdate)?)(
                    session,
                    part.as_mut_ptr(),
                    part.len() as CK_ULONG,
                    encryptedPart.as_mut_ptr(),
                    &mut encryptedPartLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            encryptedPart.set_len(encryptedPartLen as usize);
                        }
                        Ok(encryptedPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_verify_update(
        &self,
        session: CK_SESSION_HANDLE,
        encryptedPart: Vec<CK_BYTE>,
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut encrypted_part = encryptedPart;
        let mut partLen: CK_ULONG = 0;
        match (req!(self, C_DecryptVerifyUpdate)?)(
            session,
            encrypted_part.as_mut_ptr(),
            encrypted_part.len() as CK_ULONG,
            ptr::null_mut(),
            &mut partLen,
        ) {
            CKR_OK => {
                let mut part: Vec<CK_BYTE> = Vec::with_capacity(partLen as usize);
                match (req!(self, C_DecryptVerifyUpdate)?)(
                    session,
                    encrypted_part.as_mut_ptr(),
                    encrypted_part.len() as CK_ULONG,
                    part.as_mut_ptr(),
                    &mut partLen,
                ) {
                    CKR_OK => {
                        unsafe {
                            part.set_len(partLen as usize);
                        }
                        Ok(part)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn generate_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut template = template.to_vec();
        let mut object: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match (req!(self, C_GenerateKey)?)(
            session,
            &mut mechanism,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut object,
        ) {
            CKR_OK => Ok(object),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn generate_key_pair(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        publicKeyTemplate: &[CK_ATTRIBUTE],
        privateKeyTemplate: &[CK_ATTRIBUTE],
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut public_key_template = publicKeyTemplate.to_vec();
        let mut private_key_template = privateKeyTemplate.to_vec();
        let mut pubOh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        let mut privOh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match (req!(self, C_GenerateKeyPair)?)(
            session,
            &mut mechanism,
            public_key_template.as_mut_ptr(),
            public_key_template.len() as CK_ULONG,
            private_key_template.as_mut_ptr(),
            private_key_template.len() as CK_ULONG,
            &mut pubOh,
            &mut privOh,
        ) {
            CKR_OK => Ok((pubOh, privOh)),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn wrap_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        wrappingKey: CK_OBJECT_HANDLE,
        key: CK_OBJECT_HANDLE,
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut length: CK_ULONG = 0;
        match (req!(self, C_WrapKey)?)(
            session,
            &mut mechanism,
            wrappingKey,
            key,
            ptr::null_mut(),
            &mut length,
        ) {
            CKR_OK => {
                if length > 0 {
                    let mut out: Vec<CK_BYTE> = Vec::with_capacity(length as usize);
                    match (req!(self, C_WrapKey)?)(
                        session,
                        &mut mechanism,
                        wrappingKey,
                        key,
                        out.as_mut_ptr(),
                        &mut length,
                    ) {
                        CKR_OK => {
                            unsafe {
                                out.set_len(length as usize);
                            }
                            Ok(out)
                        }
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Ok(vec![])
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn unwrap_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        unwrappingKey: CK_OBJECT_HANDLE,
        wrappedKey: &[CK_BYTE],
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut wrapped_key = wrappedKey.to_vec();
        let mut template = template.to_vec();
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match (req!(self, C_UnwrapKey)?)(
            session,
            &mut mechanism,
            unwrappingKey,
            wrapped_key.as_mut_ptr(),
            wrapped_key.len() as CK_ULONG,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut oh,
        ) {
            CKR_OK => Ok(oh),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn derive_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        baseKey: CK_OBJECT_HANDLE,
        template: &[CK_ATTRIBUTE],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut template = template.to_vec();
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match (req!(self, C_DeriveKey)?)(
            session,
            &mut mechanism,
            baseKey,
            template.as_mut_ptr(),
            template.len() as CK_ULONG,
            &mut oh,
        ) {
            CKR_OK => Ok(oh),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn seed_random(&self, session: CK_SESSION_HANDLE, seed: &[CK_BYTE]) -> Result<(), Error> {
        let mut seed = seed.to_vec();
        match (req!(self, C_SeedRandom)?)(session, seed.as_mut_ptr(), seed.len() as CK_ULONG) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn generate_random(
        &self,
        session: CK_SESSION_HANDLE,
        randomLength: CK_ULONG,
    ) -> Result<Vec<CK_BYTE>, Error> {
        let mut data: Vec<CK_BYTE> = Vec::with_capacity(randomLength as usize);
        match (req!(self, C_GenerateRandom)?)(session, data.as_mut_ptr(), randomLength) {
            CKR_OK => {
                unsafe {
                    data.set_len(randomLength as usize);
                }
                Ok(data)
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_function_status(&self, session: CK_SESSION_HANDLE) -> Result<CK_RV, Error> {
        match (req!(self, C_GetFunctionStatus)?)(session) {
            CKR_OK => Ok(CKR_OK),
            CKR_FUNCTION_NOT_PARALLEL => Ok(CKR_FUNCTION_NOT_PARALLEL),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn cancel_function(&self, session: CK_SESSION_HANDLE) -> Result<CK_RV, Error> {
        match (req!(self, C_CancelFunction)?)(session) {
            CKR_OK => Ok(CKR_OK),
            CKR_FUNCTION_NOT_PARALLEL => Ok(CKR_FUNCTION_NOT_PARALLEL),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn wait_for_slot_event(&self, flags: CK_FLAGS) -> Result<Option<CK_SLOT_ID>, Error> {
        let mut slotID: CK_SLOT_ID = 0;
        let C_WaitForSlotEvent = req!(self, C_WaitForSlotEvent)?;
        match C_WaitForSlotEvent(flags, &mut slotID, ptr::null_mut()) {
            CKR_OK => Ok(Some(slotID)),
            CKR_NO_EVENT => Ok(None),
            err => Err(Error::Pkcs11(err)),
        }
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
