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
extern crate num_bigint;

#[cfg(test)]
mod tests;

pub mod types;
pub mod functions;

use types::*;
use functions::*;


use std::mem;
use std::ptr;
use std::ffi::CString;
//use libc::c_uchar;


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
            break;
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
                let func: libloading::Symbol<
                    unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV,
                > = lib.get(b"C_GetFunctionList")?;
                match func(&mut list) {
                    CKR_OK => (),
                    err => return Err(Error::Pkcs11(err)),
                }
            }

            Ok(Ctx {
                lib: lib,
                _is_initialized: false,
                C_Initialize: (*list)
                    .C_Initialize
                    .ok_or(Error::Module("C_Initialize function not found"))?,
                C_Finalize: (*list)
                    .C_Finalize
                    .ok_or(Error::Module("C_Finalize function not found"))?,
                C_GetInfo: (*list)
                    .C_GetInfo
                    .ok_or(Error::Module("C_GetInfo function not found"))?,
                C_GetFunctionList: (*list)
                    .C_GetFunctionList
                    .ok_or(Error::Module("C_GetFunctionList function not found"))?,
                C_GetSlotList: (*list)
                    .C_GetSlotList
                    .ok_or(Error::Module("C_GetSlotList function not found"))?,
                C_GetSlotInfo: (*list)
                    .C_GetSlotInfo
                    .ok_or(Error::Module("C_GetSlotInfo function not found"))?,
                C_GetTokenInfo: (*list)
                    .C_GetTokenInfo
                    .ok_or(Error::Module("C_GetTokenInfo function not found"))?,
                C_GetMechanismList: (*list)
                    .C_GetMechanismList
                    .ok_or(Error::Module("C_GetMechanismList function not found"))?,
                C_GetMechanismInfo: (*list)
                    .C_GetMechanismInfo
                    .ok_or(Error::Module("C_GetMechanismInfo function not found"))?,
                C_InitToken: (*list)
                    .C_InitToken
                    .ok_or(Error::Module("C_InitToken function not found"))?,
                C_InitPIN: (*list)
                    .C_InitPIN
                    .ok_or(Error::Module("C_InitPIN function not found"))?,
                C_SetPIN: (*list)
                    .C_SetPIN
                    .ok_or(Error::Module("C_SetPIN function not found"))?,
                C_OpenSession: (*list)
                    .C_OpenSession
                    .ok_or(Error::Module("C_OpenSession function not found"))?,
                C_CloseSession: (*list)
                    .C_CloseSession
                    .ok_or(Error::Module("C_CloseSession function not found"))?,
                C_CloseAllSessions: (*list)
                    .C_CloseAllSessions
                    .ok_or(Error::Module("C_CloseAllSessions function not found"))?,
                C_GetSessionInfo: (*list)
                    .C_GetSessionInfo
                    .ok_or(Error::Module("C_GetSessionInfo function not found"))?,
                C_GetOperationState: (*list)
                    .C_GetOperationState
                    .ok_or(Error::Module("C_GetOperationState function not found"))?,
                C_SetOperationState: (*list)
                    .C_SetOperationState
                    .ok_or(Error::Module("C_SetOperationState function not found"))?,
                C_Login: (*list)
                    .C_Login
                    .ok_or(Error::Module("C_Login function not found"))?,
                C_Logout: (*list)
                    .C_Logout
                    .ok_or(Error::Module("C_Logout function not found"))?,
                C_CreateObject: (*list)
                    .C_CreateObject
                    .ok_or(Error::Module("C_CreateObject function not found"))?,
                C_CopyObject: (*list)
                    .C_CopyObject
                    .ok_or(Error::Module("C_CopyObject function not found"))?,
                C_DestroyObject: (*list)
                    .C_DestroyObject
                    .ok_or(Error::Module("C_DestroyObject function not found"))?,
                C_GetObjectSize: (*list)
                    .C_GetObjectSize
                    .ok_or(Error::Module("C_GetObjectSize function not found"))?,
                C_GetAttributeValue: (*list)
                    .C_GetAttributeValue
                    .ok_or(Error::Module("C_GetAttributeValue function not found"))?,
                C_SetAttributeValue: (*list)
                    .C_SetAttributeValue
                    .ok_or(Error::Module("C_SetAttributeValue function not found"))?,
                C_FindObjectsInit: (*list)
                    .C_FindObjectsInit
                    .ok_or(Error::Module("C_FindObjectsInit function not found"))?,
                C_FindObjects: (*list)
                    .C_FindObjects
                    .ok_or(Error::Module("C_FindObjects function not found"))?,
                C_FindObjectsFinal: (*list)
                    .C_FindObjectsFinal
                    .ok_or(Error::Module("C_FindObjectsFinal function not found"))?,
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
        match (self.C_Initialize)(&init_args.unwrap_or(CK_C_INITIALIZE_ARGS::new())) {
            CKR_OK => {
                self._is_initialized = true;
                Ok(())
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        self.initialized()?;
        match (self.C_Finalize)(ptr::null()) {
            CKR_OK => {
                self._is_initialized = false;
                Ok(())
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_info(&self) -> Result<CK_INFO, Error> {
        self.initialized()?;
        let info = CK_INFO::new();
        match (self.C_GetInfo)(&info) {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_function_list(&self) -> Result<CK_FUNCTION_LIST, Error> {
        let list: CK_FUNCTION_LIST_PTR = unsafe { mem::uninitialized() };
        match (self.C_GetFunctionList)(&list) {
            CKR_OK => unsafe { Ok((*list).clone()) },
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
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_slot_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_SLOT_INFO, Error> {
        self.initialized()?;
        let info: CK_SLOT_INFO = Default::default();
        match (self.C_GetSlotInfo)(slot_id, &info) {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_token_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_TOKEN_INFO, Error> {
        self.initialized()?;
        let info: CK_TOKEN_INFO = Default::default();
        match (self.C_GetTokenInfo)(slot_id, &info) {
            CKR_OK => Ok(info),
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
        let info: CK_MECHANISM_INFO = Default::default();
        match (self.C_GetMechanismInfo)(slot_id, mechanism_type, &info) {
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
        let formatted_label = label_from_str(label).to_vec().as_ptr();
        match pin {
            Some(pin) => if let Ok(cpin) = CString::new(pin) {
                let cpin_bytes = cpin.into_bytes();
                match (self.C_InitToken)(
                    slot_id,
                    cpin_bytes.as_ptr(),
                    cpin_bytes.len(),
                    formatted_label,
                ) {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            } else {
                Err(Error::InvalidInput("PIN contains a nul byte"))
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

    pub fn init_pin<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        pin: Option<&'a str>,
    ) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => if let Ok(cpin) = CString::new(pin) {
                let cpin_bytes = cpin.into_bytes();
                match (self.C_InitPIN)(session, cpin_bytes.as_ptr(), cpin_bytes.len()) {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            } else {
                Err(Error::InvalidInput("PIN contains a nul byte"))
            },
            None => match (self.C_InitPIN)(session, ptr::null(), 0) {
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
            match (self.C_SetPIN)(
                session,
                old_cpin.as_ptr(),
                old_cpin.len(),
                new_cpin.as_ptr(),
                new_cpin.len(),
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
        match (self.C_OpenSession)(
            slot_id,
            flags,
            application.unwrap_or(ptr::null()),
            notify,
            &mut session,
        ) {
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
        match (self.C_SetOperationState)(
            session,
            operation_state.as_ptr(),
            operation_state.len(),
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
            Some(pin) => if let Ok(cpin) = CString::new(pin) {
                let cpin_bytes = cpin.into_bytes();
                match (self.C_Login)(session, user_type, cpin_bytes.as_ptr(), cpin_bytes.len()) {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            } else {
                Err(Error::InvalidInput("PIN contains a nul byte"))
            },
            None => match (self.C_Login)(session, user_type, ptr::null(), 0) {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            },
        }
    }

    pub fn logout(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match (self.C_Logout)(session) {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn create_object(
        &self,
        session: CK_SESSION_HANDLE,
        template: &Vec<CK_ATTRIBUTE>,
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match (self.C_CreateObject)(
            session,
            template.as_slice().as_ptr(),
            template.len(),
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
        template: &Vec<CK_ATTRIBUTE>,
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match (self.C_CopyObject)(
            session,
            object,
            template.as_slice().as_ptr(),
            template.len(),
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
        match (self.C_DestroyObject)(session, object) {
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
        match (self.C_GetObjectSize)(session, object, &mut size) {
            CKR_OK => Ok(size),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_attribute_value(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: Vec<CK_ATTRIBUTE>,
    ) -> Result<Vec<CK_ATTRIBUTE>, Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn set_attribute_value(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: Vec<CK_ATTRIBUTE>,
    ) -> Result<(), Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn find_objects_init(
        &self,
        session: CK_SESSION_HANDLE,
        template: Vec<CK_ATTRIBUTE>,
    ) -> Result<(), Error> {
        self.initialized()?;
        unimplemented!()
    }

    pub fn find_objects(
        &self,
        session: CK_SESSION_HANDLE,
        max_object_count: CK_ULONG,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Error> {
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
