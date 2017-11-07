extern crate libloading;
//extern crate libc;

use std::ptr;
//use libc::c_uchar;

#[allow(non_camel_case_types)]
type CK_BYTE = u8;
#[allow(non_camel_case_types)]
type CK_CHAR = CK_BYTE;
#[allow(non_camel_case_types)]
type CK_UTF8CHAR = CK_BYTE;
#[allow(non_camel_case_types)]
type CK_BBOOL = CK_BYTE;
#[allow(non_camel_case_types)]
type CK_ULONG = usize;
#[allow(non_camel_case_types)]
type CK_ULONG_PTR = *const CK_ULONG;
#[allow(non_camel_case_types)]
type CK_LONG = isize;
// TODO: enums here
#[allow(non_camel_case_types)]
type CK_FLAGS = CK_ULONG;
#[allow(non_camel_case_types)]
type CK_RV = CK_ULONG;
#[allow(non_camel_case_types)]
type CK_SLOT_ID = CK_ULONG;
#[allow(non_camel_case_types)]
type CK_SLOT_ID_PTR = *const CK_SLOT_ID;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(u8)]
enum CK_VOID {
    __Variant1,
    __Variant2,
}

// TODO: in rust we could protect more with *const in a lot of cases
#[allow(non_camel_case_types, non_snake_case)]
type CK_VOID_PTR = *const CK_VOID;

#[allow(non_camel_case_types, non_snake_case)]
type CK_VOID_PTR_PTR = *const CK_VOID_PTR;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_VERSION {
  major: CK_BYTE,  /* integer portion of version number */
  minor: CK_BYTE,   /* 1/100ths portion of version number */
}

#[allow(non_camel_case_types)]
type CK_CREATEMUTEX = Option<extern "C" fn(CK_VOID_PTR_PTR) -> CK_RV>;
#[allow(non_camel_case_types)]
type CK_DESTROYMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;
#[allow(non_camel_case_types)]
type CK_LOCKMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;
#[allow(non_camel_case_types)]
type CK_UNLOCKMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_C_INITIALIZE_ARGS {
  CreateMutex: CK_CREATEMUTEX,
  DestroyMutex: CK_DESTROYMUTEX,
  LockMutex: CK_LOCKMUTEX,
  UnlockMutex: CK_UNLOCKMUTEX,
  flags: u32,
  pReserved: CK_VOID_PTR,
}

impl CK_C_INITIALIZE_ARGS {
    fn new() -> CK_C_INITIALIZE_ARGS {
        CK_C_INITIALIZE_ARGS {
            flags: 0,
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            pReserved: ptr::null(),
        }
    }
}

#[allow(non_camel_case_types)]
type CK_C_INITIALIZE_ARGS_PTR = *const CK_C_INITIALIZE_ARGS;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_INFO {
  /* manufacturerID and libraryDecription have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  cryptokiVersion: CK_VERSION,              /* Cryptoki interface ver */
  manufacturerID: [CK_UTF8CHAR; 32],        /* blank padded */
  flags: CK_FLAGS,                          /* must be zero */

  libraryDescription: [CK_UTF8CHAR; 32],    /* blank padded */
  libraryVersion: CK_VERSION,               /* version of library */
}

impl CK_INFO {
    fn new() -> CK_INFO {
        CK_INFO {
            cryptokiVersion: CK_VERSION { major: 0, minor: 0 },
            manufacturerID: [0; 32],
            flags: 0,
            libraryDescription: [0; 32],
            libraryVersion: CK_VERSION { major: 0, minor: 0 },
        }
    }
}

#[allow(non_camel_case_types)]
type CK_INFO_PTR = *const CK_INFO;

#[allow(non_camel_case_types, non_snake_case)]
#[repr(C)]
struct CK_SLOT_INFO {
  /* slotDescription and manufacturerID have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  slotDescription: [CK_UTF8CHAR; 64],    /* blank padded */
  manufacturerID: [CK_UTF8CHAR; 32],     /* blank padded */
  flags: CK_FLAGS,

  hardwareVersion: CK_VERSION,  /* version of hardware */
  firmwareVersion: CK_VERSION,  /* version of firmware */
}

#[allow(non_camel_case_types)]
type CK_SLOT_INFO_PTR = *const CK_INFO;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_TOKEN_INFO {
  /* label, manufacturerID, and model have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  label: [CK_UTF8CHAR; 32],           /* blank padded */
  manufacturerID: [CK_UTF8CHAR; 32],  /* blank padded */
  model: [CK_UTF8CHAR; 16],           /* blank padded */
  serialNumber: [CK_CHAR; 16],        /* blank padded */
  flags: CK_FLAGS,                    /* see below */

  ulMaxSessionCount: CK_ULONG,     /* max open sessions */
  ulSessionCount: CK_ULONG,        /* sess. now open */
  ulMaxRwSessionCount: CK_ULONG,   /* max R/W sessions */
  ulRwSessionCount: CK_ULONG,      /* R/W sess. now open */
  ulMaxPinLen: CK_ULONG,           /* in bytes */
  ulMinPinLen: CK_ULONG,           /* in bytes */
  ulTotalPublicMemory: CK_ULONG,   /* in bytes */
  ulFreePublicMemory: CK_ULONG,    /* in bytes */
  ulTotalPrivateMemory: CK_ULONG,  /* in bytes */
  ulFreePrivateMemory: CK_ULONG,   /* in bytes */
  hardwareVersion: CK_VERSION,     /* version of hardware */
  firmwareVersion: CK_VERSION,     /* version of firmware */
  utcTime: [CK_CHAR; 16],          /* time */
}

#[allow(non_camel_case_types)]
type CK_TOKEN_INFO_PTR = *const CK_TOKEN_INFO;

#[allow(non_camel_case_types)]
type CK_MECHANISM_TYPE = CK_ULONG;
#[allow(non_camel_case_types)]
type CK_MECHANISM_TYPE_PTR = *const CK_MECHANISM_TYPE;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_MECHANISM_INFO {
    ulMinKeySize: CK_ULONG,
    ulMaxKeySize: CK_ULONG,
    flags: CK_FLAGS,
}

#[allow(non_camel_case_types)]
type CK_MECHANISM_INFO_PTR = *const CK_MECHANISM_INFO;

#[allow(non_camel_case_types)]
type C_Initialize = extern "C" fn(CK_C_INITIALIZE_ARGS_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_Finalize = extern "C" fn(CK_VOID_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetInfo = extern "C" fn(CK_INFO_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetFunctionList = extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetSlotList = extern "C" fn(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetSlotInfo = extern "C" fn(CK_SLOT_ID, CK_SLOT_INFO_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetTokenInfo = extern "C" fn(CK_SLOT_ID, CK_TOKEN_INFO_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetMechanismList = extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetMechanismInfo = extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, CK_MECHANISM_INFO_PTR) -> CK_RV;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_FUNCTION_LIST {
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
}

#[allow(non_camel_case_types)]
type CK_FUNCTION_LIST_PTR = *const CK_FUNCTION_LIST;
#[allow(non_camel_case_types)]
type CK_FUNCTION_LIST_PTR_PTR = *const CK_FUNCTION_LIST_PTR;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Module(&'static str),
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
            Error::Pkcs11(ref err) => write!(f, "PKCS#11 error: {}", err),
        }
    }
}

#[allow(non_camel_case_types, non_snake_case)]
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
}

impl Ctx {
    pub fn new(filename: &'static str) -> Result<Ctx, Error> {
        unsafe {
            let lib = libloading::Library::new(filename)?;
            let mut list: CK_FUNCTION_LIST_PTR = std::mem::uninitialized();
            {
                let func: libloading::Symbol<unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib.get(b"C_GetFunctionList")?;
                match func(&mut list) {
                    0 => (),
                    err => return Err(Error::Pkcs11(err)),
                }
            }

            let c_initialize = match (*list).C_Initialize {
                Some(func) => func,
                None => return Err(Error::Module("C_Initialize function not found")),
            };

            let c_finalize = match (*list).C_Finalize {
                Some(func) => func,
                None => return Err(Error::Module("C_Finalize function not found")),
            };

            let c_getinfo = match (*list).C_GetInfo {
                Some(func) => func,
                None => return Err(Error::Module("C_GetInfo function not found")),
            };

            let c_getfunctionlist = match (*list).C_GetFunctionList {
                Some(func) => func,
                None => return Err(Error::Module("C_GetFunctionList function not found")),
            };

            let c_getslotlist = match (*list).C_GetSlotList {
                Some(func) => func,
                None => return Err(Error::Module("C_GetSlotList function not found")),
            };

            let c_getslotinfo = match (*list).C_GetSlotInfo {
                Some(func) => func,
                None => return Err(Error::Module("C_GetSlotInfo function not found")),
            };

            let c_gettokeninfo = match (*list).C_GetTokenInfo {
                Some(func) => func,
                None => return Err(Error::Module("C_GetTokenInfo function not found")),
            };

            let c_getmechanismlist = match (*list).C_GetMechanismList {
                Some(func) => func,
                None => return Err(Error::Module("C_GetMechanismList function not found")),
            };

            let c_getmechanisminfo = match (*list).C_GetMechanismInfo {
                Some(func) => func,
                None => return Err(Error::Module("C_GetMechanismInfo function not found")),
            };

            Ok(Ctx {
                lib: lib,
                _is_initialized: false,
                C_Initialize: c_initialize,
                C_Finalize: c_finalize,
                C_GetInfo: c_getinfo,
                C_GetFunctionList: c_getfunctionlist,
                C_GetSlotList: c_getslotlist,
                C_GetSlotInfo: c_getslotinfo,
                C_GetTokenInfo: c_gettokeninfo,
                C_GetMechanismList: c_getmechanismlist,
                C_GetMechanismInfo: c_getmechanisminfo,
            })
        }
    }

    pub fn is_initialized(&self) -> bool {
        self._is_initialized
    }

    pub fn initialize(&mut self) -> Result<(), Error> {
        if self._is_initialized {
            return Err(Error::Module("module already initialized"))
        }
        match (self.C_Initialize)(&CK_C_INITIALIZE_ARGS::new()) {
            0 => {
                self._is_initialized = true;
                Ok(())
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        if !self._is_initialized {
            return Err(Error::Module("module not initialized"))
        }
        match (self.C_Finalize)(ptr::null()) {
            0 => {
                self._is_initialized = false;
                Ok(())
            },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_info(&self) -> () {
        //unsafe {
            println!("Ctx: {:?}", self);
            let mut info = Box::new(CK_INFO::new());
            let rv = (self.C_GetInfo)(&mut *info);
            println!("Rv: {:?}, Info: {:?}", rv, info);
        //}
        ()
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
    use super::*;

    #[test]
    fn can_open_context() {
        let mut ctx = Ctx::new("/usr/local/lib/softhsm/libsofthsm2.so").unwrap();
        ctx.initialize().unwrap();
        ctx.get_info();
        //println!("{:?}", res);
        //assert_eq!(res.is_ok(), true);
    }
}
