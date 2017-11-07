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
type CK_LONG = isize;
// TODO: enums here
#[allow(non_camel_case_types)]
type CK_FLAGS = CK_ULONG;
#[allow(non_camel_case_types)]
type CK_RV = CK_ULONG;

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
#[allow(non_camel_case_types)]
type C_Initialize = extern "C" fn(CK_C_INITIALIZE_ARGS_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_Finalize = extern "C" fn(CK_VOID_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetInfo = extern "C" fn(CK_INFO_PTR) -> CK_RV;
#[allow(non_camel_case_types)]
type C_GetFunctionList = extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_FUNCTION_LIST {
    version: CK_VERSION,
    C_Initialize: Option<C_Initialize>,
    C_Finalize: Option<C_Finalize>,
    C_GetInfo: Option<C_GetInfo>,
    C_GetFunctionList: Option<C_GetFunctionList>,

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
                None => return Err(Error::Module("C_GetFunctionList not found")),
            };

            Ok(Ctx {
                lib: lib,
                _is_initialized: false,
                C_Initialize: c_initialize,
                C_Finalize: c_finalize,
                C_GetInfo: c_getinfo,
                C_GetFunctionList: c_getfunctionlist,
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
