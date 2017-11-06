extern crate libloading as lib;
extern crate libc;

use std::ptr;

#[allow(non_camel_case_types)]
//type CK_BYTE = libc::c_uchar;
type CK_BYTE = u8;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_VERSION {
  major: CK_BYTE,  /* integer portion of version number */
  minor: CK_BYTE,   /* 1/100ths portion of version number */
}

#[derive(Debug)]
#[repr(u8)]
enum CkMutex {
    __Variant1,
    __Variant2,
}

#[repr(u8)]
enum CkReserved {
    __Variant1,
    __Variant2,
}

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_C_INITIALIZE_ARGS {
  CreateMutex: Option<extern "C" fn(*mut CkMutex) -> u32>,
  DestroyMutex: Option<extern "C" fn(*const CkMutex) -> u32>,
  LockMutex: Option<extern "C" fn(*const CkMutex) -> u32>,
  UnlockMutex: Option<extern "C" fn(*const CkMutex) -> u32>,
  flags: u32,
  pReserved: *mut CkReserved,
}

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_INFO {
  /* manufacturerID and libraryDecription have been changed from
   * CK_CHAR to CK_UTF8CHAR for v2.10 */
  cryptokiVersion: CK_VERSION,     /* Cryptoki interface ver */
  manufacturerID: [libc::c_char; 32], //CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
  flags: u32, //CK_FLAGS      flags;               /* must be zero */

  libraryDescription: [libc::c_char; 32], //CK_UTF8CHAR   libraryDescription[32];  /* blank padded */
  libraryVersion: CK_VERSION, //    libraryVersion;          /* version of library */
}

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_FUNCTION_LIST {
    version: CK_VERSION,
    C_Initialize: Option<extern "C" fn(*const CK_C_INITIALIZE_ARGS) -> u32>,
    C_Finalize: Option<extern "C" fn(*const CkReserved) -> u32>,
    C_GetInfo: Option<extern "C" fn(*mut CK_INFO) -> u32>,
    C_GetFunctionList: Option<extern "C" fn(*mut CK_FUNCTION_LIST) -> u32>,

}

impl CK_FUNCTION_LIST {
    fn new() -> CK_FUNCTION_LIST {
        CK_FUNCTION_LIST {
            version: CK_VERSION { major: 0, minor: 0 },
            C_Initialize: None,
            C_Finalize: None,
            C_GetInfo: None,
            C_GetFunctionList: None,
        }
    }
}

fn context_new() -> () {
    let lib = lib::Library::new("/usr/local/lib/softhsm/libsofthsm2.so").unwrap();
    let mut list = unsafe { std::mem::uninitialized() };
    let res: u32;
    unsafe {
        let func: lib::Symbol<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> u32> = lib.get(b"C_GetFunctionList").unwrap();
        res = func(&mut list);
    
    println!("{:?}", res);
    println!("{:?}", *list);
    let init_args = CK_C_INITIALIZE_ARGS { flags: 0,CreateMutex: None, DestroyMutex: None, LockMutex: None, UnlockMutex: None, pReserved: ptr::null_mut()};
    let res = ((*list).C_Initialize).unwrap()(&init_args);
    println!("{}", res);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_open_context() {
        context_new();
        //println!("{:?}", res);
        //assert_eq!(res.is_ok(), true);
    }
}
