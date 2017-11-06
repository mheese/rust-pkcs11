extern crate libloading as lib;
extern crate libc;

use std::ptr;
use libc::c_uchar;

#[allow(non_camel_case_types)]
type CK_BYTE = u8;
type CK_CHAR = CK_BYTE;
type CK_UTF8CHAR = CK_BYTE;
type CK_BBOOL = CK_BYTE;
type CK_ULONG = usize;
type CK_LONG = isize;
// TODO: enums here
type CK_FLAGS = CK_ULONG;
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
type CK_VOID_PTR_PTR = *const *const CK_VOID;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_VERSION {
  major: CK_BYTE,  /* integer portion of version number */
  minor: CK_BYTE,   /* 1/100ths portion of version number */
}

type CK_CREATEMUTEX = Option<extern "C" fn(CK_VOID_PTR_PTR) -> CK_RV>;
type CK_DESTROYMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;
type CK_LOCKMUTEX = Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>;
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

type CK_INFO_PTR = *const CK_INFO;

type C_Initialize = extern "C" fn(CK_C_INITIALIZE_ARGS_PTR) -> CK_RV;
type C_Finalize = extern "C" fn(CK_VOID_PTR) -> CK_RV;
type C_GetInfo = extern "C" fn(CK_INFO_PTR) -> CK_RV;
type C_GetFunctionList = extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV;

#[allow(non_camel_case_types, non_snake_case)]
#[derive(Debug)]
#[repr(C)]
struct CK_FUNCTION_LIST {
    version: CK_VERSION,
    //C_Initialize: Option<extern "C" fn(CK_C_INITIALIZE_ARGS_PTR) -> CK_RV>,
    C_Initialize: Option<C_Initialize>,
    //C_Finalize: Option<extern "C" fn(CK_VOID_PTR) -> CK_RV>,
    C_Finalize: Option<C_Finalize>,
    //C_GetInfo: Option<extern "C" fn(CK_INFO_PTR) -> CK_RV>,
    C_GetInfo: Option<C_GetInfo>,
    //C_GetFunctionList: Option<extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV>,
    C_GetFunctionList: Option<C_GetFunctionList>,

}

type CK_FUNCTION_LIST_PTR = *const CK_FUNCTION_LIST;
type CK_FUNCTION_LIST_PTR_PTR = *const CK_FUNCTION_LIST_PTR;

#[derive(Debug)]
pub struct Ctx {
  lib: lib::Library,
  C_Initialize: C_Initialize,
  C_Finalize: C_Finalize,
  C_GetInfo: C_GetInfo,
  C_GetFunctionList: C_GetFunctionList,
}

impl Ctx {
    fn new(filename: &'static str) -> Ctx {
        unsafe {
            let lib = lib::Library::new(filename).unwrap();
            let mut list: CK_FUNCTION_LIST_PTR;
            let res: u32;
            list = std::mem::uninitialized();
            {
                let func: lib::Symbol<unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> u32> = lib.get(b"C_GetFunctionList").unwrap();
                res = func(&mut list);
            }
            //println!("{:?}", res);
            //println!("{:?}", *list);
            let init_args = CK_C_INITIALIZE_ARGS { flags: 0,CreateMutex: None, DestroyMutex: None, LockMutex: None, UnlockMutex: None, pReserved: ptr::null_mut()};
            let res = ((*list).C_Initialize).unwrap()(&init_args);
            //println!("{}", res);
            Ctx {
                lib: lib,
                C_Initialize: ((*list).C_Initialize).unwrap(),
                C_Finalize: ((*list).C_Finalize).unwrap(),
                C_GetInfo: ((*list).C_GetInfo).unwrap(),
                C_GetFunctionList: ((*list).C_GetFunctionList).unwrap(),
            }
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
        println!("Dropping Ctx!");
        let rv = (self.C_Finalize)(ptr::null_mut::<CK_VOID>());
        println!("C_Finalize: {:?}", rv);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_open_context() {
        let ctx = Ctx::new("/usr/local/lib/softhsm/libsofthsm2.so");
        ctx.get_info();
        //println!("{:?}", res);
        //assert_eq!(res.is_ok(), true);
    }
}
