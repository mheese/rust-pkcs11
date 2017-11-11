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

/// Tests need to be run with `RUST_TEST_THREADS=1` currently to pass.
extern crate num_traits;

use tests::num_traits::Num;

use super::*;
use super::types::*;
use num_bigint::BigUint;

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
    assert!(
        res.is_ok(),
        "failed to create new context: {}",
        res.unwrap_err()
    );
}

#[test]
fn ctx_initialize() {
    let mut ctx = Ctx::new(PKCS11_MODULE_FILENAME).unwrap();
    let res = ctx.initialize(None);
    assert!(
        res.is_ok(),
        "failed to initialize context: {}",
        res.unwrap_err()
    );
    assert!(ctx.is_initialized(), "internal state is not initialized");
}

#[test]
fn ctx_new_and_initialize() {
    let res = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME);
    assert!(
        res.is_ok(),
        "failed to create or initialize new context: {}",
        res.unwrap_err()
    );
}

#[test]
fn ctx_finalize() {
    let mut ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
    let res = ctx.finalize();
    assert!(
        res.is_ok(),
        "failed to finalize context: {}",
        res.unwrap_err()
    );
}

#[test]
fn ctx_get_info() {
    let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
    let res = ctx.get_info();
    assert!(
        res.is_ok(),
        "failed to call C_GetInfo: {}",
        res.unwrap_err()
    );
    let info = res.unwrap();
    println!("{:?}", info);
}

#[test]
fn ctx_get_function_list() {
    let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
    let res = ctx.get_function_list();
    assert!(
        res.is_ok(),
        "failed to call C_GetFunctionList: {}",
        res.unwrap_err()
    );
    let list = res.unwrap();
    println!("{:?}", list);
}

#[test]
fn ctx_get_slot_list() {
    let ctx = Ctx::new_and_initialize(PKCS11_MODULE_FILENAME).unwrap();
    let res = ctx.get_slot_list(false);
    assert!(
        res.is_ok(),
        "failed to call C_GetSlotList: {}",
        res.unwrap_err()
    );
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
        assert!(
            res.is_ok(),
            "failed to call C_GetSlotInfo({}): {}",
            slot,
            res.unwrap_err()
        );
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
        assert!(
            res.is_ok(),
            "failed to call C_GetTokenInfo({}): {}",
            slot,
            res.unwrap_err()
        );
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
        assert!(
            res.is_ok(),
            "failed to call C_GetMechanismList({}): {}",
            slot,
            res.unwrap_err()
        );
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
            assert!(
                res.is_ok(),
                "failed to call C_GetMechanismInfo({}, {}): {}",
                slot,
                mechanism,
                res.unwrap_err()
            );
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
        assert!(
            res.is_ok(),
            "failed to call C_InitToken({}, {}, {}): {}",
            slot,
            pin.unwrap(),
            LABEL,
            res.unwrap_err()
        );
        println!(
            "Slot {} C_InitToken successful, PIN: {}",
            slot,
            pin.unwrap()
        );
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
        let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .unwrap();
        ctx.login(sh, CKU_SO, pin).unwrap();
        let res = ctx.init_pin(sh, pin);
        assert!(
            res.is_ok(),
            "failed to call C_InitPIN({}, {}): {}",
            sh,
            pin.unwrap(),
            res.unwrap_err()
        );
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
        let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .unwrap();
        ctx.login(sh, CKU_SO, pin).unwrap();
        let res = ctx.set_pin(sh, pin, new_pin);
        assert!(
            res.is_ok(),
            "failed to call C_SetPIN({}, {}, {}): {}",
            sh,
            pin.unwrap(),
            new_pin.unwrap(),
            res.unwrap_err()
        );
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
        assert!(
            res.is_ok(),
            "failed to call C_OpenSession({}, CKF_SERIAL_SESSION, None, None): {}",
            slot,
            res.unwrap_err()
        );
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
        let sh = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None)
            .unwrap();
        let res = ctx.close_session(sh);
        assert!(
            res.is_ok(),
            "failed to call C_CloseSession({}): {}",
            sh,
            res.unwrap_err()
        );
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
        ctx.open_session(slot, CKF_SERIAL_SESSION, None, None)
            .unwrap();
        let res = ctx.close_all_sessions(slot);
        assert!(
            res.is_ok(),
            "failed to call C_CloseAllSessions({}): {}",
            slot,
            res.unwrap_err()
        );
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
        let sh = ctx.open_session(slot, CKF_SERIAL_SESSION, None, None)
            .unwrap();
        let res = ctx.get_session_info(sh);
        assert!(
            res.is_ok(),
            "failed to call C_GetSessionInfo({}): {}",
            sh,
            res.unwrap_err()
        );
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
        let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .unwrap();
        let res = ctx.login(sh, CKU_SO, pin);
        assert!(
            res.is_ok(),
            "failed to call C_Login({}, CKU_SO, {}): {}",
            sh,
            pin.unwrap(),
            res.unwrap_err()
        );
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
        let sh = ctx.open_session(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, None, None)
            .unwrap();
        ctx.login(sh, CKU_SO, pin).unwrap();
        let res = ctx.logout(sh);
        assert!(
            res.is_ok(),
            "failed to call C_Logout({}): {}",
            sh,
            res.unwrap_err()
        );
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
    let val = vec![0, 1, 2, 3, 3, 4, 5];
    let attr = CK_ATTRIBUTE::new(CKA_VALUE).set_bytes(val.as_slice());
    println!("{:?}", attr);
    let ret: Vec<CK_BYTE> = attr.get_bytes();
    println!("{:?}", ret);
    assert_eq!(
        val,
        ret.as_slice(),
        "attr.get_bytes() shouls have been {:?}",
        val
    );
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
    assert_eq!(
        val.day,
        ret.day,
        "attr.get_date() should have been {:?}",
        val
    );
    assert_eq!(
        val.month,
        ret.month,
        "attr.get_date() should have been {:?}",
        val
    );
    assert_eq!(
        val.year,
        ret.year,
        "attr.get_date() should have been {:?}",
        val
    );
}

#[test]
fn attr_biginteger() {
    let num_str = "123456789012345678901234567890123456789012345678901234567890123456789012345678";
    let val = BigUint::from_str_radix(num_str, 10).unwrap();
    let slice = val.to_bytes_le();
    let attr = CK_ATTRIBUTE::new(CKA_LABEL).set_biginteger(&slice);
    println!("{:?}", attr);
    let ret = attr.get_biginteger();
    println!("{:?}", ret);
    assert_eq!(ret, val, "attr.get_biginteger() should have been {:?}", val);
    assert_eq!(
        ret.to_str_radix(10),
        num_str,
        "attr.get_biginteger() should have been {:?}",
        num_str
    );
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
    let (ctx, sh) = fixture_token().unwrap();
    //let b = (true).into_ck(CKA_CLASS);
    //let template = vec![
    //    CK_ATTRIBUTE { ulType: CKA_CLASS, },
    //];
    //let res = ctx.create_object(sh, template);
    //assert!(res.is_ok(), "failed C_CreateObject({}, {:?}): {}", sh, template, res.is_err());
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
