<!--
Copyright 2017 Marcus Heese

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Rust PKCS#11 Library

[![Latest version](https://img.shields.io/crates/v/pkcs11.svg)](https://crates.io/crates/pkcs11)
[![Documentation](https://docs.rs/pkcs11/badge.svg)](https://docs.rs/pkcs11)
![Build status](https://github.com/mheese/rust-pkcs11/workflows/Linux/badge.svg)
![Build status](https://github.com/mheese/rust-pkcs11/workflows/macOS/badge.svg)
![Build status](https://github.com/mheese/rust-pkcs11/workflows/Windows/badge.svg)
![Build status](https://github.com/mheese/rust-pkcs11/workflows/Audit/badge.svg)
[![codecov](https://codecov.io/gh/mheese/rust-pkcs11/branch/master/graph/badge.svg)](https://codecov.io/gh/mheese/rust-pkcs11)
![License](https://img.shields.io/crates/l/pkcs11.svg)

This is a library which brings support for PKCS#11 to Rust. It is aiming at having both a very low-level API to map the PKCS#11 functionality to Rust as well as having a higher-level API for more easy usage as well as bringing more safety for programming against PKCS#11.

## Status

The library has full support for all functions in PKCS#11 v2.40.
It should technically work with any Cryptoki version from v2.00.
For example there is special handling for `C_WaitForSlotEvent` which has been added only in v2.01.
You can successfully implement and reach all low-level Cryptoki semantics and structures.
All of them are integration tested using SoftHSM.
For better interoperability the low-level API is using nearly the same function/method calls and data structures as defined in the official standard.
That means that using the low-level API should be very easy for people who are familiar with PKCS#11 as the naming and variables/constants/defines are the same.

A high-level more Rust-friendly API is in the design process.
Its goal is to hide most of the low-level PKCS#11 semantics that one does not need to be aware of as they can be very verbose.
Furthermore using Rust datastructures it is possible to come up with a more type-safe library at compile time to help users to use PKCS#11 more successfully and to make it more robust.
It will also provide easier primitives for multi-part encrypting/decrypting/signing/etc.
Ideally by providing a streaming API.
Last but not least it will provide session management and lock/unlock free sessions as they are available from the context.
Especially on tokens that provide parallel processing this can be a very tedious and error-prone process.

## Compatiblity Matrix

**TODO:** This is still in the making, and most likely very incomplete.

As PKCS#11 implementations are not always sticking to the standard, your token might still have problems, unfortunately.
These are known tokens as reported by users that definitely work together with this library.

- [SoftHSM version 2](https://github.com/opendnssec/SoftHSMv2) (duh, who would have thought)
- [Nitrokey HSM 2](https://www.nitrokey.com)
- [CardConnect SmartCard-HSM](https://www.smartcard-hsm.com/)
- Safenet iKey 2032
- and probably a lot more...

If you use this library with an HSM that is not listed here, please open an issue (or even better a PR) so that I can update this matrix.
If your token does not work, please also open an issue, of course, so that we can investigate.

## Testing

Testing is currently done with [SoftHSM2](https://github.com/opendnssec/SoftHSMv2 "SoftHSM2 Repo").
A trillion thanks to the people at OpenDNSSEC for writing SoftHSM.
This makes it possible to develop applications that need to support PKCS#11.
I would have no idea what to do without it.
(Suggestions are always welcome.)

## TODO

Here is a list of the implementation status and plans on what to do next:

- [x] Dynamic loading of PKCS#11 module (thanks to [libloading](https://github.com/nagisa/rust_libloading "libloading Repo"))
- [x] Initializing and Dropping PKCS#11 context
- [x] Implementing Token and PIN Management functions
- [x] Implementing Session Management functions
- [x] Implementing Object Management functions
- [x] Implementing Key Management functions
- [x] Implementing Encryption/Decryption functions
- [x] Implementing Message Digest functions
- [x] Implementing Signing and MACing
- [x] Implementing Verifying of signatures and MACs
- [x] Implementing Dual-function cryptographic operations
- [x] Implementing Legacy PKCS#11 functions
- [x] Reorganize code of low-level API (too bloated, which we all know is what PKCS#11 is like)
- [x] Import the rest of the C header `pkcs11t.h` types into rust
- [x] Import the rest of the C header `pkcs11f.h` functions into rust
- [x] Publish on crates.io (wow, that was easy)
- [ ] C type constants to string converter functions, and the reverse (maybe part of the high-level API?)
- [ ] Design and implement high-level API
- [ ] Write and Generate Documentation for Rust docs
- [ ] Better Testing (lots of repetitive code + we need a testing framework and different SoftHSM versions for different platforms)
- [ ] Suppport for PKCS#11 v3.00
- [ ] make packed struct and CK_ULONG / CK_LONG feature flags with platform defaults when it becomes possible - currently the default when the target is Windows as PKCS#11 explicitly demands packed structs on Windows and `unsigned long` and `long` are both only 32bit on Microsoft compilers by default. However, on any other unix platform the defaults are not really defined and one might need to opt in for one or the other.
