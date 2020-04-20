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

# Collection of PKCS#11 Documentation

The purpose of this section is to provide all possible available documentation that makes programming against PKCS#11 easier.

## Collection of all PKCS#11 standards

I ran across this only recently (April 2020).
It is an invaluable collection of all PKCS#11 standards including all their C header files: <https://github.com/mheese/PKCS11-SPECS>

Special thanks to the guys from [Pkcs11Interop](https://pkcs11interop.net/) to provide this collection.

## Reference Documentation

When one first starts to explore the PKCS#11 world, there will be obstacles. The biggest one is to know and discover what documentation to read so that one can get familiar with the standard. It is best to read up on it in the following order:

1. [Usage Guide](http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/pkcs11-ug-v2.40.html "PKCS#11 v2.40 Usage Guide") - I discovered this unfortunately way too late for some reason. Giving this a read - before doing anything else - one gets actually a really good architectural overview of the standard.
2. [Base Specification](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html "PKCS#11 v2.40 Base Specification") - This is the most important document for implementation of this library - in particular for the low-level API. It explains in detail how the C interface is structured and how to interact with it. Following this will provide all the details on how to write the FFI wrapper.
3. [Current Mechanisms](http://docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/pkcs11-curr-v2.40.html "PKCS#11 v2.40 Current Mechanisms") - This document is in particular important for our higher-leval API. It explains in detail on how to interface in detail with all the cryptographic algorithms. E.g. go here if you need help on how to generate and use an RSA key or how to use the token for digital signatures.

## C Header Files

The C header files for PKCS #11 v2.40 can be found at this location:

- <http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11.h>
- <http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11t.h>
- <http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/pkcs11f.h>
