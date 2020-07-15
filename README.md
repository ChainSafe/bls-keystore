# @ChainSafe/bls-keystore

[![Build Status](https://travis-ci.com/ChainSafe/bls-keystore.svg?branch=master)](https://travis-ci.com/ChainSafe/bls-keystore)
![npm](https://img.shields.io/npm/v/@ChainSafe/bls-keystore)
![Discord](https://img.shields.io/discord/593655374469660673?color=blue&label=Discord&logo=discord)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![es-version](https://img.shields.io/badge/ES-2015-yellow)
![node-version](https://img.shields.io/badge/node-10.x-green)

> Typescript implementation of [EIP 2335](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md) for node and browser.

### How to use?

Functional interface
```typescript
import {Buffer} from "buffer";
import {
  IKeystore,
  create,
  decrypt,
  verifyPassword,
  isValidKeystore,
  validateKeystore,
} from "@chainsafe/bls-keystore";

// encrypt private key
const password: string | Uint8Array = "SomePassword123"; 
const privateKey: Uint8Array = ...;
const publicKey: Uint8Array = ...;
const path: string = "m/12381/60/0/0";

// keystore is an `object` that follows the EIP-2335 schema
const keystore: IKeystore = await create(password, privateKey, publicKey, path);

// verify password
await verifyPassword(keystore, password); //true | false

// decrypt
const decryptedPrivateKey: Buffer = await decrypt(keystore, password);

// convert to string
JSON.stringify(keystore); //string

// determine if unsanitized data fits the EIP-2335 schema
const data: unknown = ...;
isValidKeystore(data); // true | false

validateKeystore(data); // throws if invalid
```

Class-based interface
```typescript
import {Buffer} from "buffer";
import {
  Keystore,
} from "@chainsafe/bls-keystore";

// encrypt private key
const password: string | Uint8Array = "SomePassword123"; 
const privateKey: Uint8Array = ...;
const publicKey: Uint8Array = ...;
const path: string = "m/12381/60/0/0";

// keystore is a `Keystore` instance that follows the EIP-2335 schema with additional convenience methods
const keystore: Keystore = await Keystore.create(password, privateKey, publicKey, path);

// verify password
await keystore.verifyPassword(password); //true | false

// decrypt
const decryptedPrivateKey: Buffer = await keystore.decrypt(password);

// convert to string
keystore.stringify(); //string

// determine if unsanitized data fits the EIP-2335 schema
const data: unknown = ...;
Keystore.fromObject(data); // returns a Keystore or throws if data is invalid
```

For key derivation checkout [@chainsafe/bls-keygen](https://github.com/ChainSafe/bls-keygen)

### Contribute

- get yarn
- yarn install
- yarn test
