# @ChainSafe/bls-keystore

[![Build Status](https://travis-ci.com/ChainSafe/bls-keystore.svg?branch=master)](https://travis-ci.com/ChainSafe/bls-keystore)
![npm](https://img.shields.io/npm/v/@ChainSafe/bls-keystore)
![Discord](https://img.shields.io/discord/593655374469660673?color=blue&label=Discord&logo=discord)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Bls keystore implementation as per draft [EIP 2335](https://github.com/ethereum/EIPs/pull/2335) for node and browser.


##### Electron usage
- Set env variable ELECTRON=true because electron replaces openssl with BoreSSL which 
causes some incompatibilities when using native modules.


### How to use?
```javascript
import {Buffer} from "buffer";
import {Keystore} from "@nodefactory/bls-keystore";

// encrypt private key
const privateKey: Buffer;
const password = "SomePassword123"; 
const keystore = Keystore.encrypt(privateKey, password, "m/12381/60/0/0");

//verify password
keystore.verifyPassword(password); //true | false

//decrypt
const decryptedPrivateKey: Buffer = keystore.decrypt(password);

//save as json
keystore.toJSON(); //string
```

For key derivation checkout [@chainsafe/bls-ts-key-mgmt](https://github.com/ChainSafe/bls-ts-key-mgmt)

### Contribute

- get yarn
- yarn install
- yarn test
