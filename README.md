# @nodefactory/bls-keystore

[![Build Status](https://travis-ci.com/NodeFactoryIo/bls-keystore.svg?branch=master)](https://travis-ci.com/NodeFactoryIo/bls-keystore)
![npm](https://img.shields.io/npm/v/@nodefactory/bls-keystore)
![Discord](https://img.shields.io/discord/608204864593461248?color=blue&label=Discord&logo=discord)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Bls keystore implementation as per draft [EIP 2335](https://github.com/ethereum/EIPs/pull/2335) for node and browser.


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

#### Built by
[![NodeFactory](nf-logo.png)](https://nodefactory.io)
