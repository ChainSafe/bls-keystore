import { Keystore, Pbkdf2Keystore, ScryptKeystore } from "../src/keystore"
import { readFileSync } from "fs";

describe("BLS12-381 Keystore Test", () => {

    it("Should be able to encrypt/decrypt Pbkdf2 keystore", () => {
        const secret = Buffer.from("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "hex");
        const kdfSalt = Buffer.from("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "hex");
        const aesIv = Buffer.from("264daa3f303d7259501c93d997d84fe6", "hex");
        const password = "testpassword";
        const keystore = Pbkdf2Keystore.encrypt(secret, password, "", kdfSalt, aesIv);

        expect(keystore.crypto.cipher.message.toString("hex"))
            .toEqual("a9249e0ca7315836356e4c7440361ff22b9fe71e2e2ed34fc1eb03976924ed48");

        expect(keystore.crypto.checksum.message.toString("hex"))
            .toEqual("18b148af8e52920318084560fd766f9d09587b4915258dec0676cba5b0da09d8");
        
        expect(keystore.pubkey).toEqual("9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07");

        expect(keystore.decrypt(password)).toEqual(secret);

    })

    it("Should be able to encrypt/decrypt Scrypt keystore", () => {
        const secret = Buffer.from("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "hex");
        const kdfSalt = Buffer.from("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "hex");
        const aesIv = Buffer.from("264daa3f303d7259501c93d997d84fe6", "hex");
        const password = "testpassword";
        const keystore = ScryptKeystore.encrypt(secret, password, "", kdfSalt, aesIv);

        expect(keystore.crypto.cipher.message.toString("hex"))
            .toEqual("54ecc8863c0550351eee5720f3be6a5d4a016025aa91cd6436cfec938d6a8d30");

        expect(keystore.crypto.checksum.message.toString("hex"))
            .toEqual("149aafa27b041f3523c53d7acba1905fa6b1c90f9fef137568101f44b531a3cb");
        
        expect(keystore.pubkey).toEqual("9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07");

        expect(keystore.decrypt(password)).toEqual(secret);
    })

})