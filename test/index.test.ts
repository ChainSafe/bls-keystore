import { Keystore } from "../src/keystore"
import { readFileSync } from "fs";

describe("BLS12-381 Keystore Test", () => {

    let scryptKeystore: Keystore;
    let pbkdf2Keystore: Keystore;

    beforeAll(() => {
        const scryptJSON = JSON.parse(readFileSync("./test/keystore.scrypt.test.json").toString());
        const pbkdf2JSON = JSON.parse(readFileSync("./test/keystore.pbkdf2.test.json").toString());

        scryptKeystore = Keystore.fromJson(scryptJSON);
        pbkdf2Keystore = Keystore.fromJson(pbkdf2JSON);
    })

    it("Should be able to create Keystore from JSON", () => {
        console.log(scryptKeystore.uuid);
        console.log(pbkdf2Keystore.uuid);
        console.log(scryptKeystore.crypto.kdf.function);
        console.log(pbkdf2Keystore.crypto.kdf.function);
    })

    it("Should be able to encrypt keystore", () => {
        const secret = Buffer.from("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "hex");
        const kdfSalt = Buffer.from("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", "hex");
        const aesIv = Buffer.from("264daa3f303d7259501c93d997d84fe6", "hex");
        const password = "testpassword";
        const keystore = Keystore.encrypt(secret, password, "", kdfSalt, aesIv);

        console.log(keystore.crypto.kdf.params);
        console.log(keystore.crypto.cipher.params);
        console.log(keystore.crypto);
        console.log(keystore.crypto.checksum.message.toString("hex"));
    })

})