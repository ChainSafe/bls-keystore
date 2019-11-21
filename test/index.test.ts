import {Keystore, Pbkdf2Keystore, ScryptKeystore} from "../src"
import {readFileSync} from "fs";
import {Buffer} from "buffer";
import {CryptoFunction} from "../src/crypto/module";

describe("BLS12-381 Keystore Test", () => {

  it("Roundtrip should work", () => {
    expect(Keystore.fromJSON(Keystore.encrypt(Buffer.alloc(32), "test", "", CryptoFunction.pbkdf2).toJSON()).verifyPassword("test")).toBeTruthy();
    expect(Keystore.fromJSON(Keystore.encrypt(Buffer.alloc(32), "test", "", CryptoFunction.scrypt).toJSON()).verifyPassword("test")).toBeTruthy();
  });

    it("Should be able to parse JSON keystore", () => {
        const keystoreStr = readFileSync('./test/keystore.pbkdf2.test.json', 'utf8');

        const keystoreJSON = JSON.parse(keystoreStr);

        const keystore = Keystore.fromJSON(keystoreStr);

        expect(keystore.crypto.checksum.function).toEqual(keystoreJSON.crypto.checksum.function);
        expect(keystore.crypto.checksum.message.toString("hex")).toEqual(keystoreJSON.crypto.checksum.message);
        expect(keystore.crypto.checksum.params).toEqual(keystoreJSON.crypto.checksum.params);

        expect(keystore.crypto.kdf.function).toEqual(keystoreJSON.crypto.kdf.function);
        expect(keystore.crypto.kdf.message.toString("hex")).toEqual(keystoreJSON.crypto.kdf.message);
        expect(keystore.crypto.kdf.params.toObject()).toEqual(keystoreJSON.crypto.kdf.params);

        expect(keystore.crypto.cipher.function).toEqual(keystoreJSON.crypto.cipher.function);
        expect(keystore.crypto.cipher.message.toString("hex")).toEqual(keystoreJSON.crypto.cipher.message);
        expect(keystore.crypto.cipher.params.toObject()).toEqual(keystoreJSON.crypto.cipher.params);

        expect(keystore.pubkey).toEqual(keystoreJSON.pubkey);
        expect(keystore.uuid).toEqual(keystoreJSON.uuid);
        expect(keystore.version).toEqual(keystoreJSON.version);
        expect(keystore.path).toEqual(keystoreJSON.path);
    });


    it("Should be able to encrypt/decrypt Pbkdf2 keystore", () => {
        const keystoreStr = readFileSync('./test/keystore.pbkdf2.test.json');

        const keystoreJSON = JSON.parse(keystoreStr.toString());

        const secret = Buffer.from("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "hex");
        const password = "testpassword";

        const keystore = Pbkdf2Keystore.encrypt(
            secret,
            password,
            "",
            CryptoFunction.pbkdf2,
            Buffer.from(keystoreJSON.crypto.kdf.params.salt, "hex"),
            Buffer.from(keystoreJSON.crypto.cipher.params.iv, "hex")
        );

        expect(keystore.crypto.cipher.message.toString("hex"))
            .toEqual(keystoreJSON.crypto.cipher.message);

        expect(keystore.crypto.checksum.message.toString("hex"))
            .toEqual(keystoreJSON.crypto.checksum.message);

        expect(keystore.pubkey).toEqual(keystoreJSON.pubkey);

        expect(keystore.decrypt(password)).toEqual(secret);

        expect(() => {keystore.decrypt("wrongpassword")}).toThrow("Invalid password");

    });

    it("Should be able to encrypt/decrypt Scrypt keystore", () => {

        const keystoreStr = readFileSync('./test/keystore.scrypt.test.json');

        const keystoreJSON = JSON.parse(keystoreStr.toString());

        const secret = Buffer.from("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "hex");
        const password = "testpassword";

        const keystore = ScryptKeystore.encrypt(
            secret,
            password,
            "",
            CryptoFunction.scrypt,
            Buffer.from(keystoreJSON.crypto.kdf.params.salt, "hex"),
            Buffer.from(keystoreJSON.crypto.cipher.params.iv, "hex")
        );

        expect(keystore.crypto.cipher.message.toString("hex"))
            .toEqual(keystoreJSON.crypto.cipher.message);

        expect(keystore.crypto.checksum.message.toString("hex"))
            .toEqual(keystoreJSON.crypto.checksum.message);

        expect(keystore.pubkey).toEqual(keystoreJSON.pubkey);

        expect(keystore.decrypt(password)).toEqual(secret);

        expect(() => {keystore.decrypt("wrongpassword")}).toThrow("Invalid password");
    })

});
