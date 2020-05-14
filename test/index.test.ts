import { expect } from "chai";
import { Buffer } from "buffer";
import { create, decrypt, verifyPassword, isValidKeystore, validateKeystore } from "../src"

const pbkdf2Test = require("./keystore.pbkdf2.test.json");
const scryptTest = require("./keystore.pbkdf2.test.json");

const pubkey = Buffer.alloc(48);

describe("BLS12-381 Keystore Test", () => {
  it("Roundtrip should work", async () => {
    expect(await verifyPassword(await create("test", Buffer.alloc(32), Buffer.alloc(48), ""), "test")).to.be.true;
  });

  it("Should be able to validate a keystore", () => {
    const keystore = pbkdf2Test;
    expect(isValidKeystore(keystore)).to.be.true;
  });
});

describe("Known Test Vectors", () => {

  it("Should be able to encrypt/decrypt Pbkdf2 keystore", async () => {
    const keystore = pbkdf2Test;

    const secret = Buffer.from("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "hex");
    const password = "testpassword";

    const keystoreDup = await create(
      password,
      secret,
      Buffer.from(keystore.pubkey, "hex"),
      keystore.path,
      keystore.crypto.kdf,
      keystore.crypto.checksum,
      keystore.crypto.cipher,
    );
    keystoreDup.uuid = keystore.uuid;

    expect(() => validateKeystore(keystore)).to.not.throw;
    expect(keystore).to.deep.equal(keystoreDup);
    expect(await decrypt(keystore, password)).to.deep.equal(secret);
    //expect(async () => await decrypt(keystore, "wrongpassword")).to.throw("Invalid password");
  });

  it("Should be able to encrypt/decrypt Scrypt keystore", async () => {
    const keystore = scryptTest;

    const secret = Buffer.from("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "hex");
    const password = "testpassword";

    const keystoreDup = await create(
      password,
      secret,
      Buffer.from(keystore.pubkey, "hex"),
      keystore.path,
      keystore.crypto.kdf,
      keystore.crypto.checksum,
      keystore.crypto.cipher,
    );
    keystoreDup.uuid = keystore.uuid;

    expect(() => validateKeystore(keystore)).to.not.throw;
    expect(keystore).to.deep.equal(keystoreDup);
    expect(await decrypt(keystore, password)).to.deep.equal(secret);
    //expect(async () => await decrypt(keystore, "wrongpassword")).to.throw("Invalid password");
  });
});
