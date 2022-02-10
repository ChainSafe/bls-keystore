import { expect } from "chai";
import { hexToBytes } from "ethereum-cryptography/utils";

import { create, decrypt, verifyPassword, isValidKeystore, validateKeystore } from "../src"

describe("BLS12-381 Keystore Test", () => {
  it("Roundtrip should work", async function () {
    this.timeout(10000)
    const testKeystore = await create("test", new Uint8Array(32), new Uint8Array(48), "");
    expect(isValidKeystore(testKeystore)).to.be.true;
    expect(await verifyPassword(testKeystore, "test")).to.be.true;
  });
});

describe("Known Test Vectors", () => {
  it("Should be able to encrypt/decrypt Pbkdf2 keystores", async function () {
    this.timeout(100000)
    const keystores = [
      require('./vectors/pbkdf2-0.json'),
      require('./vectors/pbkdf2-0.json'),
    ];
    for (const keystore of keystores) {
      const password = keystore.password;
      const secret = hexToBytes(keystore.secret.slice(2));

      expect(isValidKeystore(keystore)).to.be.true;
      expect(await verifyPassword(keystore, password)).to.be.true;
      expect(await decrypt(keystore, password)).to.deep.equal(secret);
    }
  });

  it("Should be able to encrypt/decrypt Scrypt keystores", async function () {
    this.timeout(100000)
    const keystores = [
      require('./vectors/scrypt-0.json'),
      require('./vectors/scrypt-1.json'),
    ];
    for (const keystore of keystores) {
      const password = keystore.password;
      const secret = hexToBytes(keystore.secret.slice(2));

      expect(isValidKeystore(keystore)).to.be.true;
      expect(await verifyPassword(keystore, password)).to.be.true;
      expect(await decrypt(keystore, password)).to.deep.equal(secret);
    }
  });
});
