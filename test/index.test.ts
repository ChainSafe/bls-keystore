import { expect } from "chai";
import { hexToBytes } from "ethereum-cryptography/utils";

import { create, decrypt, verifyPassword, isValidKeystore, validateKeystore } from "../src"
import {normalizePassword} from "../lib/password";

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

describe("Password Normalize Tests", () => {
  it("should filter out unaccepted control codes from Uint8Array", function() {
    //C1 codes lie between 0x00 - 0x1F (inclusive) | 0 - 31
    const codeBetween0x00And0x1F = [...Array(32).keys()]
    //C1 codes lie between 0x80 and 0x9F (inclusive) | 128 - 159
    const codeBetween0x80And0x9F = [...Array(32).keys()].map(code => code + 128)
    const passWithIllegalControl = new Uint8Array(
      [103, ...codeBetween0x00And0x1F, ...codeBetween0x80And0x9F, 111]
    )

    const normalizedPassword = normalizePassword(passWithIllegalControl)
    expect(normalizedPassword).to.be.deep.equal(new Uint8Array([103, 111]), "Unaccepted control codes should be filtered out of password Uint8Array")
  })

  it("should filter out unaccepted control codes from string", function() {
    //C1 codes lie between 0x00 - 0x1F (inclusive) | 0 - 31
    const codeBetween0x00And0x1F = [...Array(32).keys()]
    const passWithIllegalControl = new TextDecoder().decode(new Uint8Array(
        [103, ...codeBetween0x00And0x1F, 32, 111] // 32 represents space which is acceptable
    ));

    const normalizedPassword = new TextDecoder().decode(normalizePassword(passWithIllegalControl))
    expect(normalizedPassword).to.equal("g o", "Unaccepted control codes should be filtered out of password string")
  })
})
