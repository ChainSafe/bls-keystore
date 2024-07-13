import { getRandomBytesSync } from "ethereum-cryptography/random";
import { encrypt as aesEncrypt, decrypt as aesDecrypt } from "ethereum-cryptography/aes";

import { ICipherModule } from "./types";
import { bytesToHex, hexToBytes } from "ethereum-cryptography/utils";

export function defaultAes128CtrModule(): Pick<ICipherModule, "function" | "params"> {
  return {
    function: "aes-128-ctr",
    params: {
      iv: bytesToHex(getRandomBytesSync(16)),
    },
  };
}

export async function cipherEncrypt(mod: ICipherModule, key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  if (mod.function === "aes-128-ctr") {
    try {
      if (globalThis?.crypto?.subtle) {
        return await cipherEncryptWebCrypto(mod, key, data);
      }
      return await aesEncrypt(
        data,
        key,
        hexToBytes(mod.params.iv),
        mod.function,
        false,
      );
    } catch (e) {
      throw new Error("Unable to encrypt");
    }
  } else {
    throw new Error("Invalid cipher type");
  }
}

async function cipherEncryptWebCrypto(
  mod: ICipherModule,
  key: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {name: "AES-CTR"},
    false,
    ["encrypt"]
  );
  return new Uint8Array(await crypto.subtle.encrypt(pickAlgorithm(mod), cryptoKey, data));
}

export async function cipherDecrypt(mod: ICipherModule, key: Uint8Array): Promise<Uint8Array> {
  if (mod.function === "aes-128-ctr") {
    try {
      if (globalThis?.crypto?.subtle) {
        return await cipherDecryptWebCrypto(mod, key);
      }
      return await aesDecrypt(
        hexToBytes(mod.message),
        key,
        hexToBytes(mod.params.iv),
        mod.function,
        false,
      );
    } catch (e) {
      throw new Error("Unable to decrypt")
    }
  } else {
    throw new Error("Invalid cipher type");
  }
}

async function cipherDecryptWebCrypto(mod: ICipherModule, key: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {name: "AES-CTR"},
    false,
    ["decrypt"]
  );
  return new Uint8Array(await crypto.subtle.decrypt(pickAlgorithm(mod), cryptoKey, hexToBytes(mod.message)));
}

function pickAlgorithm(mod: ICipherModule): AesCtrParams {
  if (mod.function === "aes-128-ctr") {
    return { name: "AES-CTR", counter: hexToBytes(mod.params.iv), length: 128 };
  } else {
    throw new Error("Invalid cipher type");
  }
}
