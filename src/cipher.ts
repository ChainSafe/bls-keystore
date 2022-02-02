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

export async function cipherDecrypt(mod: ICipherModule, key: Uint8Array): Promise<Uint8Array> {
  if (mod.function === "aes-128-ctr") {
    try {
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
