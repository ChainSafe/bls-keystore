import { getRandomBytesSync } from "ethereum-cryptography/random";
import { bytesToHex, hexToBytes } from "ethereum-cryptography/utils";

import { ICipherModule } from "../types";
import { aes128CtrDecrypt, aes128CtrEncrypt } from "./aes128Ctr";

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
      return await aes128CtrEncrypt(key, hexToBytes(mod.params.iv), data);
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
      return await aes128CtrDecrypt(key, hexToBytes(mod.params.iv), hexToBytes(mod.message));
    } catch (e) {
      throw new Error("Unable to decrypt")
    }
  } else {
    throw new Error("Invalid cipher type");
  }
}
