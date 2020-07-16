import { Buffer } from "buffer";
import { getRandomBytesSync } from "ethereum-cryptography/random";
import { encrypt as aesEncrypt, decrypt as aesDecrypt } from "ethereum-cryptography/aes";

import { ICipherModule } from "./types";

export function defaultAes128CtrModule(): Pick<ICipherModule, "function" | "params"> {
  return {
    function: "aes-128-ctr",
    params: {
      iv: getRandomBytesSync(16).toString("hex"),
    },
  };
}

export async function cipherEncrypt(mod: ICipherModule, key: Buffer, data: Uint8Array): Promise<Buffer> {
  if (mod.function === "aes-128-ctr") {
    try {
      return await aesEncrypt(
        Buffer.from(data),
        key,
        Buffer.from(mod.params.iv, "hex"),
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

export async function cipherDecrypt(mod: ICipherModule, key: Buffer): Promise<Buffer> {
  if (mod.function === "aes-128-ctr") {
    try {
      return await aesDecrypt(
        Buffer.from(mod.message, "hex"),
        key,
        Buffer.from(mod.params.iv, "hex"),
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
