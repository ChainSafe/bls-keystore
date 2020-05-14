import { Buffer } from "buffer";
import randombytes = require("randombytes");
import { ICipherModule } from "./types";
import { aes128CtrEncrypt, aes128CtrDecrypt } from "./node/aes";

export function defaultAes128CtrModule(): Pick<ICipherModule, "function" | "params"> {
  return {
    function: "aes-128-ctr",
    params: {
      iv: randombytes(16).toString("hex"),
    },
  };
}

export async function cipherEncrypt(mod: ICipherModule, key: Buffer, data: Uint8Array): Promise<Buffer> {
  if (mod.function === "aes-128-ctr") {
    return aes128CtrEncrypt(mod, key, data);
  } else {
    throw new Error("Invalid cipher type");
  }
}

export async function cipherDecrypt(mod: ICipherModule, key: Buffer): Promise<Buffer> {
  if (mod.function === "aes-128-ctr") {
    return aes128CtrDecrypt(mod, key);
  } else {
    throw new Error("Invalid cipher type");
  }
}
