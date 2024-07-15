import { getRandomBytesSync } from "ethereum-cryptography/random";
import { bytesToHex } from "ethereum-cryptography/utils"

import { IKdfModule, IPbkdf2KdfModule, IScryptKdfModule } from "../types";
import { doPbkdf2 } from "./pbkdf2";
import { doScrypt } from "./scrypt";

// default kdf configurations

export function defaultPbkdfModule(): Pick<IPbkdf2KdfModule, "function" | "params"> {
  return {
    function: "pbkdf2",
    params: {
      dklen: 32,
      c: 262144,
      prf: "hmac-sha256",
      salt: bytesToHex(getRandomBytesSync(32)),
    },
  };
}

export function defaultScryptModule(): Pick<IScryptKdfModule, "function" | "params"> {
  return {
    function: "scrypt",
    params: {
      dklen: 32,
      n: 262144,
      r: 8,
      p: 1,
      salt: bytesToHex(getRandomBytesSync(32)),
    },
  };
}

// kdf operations

export async function kdf(mod: IKdfModule, password: Uint8Array): Promise<Uint8Array> {
  if (mod.function === "pbkdf2") {
    return await doPbkdf2(mod.params, password);
  } else if (mod.function === "scrypt") {
    return await doScrypt(mod.params, password);
  } else {
    throw new Error("Invalid kdf type");
  }
}
