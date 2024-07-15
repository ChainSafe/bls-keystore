import { getRandomBytesSync } from "ethereum-cryptography/random";
import { bytesToHex, hexToBytes } from "ethereum-cryptography/utils"

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
    const { salt, c, dklen } = mod.params;
    return await doPbkdf2(hexToBytes(salt), c, dklen, password);
  } else if (mod.function === "scrypt") {
    const { salt, n, p, r, dklen } = mod.params;
    return await doScrypt(hexToBytes(salt), n, p, r, dklen, password);
  } else {
    throw new Error("Invalid kdf type");
  }
}
