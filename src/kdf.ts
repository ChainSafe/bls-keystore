import { Buffer } from "buffer";
import { getRandomBytesSync } from "ethereum-cryptography/random";
import { pbkdf2 } from "ethereum-cryptography/pbkdf2";
import { scrypt } from "ethereum-cryptography/scrypt";

import { IKdfModule, IPbkdf2KdfModule, IScryptKdfModule } from "./types";

// default kdf configurations

export function defaultPbkdfModule(): Pick<IPbkdf2KdfModule, "function" | "params"> {
  return {
    function: "pbkdf2",
    params: {
      dklen: 32,
      c: 262144,
      prf: "hmac-sha256",
      salt: getRandomBytesSync(32).toString("hex"),
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
      salt: getRandomBytesSync(32).toString("hex"),
    },
  };
}

// kdf operations

export async function kdf(mod: IKdfModule, password: Buffer): Promise<Buffer> {
  if (mod.function === "pbkdf2") {
    return await doPbkdf2(mod.params, password);
  } else if (mod.function === "scrypt") {
    return await doScrypt(mod.params, password);
  } else {
    throw new Error("Invalid kdf type");
  }
}
async function doPbkdf2(params: IPbkdf2KdfModule["params"], password: Buffer): Promise<Buffer> {
  return pbkdf2(
    password,
    Buffer.from(params.salt, "hex"),
    params.c,
    params.dklen,
    params.prf.slice(5),
  );
}

async function doScrypt(params: IScryptKdfModule["params"], password: Buffer): Promise<Buffer> {
  return scrypt(
    password,
    Buffer.from(params.salt, "hex"),
    params.n,
    params.p,
    params.r,
    params.dklen,
  );
}
