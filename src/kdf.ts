import { Buffer } from "buffer";
import { pbkdf2 as _pbkdf2 } from "pbkdf2";
import _scrypt = require("scrypt-js");
import randombytes = require("randombytes");

import { IKdfModule, IPbkdf2KdfModule, IScryptKdfModule } from "./types";

// default kdf configurations

export function defaultPbkdfModule(): Pick<IPbkdf2KdfModule, "function" | "params"> {
  return {
    function: "pbkdf2",
    params: {
      dklen: 32,
      c: 262144,
      prf: "hmac-sha256",
      salt: randombytes(32).toString("hex"),
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
      salt: randombytes(32).toString("hex"),
    },
  };
}

// kdf operations

export async function kdf(mod: IKdfModule, password: string): Promise<Buffer> {
  if (mod.function === "pbkdf2") {
    return pbkdf2(mod.params, password);
  } else if (mod.function === "scrypt") {
    return scrypt(mod.params, password);
  } else {
    throw new Error("Invalid kdf type");
  }
}
async function pbkdf2(params: IPbkdf2KdfModule["params"], password: string): Promise<Buffer> {
  return new Promise((resolve, reject) => _pbkdf2(
    Buffer.from(password),
    Buffer.from(params.salt, "hex"),
    params.c,
    params.dklen,
    params.prf.slice(5),
    (err, value) => err ? reject(err) : resolve(value),
  ));
}

async function scrypt(params: IScryptKdfModule["params"], password: string): Promise<Buffer> {
  // eslint-disable-next-line @typescript-eslint/ban-ts-ignore
  // @ts-ignore
  return _scrypt.scrypt(
    Buffer.from(password),
    Buffer.from(params.salt, "hex"),
    params.n,
    params.r,
    params.p,
    params.dklen,
  );
}
