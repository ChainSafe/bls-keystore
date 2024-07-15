import { scrypt } from "ethereum-cryptography/scrypt";

import { isNode } from "../env";


export const doScrypt = isNode ? doScryptNode : doScryptJs;

async function doScryptJs(salt: Uint8Array, n: number, p: number, r: number, dklen: number, password: Uint8Array): Promise<Uint8Array> {
  return scrypt(
    password,
    salt,
    n,
    p,
    r,
    dklen,
  );
}

async function doScryptNode(salt: Uint8Array, n: number, p: number, r: number, dklen: number, password: Uint8Array): Promise<Uint8Array> {
  const crypto = await import("crypto");
  return crypto.scryptSync(
    password,
    salt,
    dklen, {
      N: n,
      r,
      p,
      maxmem: n * r * 256,
    });
}
