import { scrypt } from "ethereum-cryptography/scrypt";
import { hexToBytes } from "ethereum-cryptography/utils"

import { IScryptKdfModule } from "../types";
import { isNode } from "../env";


export const doScrypt = isNode ? doScryptNode : doScryptJs;

async function doScryptJs(params: IScryptKdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
  return scrypt(
    password,
    hexToBytes(params.salt),
    params.n,
    params.p,
    params.r,
    params.dklen,
  );
}

async function doScryptNode(params: IScryptKdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
  const crypto = await import("crypto");
  return crypto.scryptSync(password,hexToBytes(params.salt), params.dklen, {
    N: params.n,
    r: params.r,
    p: params.p,
    maxmem: params.n * params.r * 256,
  });
}
