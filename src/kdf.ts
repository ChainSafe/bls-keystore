import { getRandomBytesSync } from "ethereum-cryptography/random";
import { pbkdf2 } from "ethereum-cryptography/pbkdf2";
import { scrypt } from "ethereum-cryptography/scrypt";
import { bytesToHex, hexToBytes } from "ethereum-cryptography/utils"

import { IKdfModule, IPbkdf2KdfModule, IScryptKdfModule } from "./types";
import { hasWebCrypto, isNode } from "./env";

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
async function doPbkdf2(params: IPbkdf2KdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
  if (isNode) {
    return await doPbkdf2Node(params, password);
  }
  if (hasWebCrypto) {
    return await doPbkdf2WebCrypto(params, password);
  }
  return pbkdf2(
    password,
    hexToBytes(params.salt),
    params.c,
    params.dklen,
    params.prf.slice(5),
  );
}

async function doPbkdf2Node(params: IPbkdf2KdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
  const crypto = await import("crypto");
  return crypto.pbkdf2Sync(password, hexToBytes(params.salt), params.c, params.dklen, params.prf.slice(5));
}

async function doPbkdf2WebCrypto(params: IPbkdf2KdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    password,
    {name: "PBKDF2"},
    false,
    ["deriveBits"],
  );
  return new Uint8Array(await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: hexToBytes(params.salt),
      iterations: params.c,
      hash: pickHash(params.prf.slice(5)),
    },
    passwordKey,
    params.dklen * 8,
  ));
}

function pickHash(hash: string): string {
  hash = hash.toLowerCase();
  switch (hash) {
    case "sha256": return "SHA-256";
    case "sha512": return "SHA-512";
    default: throw new Error("Invalid hash type");
  }
}

async function doScrypt(params: IScryptKdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
  if (isNode) {
    return await doScryptNode(params, password);
  }
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
