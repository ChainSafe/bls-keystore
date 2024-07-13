import { getRandomBytesSync } from "ethereum-cryptography/random";
import { pbkdf2 } from "ethereum-cryptography/pbkdf2";
import { scrypt } from "ethereum-cryptography/scrypt";
import { bytesToHex, hexToBytes } from "ethereum-cryptography/utils"

import { IKdfModule, IPbkdf2KdfModule, IScryptKdfModule } from "./types";

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
  if (globalThis?.crypto?.subtle) {
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

async function doPbkdf2WebCrypto(params: IPbkdf2KdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
  const passwordKey = await crypto.subtle.importKey(
    "raw",
    password,
    {name: "PBKDF2"},
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: hexToBytes(params.salt),
      iterations: params.c,
      hash: pickHash(params.prf.slice(5)),
    },
    passwordKey,
    {name: "AES-CTR", length: params.dklen * 8},
    true,
    ["encrypt", "decrypt"]
  );
  return new Uint8Array(await crypto.subtle.exportKey("raw", key));
}

function pickHash(hash: string): string {
  hash = hash.toLowerCase();
  if (hash === "sha256") {
    return "SHA-256";
  } else if (hash === "sha512") {
    return "SHA-512";
  } else {
    throw new Error("Invalid hash type");
  }
}

async function doScrypt(params: IScryptKdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
  return scrypt(
    password,
    hexToBytes(params.salt),
    params.n,
    params.p,
    params.r,
    params.dklen,
  );
}
