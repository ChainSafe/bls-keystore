import { pbkdf2 } from "ethereum-cryptography/pbkdf2";

import { hasWebCrypto, isNode } from "../env";

export const doPbkdf2 = isNode ? doPbkdf2Node : hasWebCrypto ? doPbkdf2WebCrypto : doPbkdf2Js;

async function doPbkdf2Js(salt: Uint8Array, c: number, dklen: number, password: Uint8Array): Promise<Uint8Array> {
  return pbkdf2(
    password,
    salt,
    c,
    dklen,
    "sha256",
  );
}

async function doPbkdf2Node(salt: Uint8Array, c: number, dklen: number, password: Uint8Array): Promise<Uint8Array> {
  const crypto = await import("crypto");
  return crypto.pbkdf2Sync(password, salt, c, dklen, "sha256");
}

async function doPbkdf2WebCrypto(salt: Uint8Array, c: number, dklen: number, password: Uint8Array): Promise<Uint8Array> {
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
      salt,
      iterations: c,
      hash: "SHA-256",
    },
    passwordKey,
    dklen * 8,
  ));
}
