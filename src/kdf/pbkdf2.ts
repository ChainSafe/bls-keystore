import { pbkdf2 } from "ethereum-cryptography/pbkdf2";
import { hexToBytes } from "ethereum-cryptography/utils"

import { IPbkdf2KdfModule } from "../types";
import { hasWebCrypto, isNode } from "../env";

export const doPbkdf2 = isNode ? doPbkdf2Node : hasWebCrypto ? doPbkdf2WebCrypto : doPbkdf2Js;

async function doPbkdf2Js(params: IPbkdf2KdfModule["params"], password: Uint8Array): Promise<Uint8Array> {
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
