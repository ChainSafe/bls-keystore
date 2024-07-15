import { sha256 as _sha256 } from "ethereum-cryptography/sha256";

import { hasWebCrypto } from "../env";

export const sha256 = hasWebCrypto ? sha256WebCrypto : sha256Js;

async function sha256WebCrypto(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

async function sha256Js(data: Uint8Array): Promise<Uint8Array> {
  return _sha256(data);
}
