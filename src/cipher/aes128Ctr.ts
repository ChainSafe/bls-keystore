import { encrypt as aesEncrypt, decrypt as aesDecrypt } from "ethereum-cryptography/aes";

import { hasWebCrypto } from "../env";

export const aes128CtrEncrypt = hasWebCrypto ? aes128CtrEncryptWebCrypto : aes128CtrEncryptJs;
export const aes128CtrDecrypt = hasWebCrypto ? aes128CtrDecryptWebCrypto : aes128CtrDecryptJs;

export async function aes128CtrEncryptJs(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  return await aesEncrypt(
    data,
    key,
    iv,
    "aes-128-ctr",
    false,
  );
}

async function aes128CtrEncryptWebCrypto(
  key: Uint8Array,
  iv: Uint8Array,
  data: Uint8Array
): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {name: "AES-CTR"},
    false,
    ["encrypt"]
  );
  return new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-CTR", counter: iv, length: 128 },
    cryptoKey,
    data
  ));
}

export async function aes128CtrDecryptJs(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  return await aesDecrypt(
    ciphertext,
    key,
    iv,
    "aes-128-ctr",
    false,
  );
}

async function aes128CtrDecryptWebCrypto(key: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    {name: "AES-CTR"},
    false,
    ["decrypt"]
  );
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-CTR", counter: iv, length: 128 },
    cryptoKey,
    ciphertext
  ));
}
