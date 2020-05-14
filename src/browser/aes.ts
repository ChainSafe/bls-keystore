import { Buffer } from "buffer";
import { IAes128CtrCipherModule } from "../types";

async function getKey(keyData: Buffer): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", keyData, "AES-CTR", false, ["encrypt", "decrypt"]);
}

export async function aes128CtrEncrypt(cipher: IAes128CtrCipherModule, key: Buffer, data: Uint8Array): Promise<Buffer> {
  const cryptoKey = await getKey(key);
  return Buffer.from(await crypto.subtle.encrypt(
    {
      name: "AES-CTR",
      counter: Buffer.from(cipher.params.iv, "hex"),
      length: 32
    },
    cryptoKey,
    data,
  ));
}

export async function aes128CtrDecrypt(cipher: IAes128CtrCipherModule, key: Buffer): Promise<Buffer> {
  const cryptoKey = await getKey(key);
  return Buffer.from(await crypto.subtle.encrypt(
    {
      name: "AES-CTR",
      counter: Buffer.from(cipher.params.iv, "hex"),
      length: 32
    },
    cryptoKey,
    Buffer.from(cipher.message, "hex")
  ));
}

