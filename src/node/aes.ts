import { createCipheriv, createDecipheriv } from "crypto";

import { IAes128CtrCipherModule } from "../types";

export async function aes128CtrEncrypt(cipher: IAes128CtrCipherModule, key: Buffer, data: Uint8Array): Promise<Buffer> {
  const c = createCipheriv(cipher.function, key, Buffer.from(cipher.params.iv, "hex"));
  return Buffer.concat([c.update(data), c.final()]);
}

export async function aes128CtrDecrypt(cipher: IAes128CtrCipherModule, key: Buffer): Promise<Buffer> {
  const c = createDecipheriv(cipher.function, key, Buffer.from(cipher.params.iv, "hex"));
  return Buffer.concat([c.update(Buffer.from(cipher.message, "hex")), c.final()]);
}

