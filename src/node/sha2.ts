import { createHash } from "crypto";

export async function sha2(input: Buffer): Promise<Buffer> {
  return createHash("sha256").update(input).digest();
}
