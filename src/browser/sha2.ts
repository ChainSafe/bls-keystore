export async function sha2(input: Buffer): Promise<Buffer> {
  return Buffer.from(await crypto.subtle.digest("SHA-256", input));
}
