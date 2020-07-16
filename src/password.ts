import { Buffer } from "buffer";

export function normalizePassword(password: string | Uint8Array): Buffer {
  if (typeof password === "string") {
    return Buffer.from(password.normalize("NFKD"), "utf8");
  } else {
    return Buffer.from(password);
  }
}
