import { utf8ToBytes } from "ethereum-cryptography/utils";

export function normalizePassword(password: string | Uint8Array): Uint8Array {
  if (typeof password === "string") {
    return utf8ToBytes(password.normalize("NFKD"));
  } else {
    return password;
  }
}
