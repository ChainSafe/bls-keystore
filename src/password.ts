import { utf8ToBytes } from "ethereum-cryptography/utils";

/**
 * Normalizes password to NFKD representation and strips the C0, C1, and Delete control codes.
 * C0 are the control codes between 0x00 - 0x1F (inclusive) | 0 - 31
 * C1 codes lie between 0x80 and 0x9F (inclusive) | 128 - 159
 * Delete, commonly known as “backspace”, is the UTF-8 character  | 127
 */
export function normalizePassword(password: string | Uint8Array): Uint8Array {
  if (typeof password === "string") {
    return utf8ToBytes(
      password
        .normalize("NFKD")
        .split("")
        .filter(char => controlCodeFilter(char.charCodeAt(0))).join(""));
  } else {
    return password.filter(controlCodeFilter);
  }
}


function controlCodeFilter(charCode: number): boolean {
  return (charCode > 31) && !(charCode >= 127 && charCode <= 159)
}