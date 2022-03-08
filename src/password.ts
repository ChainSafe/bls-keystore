import { utf8ToBytes } from "ethereum-cryptography/utils";

/**
 * Normalizes password to NFKD representation and strips the C0, C1, and Delete control codes.
 * C0 are the control codes between 0x00 - 0x1F (inclusive)
 * C1 codes lie between 0x80 and 0x9F (inclusive)
 * Delete, commonly known as “backspace”, is the UTF-8 character
 *
 * https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2335.md#password-requirements
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
  return (charCode > 0x1F) && !(charCode >= 0x7f && charCode <= 0x9F)
}