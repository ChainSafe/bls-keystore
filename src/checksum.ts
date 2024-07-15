import { sha256 } from "ethereum-cryptography/sha256";
import { concatBytes, equalsBytes, hexToBytes } from "ethereum-cryptography/utils";

import { IChecksumModule } from "./types";
import { hasWebCrypto } from "./env";

// default checksum configuration

export function defaultSha256Module(): Pick<IChecksumModule, "function"> {
  return {
    function: "sha256",
  };
}

// checksum operations

function checksumData(key: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return concatBytes(key.slice(16), ciphertext);
}

export function checksum(mod: IChecksumModule, key: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
  if (mod.function === "sha256") {
    return Promise.resolve(sha256(checksumData(key, ciphertext)));
  } else {
    throw new Error("Invalid checksum type");
  }
}

export async function verifyChecksum(mod: IChecksumModule, key: Uint8Array, ciphertext: Uint8Array): Promise<boolean> {
  if (mod.function === "sha256") {
    if (hasWebCrypto) {
      return verifyChecksumWebCrypto(mod, key, ciphertext);
    }
    return equalsBytes(hexToBytes(mod.message), sha256(checksumData(key, ciphertext)));
  } else {
    throw new Error("Invalid checksum type");
  }
}

async function verifyChecksumWebCrypto(mod: IChecksumModule, key: Uint8Array, ciphertext: Uint8Array): Promise<boolean> {
  if (mod.function === "sha256") {
    const data = checksumData(key, ciphertext);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
    return equalsBytes(hexToBytes(mod.message), digest);
  } else {
    throw new Error("Invalid checksum type");
  }
}
