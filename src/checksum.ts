import { sha256 } from "ethereum-cryptography/sha256";
import { concatBytes, equalsBytes, hexToBytes } from "ethereum-cryptography/utils";

import { IChecksumModule } from "./types";

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
    return equalsBytes(hexToBytes(mod.message), sha256(checksumData(key, ciphertext)));
  } else {
    throw new Error("Invalid checksum type");
  }
}
