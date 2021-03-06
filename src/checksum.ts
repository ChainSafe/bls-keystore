import { Buffer } from "buffer";
import { sha256 } from "ethereum-cryptography/sha256";

import { IChecksumModule } from "./types";

// default checksum configuration

export function defaultSha256Module(): Pick<IChecksumModule, "function"> {
  return {
    function: "sha256",
  };
}

// checksum operations

function checksumData(key: Buffer, ciphertext: Buffer): Buffer {
  return Buffer.concat([key.slice(16), ciphertext]);
}

export function checksum(mod: IChecksumModule, key: Buffer, ciphertext: Buffer): Promise<Buffer> {
  if (mod.function === "sha256") {
    return Promise.resolve(sha256(checksumData(key, ciphertext)));
  } else {
    throw new Error("Invalid checksum type");
  }
}

export async function verifyChecksum(mod: IChecksumModule, key: Buffer, ciphertext: Buffer): Promise<boolean> {
  if (mod.function === "sha256") {
    return Buffer.from(mod.message, "hex").equals(sha256(checksumData(key, ciphertext)));
  } else {
    throw new Error("Invalid checksum type");
  }
}
