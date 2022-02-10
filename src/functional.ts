import {v4 as uuidV4} from "uuid";

import { IKeystore, IKdfModule, ICipherModule, IChecksumModule } from "./types";
import { kdf, defaultPbkdfModule, defaultScryptModule } from "./kdf";
import { checksum, verifyChecksum, defaultSha256Module } from "./checksum";
import { cipherEncrypt, cipherDecrypt, defaultAes128CtrModule } from "./cipher";
import { normalizePassword } from "./password";
import { bytesToHex, hexToBytes } from "ethereum-cryptography/utils";

export {
  defaultPbkdfModule,
  defaultScryptModule,
  defaultSha256Module,
  defaultAes128CtrModule,
}

/**
 * Create a new keystore object
 *
 * @param password password used to encrypt the keystore
 * @param secret secret key material to be encrypted
 * @param pubkey public key, not checked for validity
 * @param path HD path used to generate the secret
 * @param kdfMod key derivation function (kdf) configuration module
 * @param checksumMod checksum configuration module
 * @param cipherMod cipher configuration module
 */
export async function create(
  password: string | Uint8Array,
  secret: Uint8Array,
  pubkey: Uint8Array,
  path: string,
  description: string | null = null,
  kdfMod: Pick<IKdfModule, "function" | "params"> = defaultPbkdfModule(),
  checksumMod: Pick<IChecksumModule, "function"> = defaultSha256Module(),
  cipherMod: Pick<ICipherModule, "function" | "params"> = defaultAes128CtrModule(),
): Promise<IKeystore> {
  const encryptionKey = await kdf(kdfMod as IKdfModule, normalizePassword(password));
  const ciphertext = await cipherEncrypt(cipherMod as ICipherModule, encryptionKey.slice(0, 16), secret);
  return {
    version: 4,
    uuid: uuidV4(),
    description: description || undefined,
    path: path,
    pubkey: bytesToHex(pubkey),
    crypto: {
      kdf: {
        function: kdfMod.function,
        params: {
          ...kdfMod.params,
        },
        message: "",
      } as IKdfModule,
      checksum: {
        function: checksumMod.function,
        params: {},
        message: bytesToHex(await checksum(checksumMod as IChecksumModule, encryptionKey, ciphertext)),
      },
      cipher: {
        function: cipherMod.function,
        params: {
          ...cipherMod.params,
        },
        message: bytesToHex(ciphertext),
      },
    },
  };
}

/**
 * Verify the password of a keystore object
 */
export async function verifyPassword(keystore: IKeystore, password: string | Uint8Array): Promise<boolean> {
  const decryptionKey = await kdf(keystore.crypto.kdf, normalizePassword(password));
  const ciphertext = hexToBytes(keystore.crypto.cipher.message);
  return verifyChecksum(keystore.crypto.checksum, decryptionKey, ciphertext);
}

/**
 * Decrypt a keystore, returns the secret key or throws on invalid password
 */
export async function decrypt(keystore: IKeystore, password: string | Uint8Array): Promise<Uint8Array> {
  const decryptionKey = await kdf(keystore.crypto.kdf, normalizePassword(password));
  const ciphertext = hexToBytes(keystore.crypto.cipher.message);
  if (!(await verifyChecksum(keystore.crypto.checksum, decryptionKey, ciphertext))) {
    throw new Error("Invalid password");
  }
  return cipherDecrypt(keystore.crypto.cipher, decryptionKey.slice(0, 16));
}
