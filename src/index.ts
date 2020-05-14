import Ajv = require("ajv");
import { Buffer } from "buffer";
import {v4 as uuidV4} from "uuid";
import schema = require("./schema.json");

import { IKeystore, IKdfModule, ICipherModule, IChecksumModule } from "./types";
import { kdf, defaultPbkdfModule, defaultScryptModule } from "./kdf";
import { checksum, verifyChecksum, defaultSha256Module } from "./checksum";
import { cipherEncrypt, cipherDecrypt, defaultAes128CtrModule } from "./cipher";

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
  password: string,
  secret: Uint8Array,
  pubkey: Uint8Array,
  path: string,
  kdfMod: Pick<IKdfModule, "function" | "params"> = defaultPbkdfModule(),
  checksumMod: Pick<IChecksumModule, "function"> = defaultSha256Module(),
  cipherMod: Pick<ICipherModule, "function" | "params"> = defaultAes128CtrModule(),
): Promise<IKeystore> {
  const encryptionKey = await kdf(kdfMod as IKdfModule, password);
  const ciphertext = await cipherEncrypt(cipherMod as ICipherModule, encryptionKey.slice(0, 16), secret);
  return {
    version: 4,
    uuid: uuidV4(),
    path: path,
    pubkey: Buffer.from(pubkey).toString("hex"),
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
        message: (await checksum(checksumMod as IChecksumModule, encryptionKey, ciphertext)).toString("hex"),
      },
      cipher: {
        function: cipherMod.function,
        params: {
          ...cipherMod.params,
        },
        message: ciphertext.toString("hex"),
      },
    },
  };
}

/**
 * Verify the password of a keystore object
 */
export async function verifyPassword(keystore: IKeystore, password: string): Promise<boolean> {
  const decryptionKey = await kdf(keystore.crypto.kdf, password);
  const ciphertext = Buffer.from(keystore.crypto.cipher.message, "hex");
  return verifyChecksum(keystore.crypto.checksum, decryptionKey, ciphertext);
}

/**
 * Decrypt a keystore, returns the secret key or throws on invalid password
 */
export async function decrypt(keystore: IKeystore, password: string): Promise<Buffer> {
  const decryptionKey = await kdf(keystore.crypto.kdf, password);
  const ciphertext = Buffer.from(keystore.crypto.cipher.message, "hex");
  if (!(await verifyChecksum(keystore.crypto.checksum, decryptionKey, ciphertext))) {
    throw new Error("Invalid password");
  }
  return cipherDecrypt(keystore.crypto.cipher, decryptionKey.slice(0, 16));
}

// keystore validation

/**
 * Return schema validation errors for a potential keystore object
 */
export function schemaValidationErrors(data: unknown): Ajv.ErrorObject[] | null {
  const ajv = new Ajv();
  const validated = ajv.validate(schema, data)
  if (validated) {
    return null;
  }
  return ajv.errors as Ajv.ErrorObject[];
}

/**
 * Validate an unknown object as a valid keystore, throws on invalid keystore
 */
export function validateKeystore(keystore: unknown): asserts keystore is IKeystore {
  const errors = schemaValidationErrors(keystore);
  if (errors) {
    throw new Error(
      `${errors[0].dataPath}: ${errors[0].message}`
    );
  }
}

/**
 * Predicate for validating an unknown object as a valid keystore
 */
export function isValidKeystore(keystore: unknown): keystore is IKeystore {
  return !schemaValidationErrors(keystore);
}
