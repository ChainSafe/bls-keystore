import { defaultPbkdfModule } from "./kdf";
import { defaultSha256Module } from "./checksum";
import { defaultAes128CtrModule } from "./cipher";
import { IKeystore, IKdfModule, IChecksumModule, ICipherModule } from "./types";
import { create, decrypt, verifyPassword } from "./functional";
import { validateKeystore } from "./schema-validation";

/**
 * Class-based BLS Keystore
 */
export class Keystore implements IKeystore {
  version: number;
  uuid: string;
  description?: string;
  path: string;
  pubkey: string;
  crypto: {
    kdf: IKdfModule;
    checksum: IChecksumModule;
    cipher: ICipherModule;
  };

  constructor(obj: IKeystore) {
    this.version = obj.version;
    this.uuid = obj.uuid;
    this.description = obj.description;
    this.path = obj.path;
    this.pubkey = obj.pubkey;
    this.crypto = {
      kdf: {...obj.crypto.kdf},
      checksum: {...obj.crypto.checksum},
      cipher: {...obj.crypto.cipher},
    }
  }

  /**
   * Create a new Keystore object
   */
  static async create(
    password: string | Uint8Array,
    secret: Uint8Array,
    pubkey: Uint8Array,
    path: string,
    description: string | null = null,
    kdfMod: Pick<IKdfModule, "function" | "params"> = defaultPbkdfModule(),
    checksumMod: Pick<IChecksumModule, "function"> = defaultSha256Module(),
    cipherMod: Pick<ICipherModule, "function" | "params"> = defaultAes128CtrModule(),
  ): Promise<Keystore> {
    const obj = await create(
      password, secret, pubkey, path, description, kdfMod, checksumMod, cipherMod,
    );
    return new Keystore(obj)
  }

  /**
   * Create a keystore from an unknown object
   */
  static fromObject(obj: unknown): Keystore {
    validateKeystore(obj);
    return new Keystore(obj);
  }

  /**
   * Parse a keystore from a JSON string
   */
  static parse(str: string): Keystore {
    return Keystore.fromObject(JSON.parse(str))
  }

  /**
   * Decrypt a keystore, returns the secret key or throws on invalid password
   */
  async decrypt(password: string | Uint8Array): Promise<Uint8Array> {
    return decrypt(this, password);
  }

  /**
   * Verify the password as correct or not
   */
  async verifyPassword(password: string | Uint8Array): Promise<boolean> {
    return verifyPassword(this, password);
  }

  /**
   * Return the keystore as a plain object
   */
  toObject(): IKeystore {
    return {
      ...this
    }
  }

  /**
   * Return the keystore as stringified JSON
   */
  stringify(): string {
    return JSON.stringify(this.toObject(), null, 2);
  }
}
