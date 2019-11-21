import uuid from "uuid";
import {AES_128_CTR, kdf, randomBytes, SHA256} from "./utils/crypto";
import {PrivateKey, PublicKey} from "@chainsafe/bls";
import {Buffer} from "buffer";
import {deepmerge} from "./utils/deepmerge";
import {Pbkdf2ModuleParams, ScryptModuleParams} from "./crypto/module/params";
import {bytes, IKeystore, IKeystoreParams} from "./types";
import {CryptoFunction, IKeystoreCrypto, KdfModule, KeystoreCrypto} from "./crypto";


export class Keystore implements IKeystore {
  public readonly crypto: IKeystoreCrypto;
  public readonly pubkey: string;
  public readonly path: string;
  public readonly uuid: string;
  public readonly version: number = 4;

  constructor(keystore: Partial<IKeystoreParams>){
    this.crypto = new KeystoreCrypto(keystore.crypto || {});
    this.pubkey = keystore.pubkey || "";
    this.path = keystore.path || "";
    this.uuid = keystore.uuid || uuid.v4();
  }

  public static fromJson(json: string): Keystore {
    const jsonObj = JSON.parse(json) as IKeystoreParams;
    const keystore: IKeystoreParams = {
      crypto: jsonObj.crypto,
      path: jsonObj.path,
      pubkey: jsonObj.pubkey,
      uuid: jsonObj.uuid,
      version: jsonObj.version,
    };
    return new Keystore(keystore);
  }

  /**
   * Encrypt given secret and kreate keystore object.
   * @param secret secret to be encrypted
   * @param password to be used for encryption
   * @param path key derivation path as per eip 2334
   * @param crypto pbkdf2 or scrypt
   * @param kdfSalt
   * @param aesIv
   */
  public static encrypt(
    secret: bytes,
    password: string,
    path = "",
    crypto: CryptoFunction = CryptoFunction.pbkdf2,
    kdfSalt: bytes = randomBytes(32),
    aesIv: bytes = randomBytes(16)
  ): IKeystore {
    const kdfModule = new KdfModule({
      function: crypto,
      params: {
        salt: kdfSalt
      }
    });
    const decryptionKey: bytes = kdf(password, kdfModule.function, kdfModule.params);
    const cipher = AES_128_CTR(decryptionKey.slice(0, 16), aesIv);
    let encryptedSecret = cipher.update(secret);
    encryptedSecret = Buffer.concat([encryptedSecret, cipher.final()]);
    const cipherMessage = Buffer.from(encryptedSecret);
    const checksum = SHA256(Buffer.concat([decryptionKey.slice(16, 32), cipherMessage]));
    return  new this({
      path: path,
      pubkey: PublicKey.fromPrivateKey(PrivateKey.fromBytes(secret)).toHexString().replace("0x", ""),
      crypto: new KeystoreCrypto(
        {
          kdf: {
            function: crypto,
            params: {
              salt: kdfSalt
            }
          },
          checksum: {
            message: checksum
          },
          cipher: {
            params: {
              iv: aesIv
            },
            message: cipherMessage
          }
        }
      )
    });
  }

  public verifyPassword(password: string): boolean {
    const decryptionKey: bytes = kdf(password, this.crypto.kdf.function, this.crypto.kdf.params);
    return SHA256(
      Buffer. concat([decryptionKey.slice(16, 32), this.crypto.cipher.message])
    ).compare(this.crypto.checksum.message) === 0;

  }

  /**
   * Decrypts keystore secret
   * @param password
   */
  public decrypt(password: string): Buffer {

    if(!this.verifyPassword(password)){
      throw new Error("Invalid password");
    }
    const decryptionKey: bytes = kdf(password, this.crypto.kdf.function, this.crypto.kdf.params);
    const cipher = AES_128_CTR(decryptionKey.slice(0, 16), this.crypto.cipher.params.iv);
    let decryptedSecret = cipher.update(this.crypto.cipher.message);
    decryptedSecret = Buffer.concat([decryptedSecret, cipher.final()]);
    return decryptedSecret;
  }


  public toObject(): object {
    return {
      ...this,
      crypto: this.crypto.toObject(),
    };
  }

  public toJSON(): string {
    return JSON.stringify(this.toObject());
  }

}

export class Pbkdf2Keystore extends Keystore {
  constructor(keystore: Partial<IKeystoreParams>) {
    let keystorePbkdf2 = keystore;

    keystorePbkdf2 = deepmerge({
      crypto: {
        kdf: {
          function: "pbkdf2",
          params: new Pbkdf2ModuleParams({}),
        },
        checksum: {
          function: "sha256",
        },
        cipher: {
          function: "aes-128-ctr",
        }
      }
    }, keystorePbkdf2);

    super(keystorePbkdf2);

  }
}

export class ScryptKeystore extends Keystore {
  constructor(keystore: Partial<IKeystoreParams>) {

    let keystoreScrypt = keystore;

    keystoreScrypt = deepmerge({
      crypto: {
        kdf: {
          function: "scrypt",
          params: new ScryptModuleParams({}),
        },
        cipher: {
          function: "aes-128-ctr",
        }
      }
    }, keystoreScrypt);

    super(keystoreScrypt);
  }
}
