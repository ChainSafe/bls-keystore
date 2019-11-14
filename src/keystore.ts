import uuid from "uuid";
import { scrypt, PBKDF2, DefaultPBKDF2Params, AES_128_CTR, SHA256, DefaultScryptParams } from "./utils/crypto";
import { PublicKey, PrivateKey } from "@chainsafe/bls";
import * as random from "secure-random";
import { IKeystoreCrypto, ScryptParams, PBKDF2Params, bytes, IKeystore } from ".";
import { KeystoreCrypto } from "./keystore-crypto";

export class Keystore implements IKeystore {
  public crypto: IKeystoreCrypto = new KeystoreCrypto();
  public pubkey = "";
  public path = "";
  public uuid: string = uuid.v4();
  public version = 4;

  private kdf(password: string, args: ScryptParams | PBKDF2Params): Buffer {
    switch(this.crypto.kdf.function){
      case "scrypt":
        return scrypt(password, args as ScryptParams);
      case "pbkdf2":
        return PBKDF2(password, args as PBKDF2Params);
      default:
        throw new Error("Unsupported crypto function");
    }
  }

  public static fromJson(json: IKeystore): Keystore {
    const keystore = new Keystore();
    keystore.crypto = KeystoreCrypto.fromJson(json["crypto"]);
    keystore.path = json["path"];
    keystore.pubkey = json["pubkey"];
    keystore.uuid = json["uuid"];
    keystore.version = json["version"];

    return keystore;
  }

  public static encrypt(secret: bytes, password: string, path = "", kdfSalt: bytes = random.randomBuffer(32), aesIv: bytes = random.randomBuffer(16)): IKeystore {
    const keystore = new this();

    keystore.crypto.kdf.params.salt = kdfSalt;
    const decryptionKey: bytes = keystore.kdf(password, keystore.crypto.kdf.params);
    keystore.crypto.cipher.params.iv = aesIv;
    const cipher = AES_128_CTR(decryptionKey.slice(0, 16), keystore.crypto.cipher.params.iv);

    let encryptedSecret = cipher.update(secret);
    encryptedSecret = Buffer.concat([encryptedSecret, cipher.final()]);

    keystore.crypto.cipher.message = Buffer.from(encryptedSecret);
    keystore.crypto.checksum.message = SHA256(Buffer.concat([decryptionKey.slice(16, 32), keystore.crypto.cipher.message]));

    keystore.pubkey = PublicKey.fromPrivateKey(PrivateKey.fromBytes(secret)).toHexString().replace("0x", "");
    keystore.path = path;

    return keystore;
  }

  public decrypt(password: string): Buffer {

    const decryptionKey: bytes = this.kdf(password, this.crypto.kdf.params);

    const cipher = AES_128_CTR(decryptionKey.slice(0, 16), this.crypto.cipher.params.iv);
    let decryptedSecret = cipher.update(this.crypto.cipher.message);
    decryptedSecret = Buffer.concat([decryptedSecret, cipher.final()]);
    return decryptedSecret;
  }

}

export class Pbkdf2Keystore extends Keystore {
  constructor() {
    super();
    this.crypto.kdf.function = "pbkdf2";
    this.crypto.kdf.params = DefaultPBKDF2Params;
    this.crypto.checksum.function = "sha256";
    this.crypto.cipher.function = "aes-128-ctr"
  }
}

export class ScryptKeystore extends Keystore {
  constructor() {
    super();
    this.crypto.kdf.function = "scrypt";
    this.crypto.kdf.params = DefaultScryptParams;
    this.crypto.checksum.function = "sha256";
    this.crypto.cipher.function = "aes-128-ctr"
  }
}