import uuid from "uuid";
import { scrypt, ScryptParams, PBKDF2Params, PBKDF2, DefaultPBKDF2Params, AES_128_CTR, SHA256, DefaultScryptParams } from "./utils/crypto";
import {bytes} from "@chainsafe/eth2.0-types";
import { randomBytes } from "crypto";
import {PublicKey, PrivateKey} from "@chainsafe/bls";

export interface IKeystoreModule{
  function: string;
  params: ScryptParams | PBKDF2Params | any;
  message: bytes;
}

export class KeystoreModule implements IKeystoreModule {
  public function = "";
  public params: ScryptParams | PBKDF2Params | any = {};
  public message: bytes = new Buffer("");

  public static fromJson(json: IKeystoreModule): KeystoreModule {
    const keystoreModule = new KeystoreModule();
    keystoreModule.function = json["function"];
    keystoreModule.params = json["params"];
    keystoreModule.message = json["message"];

    return keystoreModule;
  }
}

export interface IKeystoreCrypto{
  kdf: IKeystoreModule;
  checksum: IKeystoreModule;
  cipher: IKeystoreModule;
}

export class KeystoreCrypto implements IKeystoreCrypto {

  public kdf: IKeystoreModule = new KeystoreModule();
  public checksum: IKeystoreModule = new KeystoreModule();
  public cipher: IKeystoreModule = new KeystoreModule();

  public static fromJson(json: IKeystoreCrypto): KeystoreCrypto {
    const keystoreCrypto = new KeystoreCrypto();

    keystoreCrypto.kdf = KeystoreModule.fromJson(json["kdf"]);
    keystoreCrypto.checksum = KeystoreModule.fromJson(json["checksum"]);
    keystoreCrypto.cipher = KeystoreModule.fromJson(json["cipher"]);

    return keystoreCrypto;
  }
}

export interface IKeystore{
  crypto: IKeystoreCrypto;
  pubkey: string;
  path: string;
  uuid: string;
  version: number;

  decrypt(password: string): Buffer;
}

export class Keystore implements IKeystore {
  public crypto: IKeystoreCrypto = new KeystoreCrypto();
  public pubkey = "";
  public path = "";
  public uuid: string = uuid.v4();
  public version = 0;

  private kdf(password: string, args: object): Buffer{
    if(this.crypto.kdf.function === "scrypt"){
      return scrypt(password, args as ScryptParams);
    }else{
      return PBKDF2(password, args as PBKDF2Params);
    }
    // else if(this.crypto.kdf.function === "pbkdf2"){
    //     return PBKDF2(password, <PBKDF2Params> args);
    // }
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

  public static encrypt(secret: bytes, password: string, path = "", kdfSalt: bytes = randomBytes(32), aesIv: bytes = randomBytes(16)): IKeystore {
    const keystore = new this();

    keystore.crypto.kdf.params.salt = kdfSalt;
    const decryptionKey: bytes = keystore.kdf(password, keystore.crypto.kdf.params);
    keystore.crypto.cipher.params.iv = aesIv;
    const cipher = AES_128_CTR(decryptionKey.slice(0, 16), keystore.crypto.cipher.params.iv);
        
    let encryptedSecret = cipher.update(secret);
    encryptedSecret = Buffer.concat([encryptedSecret, cipher.final()]);
        
    keystore.crypto.cipher.message = Buffer.from(encryptedSecret);
    keystore.crypto.checksum.message = SHA256(Buffer.concat([decryptionKey.slice(16, 32), keystore.crypto.cipher.message]));
        
    keystore.pubkey = PublicKey.fromPrivateKey(PrivateKey.fromBytes(secret)).toHexString().substring(2);
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
  constructor(){
    super();
    this.crypto.kdf.function = "pbkdf2";
    this.crypto.kdf.params = DefaultPBKDF2Params;
    this.crypto.checksum.function = "sha256";
    this.crypto.cipher.function = "aes-128-ctr"
  }
}

export class ScryptKeystore extends Keystore {
  constructor(){
    super();
    this.crypto.kdf.function = "scrypt";
    this.crypto.kdf.params = DefaultScryptParams;
    this.crypto.checksum.function = "sha256";
    this.crypto.cipher.function = "aes-128-ctr"
  }
}