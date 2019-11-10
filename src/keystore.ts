import uuid from "uuid";
import { scrypt, ScryptParams, PBKDF2Params, PBKDF2, DefaultPBKDF2Params, AES_128_CTR, SHA256 } from "./utils/crypto";
import {bytes} from "@chainsafe/eth2.0-types";
import { randomBytes } from "crypto";

export interface IKeystoreModule{
    function: string,
    params: ScryptParams | PBKDF2Params | any,
    message: bytes
}

export class KeystoreModule implements IKeystoreModule {
    public function: string = "";
    public params: ScryptParams | PBKDF2Params | any = DefaultPBKDF2Params;
    public message: bytes = new Buffer("");

    public static fromJson(json: IKeystoreModule): KeystoreModule {
        let keystoreModule = new KeystoreModule();
        keystoreModule.function = json["function"];
        keystoreModule.params = json["params"];
        keystoreModule.message = json["message"];

        return keystoreModule;
    }
}

export interface IKeystoreCrypto{
    kdf: IKeystoreModule,
    checksum: IKeystoreModule,
    cipher: IKeystoreModule
}

export class KeystoreCrypto implements IKeystoreCrypto {

    public kdf: IKeystoreModule = new KeystoreModule();
    public checksum: IKeystoreModule = new KeystoreModule();
    public cipher: IKeystoreModule = new KeystoreModule();

    public static fromJson(json: IKeystoreCrypto): KeystoreCrypto {
        let keystoreCrypto = new KeystoreCrypto();

        keystoreCrypto.kdf = KeystoreModule.fromJson(json["kdf"]);
        keystoreCrypto.checksum = KeystoreModule.fromJson(json["checksum"]);
        keystoreCrypto.cipher = KeystoreModule.fromJson(json["cipher"]);

        return keystoreCrypto;
    }

}

export interface IKeystore{
    crypto: IKeystoreCrypto,
    pubkey: string,
    path: string,
    uuid: string,
    version: number
}

export class Keystore implements IKeystore {
    public crypto: IKeystoreCrypto = new KeystoreCrypto();
    public pubkey: string = "";
    public path: string = "";
    public uuid: string = uuid.v4();
    public version: number = 0;

    private kdf(password: string, args: object): Buffer{
        if(this.crypto.kdf.function === "scrypt"){
            return scrypt(password, <ScryptParams> args);
        }else{
            return PBKDF2(password, <PBKDF2Params> args);
        }
        // else if(this.crypto.kdf.function === "pbkdf2"){
        //     return PBKDF2(password, <PBKDF2Params> args);
        // }
    }

    public static fromJson(json: IKeystore): Keystore {
        let keystore = new Keystore();
        keystore.crypto = KeystoreCrypto.fromJson(json["crypto"]);
        keystore.path = json["path"];
        keystore.pubkey = json["pubkey"];
        keystore.uuid = json["uuid"];
        keystore.version = json["version"];

        return keystore;
    }

    public static encrypt(secret: bytes, password: string, path: string = "", kdfSalt: bytes = randomBytes(32), aesIv: bytes = randomBytes(16)): IKeystore {
        let keystore = new Keystore();

        keystore.crypto.kdf.params.salt = kdfSalt;
        const decryptionKey: bytes = keystore.kdf(password, keystore.crypto.kdf.params);
        keystore.crypto.cipher.params.iv = aesIv;
        const cipher = AES_128_CTR(decryptionKey.slice(0, 16), keystore.crypto.cipher.params.iv);
        cipher.update(secret);
        const encryptedSecret = cipher.final();
        keystore.crypto.cipher.message = encryptedSecret;
        keystore.crypto.checksum.message = SHA256(Buffer.concat([decryptionKey.slice(16, 32), keystore.crypto.cipher.message]));
        
        keystore.path = path
        return keystore;
    }

}