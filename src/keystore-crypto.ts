import { IKeystoreModule, IKeystoreCrypto } from ".";
import { KeystoreModule } from "./keystore-module";

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