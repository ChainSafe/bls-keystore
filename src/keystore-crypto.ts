import { IKeystoreModule, IKeystoreCrypto, IKeystoreCryptoParams } from ".";
import { KeystoreModule } from "./keystore-module";

export class KeystoreCrypto implements IKeystoreCrypto {

  public readonly kdf: IKeystoreModule = new KeystoreModule();
  public readonly checksum: IKeystoreModule = new KeystoreModule({});
  public readonly cipher: IKeystoreModule = new KeystoreModule({});

  constructor(params?: IKeystoreCryptoParams) {
    if(params){
      this.kdf = new KeystoreModule(params.kdf); 
      this.checksum = new KeystoreModule(params.checksum);
      this.cipher = new KeystoreModule(params.cipher);
    }
  }
}