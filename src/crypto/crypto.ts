import {IKeystoreCrypto, IKeystoreCryptoParams} from "./types";
import {CryptoCipher, IChecksumModule, ICypherModule, IKdfModule, KdfModule} from "./module";
import {ChecksumModule} from "./module/checksum";

export class KeystoreCrypto implements IKeystoreCrypto {

  public readonly kdf: IKdfModule;
  public readonly checksum: IChecksumModule;
  public readonly cipher: ICypherModule;

  constructor(params: Partial<IKeystoreCryptoParams>) {
    this.kdf = new KdfModule(params.kdf || {});
    this.checksum = new ChecksumModule(params.checksum || {});
    this.cipher = new CryptoCipher(params.cipher || {});
  }

  toJSON(): string {
    return JSON.stringify(this.toObject());
  }

  toObject(): object {
    return {
      kdf: this.kdf.toObject(),
      checksum: this.checksum.toObject(),
      cipher: this.cipher.toObject()
    };
  }
}
