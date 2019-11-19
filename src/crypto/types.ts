import {
  IBaseModuleParams,
  IChecksumModule,
  ICipherModuleParams,
  ICypherModule,
  IKdfModule,
  IKeystoreModuleParams
} from "./module";
import {Serializable} from "../types";

export interface IKeystoreCrypto extends Serializable{
  kdf: IKdfModule;
  checksum: IChecksumModule;
  cipher: ICypherModule;
}

export interface IKeystoreCryptoParams {
  kdf: Partial<IKeystoreModuleParams>;
  checksum: Partial<IBaseModuleParams>
  cipher: Partial<ICipherModuleParams>;
}
