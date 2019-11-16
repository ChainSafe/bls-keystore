import { IKeystoreModule, ScryptParams, PBKDF2Params, bytes, IKeystoreModuleParams } from ".";
import { Buffer } from "buffer";

export class KeystoreModule implements IKeystoreModule {
  public readonly function: string = "";
  public readonly params: ScryptParams | PBKDF2Params | {[key: string]: any} = {};
  public readonly message: bytes = new Buffer("");

  constructor(params?: IKeystoreModuleParams){
    if(params){
      this.function = params.function || "";
      this.params = params.params || {};
      this.message = params.message || new Buffer("");
    }
  }
}