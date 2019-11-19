import {KdfModuleParams, Pbkdf2ModuleParams, ScryptModuleParams} from "./params";
import {IKdfModule, IKeystoreModuleParams} from "./types";
import {BaseModule} from "./base";

export class KdfModule extends BaseModule implements IKdfModule {

  public readonly params: KdfModuleParams;

  constructor(params: Partial<IKeystoreModuleParams>){
    super(params);
    switch (params.function) {
      case "scrypt": {
        this.params = new ScryptModuleParams(params.params || {})
      } break;
      case "pbkdf2": {
        this.params = new Pbkdf2ModuleParams(params.params || {});
      } break;
      default: {
        throw new Error("Unsupported kdf function")
      }
    }
  }

  toObject(): object {
    return {
      ...super.toObject(),
      params: this.params.toObject(),
    };
  }
}
