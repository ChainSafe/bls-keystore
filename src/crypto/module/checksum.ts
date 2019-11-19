import {CryptoFunction, IBaseModuleParams, IChecksumModule} from "./types";
import {BaseModule} from "./base";

export class ChecksumModule extends BaseModule implements IChecksumModule {

  public readonly params: {};

  constructor(params: Partial<IBaseModuleParams>){
    params.function = params.function || CryptoFunction.sha256;
    super(params);
    this.params = {};
  }

  toObject(): object {
    return {
      ...super.toObject(),
      params: {},
    };
  }

}
