import {Aes128ctrModuleParams, IAes128CtrModuleParams} from "./params";
import {CryptoFunction, ICipherModuleParams, ICypherModule} from "./types";
import {BaseModule} from "./base";
import assert from "assert";

export class CryptoCipher extends BaseModule implements ICypherModule {

  public readonly params: Aes128ctrModuleParams;

  constructor(params: Partial<ICipherModuleParams>){
    params.function = params.function || CryptoFunction["aes-128-ctr"];
    assert(params.function === CryptoFunction["aes-128-ctr"], `Only ${CryptoFunction["aes-128-ctr"]} is supported in cypher`);
    super(params);
    this.params = new Aes128ctrModuleParams(params.params || {});
  }

  toObject(): object {
    return {
      ...super.toObject(),
      params: this.params.toObject(),
    };
  }

}
