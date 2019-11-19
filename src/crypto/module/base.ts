import {Buffer} from "buffer";
import {bytes} from "../../types";
import {CryptoFunction, IBaseModuleParams} from "./types";
import assert from "assert";

export class BaseModule {
  public readonly function: CryptoFunction;
  public readonly message: bytes;

  constructor(params: Partial<IBaseModuleParams>){
    // @ts-ignore
    this.function = CryptoFunction[params.function];
    assert(!!this.function, "Unsupported crypto function");
    this.message = params.message || Buffer.alloc(0);
  }

  toJSON(): string {
    return JSON.stringify(this.toObject())
  }

  toObject(): object {
    return {
      function: this.function,
      message: this.message.toString("hex")
    };
  }
}
