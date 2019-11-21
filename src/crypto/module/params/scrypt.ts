import {bytes} from "../../../types";
import {IScryptModuleParams} from "./types";
import {deepmerge} from "../../../utils/deepmerge";
import {randomBytes} from "../../../utils/crypto";

export const DefaultScryptParams: Partial<IScryptModuleParams> = {
  salt: randomBytes(32),
  dklen: 32,
  n: 262144,
  r: 8,
  p: 1
};

export class ScryptModuleParams implements IScryptModuleParams {
  public readonly salt: bytes;
  public readonly dklen: number;
  public readonly n: number;
  public readonly r: number;
  public readonly p: number;

  constructor(opts: Partial<IScryptModuleParams>) {
    const params: IScryptModuleParams = deepmerge(DefaultScryptParams, opts);
    this.dklen = params.dklen;
    this.salt = params.salt;
    this.n = params.n;
    this.p = params.p;
    this.r = params.r;
  }

  toJSON(): string {
    return JSON.stringify(this.toObject());
  }

  toObject(): object {
    return {
      ...this,
      salt: this.salt.toString("hex")
    };
  }

}
