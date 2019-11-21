import {bytes} from "../../../types";
import {IPBKDF2ModuleParams} from "./types";
import {deepmerge} from "../../../utils/deepmerge";
import {randomBytes} from "../../../utils/crypto";
import {Buffer} from "buffer";

export const DefaultPBKDF2Params: Partial<IPBKDF2ModuleParams> = {
  salt: randomBytes(32),
  c: 262144,
  dklen: 32,
  prf: "hmac-sha256"
};

export class Pbkdf2ModuleParams implements IPBKDF2ModuleParams {
  public readonly c: number;
  public readonly dklen: number;
  public readonly prf: string;
  public readonly salt: bytes;

  constructor(opts: Partial<IPBKDF2ModuleParams>) {
    const params: IPBKDF2ModuleParams = deepmerge(DefaultPBKDF2Params, opts);
    this.c = params.c;
    this.dklen = params.dklen;
    this.prf = params.prf;
    if(typeof params.salt === "string") {
      params.salt = Buffer.from(params.salt, "hex");
    }
    this.salt = params.salt;
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
