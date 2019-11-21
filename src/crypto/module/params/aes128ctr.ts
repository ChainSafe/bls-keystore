import {bytes} from "../../../types";
import {IAes128CtrModuleParams} from "./types";
import {Buffer} from "buffer";

export class Aes128ctrModuleParams implements IAes128CtrModuleParams {

  public readonly iv: bytes;

  constructor(opts: Partial<IAes128CtrModuleParams>) {
    if(typeof opts.iv === "string") {
      opts.iv = Buffer.from(opts.iv, "hex");
    }
    this.iv = opts.iv || Buffer.alloc(0);
  }

  toJSON(): string {
    return JSON.stringify(this.toObject());
  }

  toObject(): object {
    return {
      iv: this.iv.toString("hex")
    };
  }

}
