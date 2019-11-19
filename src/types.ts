import {Buffer} from "buffer";
import {IKeystoreCrypto, IKeystoreCryptoParams} from "./crypto";

export type bytes = Buffer;

export interface Serializable {
  toJSON(): string;
  toObject(): object;
}

export interface IKeystoreParams {
  crypto: Partial<IKeystoreCryptoParams>;
  pubkey: string;
  path: string;
  uuid: string;
  version: number;
}


export interface IKeystore extends Serializable {
  crypto: IKeystoreCrypto;
  pubkey: string;
  path: string;
  uuid: string;
  version: number;

  decrypt(password: string): Buffer;
  verifyPassword(password: string): boolean;
}
