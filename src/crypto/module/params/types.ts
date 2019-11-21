import {bytes, Serializable} from "../../../types";

export type KdfModuleParams = IScryptModuleParams | IPBKDF2ModuleParams;

export interface IScryptModuleParams extends Serializable {
  dklen: number;
  salt: bytes | string;
  n: number;
  r: number;
  p: number;
}

export interface IPBKDF2ModuleParams extends Serializable {
  salt: bytes | string;
  c: number;
  dklen: number;
  prf: string;
}

export interface IAes128CtrModuleParams extends Serializable {
  iv: bytes | string;
}
