import {Aes128ctrModuleParams, KdfModuleParams, IAes128CtrModuleParams} from "./params";
import {bytes, Serializable} from "../../types";

export enum CryptoFunction {
  sha256 = "sha256",
  pbkdf2 = "pbkdf2",
  scrypt = "scrypt",
  "aes-128-ctr" = "aes-128-ctr"
}

export interface IBaseModuleParams {
  function: keyof typeof CryptoFunction;
  message: bytes | string;
}

export interface IKeystoreModuleParams extends IBaseModuleParams {
  params: Partial<KdfModuleParams>;
}
export interface ICipherModuleParams extends IBaseModuleParams {
  params: Partial<IAes128CtrModuleParams>;
}

export interface IBaseModule {
  function: CryptoFunction;
  message: bytes;
}

export interface IKdfModule extends IBaseModule, Serializable {
  params: KdfModuleParams;
}

export interface ICypherModule extends IBaseModule, Serializable {
  params: Aes128ctrModuleParams;
}

export interface IChecksumModule extends IBaseModule, Serializable {
  params: {};
}
