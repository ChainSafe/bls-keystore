import {bytes} from "..";
import {default as SHA256Hash} from "bcrypto/lib/sha256";
import {derive as secryptDerive} from "bcrypto/lib/scrypt";
import {derive as pbkdf2Derive} from "bcrypto/lib/pbkdf2";
import {Cipher} from "bcrypto/lib/cipher";
import {IPBKDF2ModuleParams, IScryptModuleParams, KdfModuleParams} from "../crypto/module/params";
import {Buffer} from "buffer";
import {CryptoFunction} from "../crypto/module";

export function scrypt(password: string, params: IScryptModuleParams): Buffer{
  return secryptDerive(Buffer.from(password), params.salt, params.n, params.r, params.p, params.dklen);
}

export function PBKDF2(password: string, params: IPBKDF2ModuleParams): Buffer{
  const _hash: Function = SHA256Hash;
  if(params.prf && params.prf.includes("sha512")){
    throw new Error("SHA512 Hash Function not implemented");
  }
  return pbkdf2Derive(_hash, Buffer.from(password), params.salt, params.c, params.dklen);
}

export function AES_128_CTR(key: bytes, iv: bytes): Cipher {
  return new Cipher("AES-128-CTR").init(key, iv);
}

export function SHA256(data: Buffer): Buffer {
  return SHA256Hash.digest(data);
}

export function kdf(password: string, func: CryptoFunction, args: KdfModuleParams): bytes {
  switch(func){
    case CryptoFunction.scrypt:
      return scrypt(password, args as IScryptModuleParams);
    case CryptoFunction.pbkdf2:
      return PBKDF2(password, args as IPBKDF2ModuleParams);
    default:
      throw new Error("Unsupported crypto function");
  }
}

export function randomBytes(length: number): Buffer {
  //electron replaces openssl with boressl which causes incompatibilities with randomness
  if(process && process.env.ELECTRON) {
    return require("bcrypto/lib/node/random").randomBytes(length);
  } else {
    return require("bcrypto/lib/random").randomBytes(length);
  }
}
