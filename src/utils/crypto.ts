import * as random from "secure-random";
import { ScryptParams, PBKDF2Params, bytes } from "..";
import { default as SHA256Hash } from "bcrypto/lib/sha256";
import { derive as secryptDerive } from "bcrypto/lib/scrypt";
import { derive as pbkdf2Derive } from "bcrypto/lib/pbkdf2";
import { Cipher } from "bcrypto/lib/cipher";

export const DefaultPBKDF2Params: PBKDF2Params = {
  salt: random.randomBuffer(32), 
  c: 262144,
  dklen: 32,
  prf: "hmac-sha256"
}

export const DefaultScryptParams: ScryptParams = {
  salt: random.randomBuffer(32),
  dklen: 32,
  n: 262144,
  r: 8,
  p: 1
}

export function scrypt(password: string, params: ScryptParams): Buffer{
  return secryptDerive(Buffer.from(password), params.salt, params.n, params.r, params.p, params.dklen);
}

export function PBKDF2(password: string, params: PBKDF2Params): Buffer{
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