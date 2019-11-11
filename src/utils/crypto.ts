import { scryptSync, pbkdf2Sync, randomBytes, createCipheriv, createHash, Cipher } from "crypto";
import { bytes } from "@chainsafe/eth2.0-types";

export interface ScryptParams {
  dklen: number;
  salt: bytes;
  n: number;
  r: number;
  p: number;
}

export interface PBKDF2Params {
  salt: bytes;
  c: number;
  dklen: number;
  prf: string;
}

export const DefaultPBKDF2Params: PBKDF2Params = {
  salt: randomBytes(32), 
  c: 262144,
  dklen: 32,
  prf: "hmac-sha256"
}

export const DefaultScryptParams: ScryptParams = {
  salt: randomBytes(32),
  dklen: 32,
  n: 262144,
  r: 8,
  p: 1
}

export function scrypt(password: string, params: ScryptParams): Buffer{
  return scryptSync(password, params.salt, params.dklen, {N: params.n, p: params.p, r: params.r, maxmem: Math.pow(2, 32)});
}

export function PBKDF2(password: string, params: PBKDF2Params): Buffer{
  let _hash = "sha512";
  if(params.prf && params.prf.includes("sha256")){
    _hash = "sha256"
  }
  return pbkdf2Sync(password, params.salt, params.c, params.dklen, _hash);
}

export function AES_128_CTR(key: bytes, iv: bytes): Cipher {
  return createCipheriv("aes-128-ctr", key, iv);
}

export function SHA256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}