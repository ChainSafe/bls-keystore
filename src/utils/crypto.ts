import { scryptSync, pbkdf2Sync, createCipheriv, createHash, Cipher } from "crypto";
import { bytes } from "@chainsafe/eth2.0-types";
// @ts-ignore
import secureRandom from "secure-random";
import { ScryptParams, PBKDF2Params } from "..";

export const DefaultPBKDF2Params: PBKDF2Params = {
  salt: secureRandom(32, {type: "Buffer"}), 
  c: 262144,
  dklen: 32,
  prf: "hmac-sha256"
}

export const DefaultScryptParams: ScryptParams = {
  salt: secureRandom(32, {type: "Buffer"}),
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