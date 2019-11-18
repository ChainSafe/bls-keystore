declare module 'bcrypto/lib/sha256' {
  export default class SHA256 {
  
    public init(): SHA256;
  
    public update(data: Buffer): SHA256;
  
    public final(): Buffer;
    
    static digest(data: Buffer): Buffer;
  }
}

declare module 'bcrypto/lib/random' {
  export function randomBytes(size: number): Buffer;
}

declare module 'bcrypto/lib/hash256' {
  export default class Hash256 {
    public init(): Hash256;
    static digest(data: Buffer): Buffer;
    static mac(data: Buffer, key: Buffer): Buffer;
  }
}

declare module 'bcrypto/lib/scrypt' {
  export function derive(passwd: Buffer | string, salt: Buffer | string, N: number, r: number, p: number, len: number): Buffer;
}

declare module 'bcrypto/lib/pbkdf2' {
  export function derive(hash: Function, pass: Buffer | string, salt: Buffer | string, iter: number, len: number): Buffer;
}

declare module 'bcrypto/lib/cipher' {
  export class Cipher {
    public constructor(name: string);
    public init(key: Buffer, iv: Buffer): Cipher;
    public update(data: Buffer): Buffer;
    public final(): Buffer;
  }
}