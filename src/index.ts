export type bytes = Buffer;

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
export interface IKeystoreModule {
    function: string;
    params: ScryptParams | PBKDF2Params | any;
    message: bytes;
}

export interface IKeystoreCrypto {
    kdf: IKeystoreModule;
    checksum: IKeystoreModule;
    cipher: IKeystoreModule;
}
export interface IKeystore{
    crypto: IKeystoreCrypto;
    pubkey: string;
    path: string;
    uuid: string;
    version: number;
  
    decrypt(password: string): Buffer;
  }