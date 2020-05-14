/**
 * A Keystore object is broken into several parts:
 *   metadata, kdf, checksum, and cipher
 */
export interface IKeystore {
  version: number;
  uuid: string;
  path: string;
  pubkey: string;
  crypto: {
    kdf: IKdfModule;
    checksum: IChecksumModule;
    cipher: ICipherModule;
  };
}

// kdf

export type IKdfModule = IPbkdf2KdfModule | IScryptKdfModule;

export interface IPbkdf2KdfModule {
  function: "pbkdf2";
  params: {
    dklen: number;
    c: number;
    prf: "hmac-sha256";
    salt: string;
  };
  message: "";
}

export interface IScryptKdfModule {
  function: "scrypt";
  params: {
    dklen: number;
    n: number;
    p: number;
    r: number;
    salt: string;
  };
  message: "";
}

// checksum

export type IChecksumModule = ISha2ChecksumModule;

export interface ISha2ChecksumModule {
  function: "sha256";
  params: {};
  message: string;
}

// cipher

export type ICipherModule = IAes128CtrCipherModule;

export interface IAes128CtrCipherModule {
  function: "aes-128-ctr";
  params: {
    iv: string;
  };
  message: string;
}
