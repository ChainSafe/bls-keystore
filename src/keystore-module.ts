import { IKeystoreModule, ScryptParams, PBKDF2Params, bytes } from ".";

export class KeystoreModule implements IKeystoreModule {
  public function = "";
  public params: ScryptParams | PBKDF2Params | any = {};
  public message: bytes = new Buffer("");

  public static fromJson(json: IKeystoreModule): KeystoreModule {
    const keystoreModule = new KeystoreModule();
    keystoreModule.function = json["function"];
    keystoreModule.params = json["params"];
    keystoreModule.message = json["message"];

    return keystoreModule;
  }
}