const {itBench} = require("@dapplion/benchmark");
const pbkdf2  = require("../vectors/pbkdf2-0.json");
const scrypt  = require("../vectors/scrypt-0.json");
const { create, decrypt, verifyPassword, isValidKeystore, validateKeystore, defaultScryptModule } = require( "../../lib")

describe("Known Test Vectors", function () {
  itBench({
    id: "pbkdf2 / create",
    fn: async () => {
      await create("test", new Uint8Array(32), new Uint8Array(48), "")
    },
  });

  itBench({
    id: "pbkdf2 / verifyPassword",
    fn: async () => {
      await verifyPassword(pbkdf2, pbkdf2.password)
    },
  });

  itBench({
    id: "pbkdf2 / decrypt",
    fn: async () => {
      await decrypt(pbkdf2, pbkdf2.password)
    },
  });

  itBench({
    id: "scrypt / create",
    fn: async () => {
      await create("test", new Uint8Array(32), new Uint8Array(48), "", null, defaultScryptModule())
    },
  });

  itBench({
    id: "scrypt / verifyPassword",
    fn: async () => {
      await verifyPassword(scrypt, scrypt.password)
    },
  });

  itBench({
    id: "scrypt / decrypt",
    fn: async () => {
      await decrypt(scrypt, scrypt.password)
    },
  });
});

