import {Keystore as _validateKeystoreGenerated} from "./schema-validation-generated";

import { IKeystore } from "./types";

type ErrorObject = {
  instancePath: string;
  schemaPath: string;
  keyword: string;
  params: object;
  message: string;
};

// Redeclare generated function with the proper type
const _validateKeystore = _validateKeystoreGenerated as (((data: unknown) => boolean) & {errors: ErrorObject[]});

/**
 * Return schema validation errors for a potential keystore object
 */
// This function wraps the generated code weirdness
export function schemaValidationErrors(data: unknown): ErrorObject[] | null {
  const validated = _validateKeystore(data)
  if (validated) {
    return null;
  }
  return _validateKeystore.errors;
}

/**
 * Validate an unknown object as a valid keystore, throws on invalid keystore
 */
export function validateKeystore(keystore: unknown): asserts keystore is IKeystore {
  const errors = schemaValidationErrors(keystore);
  if (errors) {
    throw new Error(
      errors.map((error) => `${error.instancePath}: ${error.message}`).join('\n')
    );
  }
}

/**
 * Predicate for validating an unknown object as a valid keystore
 */
export function isValidKeystore(keystore: unknown): keystore is IKeystore {
  return !schemaValidationErrors(keystore);
}
