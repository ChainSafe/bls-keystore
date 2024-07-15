/** Is in nodejs environment */
export const isNode =
  typeof process !== "undefined" &&
  process.versions != null &&
  process.versions.node != null;

/** Is in environment with web crypto */
export const hasWebCrypto = globalThis?.crypto?.subtle != null;
