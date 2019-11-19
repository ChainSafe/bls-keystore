import merge from "deepmerge";

const isMergeableObject = (object: object): boolean => {
  const stringValue = Object.prototype.toString.call(object);
  const isSpecial = stringValue === '[object RegExp]' || stringValue === '[object Date]' || stringValue === '[object Uint8Array]'

  return object && typeof object === 'object' && !isSpecial;
};

export function deepmerge<T>(source: any, target: any): T{
  return merge(source, target, {isMergeableObject: isMergeableObject});
}
