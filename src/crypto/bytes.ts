const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(value);
}

export function decodeUtf8(value: Uint8Array): string {
  return decoder.decode(value);
}

// Accepts both alphabets, with or without padding.
export function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.fromBase64(value.replace(/-/g, "+").replace(/_/g, "/"));
}

export function concatenate(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(values.reduce((total, value) => total + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

export function equalConstantTime(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index]! ^ right[index]!;
  }
  return difference === 0;
}

export function wipe(value: Uint8Array): void {
  value.fill(0);
}
