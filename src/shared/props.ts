// Server JSON uses PascalCase or camelCase keys depending on the server version, so lookups try both.
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

// `name` is the PascalCase key; the camelCase one is derived from it.
export function prop(source: Record<string, unknown>, name: string): unknown {
  return source[name] ?? source[name[0]!.toLowerCase() + name.slice(1)];
}

export function stringProp(source: Record<string, unknown>, name: string): string | undefined {
  const value = prop(source, name);
  return typeof value === "string" ? value : undefined;
}

export function numberProp(source: Record<string, unknown>, name: string): number | undefined {
  const value = prop(source, name);
  return typeof value === "number" ? value : undefined;
}

export function recordProp(source: Record<string, unknown>, name: string): Record<string, unknown> | undefined {
  return asRecord(prop(source, name));
}

export function arrayProp(source: Record<string, unknown>, name: string): unknown[] {
  const value = prop(source, name);
  return Array.isArray(value) ? value : [];
}
