export interface ServerEnvironment {
  baseUrl: string;
  apiUrl: string;
  identityUrl: string;
  originPattern: string;
}

function isLoopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "[::1]";
}

export function normalizeServerEnvironment(input: string): ServerEnvironment {
  const trimmed = input.trim();
  if (!trimmed) {
    throw new Error("Enter your Vaultwarden server URL.");
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    throw new Error("Enter a valid absolute server URL.");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Only HTTPS server URLs are supported.");
  }

  if (url.protocol === "http:" && !isLoopback(url.hostname)) {
    throw new Error("HTTPS is required unless the server is on localhost.");
  }

  if (url.username || url.password) {
    throw new Error("Server URLs must not contain credentials.");
  }

  if (url.search || url.hash) {
    throw new Error("Server URLs must not contain a query string or fragment.");
  }

  url.pathname = url.pathname.replace(/\/+$/, "");
  const baseUrl = url.toString().replace(/\/$/, "");
  const endpointBase = `${baseUrl}/`;

  return {
    baseUrl,
    apiUrl: new URL("api/", endpointBase).toString().replace(/\/$/, ""),
    identityUrl: new URL("identity/", endpointBase).toString().replace(/\/$/, ""),
    originPattern: `${url.origin}/*`,
  };
}
