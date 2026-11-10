// Have I Been Pwned's password range API (k-anonymity): only the first five hex digits of the
// password's SHA-1 hash are sent; the answer lists every breached hash with that prefix, padded with
// fake entries so its size does not give the password away. The password never leaves the browser.
export const BREACH_ORIGIN = "https://api.pwnedpasswords.com/*";

export async function breachCount(password: string, fetchImpl: typeof fetch = fetch): Promise<number> {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-1", new TextEncoder().encode(password))).toHex().toUpperCase();
  const response = await fetchImpl(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
    headers: { "Add-Padding": "true" },
    credentials: "omit",
    referrerPolicy: "no-referrer",
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`The breach check failed with HTTP ${response.status}.`);
  const suffix = hash.slice(5);
  for (const line of (await response.text()).split("\n")) {
    const [candidate, count] = line.trim().split(":");
    if (candidate === suffix) return Number(count) || 0; // Padding entries have a count of 0.
  }
  return 0;
}
