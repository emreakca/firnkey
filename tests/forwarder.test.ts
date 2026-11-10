import { describe, expect, it } from "vitest";

import { createAlias } from "../src/shared/forwarder";

function fakeFetch(status: number, body: unknown) {
  const calls: { url: string; init: RequestInit }[] = [];
  const impl = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status });
  }) as unknown as typeof fetch;
  return { calls, impl };
}

describe("email alias forwarders", () => {
  it("creates a SimpleLogin alias for the site", async () => {
    const { calls, impl } = fakeFetch(201, { alias: "random.word@simplelogin.com" });
    await expect(createAlias("simplelogin", "sl-key", { domain: "", website: "shop.example" }, impl)).resolves.toBe("random.word@simplelogin.com");
    expect(calls[0]!.url).toBe("https://app.simplelogin.io/api/alias/random/new?hostname=shop.example");
    expect(calls[0]!.init.headers).toMatchObject({ Authentication: "sl-key" });
    expect(calls[0]!.init.credentials).toBe("omit");
  });

  it("creates an addy.io alias on the chosen domain", async () => {
    const { calls, impl } = fakeFetch(201, { data: { email: "x1y2@anonaddy.me" } });
    await expect(createAlias("addy", "addy-key", { domain: "anonaddy.me" }, impl)).resolves.toBe("x1y2@anonaddy.me");
    expect(calls[0]!.url).toBe("https://app.addy.io/api/v1/aliases");
    expect(calls[0]!.init.headers).toMatchObject({ Authorization: "Bearer addy-key" });
    expect(JSON.parse(String(calls[0]!.init.body))).toMatchObject({ domain: "anonaddy.me" });
  });

  it("explains a rejected key and refuses odd answers", async () => {
    await expect(createAlias("simplelogin", "bad", { domain: "" }, fakeFetch(401, {}).impl)).rejects.toThrow(/API key/);
    await expect(createAlias("addy", "k", { domain: "d" }, fakeFetch(200, { data: { email: "<script>" } }).impl)).rejects.toThrow(/unexpected/);
  });
});
