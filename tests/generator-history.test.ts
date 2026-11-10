import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  addGeneratorHistory,
  clearGeneratorHistory,
  GENERATOR_HISTORY_LIMIT,
  generatorSite,
  readGeneratorHistory,
} from "../src/shared/generator-history";

const key = crypto.getRandomValues(new Uint8Array(64));
const otherKey = crypto.getRandomValues(new Uint8Array(64));
let stored: Record<string, unknown>;

beforeEach(() => {
  stored = {};
  vi.stubGlobal("chrome", {
    storage: {
      local: {
        get: async (name: string) => (name in stored ? { [name]: stored[name] } : {}),
        set: async (values: Record<string, unknown>) => { Object.assign(stored, structuredClone(values)); },
      },
    },
  });
});
afterEach(() => vi.unstubAllGlobals());

it("keeps generated passwords encrypted, newest first, per account, with the site", async () => {
  await addGeneratorHistory("a", key, "first-secret", "github.com");
  await addGeneratorHistory("a", key, "second-secret");
  await addGeneratorHistory("a", key, "second-secret", "example.com"); // Copy, then use: one entry.
  await addGeneratorHistory("b", otherKey, "other-account");

  expect(JSON.stringify(stored)).not.toContain("secret");
  expect(JSON.stringify(stored)).not.toContain("github.com");
  const history = await readGeneratorHistory("a", key);
  expect(history.map((entry) => [entry.password, entry.site])).toEqual([
    ["second-secret", "example.com"],
    ["first-secret", "github.com"],
  ]);
  expect(await readGeneratorHistory("a", otherKey)).toEqual([]); // Wrong key reads as empty.
  expect((await readGeneratorHistory("b", otherKey))[0]?.password).toBe("other-account");

  await clearGeneratorHistory("a");
  expect(await readGeneratorHistory("a", key)).toEqual([]);
  expect(await readGeneratorHistory("b", otherKey)).toHaveLength(1);
});

it("caps the history", async () => {
  for (let index = 0; index <= GENERATOR_HISTORY_LIMIT; index += 1) await addGeneratorHistory("a", key, `p${index}`);
  const history = await readGeneratorHistory("a", key);
  expect(history).toHaveLength(GENERATOR_HISTORY_LIMIT);
  expect(history[0]?.password).toBe(`p${GENERATOR_HISTORY_LIMIT}`);
});

it("records only web page hosts as the site", () => {
  expect(generatorSite("https://accounts.example.com/signup?x=1")).toBe("accounts.example.com");
  expect(generatorSite("chrome://extensions")).toBeUndefined();
  expect(generatorSite("not a url")).toBeUndefined();
  expect(generatorSite(undefined)).toBeUndefined();
});
