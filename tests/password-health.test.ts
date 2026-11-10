import { expect, it, vi } from "vitest";
import { healthReport, isWeakPassword } from "../src/vault/password-health";
import { breachCount } from "../src/shared/breach";
import type { VaultItem } from "../src/vault/models";

it("flags short, simple, repetitive and name-based passwords, not long random ones", () => {
  for (const weak of ["hunter2", "password123", "aaaaaaaaaaaa", "12345678901234", "abcdefghijk1", "Anna1990!x", "qwertzuiopasd"]) {
    expect(isWeakPassword(weak, ["anna@example.com"]), weak).toBe(true);
  }
  for (const strong of ["v9#Lq2!xT7@pRw4z", "correct-horse-battery-staple-lamp", "Tq8&zM3$wK"]) {
    expect(isWeakPassword(strong, ["anna@example.com"]), strong).toBe(false);
  }
});

it("reports reused and exposed passwords, and how many logins were checked", () => {
  const login = (id: string, password: string) =>
    ({ id, type: 1, name: id, username: "me", password, favorite: false, reprompt: false, editable: true, uris: [] }) as VaultItem;
  const report = healthReport([login("a", "Shared-Secret-91x!"), login("b", "Shared-Secret-91x!"), login("c", "pass"), login("d", "")], new Map([["c", 42]]));
  expect(report.reused.map((entry) => [entry.id, entry.count])).toEqual([["a", 2], ["b", 2]]);
  expect(report.exposed).toEqual([{ id: "c", name: "c", username: "me", count: 42 }]);
  expect(report.weak.map((entry) => entry.id)).toEqual(["c"]);
  expect([report.breachChecked, report.logins]).toEqual([1, 3]);
});

it("sends only a five-character hash prefix and reads the matching count, ignoring padding", async () => {
  // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
  const fetchMock = vi.fn(async (_url: string, _init: RequestInit) => new Response("0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365\r\n"));
  expect(await breachCount("password", fetchMock as unknown as typeof fetch)).toBe(9659365);
  const [url, init] = fetchMock.mock.calls[0]!;
  expect(url).toBe("https://api.pwnedpasswords.com/range/5BAA6");
  expect(init.headers).toEqual({ "Add-Padding": "true" });
  expect(await breachCount("not in the list", fetchMock as unknown as typeof fetch)).toBe(0);
});
