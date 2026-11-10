import { expect, it } from "vitest";
import { decryptSends, encryptSend, encryptSendEdit } from "../src/vault/send";

it("edits a text Send under the same link, and keeps its deletion date and password unless changed", async () => {
  const userKey = crypto.getRandomValues(new Uint8Array(64));
  const { payload } = await encryptSend({ type: 0, name: "Old", text: "first", deletionDays: 7, password: "pw" }, userKey);
  const stored = { ...payload, Id: "s1", AccessId: "a1", Password: payload.password };
  const [before] = await decryptSends([stored], userKey, "https://vault.example.com");
  expect(before).toMatchObject({ name: "Old", text: "first", hidden: false, hasPassword: true });

  const edit = await encryptSendEdit(stored, { name: "New", text: "second", hidden: true }, userKey);
  expect(edit).toMatchObject({ type: 0, key: payload.key, deletionDate: payload.deletionDate, password: null, file: null });
  const [after] = await decryptSends([{ ...stored, ...edit, Id: "s1", AccessId: "a1" }], userKey, "https://vault.example.com");
  expect(after).toMatchObject({ name: "New", text: "second", hidden: true, link: before!.link });

  const later = await encryptSendEdit(stored, { name: "New", text: "second", deletionDays: 1 }, userKey);
  expect(Date.parse(later.deletionDate as string)).toBeLessThan(Date.parse(payload.deletionDate as string));
  await expect(encryptSendEdit(stored, { name: "New", text: "" }, userKey)).rejects.toThrow("Enter the text");
});
