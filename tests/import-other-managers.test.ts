import { describe, expect, it } from "vitest";

import { readZipEntry } from "../src/shared/zip";
import { ItemType } from "../src/vault/models";
import { parseImport, type DeriveKey } from "../src/vault/transfer";

const derive: DeriveKey = () => Promise.reject(new Error("not used"));

const ONE_PUX = {
  accounts: [{
    attrs: { name: "Me" },
    vaults: [{
      attrs: { name: "Personal" },
      items: [
        {
          categoryUuid: "001", favIndex: 1, state: "active",
          overview: { title: "Example", url: "https://example.com", urls: [{ url: "https://example.com" }, { url: "https://login.example.com" }] },
          details: {
            loginFields: [
              { designation: "username", value: "alice", fieldType: "T", name: "email" },
              { designation: "password", value: "hunter2", fieldType: "P", name: "password" },
              { designation: "", value: "", fieldType: "B", name: "submit" },
            ],
            notesPlain: "note",
            sections: [{ fields: [
              { title: "one-time password", id: "TOTP_1", value: { totp: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" } },
              { title: "PIN", id: "pin", value: { concealed: "1234" } },
            ] }],
            passwordHistory: [{ value: "old", time: 1_700_000_000 }],
          },
        },
        {
          categoryUuid: "002", overview: { title: "Visa" },
          details: { sections: [{ fields: [
            { id: "cardholder", title: "cardholder name", value: { string: "Alice" } },
            { id: "ccnum", title: "number", value: { creditCardNumber: "4111111111111111" } },
            { id: "cvv", title: "verification number", value: { concealed: "123" } },
            { id: "expiry", title: "expiry date", value: { monthYear: 202708 } },
          ] }] },
        },
        { categoryUuid: "101", overview: { title: "Bank" }, details: { sections: [{ fields: [{ id: "iban", title: "IBAN", value: { string: "DE00" } }] }] } },
        { categoryUuid: "001", trashed: true, overview: { title: "Gone" }, details: {} },
      ],
    }],
  }],
};

// A ZIP with one entry, stored (method 0) or deflated (method 8).
function zip(name: string, data: Uint8Array<ArrayBuffer>, size = data.length, method = 0): Promise<ArrayBuffer> {
  const file = new TextEncoder().encode(name);
  const local = new Uint8Array(30 + file.length);
  const localView = new DataView(local.buffer);
  localView.setUint32(0, 0x04034b50, true);
  localView.setUint32(18, data.length, true);
  localView.setUint16(8, method, true);
  localView.setUint32(22, size, true);
  localView.setUint16(26, file.length, true);
  local.set(file, 30);
  const central = new Uint8Array(46 + file.length);
  const centralView = new DataView(central.buffer);
  centralView.setUint32(0, 0x02014b50, true);
  centralView.setUint32(20, data.length, true);
  centralView.setUint16(10, method, true);
  centralView.setUint32(24, size, true);
  centralView.setUint16(28, file.length, true);
  central.set(file, 46);
  const end = new Uint8Array(22);
  const endView = new DataView(end.buffer);
  endView.setUint32(0, 0x06054b50, true);
  endView.setUint16(10, 1, true);
  endView.setUint32(16, local.length + data.length, true);
  return new Blob([local, data, central, end]).arrayBuffer();
}

describe("imports from other password managers", () => {
  it("reads a 1Password .1pux archive", async () => {
    const data = new TextEncoder().encode(JSON.stringify(ONE_PUX));
    const deflated = new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new CompressionStream("deflate-raw"))).arrayBuffer());
    const archive = await zip("export.data", deflated, data.length, 8);
    const text = new TextDecoder().decode(await readZipEntry(archive, "export.data", 10_000_000));
    expect(new TextDecoder().decode(await readZipEntry(await zip("export.data", data), "export.data", 10_000_000))).toBe(text);
    await expect(readZipEntry(archive, "missing", 10)).rejects.toThrow(/no missing/);
    await expect(readZipEntry(archive, "export.data", 10)).rejects.toThrow(/too large/);
    const [login, card, bank, ...rest] = await parseImport(text, undefined, derive);
    expect(rest).toHaveLength(0);
    expect(login).toMatchObject({
      type: ItemType.Login, name: "Example", username: "alice", password: "hunter2", favorite: true, folder: "Personal", notes: "note",
      totp: "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
      uris: [{ uri: "https://example.com" }, { uri: "https://login.example.com" }],
      fields: [{ name: "PIN", value: "1234", hidden: true }],
    });
    expect(login!.passwordHistory?.[0]?.password).toBe("old");
    expect(card).toMatchObject({ type: ItemType.Card, card: { cardholderName: "Alice", number: "4111111111111111", code: "123", expMonth: "8", expYear: "2027" } });
    expect(bank).toMatchObject({ type: ItemType.SecureNote, name: "Bank", fields: [{ name: "IBAN", value: "DE00", hidden: false }] });
  });

  it("reads 1Password, KeePassXC and KeePass 1.x CSV exports", async () => {
    const onePassword = await parseImport("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nMail,https://mail.example,bob,pw,,true,false,,hi\n", undefined, derive);
    expect(onePassword[0]).toMatchObject({ name: "Mail", username: "bob", password: "pw", favorite: true, notes: "hi", uris: [{ uri: "https://mail.example" }] });
    const keePassXc = await parseImport('"Group","Title","Username","Password","URL","Notes","TOTP"\n"Root/Email","Mail","bob","pw","https://mail.example","",""\n', undefined, derive);
    expect(keePassXc[0]).toMatchObject({ name: "Mail", folder: "Email", username: "bob" });
    const keePass = await parseImport('"Account","Login Name","Password","Web Site","Comments"\n"Bank","carol","pw2","https://bank.example","memo"\n', undefined, derive);
    expect(keePass[0]).toMatchObject({ name: "Bank", username: "carol", password: "pw2", notes: "memo", uris: [{ uri: "https://bank.example" }] });
  });
});
