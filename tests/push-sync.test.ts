import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { PushSync, type PushTarget } from "../src/background/push-sync";

class FakeSocket {
  static OPEN = 1;
  static all: FakeSocket[] = [];
  readyState = 0;
  binaryType = "blob";
  sent: unknown[] = [];
  onopen?: () => void;
  onmessage?: (event: { data: unknown }) => void;
  onclose?: () => void;
  constructor(readonly url: URL) { FakeSocket.all.push(this); }
  send(value: unknown) { this.sent.push(value); }
  close() { this.readyState = 3; this.onclose?.(); }
  open() { this.readyState = 1; this.onopen?.(); }
  receive(bytes: number[]) { this.onmessage?.({ data: new Uint8Array(bytes).buffer }); }
}

let target: PushTarget | null;
const onChange = vi.fn();
beforeEach(() => {
  vi.useFakeTimers();
  vi.stubGlobal("WebSocket", FakeSocket);
  FakeSocket.all = [];
  target = { baseUrl: "https://vault.example.com/sub", email: "a@example.com", accessToken: "tok" };
  onChange.mockClear();
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

it("handshakes, keeps alive, ignores pings and syncs on any other message", async () => {
  const push = new PushSync(async () => target, onChange);
  await push.update();
  await push.update(); // Same account: no second socket.
  const socket = FakeSocket.all[0]!;
  expect(FakeSocket.all).toHaveLength(1);
  expect(socket.url.href).toBe("wss://vault.example.com/sub/notifications/hub?access_token=tok");
  socket.open();
  expect(socket.sent[0]).toBe('{"protocol":"messagepack","version":1}\x1e');
  vi.advanceTimersByTime(20_000);
  expect(socket.sent[1]).toEqual(new Uint8Array([0x02, 0x91, 0x06]));

  socket.receive([0x02, 0x91, 0x06]); // Echoed ping.
  vi.advanceTimersByTime(5_000);
  expect(onChange).not.toHaveBeenCalled();
  expect(push.connected).toBe(false);

  socket.receive([0x7b, 0x7d, 0x1e]); // Handshake reply: catch up.
  socket.receive([0x05, 0x95, 0x01, 0x80, 0xc0, 0xa0]); // An update, coalesced with the above.
  vi.advanceTimersByTime(1_000);
  expect(onChange).toHaveBeenCalledTimes(1);
  expect(push.connected).toBe(true);
});

it("does not connect while offline", async () => {
  vi.stubGlobal("navigator", { onLine: false });
  const push = new PushSync(async () => target, onChange);
  await push.update();
  expect(FakeSocket.all).toHaveLength(0);
  vi.stubGlobal("navigator", { onLine: true });
  await push.update();
  expect(FakeSocket.all).toHaveLength(1);
});

it("follows account changes and sign-out", async () => {
  const push = new PushSync(async () => target, onChange);
  await push.update();
  target = { ...target!, email: "b@example.com" };
  await push.update();
  expect(FakeSocket.all).toHaveLength(2);
  expect(FakeSocket.all[0]!.readyState).toBe(3);
  target = null;
  await push.update();
  expect(FakeSocket.all[1]!.readyState).toBe(3);
  expect(push.connected).toBe(false);
});
