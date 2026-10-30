// Live sync through the server's notifications hub (SignalR over WebSocket, MessagePack protocol),
// as Vaultwarden and Bitwarden serve it at /notifications/hub. Any server message other than a ping
// means something changed, so the vault syncs; the first reply also catches up after a reconnect.
// The one-minute sync alarm stays as the fallback and reconnects after the worker restarts.

const HANDSHAKE = '{"protocol":"messagepack","version":1}\x1e';
// A length-prefixed SignalR ping. Vaultwarden echoes it, and that traffic every 20 seconds is what
// keeps Chrome from stopping the service worker (and the socket with it).
const PING = new Uint8Array([0x02, 0x91, 0x06]);
const KEEP_ALIVE_MS = 20_000;
const SYNC_DELAY_MS = 1_000;

export interface PushTarget {
  baseUrl: string;
  email: string;
  accessToken: string;
}

export class PushSync {
  private socket: WebSocket | null = null;
  private account = "";
  private ready = false;
  private keepAlive: ReturnType<typeof setInterval> | undefined;
  private pending: ReturnType<typeof setTimeout> | undefined;

  constructor(
    private readonly target: () => Promise<PushTarget | null>,
    private readonly onChange: () => void,
  ) {}

  // True once the server answered the handshake on a live socket.
  get connected(): boolean {
    return this.ready && this.socket?.readyState === WebSocket.OPEN;
  }

  // Connects for the signed-in account, or disconnects when there is none or it changed.
  async update(): Promise<void> {
    const target = await this.target().catch(() => null);
    const account = target ? `${target.baseUrl}\n${target.email}` : "";
    if (this.socket && account === this.account) return;
    this.disconnect();
    // Offline, a connect attempt only fails and Chrome logs ERR_INTERNET_DISCONNECTED (uncatchable).
    // The "online" event or the next sync alarm reconnects.
    if (!target || navigator.onLine === false) return;
    const url = new URL(`${target.baseUrl}/notifications/hub`);
    url.protocol = url.protocol === "http:" ? "ws:" : "wss:";
    // Browsers cannot set headers on a WebSocket; the hub takes the token as a query parameter.
    url.searchParams.set("access_token", target.accessToken);
    const socket = new WebSocket(url);
    socket.binaryType = "arraybuffer";
    this.socket = socket;
    this.account = account;
    socket.onopen = () => {
      socket.send(HANDSHAKE);
      this.keepAlive = setInterval(() => socket.readyState === WebSocket.OPEN && socket.send(PING), KEEP_ALIVE_MS);
    };
    socket.onmessage = (event: MessageEvent) => {
      const data = typeof event.data === "string" ? new TextEncoder().encode(event.data) : new Uint8Array(event.data as ArrayBuffer);
      if (data.length === PING.length && data.every((byte, index) => byte === PING[index])) return;
      this.ready = true;
      clearTimeout(this.pending);
      this.pending = setTimeout(this.onChange, SYNC_DELAY_MS); // Coalesce bursts, such as a bulk move.
    };
    socket.onclose = () => {
      if (this.socket === socket) this.disconnect();
    };
  }

  disconnect(): void {
    const socket = this.socket;
    this.socket = null;
    this.account = "";
    this.ready = false;
    clearInterval(this.keepAlive);
    clearTimeout(this.pending);
    if (socket && socket.readyState <= WebSocket.OPEN) socket.close();
  }
}
