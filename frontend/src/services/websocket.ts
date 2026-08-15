export type StreamChannel = "events" | "alerts" | "incidents" | "notifications";

const WS_BASE = (import.meta.env.VITE_WS_BASE_URL ?? "ws://localhost:8000").replace(/\/$/, "");
const WS_PATH = import.meta.env.VITE_WS_PATH ?? "/ws";

export class SocWebSocket {
  private socket: WebSocket | null = null;
  private reconnectTimer: number | undefined;
  private stopped = false;
  private attempts = 0;

  constructor(
    private readonly channel: StreamChannel,
    private readonly onMessage: (payload: unknown) => void,
    private readonly onState: (connected: boolean) => void,
  ) {}

  connect(): void {
    this.stopped = false;
    this.socket = new WebSocket(`${WS_BASE}${WS_PATH}/${this.channel}`);
    this.socket.onopen = () => {
      this.attempts = 0;
      this.onState(true);
    };
    this.socket.onmessage = (event) => {
      try {
        this.onMessage(JSON.parse(event.data) as unknown);
      } catch {
        // Ignore malformed server payloads; the API remains the source of truth.
      }
    };
    this.socket.onclose = () => {
      this.onState(false);
      this.scheduleReconnect();
    };
    this.socket.onerror = () => this.onState(false);
  }

  disconnect(): void {
    this.stopped = true;
    if (this.reconnectTimer !== undefined) window.clearTimeout(this.reconnectTimer);
    this.socket?.close();
    this.socket = null;
  }

  private scheduleReconnect(): void {
    if (this.stopped || this.reconnectTimer !== undefined) return;
    const delay = Math.min(30_000, 1_000 * 2 ** this.attempts);
    this.attempts += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = undefined;
      this.connect();
    }, delay);
  }
}
