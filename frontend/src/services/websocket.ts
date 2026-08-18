export type StreamChannel =
  | "events"
  | "alerts"
  | "incidents"
  | "notifications";

export type WebSocketState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "reconnecting";

export interface WebSocketMessage {
  type?: string;
  channel?: StreamChannel;
  data?: unknown;
  connection_id?: string;
  authentication_required?: boolean;
  code?: string;
  channels?: string[];
  user?: {
    user_id: string;
    username: string;
    roles: string[];
    permissions: string[];
  };
}

const WS_PATH = import.meta.env.VITE_WS_PATH ?? "/api/v1/ws";

function resolveWebSocketUrl(): string {
  const configured = import.meta.env.VITE_WS_BASE_URL;

  if (
    configured
    && (
      configured.startsWith("ws://")
      || configured.startsWith("wss://")
    )
  ) {
    return `${configured.replace(/\/$/, "")}${WS_PATH.startsWith("/") ? WS_PATH : `/${WS_PATH}`}`;
  }

  const protocol = window.location.protocol === "https:"
    ? "wss:"
    : "ws:";

  return `${protocol}//${window.location.host}${WS_PATH.startsWith("/") ? WS_PATH : `/${WS_PATH}`}`;
}

export class SocWebSocket {
  private socket: WebSocket | null = null;

  private reconnectTimer: number | undefined;

  private stopped = false;

  private attempts = 0;

  private authenticationTimer: number | undefined;

  constructor(
    private readonly token: string,
    private readonly channels: StreamChannel[],
    private readonly onMessage: (
      payload: WebSocketMessage,
    ) => void,
    private readonly onState: (
      state: WebSocketState,
    ) => void,
  ) {}

  connect(): void {
    this.stopped = false;
    this.onState(
      this.attempts > 0
        ? "reconnecting"
        : "connecting",
    );

    const url = resolveWebSocketUrl();

    this.socket = new WebSocket(url);

    this.socket.onopen = () => {
      this.attempts = 0;

      this.socket?.send(
        JSON.stringify({
          action: "authenticate",
          token: this.token,
        }),
      );

      this.authenticationTimer = window.setTimeout(() => {
        this.socket?.close(
          1008,
          "authentication timeout",
        );
      }, 10_000);
    };

    this.socket.onmessage = (event) => {
      try {
        const message = JSON.parse(
          event.data,
        ) as WebSocketMessage;

        if (message.type === "authenticated") {
          if (this.authenticationTimer !== undefined) {
            window.clearTimeout(
              this.authenticationTimer,
            );
            this.authenticationTimer = undefined;
          }

          this.socket?.send(
            JSON.stringify({
              action: "subscribe",
              channels: this.channels,
            }),
          );

          this.onState("connected");
        }

        this.onMessage(message);
      } catch {
        // Ignore malformed messages.
      }
    };

    this.socket.onclose = () => {
      if (this.authenticationTimer !== undefined) {
        window.clearTimeout(
          this.authenticationTimer,
        );
        this.authenticationTimer = undefined;
      }

      this.onState("disconnected");
      this.scheduleReconnect();
    };

    this.socket.onerror = () => {
      this.onState(
        "reconnecting",
      );
    };
  }

  disconnect(): void {
    this.stopped = true;

    if (this.reconnectTimer !== undefined) {
      window.clearTimeout(
        this.reconnectTimer,
      );
      this.reconnectTimer = undefined;
    }

    if (this.authenticationTimer !== undefined) {
      window.clearTimeout(
        this.authenticationTimer,
      );
      this.authenticationTimer = undefined;
    }

    this.socket?.close();
    this.socket = null;

    this.onState(
      "disconnected",
    );
  }

  private scheduleReconnect(): void {
    if (
      this.stopped
      || this.reconnectTimer !== undefined
    ) {
      return;
    }

    const delay = Math.min(
      30_000,
      1_000 * 2 ** this.attempts,
    );

    this.attempts += 1;

    this.reconnectTimer = window.setTimeout(
      () => {
        this.reconnectTimer = undefined;
        this.connect();
      },
      delay,
    );
  }
}