import { Server } from "socket.io";
import { type Server as HttpServer } from "http";
import { expressLogger } from "./logger.js";
import { config } from "./config.js";
import { logEmitter } from "./log-events.js";
import { verifyAuthToken } from "./auth.js";
import { AUTH_COOKIE_NAME, parseCookies } from "./security.js";

let io: Server | undefined;

export function setupSocketIO(httpServer: HttpServer) {
  if (!io) {
    io = new Server({
      path: `${config.server.basePath}/socket.io/`,
      cors: {
        origin:
          config.server.allowedOrigins.length === 1 && config.server.allowedOrigins[0] === "*"
            ? "*"
            : config.server.allowedOrigins,
        methods: ["GET", "POST"],
      },
    });

    // Every event on this server (live logs, notifications, download and
    // import progress) belongs to a signed-in user, so the handshake has to
    // carry the same credential the REST API accepts: the httpOnly auth
    // cookie a browser sends automatically, or a bearer token for a session
    // still on the legacy localStorage flow.
    io.use(async (socket, next) => {
      const token = getHandshakeToken(socket.handshake);
      const user = token ? await verifyAuthToken(token) : undefined;
      if (!user) {
        return next(new Error("Authentication required"));
      }
      socket.data.userId = user.id;
      return next();
    });

    io.on("connection", (socket) => {
      expressLogger.info({ socketId: socket.id }, "Client connected to WebSocket");

      socket.on("disconnect", () => {
        expressLogger.info({ socketId: socket.id }, "Client disconnected from WebSocket");
      });
    });

    logEmitter.on("line", (line: string) => {
      io!.emit("logLine", line);
    });
  }

  io.attach(httpServer);

  return io;
}

interface HandshakeLike {
  auth: Record<string, unknown>;
  headers: Record<string, string | string[] | undefined>;
}

function getHandshakeToken(handshake: HandshakeLike): string | undefined {
  const authToken = handshake.auth["token"];
  if (typeof authToken === "string" && authToken) {
    return authToken;
  }

  const authHeader = handshake.headers["authorization"];
  if (typeof authHeader === "string") {
    const [scheme, ...rest] = authHeader.split(" ");
    const bearerToken = rest.join(" ");
    if (scheme?.toLowerCase() === "bearer" && bearerToken) {
      return bearerToken;
    }
  }

  const cookieHeader = handshake.headers["cookie"];
  return parseCookies(typeof cookieHeader === "string" ? cookieHeader : undefined)[
    AUTH_COOKIE_NAME
  ];
}

export function getIO() {
  if (!io) {
    throw new Error("Socket.IO not initialized!");
  }
  return io;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function notifyUser(type: string, payload: any) {
  if (io) {
    io.emit(type, payload);
  }
}
