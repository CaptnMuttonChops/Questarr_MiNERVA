import crypto from "node:crypto";
import net from "node:net";
import path from "node:path";
import fs from "fs-extra";
import { logger } from "./logger.js";
import { safeFetch, resolveSafeAddress, normalizeHostname } from "./ssrf.js";

const securityScanLogger = logger.child({ module: "security-scan" });

const VT_LOOKUP_TIMEOUT_MS = 10_000;
const CLAMAV_CONNECT_TIMEOUT_MS = 10_000;
const CLAMAV_CHUNK_SIZE = 64 * 1024;

export interface VirusTotalSettings {
  enabled: boolean;
  apiKey: string | null;
  threshold: number;
  blockUnknownHashes: boolean;
}

export interface ClamAvSettings {
  enabled: boolean;
  host: string | null;
  port: number;
}

export type ScanVerdictSource = "virustotal" | "clamav";

export interface ScanResult {
  blocked: boolean;
  source?: ScanVerdictSource;
  reason?: string;
  hash?: string;
}

interface SystemConfigReader {
  getSystemConfig(key: string): Promise<string | undefined>;
}

function toBool(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  return value === "true";
}

function toInt(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export async function readVirusTotalSettings(
  storage: SystemConfigReader
): Promise<VirusTotalSettings> {
  const [enabled, apiKey, threshold, blockUnknown] = await Promise.all([
    storage.getSystemConfig("security.vt.enabled"),
    storage.getSystemConfig("security.vt.apiKey"),
    storage.getSystemConfig("security.vt.threshold"),
    storage.getSystemConfig("security.vt.blockUnknownHashes"),
  ]);

  return {
    enabled: toBool(enabled, false),
    apiKey: apiKey?.trim() || null,
    threshold: toInt(threshold, 2),
    blockUnknownHashes: toBool(blockUnknown, false),
  };
}

export async function readClamAvSettings(storage: SystemConfigReader): Promise<ClamAvSettings> {
  const [enabled, host, port] = await Promise.all([
    storage.getSystemConfig("security.clamav.enabled"),
    storage.getSystemConfig("security.clamav.host"),
    storage.getSystemConfig("security.clamav.port"),
  ]);

  return {
    enabled: toBool(enabled, false),
    host: host?.trim() || null,
    port: toInt(port, 3310),
  };
}

/** Streaming SHA-256 of a single file's contents, without loading it into memory. */
export async function computeFileSha256(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("error", reject);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

/**
 * Picks the "primary" artifact to hash when the download is a directory rather
 * than a single file: the largest file, on the assumption that installers/archives
 * dwarf any accompanying readme/nfo/sample files. Matches the task's framing of
 * "the downloaded archive or primary installer executable".
 */
async function resolvePrimaryFile(localPath: string): Promise<string | null> {
  const stat = await fs.stat(localPath).catch(() => null);
  if (!stat) return null;
  if (stat.isFile()) return localPath;
  if (!stat.isDirectory()) return null;

  let largest: { file: string; size: number } | null = null;
  const walk = async (dir: string): Promise<void> => {
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const entryPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(entryPath);
      } else if (entry.isFile()) {
        const entryStat = await fs.stat(entryPath).catch(() => null);
        if (entryStat && (!largest || entryStat.size > largest.size)) {
          largest = { file: entryPath, size: entryStat.size };
        }
      }
    }
  };
  await walk(localPath);
  return largest ? (largest as { file: string; size: number }).file : null;
}

async function listAllFiles(localPath: string): Promise<string[]> {
  const stat = await fs.stat(localPath).catch(() => null);
  if (!stat) return [];
  if (stat.isFile()) return [localPath];
  if (!stat.isDirectory()) return [];

  const files: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    const entries = await fs.readdir(dir, { withFileTypes: true }).catch(() => []);
    for (const entry of entries) {
      const entryPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(entryPath);
      } else if (entry.isFile()) {
        files.push(entryPath);
      }
    }
  };
  await walk(localPath);
  return files;
}

export type VirusTotalVerdict =
  | { status: "clean"; positives: number }
  | { status: "flagged"; positives: number }
  | { status: "unknown" }
  | { status: "error"; error: string };

/** GET /files/{hash} against the VirusTotal v3 API, with a hard 10s timeout. */
export async function checkVirusTotalHash(
  hash: string,
  apiKey: string
): Promise<VirusTotalVerdict> {
  try {
    const res = await safeFetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      method: "GET",
      headers: { "x-apikey": apiKey },
      timeoutMs: VT_LOOKUP_TIMEOUT_MS,
      requireHttps: true,
    });

    if (res.status === 404) {
      return { status: "unknown" };
    }

    if (!res.ok) {
      return { status: "error", error: `VirusTotal responded with ${res.status}` };
    }

    const body = (await res.json()) as {
      data?: { attributes?: { last_analysis_stats?: { malicious?: number } } };
    };
    const positives = body.data?.attributes?.last_analysis_stats?.malicious ?? 0;
    return { status: "flagged", positives };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { status: "error", error: message };
  }
}

export type ClamAvVerdict =
  | { status: "clean" }
  | { status: "infected"; signature: string }
  | { status: "error"; error: string };

/** Streams a single file to clamd over its INSTREAM protocol and parses the verdict. */
function scanFileWithClamAv(
  filePath: string,
  connectAddress: string,
  port: number
): Promise<ClamAvVerdict> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let responseBuf = "";
    let settled = false;

    const finish = (verdict: ClamAvVerdict) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(verdict);
    };

    socket.setTimeout(CLAMAV_CONNECT_TIMEOUT_MS);
    socket.once("timeout", () => finish({ status: "error", error: "ClamAV connection timed out" }));
    socket.once("error", (err) => finish({ status: "error", error: err.message }));

    socket.connect(port, connectAddress, () => {
      socket.write("zINSTREAM\0");

      const readStream = fs.createReadStream(filePath, { highWaterMark: CLAMAV_CHUNK_SIZE });
      readStream.on("error", (err) => finish({ status: "error", error: err.message }));
      readStream.on("data", (chunk) => {
        const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        const sizeHeader = Buffer.alloc(4);
        sizeHeader.writeUInt32BE(buf.length, 0);
        socket.write(sizeHeader);
        socket.write(buf);
      });
      readStream.on("end", () => {
        const zeroLength = Buffer.alloc(4);
        socket.write(zeroLength);
      });
    });

    socket.on("data", (chunk) => {
      responseBuf += chunk.toString("utf8");
    });

    socket.on("close", () => {
      if (settled) return;
      const reply = responseBuf.replace(/\0/g, "").trim();
      if (reply.includes("FOUND")) {
        const signature = reply
          .replace(/^stream:\s*/, "")
          .replace(/\s*FOUND$/, "")
          .trim();
        finish({ status: "infected", signature: signature || "unknown signature" });
      } else if (reply.includes("OK")) {
        finish({ status: "clean" });
      } else {
        finish({ status: "error", error: reply || "Empty response from ClamAV" });
      }
    });
  });
}

/** Validates the configured ClamAV host resolves to a permitted address before connecting. */
async function connectableClamAvAddress(host: string): Promise<string> {
  const { address } = await resolveSafeAddress(normalizeHostname(host), true);
  return address;
}

export interface SecurityScanServiceDeps {
  getSystemConfig(key: string): Promise<string | undefined>;
}

/**
 * Orchestrates the pre-import security scan: an optional VirusTotal hash lookup
 * followed by an optional local ClamAV deep scan. Both providers fail open on
 * network/timeout errors (a scanner outage should never itself hang or corrupt
 * the import queue) — only an actual detection, or an unknown hash under a
 * strict "block unknown hashes" policy, blocks the import.
 */
export class SecurityScanService {
  constructor(private readonly storage: SecurityScanServiceDeps) {}

  async scan(localPath: string): Promise<ScanResult> {
    const vtSettings = await readVirusTotalSettings(this.storage);
    if (vtSettings.enabled && vtSettings.apiKey) {
      const primaryFile = await resolvePrimaryFile(localPath);
      if (primaryFile) {
        const hash = await computeFileSha256(primaryFile).catch((err) => {
          securityScanLogger.warn({ err, primaryFile }, "Failed to hash file for VirusTotal");
          return null;
        });

        if (hash) {
          const verdict = await checkVirusTotalHash(hash, vtSettings.apiKey);
          if (verdict.status === "flagged" && verdict.positives > vtSettings.threshold) {
            return {
              blocked: true,
              source: "virustotal",
              hash,
              reason: `VirusTotal detected ${verdict.positives} engine(s) flagging this file (threshold: ${vtSettings.threshold})`,
            };
          }

          if (verdict.status === "unknown") {
            securityScanLogger.warn(
              { hash },
              "Hash not found on VirusTotal (Unknown File). Proceeding based on user security tolerance."
            );
            if (vtSettings.blockUnknownHashes) {
              return {
                blocked: true,
                source: "virustotal",
                hash,
                reason: "Hash not found on VirusTotal and 'Block unknown hashes' is enabled",
              };
            }
          }

          if (verdict.status === "error") {
            securityScanLogger.warn(
              { hash, error: verdict.error },
              "VirusTotal lookup failed, proceeding without a verdict"
            );
          }
        }
      }
    }

    const clamAvSettings = await readClamAvSettings(this.storage);
    if (clamAvSettings.enabled && clamAvSettings.host) {
      try {
        const connectAddress = await connectableClamAvAddress(clamAvSettings.host);
        const files = await listAllFiles(localPath);
        for (const file of files) {
          const verdict = await scanFileWithClamAv(file, connectAddress, clamAvSettings.port);
          if (verdict.status === "infected") {
            return {
              blocked: true,
              source: "clamav",
              reason: `ClamAV detected ${verdict.signature} in ${path.basename(file)}`,
            };
          }
          if (verdict.status === "error") {
            securityScanLogger.warn(
              { file, error: verdict.error },
              "ClamAV scan failed for file, proceeding without a verdict"
            );
          }
        }
      } catch (error) {
        securityScanLogger.warn(
          { error, host: clamAvSettings.host },
          "Could not reach ClamAV, proceeding without a scan"
        );
      }
    }

    return { blocked: false };
  }
}
