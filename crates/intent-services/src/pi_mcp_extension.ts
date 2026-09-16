// Bundled pi extension: bridge intentd's per-agent MCP endpoint into pi.
//
// intentd embeds this file via `include_str!` (agent_manager.rs), writes it to a
// per-agent temp file, and launches pi through a wrapper script that adds
// `-e <this file>`. The daemon exports INTENTD_MCP_BRIDGE_ADDR (host:port of the
// per-agent TCP MCP bridge, see intent-acp/src/mcp_bridge.rs); on load the
// extension dials it, runs the MCP handshake (initialize →
// notifications/initialized → tools/list) over newline-delimited JSON-RPC, and
// registers every advertised tool with pi. Tool calls forward to `tools/call`.
// Bridge failures are never fatal to pi: we log to stderr and degrade (no tools,
// or a single reconnect attempt on the next call).
//
// Intentionally written in plain-JS syntax (no TS-only constructs, node
// built-ins only) so the MCP client core also runs standalone under `node` for
// the fixture test in crates/intentd/tests/fixtures/pi-mcp-extension-test.mjs.

import net from "node:net";

const CONNECT_TIMEOUT_MS = 5_000;
const HANDSHAKE_TIMEOUT_MS = 10_000;

export const MCP_PROTOCOL_VERSION = "2024-11-05";

function log(message) {
  process.stderr.write(`[pi-mcp-extension] ${message}\n`);
}

/// Minimal MCP client speaking newline-delimited JSON-RPC 2.0 over a pair of
/// streams (a net.Socket, or any readable/writable pair such as a child
/// process's stdio). Matches the framing of intentd's mcp bridge: one JSON
/// object per LF-terminated line, requests carry `id`, notifications do not.
export class McpLineClient {
  constructor(readable, writable) {
    this.readable = readable;
    this.writable = writable;
    this.pending = new Map();
    this.nextId = 1;
    this.closed = false;
    this.buffer = "";

    readable.on("data", (chunk) => this.onData(chunk));
    const close = (err) => this.markClosed(err);
    readable.on("error", close);
    readable.on("close", () => close());
    readable.on("end", () => close());
    writable.on("error", close);
  }

  onData(chunk) {
    this.buffer += chunk.toString("utf8");
    let idx;
    while ((idx = this.buffer.indexOf("\n")) >= 0) {
      const line = this.buffer.slice(0, idx).trim();
      this.buffer = this.buffer.slice(idx + 1);
      if (!line) continue;
      let msg;
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      this.onMessage(msg);
    }
  }

  onMessage(msg) {
    if (msg === null || typeof msg !== "object") return;
    const entry = this.pending.get(msg.id);
    if (!entry) return; // server notification or unknown id: ignore
    this.pending.delete(msg.id);
    entry.settle();
    if (msg.error) {
      const err = new Error(
        `mcp error ${msg.error.code}: ${msg.error.message}`,
      );
      err.jsonRpcError = true;
      err.code = msg.error.code;
      err.data = msg.error.data;
      entry.reject(err);
    } else {
      entry.resolve(msg.result);
    }
  }

  markClosed(err) {
    if (this.closed) return;
    this.closed = true;
    const reason = err instanceof Error ? err : new Error("mcp connection closed");
    for (const entry of this.pending.values()) {
      entry.settle();
      entry.reject(reason);
    }
    this.pending.clear();
  }

  isClosed() {
    return this.closed;
  }

  close() {
    this.markClosed();
    if (typeof this.writable.destroy === "function") this.writable.destroy();
    if (
      this.readable !== this.writable &&
      typeof this.readable.destroy === "function"
    ) {
      this.readable.destroy();
    }
  }

  /// Send a request and await its result. `timeoutMs` of 0 means no timeout.
  /// An optional AbortSignal rejects the pending call when aborted.
  request(method, params, { timeoutMs = 0, signal } = {}) {
    if (this.closed) {
      return Promise.reject(new Error("mcp connection closed"));
    }
    if (signal && signal.aborted) {
      return Promise.reject(new Error(`${method} aborted`));
    }
    const id = this.nextId;
    this.nextId += 1;
    const frame = JSON.stringify({ jsonrpc: "2.0", id, method, params: params ?? {} });
    return new Promise((resolve, reject) => {
      let timer = null;
      let onAbort = null;
      const settle = () => {
        if (timer) clearTimeout(timer);
        if (onAbort && signal) signal.removeEventListener("abort", onAbort);
      };
      const entry = { resolve, reject, settle };
      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          this.pending.delete(id);
          settle();
          reject(new Error(`${method} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
      }
      if (signal) {
        onAbort = () => {
          this.pending.delete(id);
          settle();
          reject(new Error(`${method} aborted`));
        };
        signal.addEventListener("abort", onAbort, { once: true });
      }
      this.pending.set(id, entry);
      this.writable.write(frame + "\n", (err) => {
        if (err && this.pending.delete(id)) {
          settle();
          reject(err);
        }
      });
    });
  }

  /// Fire-and-forget notification (no `id`, no response expected).
  notify(method, params) {
    if (this.closed) return;
    const frame = JSON.stringify({ jsonrpc: "2.0", method, params: params ?? {} });
    this.writable.write(frame + "\n", () => {});
  }

  /// Run the MCP handshake: `initialize` → `notifications/initialized`.
  async initialize(clientInfo) {
    const result = await this.request(
      "initialize",
      {
        protocolVersion: MCP_PROTOCOL_VERSION,
        capabilities: {},
        clientInfo,
      },
      { timeoutMs: HANDSHAKE_TIMEOUT_MS },
    );
    this.notify("notifications/initialized", {});
    return result;
  }

  async listTools() {
    const result = await this.request("tools/list", {}, {
      timeoutMs: HANDSHAKE_TIMEOUT_MS,
    });
    const tools = result && Array.isArray(result.tools) ? result.tools : [];
    return tools;
  }

  callTool(name, args, { signal } = {}) {
    return this.request(
      "tools/call",
      { name, arguments: args ?? {} },
      { signal },
    );
  }
}

/// Dial `host:port` and return a connected [`McpLineClient`].
export function connectMcpTcp(addr, timeoutMs = CONNECT_TIMEOUT_MS) {
  const idx = addr.lastIndexOf(":");
  if (idx <= 0) {
    return Promise.reject(new Error(`invalid bridge addr: ${addr}`));
  }
  const host = addr.slice(0, idx).replace(/^\[|\]$/g, "");
  const port = Number(addr.slice(idx + 1));
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    return Promise.reject(new Error(`invalid bridge addr: ${addr}`));
  }
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`connect to ${addr} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    socket.once("connect", () => {
      clearTimeout(timer);
      socket.setNoDelay(true);
      resolve(new McpLineClient(socket, socket));
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/// Map an MCP `tools/call` result to a pi tool result. Tool-level failures
/// (`isError: true`) are signaled by throwing, which pi reports to the LLM
/// with `isError: true` (per the extension docs).
export function mapToolResult(result) {
  const raw = result && Array.isArray(result.content) ? result.content : null;
  const content = raw
    ? raw.map((item) =>
        item && item.type === "text"
          ? item
          : { type: "text", text: JSON.stringify(item) },
      )
    : [{ type: "text", text: JSON.stringify(result ?? null) }];
  if (result && result.isError) {
    const text = content
      .map((item) => item.text)
      .filter(Boolean)
      .join("\n");
    throw new Error(text || "tool call failed");
  }
  const details =
    result && result.structuredContent !== undefined
      ? result.structuredContent
      : {};
  return { content, details };
}

/// MCP notification carrying one finished LLM call's usage to intentd
/// (intent-hq/intent#3802). Must match `intent_acp::EXTENSION_USAGE_NOTIFICATION`.
export const USAGE_NOTIFICATION = "notifications/intentd/usage";

/// pi-acp never puts usage on the ACP wire (no `PromptResponse.usage`, no
/// `usage_update`), so a pi session reads as zero tokens / zero cost. pi
/// itself knows: every finished assistant message carries pi-ai `Usage`
/// (`input` / `output` / `cacheRead` / `cacheWrite` / optional `reasoning` /
/// `totalTokens` / `cost.total` in USD). Map it to the ACP `Usage` wire shape
/// the daemon already understands, plus `cost: { amount, currency }`.
///
/// pi reports `reasoning` as a subset of `output`; the daemon stores thought
/// and output tokens disjointly, so the subset is carved out here. Returns
/// `null` for anything that is not an assistant message with non-zero usage.
export function mapUsageReport(message) {
  if (!message || message.role !== "assistant") return null;
  const raw = message.usage;
  if (!raw || typeof raw !== "object") return null;
  const count = (v) =>
    typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.round(v) : 0;
  const inputTokens = count(raw.input);
  const cachedReadTokens = count(raw.cacheRead);
  const cachedWriteTokens = count(raw.cacheWrite);
  let outputTokens = count(raw.output);
  const thoughtTokens =
    typeof raw.reasoning === "number" ? Math.min(count(raw.reasoning), outputTokens) : null;
  if (thoughtTokens !== null) outputTokens -= thoughtTokens;
  const totalTokens =
    count(raw.totalTokens) ||
    inputTokens + outputTokens + (thoughtTokens ?? 0) + cachedReadTokens + cachedWriteTokens;
  const usage = { totalTokens, inputTokens, outputTokens };
  if (thoughtTokens !== null) usage.thoughtTokens = thoughtTokens;
  usage.cachedReadTokens = cachedReadTokens;
  usage.cachedWriteTokens = cachedWriteTokens;
  const total = raw.cost && typeof raw.cost.total === "number" ? raw.cost.total : NaN;
  const params = { usage };
  if (Number.isFinite(total) && total > 0) params.cost = { amount: total, currency: "USD" };
  if (totalTokens === 0 && !params.cost) return null;
  return params;
}

/// Extension entry point. pi awaits the async factory before `session_start`,
/// so the bridge tools are registered before the first prompt.
export default async function piMcpExtension(pi) {
  const addr = process.env.INTENTD_MCP_BRIDGE_ADDR;
  if (!addr) {
    log("INTENTD_MCP_BRIDGE_ADDR not set; workspace MCP tools disabled");
    return;
  }

  let clientPromise = null;
  const ensureClient = () => {
    if (!clientPromise) {
      clientPromise = (async () => {
        const client = await connectMcpTcp(addr);
        try {
          await client.initialize({ name: "intentd-pi-mcp-extension", version: "0.1.0" });
        } catch (err) {
          client.close();
          throw err;
        }
        return client;
      })().catch((err) => {
        clientPromise = null;
        throw err;
      });
    }
    return clientPromise.then((client) => {
      if (!client.isClosed()) return client;
      clientPromise = null;
      return ensureClient();
    });
  };

  let tools;
  try {
    tools = await (await ensureClient()).listTools();
  } catch (err) {
    log(`bridge at ${addr} unavailable (${err.message}); workspace MCP tools disabled`);
    return;
  }

  // Forward a tool call; on transport failure (bridge restarted, socket
  // dropped) reconnect once and retry. Server-side JSON-RPC errors are not
  // retried — the call reached the bridge and failed there.
  const forwardCall = async (name, args, signal) => {
    const client = await ensureClient();
    try {
      return await client.callTool(name, args, { signal });
    } catch (err) {
      if (err.jsonRpcError) throw err;
      log(`bridge call failed (${err.message}); reconnecting once`);
      clientPromise = null;
      const retry = await ensureClient();
      return retry.callTool(name, args, { signal });
    }
  };

  // Registration failures (e.g. a name collision with a tool from a
  // user-installed extension) skip that tool only — never break pi.
  let registered = 0;
  for (const tool of tools) {
    try {
      pi.registerTool({
        name: tool.name,
        label: tool.name,
        description: tool.description ?? "",
        // MCP `inputSchema` is already JSON Schema, which is what pi feeds the
        // model; no typebox needed.
        parameters: tool.inputSchema ?? { type: "object", properties: {} },
        async execute(_toolCallId, params, signal) {
          const result = await forwardCall(tool.name, params ?? {}, signal);
          return mapToolResult(result);
        },
      });
      registered += 1;
    } catch (err) {
      log(`failed to register tool ${tool.name} (${err.message}); skipping it`);
    }
  }
  log(`registered ${registered} of ${tools.length} workspace tool(s) from ${addr}`);

  if (typeof pi.on === "function") {
    // intent-hq/intent#3802: forward each finished LLM call's usage to the
    // daemon, which folds the calls into the turn's token/cost tally. Best
    // effort — a dropped report only under-counts, it never breaks pi.
    pi.on("turn_end", async (event) => {
      const report = mapUsageReport(event && event.message);
      if (!report) return;
      try {
        (await ensureClient()).notify(USAGE_NOTIFICATION, report);
      } catch (err) {
        log(`usage report dropped (${err.message})`);
      }
    });
    pi.on("session_shutdown", async () => {
      const promise = clientPromise;
      clientPromise = null;
      if (!promise) return;
      try {
        (await promise).close();
      } catch {
        // already down — nothing to clean up
      }
    });
  }
}
