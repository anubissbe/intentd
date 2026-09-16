#!/usr/bin/env node
// Node-side test for the bundled pi MCP extension
// (intent-services/src/pi_mcp_extension.ts). Exercises the MCP client core
// against the mock-mcp-server.mjs fixture and the extension factory against a
// TCP bridge stand-in (per-connection mock child, socket↔stdio pipe — the
// mirror image of intentd's `mcp-bridge` proxy). Invoked from the Rust test
// `pi_mcp_extension_node.rs`:
//   node pi-mcp-extension-test.mjs <path to pi_mcp_extension.ts> <path to mock-mcp-server.mjs>
// Exits 0 on success, 1 on failure.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, copyFileSync, rmSync } from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { PassThrough } from "node:stream";

const [extPath, mockPath] = process.argv.slice(2);
assert.ok(extPath && mockPath, "usage: pi-mcp-extension-test.mjs <ext.ts> <mock-mcp-server.mjs>");

// The extension is plain-JS-syntax ESM in a .ts file (loaded by pi via jiti);
// copy it to a .mjs so any ESM-capable node can import it, no type stripping
// needed.
const tmpDir = mkdtempSync(path.join(os.tmpdir(), "pi-mcp-ext-test-"));
const extMjs = path.join(tmpDir, "pi_mcp_extension.mjs");
copyFileSync(extPath, extMjs);
const ext = await import(pathToFileURL(extMjs).href);
const { McpLineClient, mapToolResult, mapUsageReport, USAGE_NOTIFICATION } = ext;

function spawnMock() {
  return spawn(process.execPath, [mockPath], { stdio: ["pipe", "pipe", "inherit"] });
}

// --- 1. Client core over the mock server's stdio -------------------------
{
  const child = spawnMock();
  const client = new McpLineClient(child.stdout, child.stdin);

  const init = await client.initialize({ name: "test", version: "0.0.0" });
  assert.equal(init.serverInfo.name, "mock-mcp-server", "initialize returns serverInfo");
  assert.ok(init.protocolVersion, "initialize returns protocolVersion");

  // Concurrent in-flight requests resolve independently.
  const [tools, ping] = await Promise.all([
    client.listTools(),
    client.request("ping", {}),
  ]);
  assert.deepEqual(ping, {}, "ping returns empty result");
  assert.deepEqual(
    tools.map((t) => t.name),
    ["echo", "reverse"],
    "tools/list returns the mock's two tools",
  );
  assert.equal(tools[0].inputSchema.type, "object", "tools carry a JSON-schema inputSchema");

  // tools/call round-trips (mock answers `<tool>:<args.input>` as text content).
  assert.deepEqual(await client.callTool("echo", { input: "x" }), {
    content: [{ type: "text", text: "echo:x" }],
  });

  // Server death rejects new requests instead of hanging.
  child.kill();
  await new Promise((resolve) => child.once("close", resolve));
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(client.isClosed(), "client observes the closed connection");
  await assert.rejects(client.request("ping", {}), /closed/);
}

// --- 2. Timeouts against a server that never answers ---------------------
{
  const silent = new McpLineClient(new PassThrough(), new PassThrough());
  await assert.rejects(
    silent.request("ping", {}, { timeoutMs: 50 }),
    /timed out/,
    "unanswered request times out",
  );
  silent.close();
}

// --- 3. mapToolResult mapping --------------------------------------------
{
  const ok = mapToolResult({
    content: [{ type: "text", text: "hi" }, { type: "image", data: "…" }],
    structuredContent: { a: 1 },
  });
  assert.equal(ok.content[0].text, "hi", "text content passes through");
  assert.equal(ok.content[1].type, "text", "non-text content is stringified");
  assert.deepEqual(ok.details, { a: 1 }, "structuredContent maps to details");

  assert.deepEqual(
    mapToolResult({}).content,
    [{ type: "text", text: "{}" }],
    "content-less results are stringified");

  assert.throws(
    () => mapToolResult({ isError: true, content: [{ type: "text", text: "boom" }] }),
    /boom/,
    "isError results throw so pi reports isError:true",
  );
}

// --- 3b. mapUsageReport mapping (intent-hq/intent#3802) -------------------
{
  assert.equal(USAGE_NOTIFICATION, "notifications/intentd/usage");
  const full = mapUsageReport({
    role: "assistant",
    usage: {
      input: 1000,
      output: 300,
      cacheRead: 400,
      cacheWrite: 50,
      reasoning: 100,
      totalTokens: 1750,
      cost: { input: 0.001, output: 0.002, cacheRead: 0, cacheWrite: 0, total: 0.0123 },
    },
  });
  assert.deepEqual(
    full,
    {
      usage: {
        totalTokens: 1750,
        inputTokens: 1000,
        // pi reports reasoning ⊂ output; the daemon stores them disjointly.
        outputTokens: 200,
        thoughtTokens: 100,
        cachedReadTokens: 400,
        cachedWriteTokens: 50,
      },
      cost: { amount: 0.0123, currency: "USD" },
    },
    "pi usage maps to ACP wire shape with a USD cost",
  );

  const noReasoning = mapUsageReport({
    role: "assistant",
    usage: { input: 10, output: 5, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { total: 0 } },
  });
  assert.deepEqual(
    noReasoning,
    {
      usage: { totalTokens: 15, inputTokens: 10, outputTokens: 5, cachedReadTokens: 0, cachedWriteTokens: 0 },
    },
    "missing reasoning omits thoughtTokens; zero totalTokens is recomputed; zero cost is omitted",
  );

  assert.equal(mapUsageReport({ role: "user", content: "hi" }), null, "user messages report nothing");
  assert.equal(mapUsageReport({ role: "assistant" }), null, "usage-less assistant messages report nothing");
  assert.equal(
    mapUsageReport({
      role: "assistant",
      usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { total: 0 } },
    }),
    null,
    "all-zero usage reports nothing",
  );
  assert.equal(mapUsageReport(undefined), null, "no message reports nothing");
}

// --- 4. Extension factory against a TCP bridge stand-in ------------------
const serverSockets = [];
// Every frame the extension sends to the bridge, parsed (the usage
// notification travels this way, so the test can observe it).
const bridgeFrames = [];
const bridge = net.createServer((socket) => {
  serverSockets.push(socket);
  const child = spawnMock();
  let buffer = "";
  socket.on("data", (chunk) => {
    buffer += chunk.toString("utf8");
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      try {
        bridgeFrames.push(JSON.parse(line));
      } catch {
        // partial / non-JSON: ignore
      }
    }
  });
  socket.pipe(child.stdin);
  child.stdout.pipe(socket);
  socket.on("close", () => child.kill());
  socket.on("error", () => {});
});
await new Promise((resolve) => bridge.listen(0, "127.0.0.1", resolve));
const addr = `127.0.0.1:${bridge.address().port}`;

function fakePi() {
  return {
    tools: [],
    handlers: new Map(),
    registerTool(def) {
      this.tools.push(def);
    },
    on(event, handler) {
      this.handlers.set(event, handler);
    },
  };
}

async function waitFor(predicate, what, timeoutMs = 2000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const hit = predicate();
    if (hit) return hit;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail(`timed out waiting for ${what}`);
}

{
  process.env.INTENTD_MCP_BRIDGE_ADDR = addr;
  const pi = fakePi();
  await ext.default(pi);
  assert.deepEqual(
    pi.tools.map((t) => t.name),
    ["echo", "reverse"],
    "factory registers every bridge tool",
  );
  const echo = pi.tools[0];
  assert.equal(typeof echo.parameters, "object", "tool parameters carry the MCP inputSchema");
  assert.deepEqual(
    await echo.execute("tc-1", { input: "x" }),
    { content: [{ type: "text", text: "echo:x" }], details: {} },
    "execute forwards tools/call and maps the result",
  );

  // Mid-session drop: kill the bridge-side socket, next call reconnects.
  for (const s of serverSockets.splice(0)) s.destroy();
  await new Promise((resolve) => setTimeout(resolve, 50));
  const retried = await echo.execute("tc-2", { input: "y" });
  assert.equal(retried.content[0].text, "echo:y", "execute reconnects after a dropped connection");

  // intent-hq/intent#3802: a finished assistant message's usage is forwarded
  // to the bridge as a JSON-RPC notification (no `id`); non-assistant
  // messages are not.
  const onTurnEnd = pi.handlers.get("turn_end");
  assert.equal(typeof onTurnEnd, "function", "factory subscribes to turn_end");
  const before = bridgeFrames.filter((f) => f.method === USAGE_NOTIFICATION).length;
  await onTurnEnd({ turnIndex: 0, message: { role: "user", content: "hi" }, toolResults: [] });
  await onTurnEnd({
    turnIndex: 1,
    message: {
      role: "assistant",
      content: [],
      usage: {
        input: 20,
        output: 7,
        cacheRead: 3,
        cacheWrite: 0,
        totalTokens: 30,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0.005 },
      },
    },
    toolResults: [],
  });
  const frames = await waitFor(
    () => {
      const hits = bridgeFrames.filter((f) => f.method === USAGE_NOTIFICATION);
      return hits.length > before ? hits.slice(before) : null;
    },
    "the usage notification to reach the bridge",
  );
  assert.equal(frames.length, 1, "only the assistant message produces a report");
  assert.equal(frames[0].id, undefined, "usage report is a notification (no id)");
  assert.deepEqual(frames[0].params, {
    usage: { totalTokens: 30, inputTokens: 20, outputTokens: 7, cachedReadTokens: 3, cachedWriteTokens: 0 },
    cost: { amount: 0.005, currency: "USD" },
  });
}

// --- 5. Graceful degradation ----------------------------------------------
{
  // A throwing registerTool (e.g. name collision with a user-installed
  // extension's tool) skips that tool only; the rest still register.
  process.env.INTENTD_MCP_BRIDGE_ADDR = addr;
  const pi = fakePi();
  const realRegister = pi.registerTool.bind(pi);
  pi.registerTool = (def) => {
    if (def.name === "echo") throw new Error("name collision");
    realRegister(def);
  };
  await ext.default(pi);
  assert.deepEqual(
    pi.tools.map((t) => t.name),
    ["reverse"],
    "a throwing registerTool skips that tool only",
  );
}
{
  delete process.env.INTENTD_MCP_BRIDGE_ADDR;
  const pi = fakePi();
  await ext.default(pi);
  assert.equal(pi.tools.length, 0, "no env var: no tools, no crash");
}
{
  // A bound-then-closed listener yields a port with nothing listening.
  const dead = net.createServer();
  await new Promise((resolve) => dead.listen(0, "127.0.0.1", resolve));
  const deadAddr = `127.0.0.1:${dead.address().port}`;
  await new Promise((resolve) => dead.close(resolve));

  process.env.INTENTD_MCP_BRIDGE_ADDR = deadAddr;
  const pi = fakePi();
  await ext.default(pi);
  assert.equal(pi.tools.length, 0, "unreachable bridge: no tools, no crash");
}

for (const s of serverSockets) s.destroy();
await new Promise((resolve) => bridge.close(resolve));
rmSync(tmpDir, { recursive: true, force: true });
console.log("pi-mcp-extension-test: all assertions passed");
process.exit(0);
