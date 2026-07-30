import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { describe, expect, it, vi } from "vitest";
import { AllowlyMCPMiddleware } from "../middleware.js";

type Decision = "allow" | "deny" | "confirm" | "escalate";

function actionResult(decision: Decision) {
  const base = { decision, reason: `test_${decision}` };
  if (decision === "confirm") {
    return {
      ...base,
      confirmNonce: "cnf_1",
      confirmExpiresAt: "2026-07-29T12:00:00.000Z",
      confirmPromptHint: "send_email",
    };
  }
  if (decision === "escalate") {
    return {
      ...base,
      escalationId: "esc_1",
      escalationTo: "compliance",
      escalationExpiresAt: "2026-07-19T00:00:00Z",
    };
  }
  return base;
}

async function gated(
  decision: Decision,
  identity: "context" | "missing" | "untrusted-argument" | "legacy-argument" = "context",
) {
  const toolName = "send_email";
  const mcp = new McpServer({ name: "test-server", version: "1.0.0" });

  let toolRan = 0;
  let originalHandlerReceivedExtra = false;
  mcp.registerTool(toolName, {}, async (extra) => {
    toolRan++;
    originalHandlerReceivedExtra = Boolean(extra.requestId);
    return { content: [{ type: "text", text: "tool result" }] };
  });

  let userIdFnReceivedExtra = false;
  const middleware = new AllowlyMCPMiddleware({
    apiKey: "test-key",
    authorizationIdFn: (userId) => userId === "u1" ? "auth_1" : null,
    ...(identity === "legacy-argument" ? { allowUserIdArgument: true } : {}),
    ...(identity === "context" || identity === "missing" ? {
      userIdFn: ({ extra }) => {
        userIdFnReceivedExtra = Boolean(extra);
        return identity === "context" ? "u1" : null;
      },
    } : {}),
  });
  const check = vi.spyOn(middleware.client, "check").mockResolvedValue({
    results: { [toolName]: actionResult(decision) },
  } as any);
  middleware.attach(mcp.server);

  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await mcp.connect(serverTransport);
  const client = new Client({ name: "test-client", version: "1.0.0" });
  await client.connect(clientTransport);
  try {
    const result = await client.callTool({
      name: toolName,
      arguments: identity.endsWith("argument") ? { user_id: "u1" } : {},
    });
    return { check, originalHandlerReceivedExtra, result, toolRan, userIdFnReceivedExtra };
  } finally {
    await client.close();
    await mcp.close();
  }
}

describe("AllowlyMCPMiddleware against a real McpServer", () => {
  it("runs an allowed tool and preserves handler context", async () => {
    const result = await gated("allow");

    expect(result.toolRan).toBe(1);
    expect(result.result.isError).toBeFalsy();
    expect(result.userIdFnReceivedExtra).toBe(true);
    expect(result.originalHandlerReceivedExtra).toBe(true);
    expect(result.check).toHaveBeenCalledWith({ authorizationId: "auth_1", actions: ["send_email"] });
  });

  it.each([
    ["deny", {}],
    ["confirm", { confirm_nonce: "cnf_1", confirm_expires_at: "2026-07-29T12:00:00.000Z", confirm_prompt_hint: "send_email" }],
    ["escalate", { escalation_id: "esc_1", escalation_to: "compliance" }],
  ] as const)("blocks a %s decision with its payload", async (decision, expected) => {
    const { result, toolRan } = await gated(decision);
    const body = JSON.parse(((result as any).content[0] as { text: string }).text);

    expect(toolRan).toBe(0);
    expect(result.isError).toBe(true);
    expect(body).toMatchObject({ decision, reason: `test_${decision}`, ...expected });
  });

  it("denies missing identity and ignores caller-supplied identity by default", async () => {
    for (const identity of ["missing", "untrusted-argument", "legacy-argument"] as const) {
      const { check, result, toolRan } = await gated("allow", identity);
      expect(toolRan).toBe(0);
      expect(check).not.toHaveBeenCalled();
      expect(JSON.parse(((result as any).content[0] as { text: string }).text).decision).toBe("deny");
    }
  });

  it("requires tools to be registered before attach", () => {
    const mcp = new McpServer({ name: "test-server", version: "1.0.0" });
    const middleware = new AllowlyMCPMiddleware({
      apiKey: "test-key",
      authorizationIdFn: () => "auth_1",
      userIdFn: () => "u1",
    });

    expect(() => middleware.attach(mcp.server)).toThrow("Register MCP tools before attaching");
  });
});
