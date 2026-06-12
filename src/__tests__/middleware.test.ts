import { describe, it, expect, vi } from "vitest";
import { AllowlyMCPMiddleware } from "../middleware.js";

const BASE = "https://api.example.com";

function makeAllowResponse() {
  return {
    userId: "u1", agentId: "gmail-tools", authorizationId: "auth_1",
    authorizationExpiresAt: "2026-12-31T00:00:00Z", engineVersion: "2026-04-19.1",
    results: {
      read_email: {
        decision: "allow" as const,
        reason: "authorization_granted_action_active",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
        escalation: null,
        policyEval: null,
      },
      send_email: {
        decision: "allow" as const,
        reason: "authorization_granted_action_active",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
        escalation: null,
        policyEval: null,
      },
    },
  };
}

function makeDenyResponse() {
  return {
    userId: "u1", agentId: "gmail-tools", authorizationId: "auth_1",
    authorizationExpiresAt: "2026-12-31T00:00:00Z", engineVersion: "2026-04-19.1",
    results: {
      send_email: {
        decision: "deny" as const,
        reason: "authorization_not_found",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
        escalation: null,
        policyEval: null,
      },
    },
  };
}

function makeConfirmResponse() {
  return {
    userId: "u1", agentId: "gmail-tools", authorizationId: "auth_1",
    authorizationExpiresAt: "2026-12-31T00:00:00Z", engineVersion: "2026-04-19.1",
    results: {
      send_email: {
        decision: "confirm" as const,
        reason: "action_requires_user_confirmation",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
        escalation: null,
        policyEval: null,
        confirmNonce: "cnf_abc", confirmExpiresAt: "2026-04-20T00:15:00Z",
        confirmPromptHint: "email.send",
      },
    },
  };
}

function makeEscalateResponse() {
  return {
    userId: "u1", agentId: "gmail-tools", authorizationId: "auth_1",
    authorizationExpiresAt: "2026-12-31T00:00:00Z", engineVersion: "2026-04-19.1",
    results: {
      delete_candidate: {
        decision: "escalate" as const,
        reason: "escalation_required",
        receipt: { status: "pending" as const, receiptId: "rcp_abc", readyAtEstimate: "", url: "" },
        isFallback: false,
        fallbackMode: null,
        budget: null,
        escalation: {
          escalationId: "esc_abc",
          status: "pending",
          escalationTo: "compliance",
          expiresAt: "2026-04-21T17:00:00Z",
        },
        escalationId: "esc_abc",
        escalationTo: "compliance",
        escalationExpiresAt: "2026-04-21T17:00:00Z",
        policyEval: null,
      },
    },
  };
}

function makeCallToolReq(name: string, args: Record<string, unknown> = {}, authenticatedUserId: string | null = "u1") {
  const req: { params: { name: string; arguments: Record<string, unknown> }; meta?: { authenticatedUserId: string } } = {
    params: { name, arguments: args },
  };
  if (authenticatedUserId) req.meta = { authenticatedUserId };
  return req;
}

function makeMiddleware(authorizationIdFn = (userId: string) => userId ? "auth_1" : null) {
  return new AllowlyMCPMiddleware({
    apiKey: "test-key",
    baseUrl: BASE,
    userIdFn: ({ request }) => {
      const req = request as { meta?: { authenticatedUserId?: string } };
      return req.meta?.authenticatedUserId ?? null;
    },
    authorizationIdFn,
  });
}

function makeServer() {
  const handlers = new Map<string, (req: unknown) => Promise<unknown>>();
  const originalHandler = vi.fn().mockResolvedValue({ content: [{ type: "text", text: "tool result" }] });
  handlers.set("tools/call", originalHandler);
  return {
    _requestHandlers: handlers,
    setRequestHandler: vi.fn((schema: unknown, handler: (req: unknown) => Promise<unknown>) => {
      handlers.set("tools/call", handler);
    }),
    originalHandler,
    handlers,
  };
}

describe("AllowlyMCPMiddleware - low-level Server", () => {
  it("allows tool call and delegates to original handler", async () => {
    const mw = makeMiddleware();
    vi.spyOn(mw.client, "check").mockResolvedValue(makeAllowResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("read_email", { user_id: "u1" })) as any;

    expect(server.originalHandler).toHaveBeenCalledWith(makeCallToolReq("read_email", { user_id: "u1" }));
    expect(result.isError).toBeFalsy();
  });

  it("blocks tool call on deny", async () => {
    const mw = makeMiddleware();
    vi.spyOn(mw.client, "check").mockResolvedValue(makeDenyResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("send_email", { user_id: "u1" })) as any;

    expect(server.originalHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.decision).toBe("deny");
    expect(body.reason).toBe("authorization_not_found");
  });

  it("returns confirm nonce and prompt hint", async () => {
    const mw = makeMiddleware();
    vi.spyOn(mw.client, "check").mockResolvedValue(makeConfirmResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("send_email", { user_id: "u1" })) as any;

    expect(server.originalHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.decision).toBe("confirm");
    expect(body.confirm_nonce).toBe("cnf_abc");
    expect(body.confirm_prompt_hint).toBe("email.send");
  });

  it("returns escalation payload", async () => {
    const mw = makeMiddleware();
    vi.spyOn(mw.client, "check").mockResolvedValue(makeEscalateResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("delete_candidate", { user_id: "u1" })) as any;

    expect(server.originalHandler).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.decision).toBe("escalate");
    expect(body.escalation_id).toBe("esc_abc");
    expect(body.escalation_to).toBe("compliance");
  });

  it("denies when user_id is missing", async () => {
    const mw = makeMiddleware();
    const checkSpy = vi.spyOn(mw.client, "check");

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("read_email", {}, null)) as any;

    expect(checkSpy).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    const body = JSON.parse(result.content[0].text);
    expect(body.decision).toBe("deny");
  });

  it("ignores caller-supplied user_id by default", async () => {
    const mw = new AllowlyMCPMiddleware({
      apiKey: "test-key",
      baseUrl: BASE,
      authorizationIdFn: (userId) => userId ? "auth_1" : null,
    });
    const checkSpy = vi.spyOn(mw.client, "check");

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    const result = await handler(makeCallToolReq("read_email", { user_id: "u1" }, null)) as any;

    expect(checkSpy).not.toHaveBeenCalled();
    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).decision).toBe("deny");
  });

  it("can opt into legacy user_id tool arguments", async () => {
    const mw = new AllowlyMCPMiddleware({
      apiKey: "test-key",
      baseUrl: BASE,
      allowUserIdArgument: true,
      authorizationIdFn: (userId) => userId ? "auth_1" : null,
    });
    const checkSpy = vi.spyOn(mw.client, "check").mockResolvedValue(makeAllowResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    await handler(makeCallToolReq("read_email", { user_id: "u1" }, null));

    expect(checkSpy).toHaveBeenCalledWith({ authorizationId: "auth_1", actions: ["read_email"] });
  });

  it("calls check with resolved authorization_id", async () => {
    const mw = makeMiddleware();
    const checkSpy = vi.spyOn(mw.client, "check").mockResolvedValue(makeAllowResponse());

    const server = makeServer();
    mw.attach(server as any);

    const handler = server.handlers.get("tools/call")!;
    await handler(makeCallToolReq("read_email", { user_id: "u1" }));

    expect(checkSpy).toHaveBeenCalledWith({ authorizationId: "auth_1", actions: ["read_email"] });
  });
});
