/**
 * Allowly middleware for MCP servers.
 *
 * McpServer (high-level) usage:
 *   const mcp = new McpServer({ name: "my-agent", version: "1.0" });
 *   const allowly = new AllowlyMCPMiddleware({
 *     apiKey: process.env.ALLOWLY_API_KEY!,
 *     userIdFn: ({ extra }) => {
 *       const userId = extra.authInfo?.extra?.userId;
 *       return typeof userId === "string" ? userId : null;
 *     },
 *     authorizationIdFn: (userId) => db.getAuthorizationId(userId),
 *   });
 *   allowly.attach(mcp.server);
 *
 * Low-level Server usage:
 *   const server = new Server({ name: "my-agent", version: "1.0" });
 *   const allowly = new AllowlyMCPMiddleware({ ... });
 *   allowly.attach(server);
 */
import { Allowly } from "@allowly/sdk";
import type { ActionCheckResultConfirm, ActionCheckResultEscalate } from "@allowly/sdk";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { RequestHandlerExtra } from "@modelcontextprotocol/sdk/shared/protocol.js";
import {
  CallToolRequestSchema,
  type CallToolRequest,
  type ServerNotification,
  type ServerRequest,
} from "@modelcontextprotocol/sdk/types.js";

type AuthorizationIdFn = (userId: string) => string | null | Promise<string | null>;
type UserIdFn = (context: MCPAuthorizationContext) => string | null | Promise<string | null>;
type AgentTokenFn = (context: MCPAuthorizationContext) => string | null | Promise<string | null>;
type HandlerExtra = RequestHandlerExtra<ServerRequest, ServerNotification>;

export interface MCPAuthorizationContext {
  toolName: string;
  arguments: Record<string, unknown>;
  request: CallToolRequest;
  extra: HandlerExtra;
}

export interface MCPCheckInput {
  /** Policy action to evaluate. Defaults to the exact MCP tool name. */
  action?: string;
  /** Exact resource derived by the server from the tool request. */
  resource?: string;
  /** Explicit policy context selected by the server. Tool arguments are never copied automatically. */
  context?: Record<string, unknown>;
  clientTimestamp?: Date | string;
  estimatedCostMicros?: number;
  idempotencyKey?: string;
}

type CheckInputFn = (
  context: MCPAuthorizationContext,
) => MCPCheckInput | Promise<MCPCheckInput>;

export interface AllowlyMCPMiddlewareOptions {
  apiKey: string;
  authorizationIdFn: AuthorizationIdFn;
  userIdFn?: UserIdFn;
  /** Resolve a trusted Auth0 M2M token from server-side request state. */
  agentTokenFn?: AgentTokenFn;
  /** Map this exact tool request to the policy action/resource/context that will be checked. */
  checkInputFn?: CheckInputFn;
  baseUrl?: string;
}

export class AllowlyMCPMiddleware {
  readonly client: Allowly;
  private readonly authorizationIdFn: AuthorizationIdFn;
  private readonly userIdFn?: UserIdFn;
  private readonly agentTokenFn?: AgentTokenFn;
  private readonly checkInputFn?: CheckInputFn;

  constructor(opts: AllowlyMCPMiddlewareOptions) {
    this.client = new Allowly({
      apiKey: opts.apiKey,
      ...(opts.baseUrl ? { baseUrl: opts.baseUrl } : {}),
    });
    this.authorizationIdFn = opts.authorizationIdFn;
    this.userIdFn = opts.userIdFn;
    this.agentTokenFn = opts.agentTokenFn;
    this.checkInputFn = opts.checkInputFn;
  }

  private async resolveAuthorizationId(context: MCPAuthorizationContext): Promise<string | null> {
    const userId = await this.resolveUserId(context);
    if (!userId) return null;
    return this.authorizationIdFn(userId);
  }

  private async resolveUserId(context: MCPAuthorizationContext): Promise<string | null> {
    if (this.userIdFn) {
      return this.userIdFn(context);
    }
    return null;
  }

  /**
   * Attach to a low-level MCP `Server` instance.
   *
   * Wraps the existing `CallToolRequestSchema` handler so every tool call is
   * gated on an Allowly check before the original handler runs.
   */
  attach(server: Pick<Server, "setRequestHandler">): void {
    const originalHandlers: Map<string, (req: CallToolRequest, extra: HandlerExtra) => Promise<any>> =
      (server as any)._requestHandlers ?? new Map();
    const originalHandler = originalHandlers.get("tools/call") as
      | ((req: CallToolRequest, extra: HandlerExtra) => Promise<any>)
      | undefined;
    if (!originalHandler) {
      throw new Error("Register MCP tools before attaching Allowly middleware");
    }

    server.setRequestHandler(CallToolRequestSchema, async (req, extra) => {
      const args = req.params.arguments ?? {};
      const context = { toolName: req.params.name, arguments: args, request: req, extra };

      const authorizationId = await this.resolveAuthorizationId(context);
      if (authorizationId === null) {
        return {
          content: [{ type: "text", text: JSON.stringify({ decision: "deny", reason: "authorization_not_found" }) }],
          isError: true,
        };
      }

      let checkInput: MCPCheckInput;
      try {
        checkInput = this.checkInputFn
          ? await this.checkInputFn(context)
          : {};
      } catch {
        return {
          content: [{ type: "text", text: JSON.stringify({ decision: "deny", reason: "check_input_unavailable" }) }],
          isError: true,
        };
      }
      if (!checkInput || typeof checkInput !== "object") {
        return {
          content: [{ type: "text", text: JSON.stringify({ decision: "deny", reason: "check_input_invalid" }) }],
          isError: true,
        };
      }
      const action = checkInput.action ?? req.params.name;
      if (typeof action !== "string" || !action.trim()) {
        return {
          content: [{ type: "text", text: JSON.stringify({ decision: "deny", reason: "check_action_invalid" }) }],
          isError: true,
        };
      }
      let agentToken: string | null = null;
      if (this.agentTokenFn) {
        try {
          agentToken = await this.agentTokenFn(context);
        } catch {
          return {
            content: [{ type: "text", text: JSON.stringify({ decision: "deny", reason: "agent_token_unavailable" }) }],
            isError: true,
          };
        }
        if (typeof agentToken !== "string" || !agentToken.trim()) {
          return {
            content: [{ type: "text", text: JSON.stringify({ decision: "deny", reason: "agent_token_not_found" }) }],
            isError: true,
          };
        }
      }
      const result = await this.client.check({
        authorizationId,
        actions: [action],
        ...(checkInput.resource !== undefined ? { resource: checkInput.resource } : {}),
        ...(checkInput.context !== undefined ? { context: checkInput.context } : {}),
        ...(checkInput.clientTimestamp !== undefined
          ? { clientTimestamp: checkInput.clientTimestamp }
          : {}),
        ...(checkInput.estimatedCostMicros !== undefined
          ? { estimatedCostMicros: checkInput.estimatedCostMicros }
          : {}),
        ...(checkInput.idempotencyKey !== undefined
          ? { idempotencyKey: checkInput.idempotencyKey }
          : {}),
        ...(agentToken !== null ? { agentToken } : {}),
      });
      const actionResult = result.results[action];
      if (!actionResult) {
        return {
          content: [{ type: "text", text: JSON.stringify({ decision: "deny", reason: "missing_result" }) }],
          isError: true,
        };
      }

      if (actionResult.decision === "allow") {
        return originalHandler(req, extra);
      }

      if (actionResult.decision === "confirm") {
        const c = actionResult as ActionCheckResultConfirm;
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              decision: "confirm",
              reason: c.reason,
              confirm_nonce: c.confirmNonce,
              confirm_expires_at: c.confirmExpiresAt,
              confirm_prompt_hint: c.confirmPromptHint,
            }),
          }],
          isError: true,
        };
      }

      if (actionResult.decision === "escalate") {
        const e = actionResult as ActionCheckResultEscalate;
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              decision: "escalate",
              reason: e.reason,
              escalation_id: e.escalationId,
              escalation_to: e.escalationTo,
              escalation_expires_at: e.escalationExpiresAt,
            }),
          }],
          isError: true,
        };
      }

      return {
        content: [{ type: "text", text: JSON.stringify({ decision: actionResult.decision, reason: actionResult.reason }) }],
        isError: true,
      };
    });
  }
}
