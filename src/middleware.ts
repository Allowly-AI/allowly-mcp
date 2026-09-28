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
import type {
  ActionCheckResultConfirm,
  ActionCheckResultEscalate,
  CustomerHttpOptions,
  CustomerPolicyInput,
} from "@allowly/sdk";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodRawShapeCompat } from "@modelcontextprotocol/sdk/server/zod-compat.js";
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

/** Trusted, server-side configuration for one local Execute tool. */
export interface MCPLocalExecuteTool {
  /** MCP validates these business inputs before Execute is invoked. */
  inputSchema: ZodRawShapeCompat;
  description?: string;
  /** Fixed provider URL; never take it from MCP tool arguments. */
  url: string | URL;
  enabledExecutableId: string;
  catalogOperationId: string;
  action: string;
  method?: CustomerHttpOptions["method"];
  journalDirectory: string;
  evidenceMode?: CustomerHttpOptions["evidenceMode"];
  /** Provide a fresh evidence directory for each witnessed operation. */
  witnessFn?: (args: Record<string, unknown>, operationId: string) => CustomerHttpOptions["witness"] | Promise<CustomerHttpOptions["witness"]>;
  /** Stable ID for this logical provider call, including retries. */
  operationIdFn: (args: Record<string, unknown>, extra: HandlerExtra) => string | Promise<string>;
  /** Reads credentials only from trusted server request state or a local secret store. */
  providerHeadersFn?: (extra: HandlerExtra) => Record<string, string> | Promise<Record<string, string>>;
  /** Selects bounded business arguments for the provider body. */
  bodyFn?: (args: Record<string, unknown>) => string | Promise<string>;
  /** Selects only fields that policy should receive. */
  policyInputFn?: (args: Record<string, unknown>, extra: HandlerExtra) => CustomerPolicyInput | Promise<CustomerPolicyInput>;
}

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
  private readonly localExecuteServers = new WeakMap<Server, Set<string>>();

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

  /** Register a schema-validated MCP tool backed by SDK customer-runtime Execute. */
  registerLocalExecuteTool(
    mcp: McpServer,
    name: string,
    tool: MCPLocalExecuteTool,
  ): void {
    const names = this.localExecuteServers.get(mcp.server) ?? new Set<string>();
    if (names.has(name)) throw new Error(`Local Execute tool already registered: ${name}`);
    mcp.registerTool(name, {
      description: tool.description,
      inputSchema: tool.inputSchema,
    }, async (args, extra) => {
      const context: MCPAuthorizationContext = {
        toolName: name,
        arguments: args as Record<string, unknown>,
        request: { method: "tools/call", params: { name, arguments: args } } as CallToolRequest,
        extra,
      };
      const denied = (reason: string) => ({
        content: [{ type: "text" as const, text: JSON.stringify({ decision: "deny", reason }) }],
        isError: true,
      });
      try {
        const authorizationId = await this.resolveAuthorizationId(context);
        if (!authorizationId) return denied("authorization_not_found");
        let agentToken: string | undefined;
        if (this.agentTokenFn) {
          agentToken = (await this.agentTokenFn(context)) ?? undefined;
          if (typeof agentToken !== "string" || !agentToken.trim()) {
            return denied("agent_token_not_found");
          }
        }
        const operationId = await tool.operationIdFn(args, extra);
        if (typeof operationId !== "string" || !operationId.trim()) {
          return denied("operation_id_not_found");
        }
        const result = await this.client.executeHttp(tool.url, {
          operationId,
          authorizationId,
          enabledExecutableId: tool.enabledExecutableId,
          catalogOperationId: tool.catalogOperationId,
          action: tool.action,
          method: tool.method,
          headers: await tool.providerHeadersFn?.(extra),
          body: await tool.bodyFn?.(args),
          policyInput: await tool.policyInputFn?.(args, extra),
          evidenceMode: tool.evidenceMode,
          witness: await tool.witnessFn?.(args, operationId),
          journalDirectory: tool.journalDirectory,
          agentToken,
        });
        return {
          content: [{ type: "text" as const, text: JSON.stringify(result) }],
          isError: result.state !== "response_observed" || result.response.status !== "succeeded",
        };
      } catch {
        return denied("local_execute_failed");
      }
    });
    names.add(name);
    this.localExecuteServers.set(mcp.server, names);
  }

  /**
   * Attach to a low-level MCP `Server` instance.
   *
   * Checks ordinary tools before their handler runs. Registered local Execute
   * tools use the SDK's integrated decision and execution path instead.
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

      if (this.localExecuteServers.get(server as Server)?.has(req.params.name)) {
        return originalHandler(req, extra);
      }

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
        resource: checkInput.resource,
        context: checkInput.context,
        clientTimestamp: checkInput.clientTimestamp,
        estimatedCostMicros: checkInput.estimatedCostMicros,
        idempotencyKey: checkInput.idempotencyKey,
        agentToken: agentToken ?? undefined,
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
