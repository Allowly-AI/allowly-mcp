# @allowly/mcp

Allowly guardrail middleware for MCP tool calls.

Use this package when you already have an MCP server and want each tool call to pass through Allowly before the tool runs. The MCP tool name is the default action name. Use `checkInputFn` when your policy needs a different action, resource, or selected input fields.

This is the TypeScript MCP middleware, separate from `@allowly/sdk` because npm has no extras. The Python equivalent ships inside the Python SDK as `allowly[fastmcp]`.

## Install

```bash
npm install @allowly/mcp @allowly/sdk @modelcontextprotocol/sdk zod
```

`@allowly/mcp` is ESM-only and requires Node.js 20 or newer.

## Usage

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AllowlyMCPMiddleware } from "@allowly/mcp";

const mcp = new McpServer({ name: "my-agent", version: "1.0.0" });
registerAgentTools(mcp);

const allowly = new AllowlyMCPMiddleware({
  apiKey: process.env.ALLOWLY_API_KEY!,
  userIdFn: ({ extra }) => {
    const userId = extra.authInfo?.extra?.userId;
    return typeof userId === "string" ? userId : null;
  },
  authorizationIdFn: async (userId) => {
    return getAuthorizationIdForUser(userId);
  },
  agentTokenFn: ({ extra }) => getAuth0AgentToken(extra.authInfo),
  checkInputFn: ({ arguments: args }) => ({
    action: "email.send",
    resource: `gmail:thread:${String(args.thread_id)}`,
    context: { recipient_domain: String(args.recipient_domain) },
    idempotencyKey: String(args.operation_id),
  }),
});

allowly.attach(mcp.server);
```

Register tools before calling `attach()`; the middleware fails fast when there is no tool handler to wrap.

## Behavior

- `allow`: the original MCP tool handler runs.
- `deny`: the middleware returns an MCP error response with the Allowly reason.
- `confirm`: the middleware returns a confirmation payload with `confirm_nonce`,
  `confirm_expires_at`, and `confirm_prompt_hint`; do not present an expired prompt.
- `escalate`: the middleware returns an escalation payload with `escalation_id`.

The MCP server and its tool handler run on your host. Keep provider credentials
in that host's local secret store. For ordinary checked tools, this middleware
sends policy fields to Allowly and then calls the local handler on `allow`. The
check receipt records Allowly's decision, without proving the provider response.

The middleware calls:

```ts
allowly.check({
  authorizationId,
  actions: [mappedAction],
  resource: mappedResource,
  context: selectedPolicyContext,
  agentToken,
});
```

Tool arguments are not copied into policy context automatically. Select the exact fields your policy evaluates in `checkInputFn`. This keeps unrelated or sensitive arguments out of the receipt. `agentTokenFn` must read trusted server-side request state; a tool argument is not trusted identity.
When `agentTokenFn` is configured, an error or an empty result denies the tool
before `/check`; it never falls back to an API-key-only request.

Authorization creation stays outside this package. Store the user's Allowly authorization ID in your app, then resolve it in `authorizationIdFn`.

## Local Execute tools

For an Execute receipt with a reported provider outcome, call
`registerLocalExecuteTool` before `attach()`. MCP validates the tool's business
inputs, then the middleware calls `@allowly/sdk`'s `executeHttp`. The SDK
requests Allowly's decision and sends the approved provider request from your
MCP server host. Allowly receives the provider URL origin, path, query,
selected policy input, header names and hashes, body hash and byte count, and
the reported outcome. Provider header values and body bytes stay local. Keep
secrets out of the URL, query, and policy input.

```ts
import { z } from "zod";
import { createHash } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AllowlyMCPMiddleware } from "@allowly/mcp";

const mcp = new McpServer({ name: "order-server", version: "1.0.0" });
const allowly = new AllowlyMCPMiddleware({
  apiKey: process.env.ALLOWLY_API_KEY!,
  userIdFn: ({ extra }) => {
    const id = extra.authInfo?.extra?.userId;
    return typeof id === "string" ? id : null;
  },
  authorizationIdFn: (userId) => getAuthorizationIdForUser(userId),
});
allowly.registerLocalExecuteTool(mcp, "submit_order", {
  inputSchema: { order_id: z.string().min(1) },
  url: "https://provider.example/v1/orders",
  method: "POST",
  enabledExecutableId: "exe_...",
  catalogOperationId: "provider.orders.submit",
  action: "order.submit",
  journalDirectory: "/var/lib/my-mcp/allowly-executions",
  evidenceMode: "receipt",
  operationIdFn: (args, extra) => {
    const principal = extra.authInfo?.extra?.userId;
    if (typeof principal !== "string" || !principal) throw new Error("Identity unavailable");
    return createHash("sha256")
      .update(JSON.stringify([principal, args.order_id]))
      .digest("hex");
  },
  providerHeadersFn: () => {
    const token = process.env.PROVIDER_API_KEY;
    if (!token) throw new Error("Provider credential unavailable");
    return { authorization: `Bearer ${token}`, "content-type": "application/json" };
  },
  bodyFn: (args) => JSON.stringify({ order_id: args.order_id }),
  policyInputFn: (args) => ({ resource: `order:${String(args.order_id)}` }),
});
allowly.attach(mcp.server);
```

Configure the fixed URL, executable, action, and provider credentials on the
server, never as tool arguments. The example derives its operation ID from the
authenticated principal and immutable order ID, so retrying the same order
cannot choose a new ID. The SDK's local journal prevents a second provider
dispatch for that ID. A `not_allowed`,
`unknown`, or failed result is an MCP error. Do not retry an `unknown` result
under a new ID. For witnessed mode, set `evidenceMode: "witnessed"` and provide
`witnessFn`, returning a fresh evidence directory for that operation. The SDK
fails closed if the policy requires a witness and none is configured. Receipt
mode signs the customer runtime's reported HTTP outcome; it has no independent
witness of the provider response.

## SEAL evidence is explicit

This middleware does not send MCP tool arguments or results to SEAL. If your
workflow needs signed evidence for a JSON record, post that chosen record to a
private managed SEAL webhook after the tool completes. Keep the original JSON
in your workflow and keep the webhook URL out of MCP arguments, logs, tickets,
and source control. The webhook path and retry rules are documented at
[allowly.ai/docs/api-reference/seal](https://allowly.ai/docs/api-reference/seal/).

## User IDs

By default, the middleware does not trust tool arguments for identity. Provide `userIdFn` and read identity from the MCP handler's trusted `extra` context, such as `extra.authInfo` or `extra.sessionId`.
