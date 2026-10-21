# @allowly/mcp

One Allowly MCP package for checked tools and customer-side Execute.

Use this package when you already have an MCP server and want each tool call to pass through Allowly before the tool runs. The MCP tool name is the default action name. Use `checkInputFn` when your policy needs a different action, resource, or selected input fields.

This is the TypeScript MCP integration, separate from `@allowly/sdk` because npm has no extras. The Python check-only equivalent ships inside the Python SDK as `allowly[fastmcp]`.

Local Execute tools use `receipt`: an Allowly decision before the call and a
signed customer-reported outcome after it.

Ordinary tools wrapped with `attach()` still use the before-only `/check` flow.

## Install

```bash
npm install @allowly/mcp@0.5.1 @allowly/sdk@^0.8.0 @modelcontextprotocol/sdk zod
```

`@allowly/mcp` is ESM-only and requires Node.js 20 or newer.

Receipt mode needs no native executable.

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

Authorization creation stays outside this package. Use the SDK to select an exact logical `policy_id` and positive integer `policy_version`, with an optional list of action names from that retained edition. Inline rules or decision flags are not grant inputs. Store the returned raw `policy_ref` with the user's authorization ID, then resolve that ID in `authorizationIdFn`. Setup credentials author policy definitions; runtime API keys create grants and check them. Policy Preview is provisional OPA evidence, not permission to run a tool.

## Local Execute tools

For an Execute receipt with a reported provider outcome, call
`registerLocalExecuteTool` before `attach()`. MCP validates the tool's business
inputs, then the middleware calls `@allowly/sdk`'s `executeHttp`. The SDK
requests Allowly's decision and sends the approved provider request from your
MCP server host. Allowly receives the provider URL origin, path, query,
selected policy input, header names and hashes, body hash and byte count, and
the reported outcome. Provider header values and request body bytes are not
uploaded to Allowly. The MCP tool result includes the observed provider response
bytes. Keep secrets out of the URL, query, and policy input.

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
under a new ID. Receipt mode signs the customer runtime's reported HTTP
outcome; it does not independently observe the provider response.

An observed 2xx provider response remains a successful MCP result when its
outcome upload is pending. That result has `outcomePending: true` and
`response: null`; Allowly has not confirmed the report. Reuse the same operation
ID to retry the saved report without sending another provider request. Provider
response bytes are available only on the call that observed them, not a journal
retry.

A reported provider response does not independently prove execution or business completion. The customer must close every alternative provider route.

## SEAL evidence is explicit

This middleware does not send MCP tool arguments or results to SEAL. If your
workflow needs signed evidence for a JSON record, post that chosen record to a
private managed SEAL webhook after the tool completes. Keep the original JSON
in your workflow and keep the webhook URL out of MCP arguments, logs, tickets,
and source control. The webhook path and retry rules are documented at
[allowly.ai/docs/api-reference/seal](https://allowly.ai/docs/api-reference/seal/).

## User IDs

By default, the middleware does not trust tool arguments for identity. Provide `userIdFn` and read identity from the MCP handler's trusted `extra` context, such as `extra.authInfo` or `extra.sessionId`.
## Development dependencies

Published MCP 0.5.1 uses SDK 0.8.x. This development source requires SDK 0.9.x
and uses SDK 0.9.0 and verifier 5.0.0 from the registry-backed lockfile.
Receipt verification accepts wire 5 only. Signature checks
do not replay policy or prove that a provider request happened. Native OPA
replay is a separate check with the retained policy, input, and engine artifacts.
Sibling-file links are for local development only; do not publish with them.
