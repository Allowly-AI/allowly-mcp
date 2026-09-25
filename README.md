# @allowly/mcp

Allowly guardrail middleware for MCP tool calls.

Use this package when you already have an MCP server and want each tool call to pass through Allowly before the tool runs. The MCP tool name is the default action name. Use `checkInputFn` when your policy needs a different action, resource, or selected input fields.

This is the TypeScript MCP middleware, separate from `@allowly/sdk` because npm has no extras. The Python equivalent ships inside the Python SDK as `allowly[fastmcp]`.

## Install

```bash
npm install @allowly/mcp @allowly/sdk @modelcontextprotocol/sdk
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

## SEAL evidence is explicit

This middleware does not send MCP tool arguments or results to SEAL. If your
workflow needs signed evidence for a JSON record, post that chosen record to a
private managed SEAL webhook after the tool completes. Keep the original JSON
in your workflow and keep the webhook URL out of MCP arguments, logs, tickets,
and source control. The webhook path and retry rules are documented at
[allowly.ai/docs/api-reference/seal](https://allowly.ai/docs/api-reference/seal/).

## User IDs

By default, the middleware does not trust tool arguments for identity. Provide `userIdFn` and read identity from the MCP handler's trusted `extra` context, such as `extra.authInfo` or `extra.sessionId`.
