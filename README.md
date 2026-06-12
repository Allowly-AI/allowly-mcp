# @allowly/mcp

Allowly guardrail middleware for MCP tool calls.

Use this package when you already have an MCP server and want each tool call to pass through Allowly before the tool runs. The MCP tool name is sent to Allowly as the action name.

## Install

```bash
npm install @allowly/mcp @allowly/sdk @modelcontextprotocol/sdk
```

## Usage

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AllowlyMCPMiddleware } from "@allowly/mcp";

const mcp = new McpServer({ name: "my-agent", version: "1.0.0" });

const allowly = new AllowlyMCPMiddleware({
  apiKey: process.env.ALLOWLY_API_KEY!,
  userIdFn: ({ request }) => {
    const req = request as { meta?: { authenticatedUserId?: string } };
    return req.meta?.authenticatedUserId ?? null;
  },
  authorizationIdFn: async (userId) => {
    return getAuthorizationIdForUser(userId);
  },
});

allowly.attach(mcp.server);
```

## Behavior

- `allow`: the original MCP tool handler runs.
- `deny`: the middleware returns an MCP error response with the Allowly reason.
- `confirm`: the middleware returns a confirmation payload with `confirm_nonce`.
- `escalate`: the middleware returns an escalation payload with `escalation_id`.

The middleware calls:

```ts
allowly.check({
  authorizationId,
  actions: [toolName],
});
```

Authorization creation stays outside this package. Store the user's Allowly authorization ID in your app, then resolve it in `authorizationIdFn`.

## User IDs

By default, the middleware does not trust tool arguments for identity. Provide `userIdFn` and read identity from your authenticated request/session context.

`allowUserIdArgument` exists only for simple local demos and legacy wrappers. Avoid it for production systems.
