# @allowly/mcp

Allowly guardrail middleware for MCP tool calls.

Use this package when you already have an MCP server and want each tool call to pass through Allowly before the tool runs. The MCP tool name is sent to Allowly as the action name.

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
});

allowly.attach(mcp.server);
```

Register tools before calling `attach()`; the middleware fails fast when there is no tool handler to wrap.

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

By default, the middleware does not trust tool arguments for identity. Provide `userIdFn` and read identity from the MCP handler's trusted `extra` context, such as `extra.authInfo` or `extra.sessionId`.

`allowUserIdArgument` exists only for simple local demos and legacy wrappers. Avoid it for production systems.
