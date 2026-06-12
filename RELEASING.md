# Releasing

This package is intended to publish as `@allowly/mcp`.

Before publishing:

1. Ensure `@allowly/sdk` has a compatible published version.
2. Change the local development dependency `"@allowly/sdk": "file:../allowly-sdk-ts"` to the published semver range, for example `"^0.1.0"`.
3. Run `npm test`.
4. Run `npm run typecheck`.
5. Run `npm run build`.
6. Publish with npm provenance from CI.

Keep release-process details here rather than in the user-facing README.
