const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const target = "https://api.github.com/repos/octocat/Hello-World/issues?per_page=1&state=all&sort=created&direction=asc";

function element() {
  return {
    textContent: "",
    dataset: {},
    disabled: false,
    childNodes: [],
    listeners: {},
    addEventListener(name, callback) { this.listeners[name] = callback; },
    append(...children) { this.childNodes.push(...children); },
    replaceChildren(...children) { this.childNodes = children; },
  };
}

async function drain() {
  await new Promise((resolve) => setImmediate(resolve));
}

test("readiness refresh preserves the Auth0 result of the completed run", async () => {
  const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
  const script = html.match(/<script>\s*([\s\S]*?)<\/script>/)?.[1];
  assert.ok(script, "the demo must contain its browser script");
  const nodes = new Map();
  const document = {
    querySelector(selector) {
      if (!nodes.has(selector)) nodes.set(selector, element());
      return nodes.get(selector);
    },
    createElement: element,
    createDocumentFragment: element,
  };
  const status = {
    ready: true,
    csrf_token: "local-browser-token",
    api_base_url: "http://127.0.0.1:8892",
    target_url: target,
    action: "github.issues.list",
    identity: "Auth0 configured; token not checked yet",
    existing_workspace: true,
    signer_mode: "local_test",
    notary_fingerprint: "a".repeat(64),
  };
  const replies = [
    ["/api/status", 200, status],
    ["/api/run", 202, { run_id: "run-1" }],
    ["/api/run/run-1", 200, {
      run_id: "run-1", operation_id: "run-1", state: "complete", stage: "complete",
      policy_decision: "allow", report_state: "accepted", witness_verified: true,
      receipt_state: "unverified", identity_verification: "accepted_by_runtime",
      http_status: 200, events: [],
    }],
    ["/api/status", 200, status],
  ];
  const fetch = async (url) => {
    const [expected, code, payload] = replies.shift() || [];
    assert.equal(url, expected);
    return { ok: code < 400, status: code, text: async () => JSON.stringify(payload) };
  };
  const window = {
    setTimeout() { return 1; },
    clearTimeout() {},
    addEventListener() {},
  };
  vm.runInNewContext(script, { document, window, fetch, AbortController, DOMException });
  await drain();
  assert.equal(nodes.get("#identity-value").textContent, status.identity);
  await nodes.get("#run-button").listeners.click();
  assert.equal(nodes.get("#identity-value").textContent,
    "Auth0 machine token accepted by Allowly");
  assert.equal(nodes.get("#run-state").textContent, "complete");
  assert.equal(nodes.get("#service-status-text").textContent,
    "Run complete · witness verified; receipts unverified");
  assert.equal(replies.length, 0);
});
