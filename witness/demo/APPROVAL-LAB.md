# HTML approval lab

This is an independent client for native Execute continuation. It does not
call n8n or install a Slack app. Local mode does not change production. It uses
the Python SDK and a local LangGraph SQLite checkpointer. No LLM or hosted
LangGraph service runs.

The fixed provider action is a public HTTPS GET of one issue from
`octocat/Hello-World`. Provider credentials are not needed. This lab uses
**receipt mode**, not a TLS witness. An outcome receipt records the customer's
reported response; it is not independent proof of the GitHub exchange.

## Requirements

Use Python SDK 0.7.0 and verifier 4.3.1 from PyPI with a runtime supporting native
continuation. Use Python 3.12 on Linux or macOS. The API database needs migration
`0067_execute_continuation`; for a local experiment, use a separate test database
rather than migrating the shared local app.

From this repository's `witness/` directory, install the pinned released packages
in a private environment:

```bash
python3.12 -m venv /absolute/private/html-lab-venv
/absolute/private/html-lab-venv/bin/python -m pip install -r demo/requirements-approval-lab.txt
```

Do not enable tracing: private checkpoints contain the saved request and
confirmation token.

The private configuration is a mode-0600 JSON file, outside Git:

```json
{
  "api_base_url": "http://127.0.0.1:8095",
  "api_key": "LOCAL_TEST_RUNTIME_KEY",
  "workspace_id": "ws_...",
  "enabled_executable_id": "exe_...",
  "action": "github.read",
  "resource": "github:octocat/Hello-World",
  "scenarios": {
    "confirm": {"authorization_id": "auth_...", "context": {}},
    "escalate": {"authorization_id": "auth_...", "context": {}}
  }
}
```

Each authorization must bind the same enabled executable and fixed GitHub
catalog operation, allow receipt evidence, and evaluate to the named review
kind with its configured input. The adapter refuses an unexpected initial
Allow before the SDK can dispatch. An identity-bound authorization also needs
its existing protected agent credential configuration.

From `witness/`, start the adapter with that environment:

```bash
/absolute/private/html-lab-venv/bin/python demo/approval_lab.py \
  --config /absolute/private/lab-config.json \
  --state-dir /absolute/private/html-lab-state \
  --port 8812
```

Open `http://127.0.0.1:8812`, not `localhost`. Host, Origin, and the local form
token are checked. Keep the server running while using the page.

## Test

1. Start Confirm or Escalate. Wait for `waiting_for_review` and zero dispatch
   attempts in the local SDK journal.
2. Approve. The buttons hide immediately. The adapter records the choice, then
   continues the same operation through Allowly. A successful public read shows
   HTTP 200 and one journal dispatch attempt.
3. Start a separate run and Reject. It must show `rejected`, with no dispatch.
4. Refresh the page or restart the adapter with the same state directory. Saved
   operations must restore without creating another request. Never retry an
   unknown result under a new operation ID.

The review is by a **customer-declared local test reviewer**, not an
authenticated dashboard human. Signed receipts require a signing worker;
without one they remain pending and unverified. The displayed dispatch count
comes from the SDK journal, not an independent network observer.

The checkpoint and SDK journal stay private. Do not publish the state directory,
configuration, database snapshot, or confirmation token. Keep the same original
request and configuration when recovering a saved run; changed input stops it.

## Focused tests

From `witness/`, using the same environment and Node 24:

```bash
/absolute/private/html-lab-venv/bin/python -m pip install pytest==8.4.2
/absolute/private/html-lab-venv/bin/python -m pytest -q demo/test_approval_lab.py demo/test_approval_hosted.py
node --test demo/test_approval_index.cjs demo/test_index.cjs
```

## Hosted client with existing Slack reviews

Hosted mode is a **customer-run client**, not another Allowly backend. It calls
the existing HTTPS runtime; the existing Allowly control plane routes each
review to the agent owner or escalation owner in Slack. This page only starts
the fixed read and shows its saved state. It has no Approve/Reject resolver in
hosted mode, even if someone sends that POST directly.

Python SDK 0.7.0 and verifier 4.3.1 are published packages. Installing them does
not update the hosted runtime. Native continuation and migration
`0067_execute_continuation` must be deployed in the workspace's assigned runtime
before this mode is tested; a package release alone does not prove that.

Use an existing production workspace, narrowly scoped runtime key, executable,
and immutable authorizations. Enable the workspace's existing Slack connection
through Allowly Settings. Do not run a second app/API, copy production DBs, or
put this client on the n8n-demo VM. Migration0067 and native continuation must be
deployed in that workspace's assigned runtime before testing this mode.

Add these fields to the protected config, with operator-chosen values:

```json
{
  "api_base_url": "https://api.allowly.ai",
  "external_review": true,
  "public_origin": "https://YOUR_CUSTOMER_CONTROLLED_HOST",
  "browser_auth_file": "/etc/allowly-approval/browser-auth.json"
}
```

The origin must be HTTPS with no path, query, credentials, or trailing slash.
All existing workspace/key/action/scenario fields remain required. The browser
authentication file is separate, owned by the runtime user with mode 0600:

```json
{"username":"OPERATOR_CHOSEN_USER","password":"FRESH_RANDOM_URL_SAFE_PASSWORD_AT_LEAST_32_CHARACTERS"}
```

Generate a fresh random password in your secret manager. Do not reuse your
Allowly login, runtime key, or provider credentials. HTTP Basic Auth is only
suitable behind HTTPS on a trusted customer host. It is one shared lab/operator
login, not workspace role management and not verified Slack reviewer identity.
Every GET/POST, including HTML and CSRF status, requires it. POST also requires
the same-origin CSRF token. Runtime keys, agent credentials and confirmation
nonces never go to the browser or proxy config. `X-Forwarded-*` headers are not
trusted for authentication, Host, or Origin.

The listener always binds 127.0.0.1. Publish only the HTTPS reverse proxy, never
port 8812. Put TLS certificates, browser authentication and state on protected
persistent storage. One adapter process owns a state directory; it has a file
lock to prevent a second writer. Keep private checkpoint/journal backups
together. Do not copy a live SQLite database file alone.

### Install reviewed source and released packages

Copy these files from a reviewed, pinned repository revision into the install
bundle. The requirements file installs the released SDK and verifier from PyPI:

```text
approval_lab.py
index.html
requirements-approval-lab.txt
APPROVAL-LAB.md
```

Record and independently check source checksums before installing. Never include test
config, keys, checkpoints or the copied local API database. From the reviewed
bundle on a customer-controlled host:

```bash
python3 -m venv /opt/allowly-approval/venv
/opt/allowly-approval/venv/bin/python -m pip install \
  -r requirements-approval-lab.txt
```

For an offline install, download and checksum the published SDK/verifier wheels
and all platform-specific transitive wheels first. Add
`--no-index --find-links /path/to/reviewed-wheelhouse`.
Test on the same OS/Python version used by the customer. The Python dependencies
do not install Allowly's app, API, Slack app, an LLM or hosted LangGraph.

### HTTPS reverse-proxy template

Merge this Nginx snippet into the customer's reviewed TLS configuration. Replace
the hostname/certificate paths; they are not supplied Allowly infrastructure.
Keep a default server that rejects all other hostnames. Check `nginx -t` before
enabling it. Headers are preserved explicitly using Nginx's documented
[proxy settings](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_set_header)
and [TLS directives](https://nginx.org/en/docs/http/ngx_http_ssl_module.html).

```nginx
server {
    listen 443 ssl;
    server_name YOUR_CUSTOMER_CONTROLLED_HOST;
    ssl_certificate /YOUR_PROTECTED_TLS/fullchain.pem;
    ssl_certificate_key /YOUR_PROTECTED_TLS/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 4k;
    client_header_timeout 10s;
    client_body_timeout 10s;
    access_log off;
    location / {
        proxy_pass http://127.0.0.1:8812;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header Authorization $http_authorization;
        proxy_set_header Connection "";
        proxy_set_header X-Forwarded-Host "";
        proxy_set_header X-Forwarded-Proto "";
        proxy_cache off;
        proxy_buffering off;
        proxy_read_timeout 40s;
    }
}
```

Do not serve this app over public HTTP or cache its private responses. Add your
edge's normal rate/connection limits. Do not log authorization headers. Direct
loopback requests still need the configured public Host and browser password;
spoofed forwarded headers do not bypass the checks.

### Linux service template

Create a dedicated non-root `allowly-approval` service user. Make both JSON files
and any agent credential owned by that user, mode 0600, outside the bundle.
Install reviewed bundle files in `/opt/allowly-approval` read-only to that user.
The state directory must be owner-only and persistent. Adjust paths for the
customer's host and validate this template with their systemd tooling:

```ini
[Unit]
Description=Customer Allowly approval continuation lab
After=network-online.target
Wants=network-online.target

[Service]
User=allowly-approval
Group=allowly-approval
WorkingDirectory=/opt/allowly-approval
ExecStart=/opt/allowly-approval/venv/bin/python /opt/allowly-approval/approval_lab.py --config /etc/allowly-approval/config.json --state-dir /var/lib/allowly-approval --port 8812
StateDirectory=allowly-approval
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/allowly-approval
Restart=on-failure
TimeoutStopSec=45

[Install]
WantedBy=multi-user.target
```

### Acceptance and operation

1. Without browser credentials, HTML/status/job routes must return 401. With
   credentials, wrong Host/Origin or missing CSRF must return 403. A direct
   hosted `/resolve` must return 403 even with correct auth/CSRF.
2. Start one Confirm and one Escalate. Both must wait with zero SDK dispatch
   intent. Their existing Slack reviews must show the fixed request and policy
   condition. This page has no local decision buttons.
3. Approve in Slack. The adapter polls the bound monitor every five seconds,
   even with the browser closed, and continues the same operation through the
   SDK. A status notification is not permission; the runtime checks current
   policy again before one dispatch claim.
4. Reject a separate review in Slack. It must stop with no provider send.
   Test revoked/expired grants, unavailable status, refresh/restart and duplicate
   notification. Unknown/attempted sends are recovery-only; never give them a
   replacement operation ID or automatic provider retry.
5. Use the same private state/config on restart. If a request/config changes,
   recovery stops. If a journal is missing, prior send count is unknown. Inspect
   the saved outcome and original API operation; do not delete state to rerun it.

The lab has a fixed read-only target and a maximum of 50 saved runs per state
directory; it is not a general execution service. Job-list responses omit
provider bodies; one selected job returns at most 64 KiB. At capacity, stop new
runs, finish/reconcile existing jobs, and archive a consistent private backup
before an operator starts a new test-state directory. Never use that as retry
for an old uncertain operation. Signing/verified receipt checks remain separate;
pending or present signatures must not be displayed as verified evidence.

Focused hosted tests (fake runtime/provider, temporary loopback listener):

```bash
python -m pytest -q demo/test_approval_lab.py demo/test_approval_hosted.py
```

No hosted DNS/TLS/service installation or production acceptance is performed by
building these files. Operator hostname, certificates, runtime credentials and
existing Slack routing must be configured and checked in an approved rollout.
