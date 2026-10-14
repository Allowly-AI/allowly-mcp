# Changelog

## 0.5.1

- Read witnessed demo receipt details only after verifying the original wire-5
  JWS against the configured workspace; keep the original JWS for saved evidence.
- Make the Witness Bridge image health probe use its configured port and TLS
  certificate, including wildcard listeners, and reject invalid certificates.
- Correct development guidance for the published SDK 0.8.0 and verifier 5.0.0.

## 0.5.0

- Require the published SDK 0.8.0 and verify original wire-5 JWS receipts.
  This breaking release uses exact immutable policy editions and OPA evidence.
- Preserve receipt and witnessed Execute modes and fail-closed tool dispatch.
