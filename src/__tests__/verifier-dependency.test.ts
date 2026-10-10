import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decodeReceipt, loadKeysFromJson, verifyReceipt } from "@allowly/sdk";

const vectors = JSON.parse(readFileSync(new URL("../../../allowly-receipt-format/vectors/policy/profile-v1.json", import.meta.url), "utf8"));
describe("local verifier dependency", () => {
  it("uses the real SDK signature verifier for complete wire-5 OPA receipts", async () => {
    const keys = loadKeysFromJson(vectors.public_keys);
    const options = { expectedWorkspaceId: vectors.expected_workspace_id, trustedKeyFingerprints: new Set<string>(vectors.trusted_key_fingerprints), now: new Date(vectors.verification_now) };
    for (const item of vectors.signature_cases) await expect(verifyReceipt(item.receipt, keys, options)).resolves.toEqual(decodeReceipt(item.receipt));
  });
  it("rejects wire4 and changes to the signed immutable policy reference", async () => {
    const keys = loadKeysFromJson(vectors.public_keys);
    const options = { expectedWorkspaceId: vectors.expected_workspace_id, trustedKeyFingerprints: new Set<string>(vectors.trusted_key_fingerprints), now: new Date(vectors.verification_now) };
    const receipt = vectors.signature_cases[0].receipt;
    const claims = decodeReceipt(receipt);
    const changed = (fields: Record<string, unknown>) => ({ ...receipt, payload: Buffer.from(JSON.stringify({ ...claims, ...fields })).toString("base64url") });
    await expect(verifyReceipt(changed({ schema_version: "4" }), keys, options)).rejects.toThrow(/unsupported schema_version/);
    await expect(verifyReceipt(changed({ policy_ref: { ...claims.policy_ref, policy_version: 2 } }), keys, options)).rejects.toThrow(/signature verification failed/);
  });
});
