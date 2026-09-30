//! Experimental witness-only adapter for the TLSNotary P-256 signer interface.
//!
//! The Python helper uses Google ADC and never exports the KMS private key.
//! TLSNotary calls `sign` with its serialized attestation header; these exact
//! bytes go through stdin, without JSON receipt canonicalization or prehashing.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use tlsn_attestation::signing::{
    KeyAlgId, Secp256r1Verifier, Signature, SignatureAlgId, SignatureError, SignatureVerifier,
    Signer, VerifyingKey,
};

const KMS_ALGORITHM: &str = "EC_SIGN_P256_SHA256";

#[derive(Deserialize)]
struct HelperReply {
    key_version: String,
    algorithm: String,
    sec1_hex: Option<String>,
    signature_hex: Option<String>,
    timing_ms: Option<HelperTimings>,
}

/// Numeric diagnostics only; never forward helper messages or signing material.
#[derive(Deserialize, Serialize)]
struct HelperTimings {
    client_auth_init_ms: f64,
    public_key_rpc_and_validation_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sign_rpc_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature_validation_ms: Option<f64>,
    helper_work_total_ms: f64,
}

struct KmsSigner {
    python: String,
    helper: PathBuf,
    key_version: String,
    key: VerifyingKey,
}

impl KmsSigner {
    fn invoke(&self, operation: &str, message: &[u8]) -> Result<HelperReply> {
        ensure!(message.len() <= 65_536, "signing message exceeds PoC limit");
        let helper_started = Instant::now();
        let mut child = Command::new(&self.python)
            .arg(&self.helper)
            .arg(operation)
            .arg("--key-version")
            .arg(&self.key_version)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Auth/API diagnostics must not leak credentials to customer logs.
            .stderr(Stdio::null())
            .spawn()
            .context("could not start witness KMS helper")?;
        let write_result = child
            .stdin
            .take()
            .context("missing helper stdin")?
            .write_all(message);
        if let Err(error) = write_result {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error).context("could not send signing message to KMS helper");
        }
        let deadline = Instant::now() + Duration::from_secs(35);
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("witness KMS helper deadline exceeded");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output()?;
        ensure!(output.status.success(), "witness KMS helper failed");
        ensure!(
            output.stdout.len() <= 4096,
            "KMS helper returned oversized output"
        );
        let reply: HelperReply =
            serde_json::from_slice(&output.stdout).context("invalid KMS helper response")?;
        ensure!(
            reply.key_version == self.key_version,
            "KMS key version mismatch"
        );
        ensure!(reply.algorithm == KMS_ALGORITHM, "KMS algorithm mismatch");
        if std::env::var("ALLOWLY_TIMINGS").as_deref() == Ok("1") {
            eprintln!(
                "ALLOWLY_TIMING {}",
                serde_json::json!({
                    "kind": "kms",
                    "operation": operation,
                    // Includes Python startup/imports, helper work, stdout
                    // decoding, process exit and the 20 ms wait-poll interval.
                    "helper_process_ms": helper_started.elapsed().as_secs_f64() * 1000.0,
                    "timing_ms": reply.timing_ms,
                })
            );
        }
        Ok(reply)
    }
}

/// Construct a P-256 signer from a dedicated KMS key version on the witness.
pub fn build_kms_signer(
    python: &str,
    helper: &Path,
    key_version: &str,
) -> Result<Box<dyn Signer + Send + Sync>> {
    let mut signer = KmsSigner {
        python: python.to_owned(),
        helper: helper.to_path_buf(),
        key_version: key_version.to_owned(),
        key: VerifyingKey {
            alg: KeyAlgId::P256,
            data: Vec::new(),
        },
    };
    let reply = signer.invoke("public", &[])?;
    signer.key.data = hex::decode(reply.sec1_hex.context("KMS helper omitted public key")?)
        .context("invalid KMS public key encoding")?;
    ensure!(
        matches!(signer.key.data.len(), 33 | 65),
        "invalid SEC1 public key length"
    );
    Ok(Box::new(signer))
}

impl Signer for KmsSigner {
    fn alg_id(&self) -> SignatureAlgId {
        SignatureAlgId::SECP256R1
    }

    fn sign(&self, message: &[u8]) -> Result<Signature, SignatureError> {
        let sign = || -> Result<Signature> {
            let reply = self.invoke("sign", message)?;
            let data = hex::decode(
                reply
                    .signature_hex
                    .context("KMS helper omitted signature")?,
            )?;
            // Normal upstream verifier checks the fixed-width signature and
            // the original, unhashed TLSNotary message against the pinned key.
            Secp256r1Verifier.verify(&self.key, message, &data)?;
            Ok(Signature {
                alg: self.alg_id(),
                data,
            })
        };
        sign().map_err(|error| SignatureError::from_str(&error.to_string()))
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct AdapterVector {
        kind: String,
        message_hex: String,
        sec1_hex: String,
        signature_hex: String,
        wrong_sec1_hex: String,
    }

    fn test_signer(scenario: &str) -> Result<Box<dyn Signer + Send + Sync>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let python = root.join(".venv/bin/python");
        ensure!(
            python.exists(),
            "install kms/requirements.txt into the PoC .venv first"
        );
        build_kms_signer(
            python.to_str().unwrap(),
            &root.join("kms/fake_helper_for_rust_tests.py"),
            &format!(
                "projects/test-only/locations/global/keyRings/tests/cryptoKeys/{scenario}/cryptoKeyVersions/1"
            ),
        )
    }

    #[test]
    fn subprocess_bridge_accepts_real_p256_signature_from_fake_kms() {
        let signer = test_signer("good").unwrap();
        let message = b"\x00\xff raw TLSNotary header bytes \n";
        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.alg, SignatureAlgId::SECP256R1);
        Secp256r1Verifier
            .verify(&signer.verifying_key(), message, &signature.data)
            .unwrap();
    }

    #[test]
    fn subprocess_bridge_rejects_public_key_failures() {
        for scenario in [
            "fail-public",
            "wrong-public-version",
            "wrong-public-algorithm",
            "missing-public",
        ] {
            assert!(test_signer(scenario).is_err(), "accepted {scenario}");
        }
    }

    #[test]
    fn subprocess_bridge_rejects_signing_failures() {
        for scenario in [
            "fail-sign",
            "wrong-sign-version",
            "wrong-signing-key",
            "bad-signature",
        ] {
            let signer = test_signer(scenario).unwrap();
            assert!(signer.sign(b"test header").is_err(), "accepted {scenario}");
        }
    }

    #[test]
    fn python_kms_adapter_format_matches_native_tlsnotary_verifier() {
        // Created with Python cryptography's standards-based FakeKms using
        // ECDSA(Prehashed(SHA256)); this is NOT evidence of a Cloud KMS call.
        let vector: AdapterVector =
            serde_json::from_str(include_str!("../kms/adapter_test_vector.json")).unwrap();
        assert_eq!(vector.kind, "LOCAL_FAKE_KMS_ADAPTER_TEST_ONLY");
        let key = VerifyingKey {
            alg: KeyAlgId::P256,
            data: hex::decode(vector.sec1_hex).unwrap(),
        };
        let message = hex::decode(vector.message_hex).unwrap();
        let signature = hex::decode(vector.signature_hex).unwrap();
        Secp256r1Verifier
            .verify(&key, &message, &signature)
            .unwrap();

        let mut changed_message = message.clone();
        changed_message[0] ^= 1;
        assert!(
            Secp256r1Verifier
                .verify(&key, &changed_message, &signature)
                .is_err()
        );
        let mut changed_signature = signature.clone();
        changed_signature[0] ^= 1;
        assert!(
            Secp256r1Verifier
                .verify(&key, &message, &changed_signature)
                .is_err()
        );
        let wrong_key = VerifyingKey {
            alg: KeyAlgId::P256,
            data: hex::decode(vector.wrong_sec1_hex).unwrap(),
        };
        assert!(
            Secp256r1Verifier
                .verify(&wrong_key, &message, &signature)
                .is_err()
        );
    }
}
