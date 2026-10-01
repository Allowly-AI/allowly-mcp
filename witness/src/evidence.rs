//! Offline verification. The notary trust anchor is always a separate input.

use std::{fs::File, io::Read, path::Path};

use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tlsn::{
    attestation::{
        CryptoProvider,
        presentation::Presentation,
        signing::{KeyAlgId, SignatureAlgId, VerifyingKey},
    },
    verifier::ServerCertVerifier,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

const MAX_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;

pub fn verify(presentation_path: &Path, trusted_key_path: &Path, fixture: bool) -> Result<Value> {
    let encoded = read_bounded(presentation_path, MAX_ARTIFACT_BYTES)?;
    let value: Value = serde_json::from_slice(&encoded).context("invalid presentation JSON")?;
    // Upstream expands the compressed transcript when deserializing. Check the
    // expanded lengths BEFORE asking serde to construct a Presentation.
    check_transcript_bounds(&value)?;
    let presentation: Presentation =
        serde_json::from_value(value).context("invalid TLSNotary presentation")?;
    let trusted: VerifyingKey = serde_json::from_slice(&read_bounded(trusted_key_path, 4096)?)
        .context("invalid independently trusted key JSON")?;
    let normalized = normalized_key(&trusted)?;
    ensure!(
        normalized_key(presentation.verifying_key())? == normalized,
        "presentation signer does not match the independently trusted key"
    );

    let provider = if fixture {
        let roots = RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        };
        CryptoProvider {
            cert: ServerCertVerifier::new(&roots)?,
            ..Default::default()
        }
    } else {
        CryptoProvider::default()
    };
    let output = presentation
        .verify(&provider)
        .context("TLSNotary signature, certificate, or transcript verification failed")?;
    ensure!(
        output.attestation.signature.alg == SignatureAlgId::SECP256R1,
        "expected the native TLSNotary P-256/SHA-256 signature algorithm"
    );
    let server = output
        .server_name
        .context("presentation is missing a server identity proof")?
        .to_string();
    let (expected_server, target) = if fixture {
        (SERVER_DOMAIN, "/formats/json")
    } else {
        ("example.com", "/")
    };
    ensure!(
        server == expected_server,
        "server identity is outside the fixed demo scope"
    );
    let transcript = output
        .transcript
        .context("presentation is missing a transcript proof")?;
    ensure!(
        transcript.is_complete(),
        "this PoC requires every request and response byte to be authenticated"
    );
    // These unsafe-named accessors are safe here only because is_complete passed.
    let sent = transcript.sent_unsafe();
    let received = transcript.received_unsafe();
    ensure!(
        sent.len() <= crate::execute::MAX_SENT && received.len() <= crate::execute::MAX_RECV,
        "transcript exceeds the bounded demo size"
    );
    let request = parse_request(sent, expected_server, target)?;
    let response = parse_response(received)?;
    Ok(json!({
        "verified": true,
        "server_name": server,
        "time_unix_seconds": output.connection_info.time,
        "tls_version": output.connection_info.version,
        "trust_mode": if fixture { "explicit_test_fixture_ca" } else { "mozilla_public_roots" },
        "signer_fingerprint_sha256": hex::encode(Sha256::digest(&normalized)),
        "fingerprint_encoding": "sha256(compressed SEC1 P-256 public key)",
        "request": request,
        "response": response,
        "transcript": {
            "fully_authenticated": true,
            "sent_bytes": sent.len(),
            "received_bytes": received.len(),
            "sent_sha256": hex::encode(Sha256::digest(sent)),
            "received_sha256": hex::encode(Sha256::digest(received))
        }
    }))
}

pub(crate) fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("cannot open {}", path.display()))?
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "input file exceeds the size limit");
    Ok(bytes)
}

fn check_transcript_bounds(value: &Value) -> Result<()> {
    let transcript = value
        .pointer("/transcript/transcript")
        .context("presentation is missing the required transcript")?;
    for (name, limit) in [
        ("sent_total", crate::execute::MAX_SENT as u64),
        ("recv_total", crate::execute::MAX_RECV as u64),
    ] {
        let len = transcript
            .get(name)
            .and_then(Value::as_u64)
            .with_context(|| format!("invalid compressed transcript {name}"))?;
        ensure!(
            len > 0 && len <= limit,
            "compressed transcript {name} is outside the demo size limit"
        );
    }
    Ok(())
}

pub(crate) fn normalized_key(key: &VerifyingKey) -> Result<Vec<u8>> {
    ensure!(key.alg == KeyAlgId::P256, "trusted signer must use P-256");
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.data)
        .context("invalid SEC1 P-256 public key")?;
    Ok(key.to_encoded_point(true).as_bytes().to_vec())
}

pub(crate) fn header_value<'a>(
    headers: &'a [httparse::Header<'a>],
    name: &str,
) -> Result<Option<&'a str>> {
    let mut values = headers.iter().filter(|h| h.name.eq_ignore_ascii_case(name));
    let value = values
        .next()
        .map(|h| std::str::from_utf8(h.value))
        .transpose()?;
    ensure!(
        values.next().is_none(),
        "duplicate {name} header is outside the demo scope"
    );
    Ok(value)
}

fn headers_json(headers: &[httparse::Header<'_>]) -> Result<Value> {
    headers
        .iter()
        .map(|h| Ok(json!({"name": h.name, "value": std::str::from_utf8(h.value)?})))
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

fn parse_request(bytes: &[u8], server: &str, target: &str) -> Result<Value> {
    let mut storage = [httparse::EMPTY_HEADER; 32];
    let mut request = httparse::Request::new(&mut storage);
    let end = match request
        .parse(bytes)
        .context("invalid authenticated HTTP request")?
    {
        httparse::Status::Complete(end) => end,
        httparse::Status::Partial => bail!("truncated authenticated HTTP request"),
    };
    ensure!(
        request.method == Some("GET") && request.path == Some(target) && request.version == Some(1),
        "request is outside the fixed GET demo scope"
    );
    ensure!(
        end == bytes.len(),
        "request body or additional requests are not supported"
    );
    ensure!(
        header_value(request.headers, "Host")? == Some(server),
        "HTTP Host does not match the authenticated server identity"
    );
    ensure!(
        header_value(request.headers, "Connection")? == Some("close"),
        "demo request must explicitly close the HTTP connection"
    );
    // Only known, credential-free headers are accepted. No arbitrary header or
    // value from an agent is permitted in this public-evidence demonstration.
    for h in request.headers.iter() {
        let value = std::str::from_utf8(h.value)?;
        let allowed = match h.name.to_ascii_lowercase().as_str() {
            "host" => value == server,
            "connection" => value == "close",
            "accept" => matches!(value, "*/*" | "application/json" | "text/html"),
            "accept-encoding" => value == "identity",
            "user-agent" => value == "allowly-witness-poc",
            _ => false,
        };
        ensure!(
            allowed,
            "request has a header outside the credential-free demo scope"
        );
        header_value(request.headers, h.name)?;
    }
    Ok(json!({"method": "GET", "target": target, "host": server,
        "headers": headers_json(request.headers)?}))
}

fn parse_response(bytes: &[u8]) -> Result<Value> {
    let result = parse_execution_response(bytes)?;
    ensure!(
        result["status"] == 200,
        "demo requires an HTTP/1.1 200 response"
    );
    Ok(result)
}

pub(crate) fn parse_execution_response(bytes: &[u8]) -> Result<Value> {
    let mut storage = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut storage);
    let end = match response
        .parse(bytes)
        .context("invalid authenticated HTTP response")?
    {
        httparse::Status::Complete(end) => end,
        httparse::Status::Partial => bail!("truncated authenticated HTTP response"),
    };
    ensure!(
        response.code.is_some_and(|code| (200..600).contains(&code)) && response.version == Some(1),
        "expected one final HTTP/1.1 response"
    );
    ensure!(
        matches!(
            header_value(response.headers, "Content-Encoding")?,
            None | Some("identity")
        ),
        "compressed response content is outside the demo scope"
    );
    let length = header_value(response.headers, "Content-Length")?;
    let transfer = header_value(response.headers, "Transfer-Encoding")?;
    ensure!(
        length.is_none() || transfer.is_none(),
        "ambiguous HTTP response framing"
    );
    let raw_body = &bytes[end..];
    let (body, framing) =
        if matches!(response.code, Some(204 | 304)) && raw_body.is_empty() && transfer.is_none() {
            (Vec::new(), "no-content")
        } else if let Some(length) = length {
            ensure!(
                !length.is_empty() && length.bytes().all(|b| b.is_ascii_digit()),
                "invalid response Content-Length"
            );
            let length: usize = length.parse()?;
            ensure!(
                length == raw_body.len(),
                "response body length mismatch or extra responses"
            );
            (raw_body.to_vec(), "content-length")
        } else if transfer == Some("chunked") {
            (decode_chunked(raw_body)?, "chunked")
        } else {
            // TLSNotary application bytes alone do not prove a clean transport EOF.
            // Require self-delimiting content, rather than accept a truncated body.
            bail!("response needs Content-Length or a supported chunked encoding");
        };
    let text = std::str::from_utf8(&body).context("demo response is not UTF-8")?;
    Ok(json!({
        "status": response.code,
        "headers": headers_json(response.headers)?,
        "framing": framing,
        "body": text,
        "body_bytes": body.len(),
        "body_sha256": hex::encode(Sha256::digest(&body))
    }))
}

fn decode_chunked(mut bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = bytes
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("truncated HTTP chunk size")?;
        let size = &bytes[..line_end];
        ensure!(
            !size.is_empty() && size.iter().all(u8::is_ascii_hexdigit),
            "chunk extensions or invalid chunk sizes are outside the demo scope"
        );
        let size = usize::from_str_radix(std::str::from_utf8(size)?, 16)?;
        bytes = &bytes[line_end + 2..];
        if size == 0 {
            ensure!(
                bytes == b"\r\n",
                "chunk trailers or extra responses are outside the demo scope"
            );
            return Ok(decoded);
        }
        ensure!(
            size <= bytes.len().saturating_sub(2),
            "truncated HTTP chunk body"
        );
        ensure!(
            &bytes[size..size + 2] == b"\r\n",
            "invalid HTTP chunk delimiter"
        );
        decoded.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_binds_method_target_host_and_rejects_credentials() {
        let good = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
        assert_eq!(
            parse_request(good, "example.com", "/").unwrap()["host"],
            "example.com"
        );
        for bad in [
            "POST / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            "GET /private HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: other.example\r\nConnection: close\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\nHost: example.com\r\nConnection: close\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nAuthorization: secret\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nCookie: secret\r\n\r\n",
            "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\nextra",
        ] {
            assert!(parse_request(bad.as_bytes(), "example.com", "/").is_err());
        }
    }

    #[test]
    fn response_requires_one_complete_successful_message() {
        let good = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(parse_response(good).unwrap()["body"], "hello");
        for bad in [
            "HTTP/1.1 500 Error\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Encoding: gzip\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
        ] {
            assert!(parse_response(bad.as_bytes()).is_err());
        }
    }

    #[test]
    fn chunked_requires_final_chunk_and_no_extra_message() {
        assert_eq!(
            decode_chunked(b"3\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n").unwrap(),
            b"hello"
        );
        for bad in [
            b"3\r\nhel\r\n".as_slice(),
            b"0\r\n\r\nextra",
            b"3\r\nhe",
            b"3\r\nhelXX0\r\n\r\n",
            b"3;extension\r\nhel\r\n0\r\n\r\n",
            b"0\r\nTrailer: value\r\n\r\n",
        ] {
            assert!(decode_chunked(bad).is_err());
        }
    }

    #[test]
    fn malicious_expanded_transcript_lengths_are_rejected_before_deserialization() {
        for length in [0, crate::execute::MAX_RECV as u64 + 1, u64::MAX] {
            let value =
                json!({"transcript": {"transcript": {"sent_total": 50, "recv_total": length}}});
            assert!(check_transcript_bounds(&value).is_err());
        }
        let value = json!({"transcript": {"transcript": {"sent_total": 50, "recv_total": 100}}});
        assert!(check_transcript_bounds(&value).is_ok());
    }

    #[test]
    fn public_key_trust_is_independent_of_sec1_compression() {
        let signing = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let key = signing.verifying_key();
        let compressed = VerifyingKey {
            alg: KeyAlgId::P256,
            data: key.to_encoded_point(true).as_bytes().to_vec(),
        };
        let uncompressed = VerifyingKey {
            alg: KeyAlgId::P256,
            data: key.to_encoded_point(false).as_bytes().to_vec(),
        };
        assert_eq!(
            normalized_key(&compressed).unwrap(),
            normalized_key(&uncompressed).unwrap()
        );
        assert!(
            normalized_key(&VerifyingKey {
                alg: KeyAlgId::K256,
                data: compressed.data
            })
            .is_err()
        );
    }
}
