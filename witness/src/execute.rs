//! Customer-held execution evidence. The online notary signs an approval
//! reference, not a claim that it saw or approved private HTTP plaintext.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tlsn::attestation::{
    Attestation, CryptoProvider, Extension, presentation::Presentation, signing::VerifyingKey,
};

pub const MAX_SENT: usize = 2 * 1024;
pub const MAX_RECV: usize = 16 * 1024;
pub const EXTENSION: &[u8] = b"allowly.execution.binding.v1";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub approval_sha256: String,
    pub approval: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    #[serde(flatten)]
    pub binding: Approval,
    pub request: Request,
    #[serde(default)]
    pub witness: Option<WitnessSession>,
    #[serde(default)]
    pub require_dispatch_ack: bool,
}

pub async fn wait_dispatch_ack(output: &Path, binding: &Approval) -> Result<()> {
    binding.live()?;
    crate::write_new(
        &output.join("witness.ready.json"),
        &serde_json::to_vec(&json!({"approval_sha256":binding.approval_sha256}))?,
    )?;
    let gate = output.join("dispatch.approved.json");
    loop {
        binding.live()?;
        match crate::evidence::read_bounded(&gate, 1024) {
            Ok(bytes) => {
                let ack: Value = serde_json::from_slice(&bytes)?;
                ensure!(
                    ack == json!({"approval_sha256":binding.approval_sha256}),
                    "dispatch acknowledgement does not match approval"
                );
                return Ok(());
            }
            Err(error) => {
                if !error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
                {
                    return Err(error);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSession {
    pub url: String,
    pub session_id: String,
    pub admission_token: String,
    pub workspace_id: String,
}

fn pinned_witness_connector(pem: &[u8]) -> Result<tokio_tungstenite::Connector> {
    use rustls_pki_types::pem::PemObject;
    let mut certificates = rustls_pki_types::CertificateDer::pem_slice_iter(pem);
    let certificate = certificates
        .next()
        .context("missing witness CA certificate")??;
    ensure!(
        certificates.next().is_none(),
        "expected one witness CA certificate"
    );
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
        client,
    )))
}

/// A TLS-authenticated WebSocket carries the native MPC byte stream. The
/// ephemeral loopback bridge is private to this invocation and never retries.
pub async fn witness_bridge(
    session: &WitnessSession,
    fixture: bool,
    witness_ca_cert: Option<&Path>,
) -> Result<(std::net::SocketAddr, tokio::task::JoinHandle<Result<()>>)> {
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};
    let request = session.url.as_str().into_client_request()?;
    let uri = request.uri();
    ensure!(
        uri.scheme_str() == Some("wss")
            || (fixture
                && uri.scheme_str() == Some("ws")
                && matches!(uri.host(), Some("127.0.0.1" | "localhost"))),
        "witness transport requires wss"
    );
    ensure!(
        uri.query().is_none(),
        "witness credentials must not be in a URL"
    );
    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(1024 * 1024))
        .max_frame_size(Some(1024 * 1024));
    let connector = if let Some(ca_file) = witness_ca_cert {
        ensure!(uri.scheme_str() == Some("wss"), "witness CA requires wss");
        let pem = crate::evidence::read_bounded(ca_file, 64 * 1024)?;
        Some(pinned_witness_connector(&pem)?)
    } else {
        None
    };
    let (mut websocket, _) =
        tokio_tungstenite::connect_async_tls_with_config(request, Some(config), true, connector)
            .await?;
    websocket.send(Message::Text(serde_json::to_string(&json!({"session_id":session.session_id,"admission_token":session.admission_token,"workspace_id":session.workspace_id}))?.into())).await?;
    let ready = websocket
        .next()
        .await
        .context("witness admission closed")??;
    ensure!(
        ready.is_text() && serde_json::from_str::<Value>(ready.to_text()?)?["ready"] == true,
        "witness session admission failed"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        drop(listener);
        let (mut reader, mut writer) = socket.into_split();
        let (mut outbound, mut inbound) = websocket.split();
        let upload = async {
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let n = reader.read(&mut buffer).await?;
                if n == 0 {
                    outbound.close().await?;
                    break;
                }
                outbound
                    .send(Message::Binary(buffer[..n].to_vec().into()))
                    .await?;
            }
            Ok::<_, anyhow::Error>(())
        };
        let download = async {
            while let Some(message) = inbound.next().await {
                match message? {
                    Message::Binary(bytes) => writer.write_all(&bytes).await?,
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => {}
                    _ => anyhow::bail!("unexpected witness protocol message"),
                }
            }
            writer.shutdown().await?;
            Ok::<_, anyhow::Error>(())
        };
        tokio::try_join!(upload, download)?;
        Ok(())
    });
    Ok((address, task))
}

pub fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing string {key}"))
}

impl Approval {
    pub fn read(path: &Path) -> Result<Self> {
        let result: Self =
            serde_json::from_slice(&crate::evidence::read_bounded(path, 128 * 1024)?)?;
        result.validate()?;
        Ok(result)
    }

    pub fn validate(&self) -> Result<()> {
        let hash = self
            .approval_sha256
            .strip_prefix("sha256:")
            .context("invalid approval fingerprint")?;
        ensure!(
            hash.len() == 64
                && hash
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "invalid approval fingerprint"
        );
        ensure!(
            digest(&serde_jcs::to_vec(&self.approval)?) == self.approval_sha256,
            "approval contents do not match the canonical approval fingerprint"
        );
        ensure!(
            self.approval["profile"] == "allowly.execution.approval.v1",
            "unsupported approval profile"
        );
        ensure!(
            self.approval["evidence_mode"] == "witnessed",
            "approval does not require witnessed transport"
        );
        self.domain()?;
        self.window()?;
        Ok(())
    }

    pub fn window(&self) -> Result<(i64, i64)> {
        let issued =
            chrono::DateTime::parse_from_rfc3339(string(&self.approval, "issued_at")?)?.timestamp();
        let expires = chrono::DateTime::parse_from_rfc3339(string(&self.approval, "expires_at")?)?
            .timestamp();
        ensure!(issued < expires, "empty approval validity window");
        Ok((issued, expires))
    }

    pub fn live(&self) -> Result<()> {
        self.validate()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;
        let (issued, expires) = self.window()?;
        ensure!(
            issued <= now && now < expires,
            "approval is not currently valid"
        );
        Ok(())
    }

    pub fn domain(&self) -> Result<&str> {
        let origin = string(&self.approval["request"], "origin")?;
        let domain = origin
            .strip_prefix("https://")
            .context("only HTTPS origins are supported")?;
        ensure!(
            domain.len() <= 253
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.'),
            "invalid DNS origin"
        );
        ensure!(
            domain.split('.').all(|label| !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')),
            "origin must be a normalized DNS name on port 443"
        );
        ensure!(
            domain.parse::<IpAddr>().is_err(),
            "literal IP origins are not supported"
        );
        Ok(domain)
    }

    pub fn extension(&self, server_name: &str) -> Result<Extension> {
        Ok(Extension {
            id: EXTENSION.to_vec(),
            value: serde_json::to_vec(&json!({
                "profile": "allowly.execution.binding.v1",
                "approval_sha256": self.approval_sha256,
                "server_name": server_name,
                "request_binding_verification": "customer_held_bundle"
            }))?,
        })
    }
}

fn header_hash(name: &str, value: &str) -> String {
    digest(
        &[
            b"allowly.execution.header.v1\0".as_slice(),
            name.as_bytes(),
            b"\0",
            value.as_bytes(),
        ]
        .concat(),
    )
}

pub fn build_request(binding: &Approval, input: &Request) -> Result<Vec<u8>> {
    binding.validate()?;
    let req = &binding.approval["request"];
    let method = string(req, "method")?;
    ensure!(
        ["GET", "POST", "PUT", "PATCH", "DELETE"].contains(&method),
        "unsupported method"
    );
    let path = string(req, "path")?;
    let query = string(req, "query")?;
    ensure!(
        path.starts_with('/') && !path.starts_with("//") && !path.contains('?'),
        "invalid request path"
    );
    ensure!(!query.starts_with('?'), "query must omit question mark");
    ensure!(
        path.bytes()
            .chain(query.bytes())
            .all(|c| c.is_ascii_graphic() && c != b'#'),
        "path and query must be encoded ASCII without fragments"
    );
    ensure!(
        req["body_size"].as_u64() == Some(input.body.len() as u64)
            && req["body_sha256"] == digest(input.body.as_bytes()),
        "request body differs from approved bytes"
    );
    let headers = req["headers"]
        .as_array()
        .context("missing header commitments")?;
    ensure!(
        headers.len() == input.headers.len(),
        "header set differs from approval"
    );
    let mut previous = "";
    for entry in headers {
        let name = string(entry, "name")?;
        ensure!(
            name > previous,
            "header commitments must be unique and sorted"
        );
        previous = name;
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-'),
            "invalid normalized header name"
        );
        ensure!(
            ![
                "host",
                "content-length",
                "transfer-encoding",
                "connection",
                "keep-alive",
                "te",
                "trailer",
                "upgrade",
                "proxy-authorization",
                "proxy-connection",
                "accept-encoding",
                "expect"
            ]
            .contains(&name),
            "unsafe or derived header supplied"
        );
        let value = input
            .headers
            .get(name)
            .context("approved header is missing")?;
        ensure!(
            value.bytes().all(|c| (0x20..=0x7e).contains(&c)),
            "header value must be visible ASCII"
        );
        ensure!(
            entry["value_sha256"] == header_hash(name, value),
            "request header differs from approval"
        );
    }
    match req.get("content_type").filter(|v| !v.is_null()) {
        Some(content_type) => ensure!(
            content_type.as_str() == input.headers.get("content-type").map(String::as_str),
            "content type differs from approval"
        ),
        None => ensure!(input.body.is_empty(), "body needs an approved content type"),
    }
    let target = if query.is_empty() {
        path.to_owned()
    } else {
        format!("{path}?{query}")
    };
    let mut raw = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n",
        binding.domain()?
    );
    for (name, value) in &input.headers {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str(&format!(
        "Content-Length: {}\r\n\r\n{}",
        input.body.len(),
        input.body
    ));
    ensure!(
        raw.len() <= MAX_SENT,
        "request exceeds native witness capability"
    );
    Ok(raw.into_bytes())
}

// Check the proven bytes themselves; no customer summary stands in for a proof.
fn match_request(binding: &Approval, sent: &[u8]) -> Result<()> {
    let mut storage = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut storage);
    let end = match request.parse(sent)? {
        httparse::Status::Complete(n) => n,
        _ => anyhow::bail!("incomplete request"),
    };
    let mut headers = BTreeMap::new();
    for header in request.headers.iter() {
        crate::evidence::header_value(request.headers, header.name)?;
        let name = header.name.to_ascii_lowercase();
        if !["host", "connection", "accept-encoding", "content-length"].contains(&name.as_str()) {
            ensure!(
                headers
                    .insert(name, std::str::from_utf8(header.value)?.to_owned())
                    .is_none(),
                "duplicate header"
            );
        }
    }
    let body = std::str::from_utf8(&sent[end..])?.to_owned();
    ensure!(
        build_request(binding, &Request { headers, body })? == sent,
        "authenticated HTTP request differs from the approved request profile"
    );
    Ok(())
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168
                        || (b == 0 && (c == 0 || c == 2))
                        || (b == 88 && c == 99 && d == 2)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        // Restrict to ordinary global unicast and exclude special-use space.
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000 == 0x2000)
                && !(s[0] == 0x2001 && s[1] <= 0x01ff)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] <= 0x0fff)
        }
    }
}

pub async fn connect_server(binding: &Approval, fixture: bool) -> Result<tokio::net::TcpStream> {
    if fixture {
        ensure!(
            binding.domain()? == tlsn_server_fixture_certs::SERVER_DOMAIN,
            "fixture domain mismatch"
        );
        return Ok(tokio::net::TcpStream::connect("127.0.0.1:3000").await?);
    }
    let addresses: Vec<_> = tokio::net::lookup_host((binding.domain()?, 443))
        .await?
        .collect();
    ensure!(
        !addresses.is_empty() && addresses.iter().all(|address| public_ip(address.ip())),
        "DNS includes a non-public destination"
    );
    // Use this validated resolution for the connection, never resolve twice.
    Ok(tokio::net::TcpStream::connect(addresses[0]).await?)
}

pub fn verify(
    presentation_path: &Path,
    trusted_key: &Path,
    binding: &Approval,
    fixture: bool,
    compact: bool,
) -> Result<Value> {
    binding.validate()?;
    let encoded = crate::evidence::read_bounded(presentation_path, 16 * 1024 * 1024)?;
    let value: Value = serde_json::from_slice(&encoded)?;
    let provider = if fixture {
        CryptoProvider {
            cert: tlsn::verifier::ServerCertVerifier::new(&crate::roots(true))?,
            ..Default::default()
        }
    } else {
        CryptoProvider::default()
    };
    let presentation: Presentation = if compact {
        let attestation: Attestation = serde_json::from_value(value)?;
        attestation.presentation_builder(&provider).build()?
    } else {
        for (name, max) in [("sent_total", MAX_SENT), ("recv_total", MAX_RECV)] {
            let n = value
                .pointer(&format!("/transcript/transcript/{name}"))
                .and_then(Value::as_u64)
                .context("missing bounded transcript")?;
            ensure!(n > 0 && n <= max as u64, "oversized expanded transcript");
        }
        serde_json::from_value(value)?
    };
    let trusted: VerifyingKey =
        serde_json::from_slice(&crate::evidence::read_bounded(trusted_key, 4096)?)?;
    let normalized = crate::evidence::normalized_key(&trusted)?;
    ensure!(
        crate::evidence::normalized_key(presentation.verifying_key())? == normalized,
        "unexpected notary signer"
    );
    let output = presentation.verify(&provider)?;
    ensure!(
        output.attestation.signature.alg == tlsn::attestation::signing::SignatureAlgId::SECP256R1,
        "unsupported notary signature algorithm"
    );
    let extensions: Vec<_> = output
        .extensions
        .iter()
        .filter(|ext| ext.id == EXTENSION)
        .collect();
    ensure!(
        extensions.len() == 1,
        "exactly one execution binding is required"
    );
    let expected = binding.extension(binding.domain()?)?;
    ensure!(
        extensions[0] == &expected,
        "notary approval reference does not match"
    );
    let (issued, expires) = binding.window()?;
    let at = output.connection_info.time as i64;
    ensure!(
        issued <= at && at < expires,
        "TLS session is outside approval validity"
    );
    let mut result = json!({"verified":true,"approval_sha256":binding.approval_sha256,
        "profile":"customer_held_tlsn_bundle_v1", "artifact_sha256":digest(&encoded),
        "signer_fingerprint_sha256":hex::encode(Sha256::digest(&normalized)),
        "server_name":binding.domain()?, "time_unix_seconds":at,
        "request_binding_verification":if compact {"customer_held_bundle"} else {"verified_from_full_presentation"},
        "trust_mode":if fixture {"explicit_test_fixture_ca"} else {"mozilla_public_roots"}});
    if !compact {
        ensure!(
            output
                .server_name
                .context("missing server identity proof")?
                .to_string()
                == binding.domain()?,
            "wrong TLS server"
        );
        let transcript = output.transcript.context("missing transcript")?;
        ensure!(
            transcript.is_complete(),
            "full customer-held transcript is required"
        );
        match_request(binding, transcript.sent_unsafe())?;
        result["response"] =
            crate::evidence::parse_execution_response(transcript.received_unsafe())?;
        result["sent_sha256"] = json!(digest(transcript.sent_unsafe()));
        result["received_sha256"] = json!(digest(transcript.received_unsafe()));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn witness_ca_accepts_one_root_and_rejects_missing_or_extra_roots() {
        let ca = include_bytes!("../vendor/tlsn/crates/server-fixture/certs/src/tls/root_ca.crt");
        assert!(pinned_witness_connector(ca).is_ok());
        assert!(pinned_witness_connector(b"not a PEM certificate").is_err());
        let mut doubled = ca.to_vec();
        doubled.extend_from_slice(ca);
        assert!(pinned_witness_connector(&doubled).is_err());
    }
    fn approval() -> Approval {
        let mut result = Approval {
            approval_sha256: String::new(),
            approval: json!({
            "profile":"allowly.execution.approval.v1", "evidence_mode":"witnessed",
            "issued_at":"2026-01-01T00:00:00Z", "expires_at":"2027-01-01T00:00:00Z",
            "request":{"origin":"https://example.com", "method":"POST", "path":"/refunds", "query":"", "headers":[
                {"name":"authorization", "value_sha256":header_hash("authorization","Bearer private")},
                {"name":"content-type", "value_sha256":header_hash("content-type","application/json")}],
                "body_sha256":digest(b"{}"),"body_size":2,"content_type":"application/json"}}),
        };
        result.approval_sha256 = digest(&serde_jcs::to_vec(&result.approval).unwrap());
        result
    }
    #[test]
    fn exact_request_binding_rejects_changed_body_header_path_and_extra_bytes() {
        let a = approval();
        let r = Request {
            headers: BTreeMap::from([
                ("authorization".into(), "Bearer private".into()),
                ("content-type".into(), "application/json".into()),
            ]),
            body: "{}".into(),
        };
        let raw = build_request(&a, &r).unwrap();
        match_request(&a, &raw).unwrap();
        for mutated in [
            String::from_utf8(raw.clone()).unwrap().replace("{}", "[]"),
            String::from_utf8(raw.clone())
                .unwrap()
                .replace("private", "changed"),
            String::from_utf8(raw.clone())
                .unwrap()
                .replace("/refunds", "/other"),
            format!("{}extra", String::from_utf8(raw).unwrap()),
        ] {
            assert!(match_request(&a, mutated.as_bytes()).is_err());
        }
    }
    #[test]
    fn dns_address_filter_rejects_internal_and_metadata_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "192.168.2.3",
            "192.88.99.2",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "2001:db8::1",
            "2002:7f00:1::1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ip("1.1.1.1".parse().unwrap()));
        assert!(public_ip("2606:4700:4700::1111".parse().unwrap()));
    }
}
