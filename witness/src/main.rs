//! Experimental separate-process TLSNotary MPC witness. No production receipts.
mod evidence;
mod execute;
mod kms;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    future::IntoFuture,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider,
        request::{Request as AttestationRequest, RequestConfig},
        signing::{Secp256r1Signer, SignatureAlgId, Signer},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig, verifier::VerifierConfig,
    },
    connection::{CertBinding, ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::ProverOutput,
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;

const MAX_FRAME: usize = 1024 * 1024;
const SESSION_TIMEOUT: Duration = Duration::from_secs(150);

// Tokio detaches tasks when their JoinHandle is dropped. Keep this guard alive
// across every await so errors and outer session timeouts close their sockets.
struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Parser)]
#[command(about = "Experimental Allowly TLSNotary witness PoC")]
struct Args {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Online verifier; its key never enters the customer MCP process.
    Witness {
        #[arg(long, default_value = "127.0.0.1:7047")]
        listen: SocketAddr,
        #[arg(long)]
        public_key: PathBuf,
        #[arg(
            long,
            conflicts_with = "kms_key_version",
            required_unless_present = "kms_key_version"
        )]
        local_test_key: bool,
        #[arg(long)]
        kms_key_version: Option<String>,
        #[arg(long, default_value = ".venv/bin/python")]
        kms_python: String,
        #[arg(long, default_value = "kms/gcp_signer.py")]
        kms_helper: PathBuf,
        #[arg(long)]
        fixture: bool,
        /// Trusted runtime-owned approval. A single-use, privately admitted session.
        #[arg(long)]
        execution_approval: Option<PathBuf>,
        /// Private supervisor readiness file, including the allocated port.
        #[arg(long)]
        ready_file: Option<PathBuf>,
    },
    /// Fixed credential-free HTTPS GET, witnessed before a successful result.
    Prove {
        #[arg(long, default_value = "127.0.0.1:7047")]
        witness: SocketAddr,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long)]
        fixture: bool,
    },
    Verify {
        #[arg(long)]
        presentation: PathBuf,
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long)]
        fixture: bool,
    },
    /// Customer-side execution; stdin carries approval plus private request values.
    ProveExecute {
        #[arg(long)]
        witness: Option<SocketAddr>,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        trusted_key: PathBuf,
        /// Pinned local CA for the witness WebSocket only; provider TLS roots are unchanged.
        #[arg(long)]
        witness_ca_cert: Option<PathBuf>,
        #[arg(long)]
        fixture: bool,
    },
    /// Verify the full customer-held transcript against an independently obtained approval.
    VerifyExecute {
        #[arg(long)]
        presentation: PathBuf,
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        fixture: bool,
    },
    /// Verify the notary signature/reference only. Does not verify private HTTP values.
    VerifyExecuteAttestation {
        #[arg(long)]
        attestation: PathBuf,
        #[arg(long)]
        trusted_key: PathBuf,
        #[arg(long)]
        approval: PathBuf,
        #[arg(long)]
        fixture: bool,
    },
    /// Local HTTPS fixture using upstream public test certificates only.
    Fixture,
}

fn roots(fixture: bool) -> RootCertStore {
    if fixture {
        RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        }
    } else {
        RootCertStore::mozilla()
    }
}
fn destination(fixture: bool) -> (&'static str, &'static str, u16, &'static str) {
    if fixture {
        (SERVER_DOMAIN, "127.0.0.1", 3000, "/formats/json")
    } else {
        ("example.com", "example.com", 443, "/")
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}
async fn send_frame<S: AsyncWrite + Unpin, T: Serialize>(socket: &mut S, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_FRAME, "protocol frame exceeds limit");
    socket
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    socket.write_all(&bytes).await?;
    socket.flush().await?;
    Ok(())
}
async fn read_frame<S: AsyncRead + Unpin, T: DeserializeOwned>(socket: &mut S) -> Result<T> {
    let mut size = [0; 4];
    socket.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    ensure!(size <= MAX_FRAME, "protocol frame exceeds limit");
    let mut bytes = vec![0; size];
    socket.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command {
        Command::Fixture => {
            let listener = TcpListener::bind("127.0.0.1:3000").await?;
            eprintln!("Test HTTPS fixture listening on 127.0.0.1:3000");
            loop {
                let (socket, _) = listener.accept().await?;
                tokio::spawn(async move {
                    let _ = tlsn_server_fixture::bind(socket.compat()).await;
                });
            }
        }
        Command::Witness {
            listen,
            public_key,
            local_test_key,
            kms_key_version,
            kms_python,
            kms_helper,
            fixture,
            execution_approval,
            ready_file,
        } => {
            ensure!(
                listen.ip().is_loopback(),
                "PoC witness must bind to loopback; use a private authenticated tunnel between hosts"
            );
            ensure!(
                !local_test_key || fixture,
                "local test signing keys require explicit fixture mode"
            );
            let signer: Box<dyn Signer + Send + Sync> = if local_test_key {
                let key = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
                Box::new(Secp256r1Signer::new(&key.to_bytes())?)
            } else {
                kms::build_kms_signer(
                    &kms_python,
                    &kms_helper,
                    &kms_key_version.context("missing dedicated KMS version")?,
                )?
            };
            let public = signer.verifying_key();
            let mut provider = CryptoProvider::default();
            provider.signer.set_signer(signer);
            let provider = Arc::new(provider);
            let execution = execution_approval
                .as_deref()
                .map(execute::Approval::read)
                .transpose()?;
            if let Some(binding) = &execution {
                binding.live()?;
            }
            // Public key is provisioned separately; never included as a bundle trust anchor.
            let listener = TcpListener::bind(listen).await?;
            write_new(&public_key, &serde_json::to_vec_pretty(&public)?)?;
            if let Some(path) = ready_file {
                use sha2::{Digest, Sha256};
                write_new(
                    &path,
                    &serde_json::to_vec(&serde_json::json!({
                        "listen":listener.local_addr()?.to_string(),
                        "signer_fingerprint_sha256":hex::encode(Sha256::digest(evidence::normalized_key(&public)?))
                    }))?,
                )?;
            }
            eprintln!(
                "Witness ready on {listen}; signer={}",
                if local_test_key {
                    "LOCAL TEST ONLY"
                } else {
                    "Google Cloud KMS"
                }
            );
            loop {
                let (socket, _) = listener.accept().await?;
                // Deliberately one session at a time in this small PoC.
                match tokio::time::timeout(
                    SESSION_TIMEOUT,
                    notarize(socket, provider.clone(), fixture, execution.as_ref()),
                )
                .await
                {
                    Ok(Ok(())) => eprintln!("TLSNotary attestation issued"),
                    Ok(Err(err)) => eprintln!("Witness session failed: {err}"),
                    Err(_) => eprintln!("Witness session timed out"),
                }
                // Runtime admission owns retries. Never reopen a consumed session.
                if execution.is_some() {
                    break;
                }
            }
        }
        Command::Prove {
            witness,
            output,
            trusted_key,
            fixture,
        } => {
            ensure!(
                witness.ip().is_loopback(),
                "PoC client requires loopback witness or private tunnel"
            );
            // Fail before dispatch if trust configuration is absent or malformed.
            let _: tlsn::attestation::signing::VerifyingKey =
                serde_json::from_slice(&std::fs::read(&trusted_key)?)?;
            let result = tokio::time::timeout(
                SESSION_TIMEOUT,
                prove(witness, &output, &trusted_key, fixture, None),
            )
            .await??;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::Verify {
            presentation,
            trusted_key,
            fixture,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&evidence::verify(
                    &presentation,
                    &trusted_key,
                    fixture
                )?)?
            );
        }
        Command::ProveExecute {
            witness,
            output,
            trusted_key,
            witness_ca_cert,
            fixture,
        } => {
            use std::io::Read;
            let mut input = Vec::new();
            std::io::stdin()
                .take(128 * 1024 + 1)
                .read_to_end(&mut input)?;
            ensure!(input.len() <= 128 * 1024, "execute input exceeds bound");
            let input: execute::Input = serde_json::from_slice(&input)?;
            ensure!(
                fixture || input.require_dispatch_ack,
                "production execute requires the remote dispatch acknowledgement gate"
            );
            input.binding.live()?;
            execute::build_request(&input.binding, &input.request)?;
            let _: tlsn::attestation::signing::VerifyingKey =
                serde_json::from_slice(&evidence::read_bounded(&trusted_key, 4096)?)?;
            ensure!(
                witness.is_some() != input.witness.is_some(),
                "provide exactly one admitted witness transport"
            );
            // Reject reuse before any network I/O; an earlier uncertain write is not a retry.
            std::fs::create_dir(&output).context("execution evidence directory must be new")?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700))?;
            }
            let result = tokio::time::timeout(SESSION_TIMEOUT, async {
                let (witness, _bridge_abort) = if let Some(session) = &input.witness {
                    let (address, task) =
                        execute::witness_bridge(session, fixture, witness_ca_cert.as_deref())
                            .await?;
                    (address, Some(AbortOnDrop(task.abort_handle())))
                } else {
                    ensure!(
                        witness_ca_cert.is_none(),
                        "witness CA certificate requires a WebSocket witness session"
                    );
                    let address = witness.context("missing witness")?;
                    ensure!(
                        address.ip().is_loopback(),
                        "use an authenticated private witness tunnel"
                    );
                    (address, None)
                };
                prove(witness, &output, &trusted_key, fixture, Some(&input)).await
            })
            .await??;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::VerifyExecute {
            presentation,
            trusted_key,
            approval,
            fixture,
        } => {
            let binding = execute::Approval::read(&approval)?;
            println!(
                "{}",
                serde_json::to_string(&execute::verify(
                    &presentation,
                    &trusted_key,
                    &binding,
                    fixture,
                    false
                )?)?
            );
        }
        Command::VerifyExecuteAttestation {
            attestation,
            trusted_key,
            approval,
            fixture,
        } => {
            let binding = execute::Approval::read(&approval)?;
            println!(
                "{}",
                serde_json::to_string(&execute::verify(
                    &attestation,
                    &trusted_key,
                    &binding,
                    fixture,
                    true
                )?)?
            );
        }
    }
    Ok(())
}

async fn prove(
    witness: SocketAddr,
    output: &Path,
    trusted_key: &Path,
    fixture: bool,
    execution: Option<&execute::Input>,
) -> Result<serde_json::Value> {
    // Optional local diagnostics, outside every signed evidence structure.
    let mut timings = serde_json::Map::new();
    let mut previous = Instant::now();
    let mut lap = |name: &str| {
        let now = Instant::now();
        timings.insert(
            name.to_owned(),
            serde_json::json!((now - previous).as_secs_f64() * 1000.0),
        );
        previous = now;
    };
    let (demo_domain, host, port, path) = destination(fixture);
    let domain = match execution {
        Some(input) => input.binding.domain()?,
        None => demo_domain,
    };
    // The witness session must be available before any destination connection.
    let mut witness_socket = TcpStream::connect(witness).await?.compat();
    if let Some(input) = execution {
        input.binding.live()?;
        send_frame(&mut witness_socket, &input.binding.approval_sha256).await?;
        let accepted: bool = read_frame(&mut witness_socket).await?;
        ensure!(accepted, "witness admission refused");
    }
    let session = Session::new(witness_socket);
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let _driver_abort = AbortOnDrop(driver_task.abort_handle());
    lap("witness_connect");
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(execute::MAX_SENT)
                .max_recv_data(execute::MAX_RECV)
                .build()?,
        )
        .await?;
    lap("mpc_setup");
    if let Some(input) = execution {
        if input.require_dispatch_ack {
            execute::wait_dispatch_ack(output, &input.binding).await?;
        }
    }
    let server_socket = match execution {
        Some(input) => {
            input.binding.live()?;
            execute::connect_server(&input.binding, fixture).await?
        }
        None => TcpStream::connect((host, port)).await?,
    };
    lap("destination_connect");
    let server_name = ServerName::Dns(domain.try_into()?);
    let (mut tls, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(server_name.clone())
            .root_store(roots(fixture))
            .build()?,
        server_socket.compat(),
    )?;
    let prover_task = tokio::spawn(prover.into_future());
    let _prover_abort = AbortOnDrop(prover_task.abort_handle());
    let request = match execution {
        Some(input) => {
            input.binding.live()?;
            let request = execute::build_request(&input.binding,&input.request)?;
            write_new(&output.join("dispatch.started.json"),&serde_json::to_vec(&serde_json::json!({"approval_sha256":input.binding.approval_sha256,"state":"dispatch_may_have_started","retry_business_request":false}))?)?;
            request
        },
        None => format!("GET {path} HTTP/1.1\r\nHost: {domain}\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").into_bytes(),
    };
    if let Some(input) = execution {
        // Persisting the marker can block long enough for the approval to expire.
        input.binding.live()?;
    }
    tls.write_all(&request).await?;
    tls.flush().await?;
    let mut response = Vec::new();
    (&mut tls)
        .take((execute::MAX_RECV + 1) as u64)
        .read_to_end(&mut response)
        .await?;
    ensure!(
        response.len() <= execute::MAX_RECV,
        "response exceeds bound"
    );
    if execution.is_some() {
        // Preserve the observed result even if later proof/signing fails.
        write_new(
            &output.join("response.json"),
            &serde_json::to_vec(&evidence::parse_execution_response(&response)?)?,
        )?;
    }
    drop(tls);
    let mut prover = prover_task.await??;
    lap("tls_and_http");
    let sent_len = prover.transcript().sent().len();
    let recv_len = prover.transcript().received().len();
    let mut commitment = TranscriptCommitConfig::builder(prover.transcript());
    commitment
        .commit_sent(0..sent_len)?
        .commit_recv(0..recv_len)?;
    let commitment = commitment.build()?;
    let mut request_config = RequestConfig::builder();
    request_config
        .signature_alg(SignatureAlgId::SECP256R1)
        .transcript_commit(commitment.clone());
    let request_config = request_config.build()?;
    let mut prove_config = ProveConfig::builder(prover.transcript());
    prove_config.server_identity().transcript_commit(commitment);
    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&prove_config.build()?).await?;
    lap("proof_generation");
    let transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;
    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(server_name)
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .context("missing server certificates")?
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .context("missing server signature")?
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let provider = CryptoProvider::default();
    let (request, secrets) = builder.build(&provider)?;
    handle.close();
    let mut socket = driver_task.await??;
    lap("attestation_preparation");
    send_frame(&mut socket, &request).await?;
    let attestation: Attestation = read_frame(&mut socket).await?;
    lap("attestation_wait");
    request.validate(&attestation, &provider)?;
    let mut proof = secrets.transcript_proof_builder();
    proof.reveal_sent(0..sent_len)?.reveal_recv(0..recv_len)?;
    let mut presentation = attestation.presentation_builder(&provider);
    presentation
        .identity_proof(secrets.identity_proof())
        .transcript_proof(proof.build()?);
    let presentation = presentation.build()?;
    std::fs::create_dir_all(output)?;
    let presentation_path = output.join("presentation.json");
    write_new(&presentation_path, &serde_json::to_vec(&presentation)?)?;
    lap("presentation");
    let mut verified = match execution {
        Some(input) => execute::verify(
            &presentation_path,
            trusted_key,
            &input.binding,
            fixture,
            false,
        )?,
        None => evidence::verify(&presentation_path, trusted_key, fixture)?,
    };
    lap("verification");
    write_new(
        &output.join("attestation.json"),
        &serde_json::to_vec_pretty(&attestation)?,
    )?;
    if execution.is_some() {
        verified["attestation_sha256"] = serde_json::json!(execute::digest(&std::fs::read(
            output.join("attestation.json")
        )?));
    }
    verified["evidence_path"] = serde_json::json!(std::fs::canonicalize(&presentation_path)?);
    verified["attestation_path"] =
        serde_json::json!(std::fs::canonicalize(output.join("attestation.json"))?);
    write_new(
        &output.join("verified.json"),
        &serde_json::to_vec_pretty(&verified)?,
    )?;
    lap("save_artifacts");
    if std::env::var("ALLOWLY_TIMINGS").as_deref() == Ok("1") {
        eprintln!(
            "ALLOWLY_TIMING {}",
            serde_json::json!({"kind": "prover", "phase_ms": timings})
        );
    }
    // Secrets remain in memory and are never exported.
    Ok(verified)
}

async fn notarize(
    socket: TcpStream,
    provider: Arc<CryptoProvider>,
    fixture: bool,
    execution: Option<&execute::Approval>,
) -> Result<()> {
    let mut socket = socket.compat();
    if let Some(binding) = execution {
        binding.live()?;
        let fingerprint: String = read_frame(&mut socket).await?;
        ensure!(
            fingerprint == binding.approval_sha256,
            "wrong admitted approval"
        );
        send_frame(&mut socket, &true).await?;
    }
    let session = Session::new(socket);
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);
    let _driver_abort = AbortOnDrop(driver_task.abort_handle());
    let verifier = handle.new_verifier(
        VerifierConfig::builder()
            .root_store(roots(fixture))
            .build()?,
    )?;
    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(verifier) => {
            let config = verifier.config();
            if config.max_sent_data() > execute::MAX_SENT
                || config.max_recv_data() > execute::MAX_RECV
            {
                verifier
                    .reject(Some("PoC transcript limits exceeded"))
                    .await?;
                bail!("oversized session refused");
            }
            verifier.accept().await?.run().await?
        }
        VerifierCommitStart::Proxy(verifier) => {
            verifier
                .reject(Some("MPC only; proxy mode disabled"))
                .await?;
            bail!("proxy mode refused");
        }
    };
    let (verified, verifier) = verifier.verify().await?.accept().await?;
    ensure!(
        verified.server_name
            == Some(ServerName::Dns(
                match execution {
                    Some(binding) => binding.domain()?,
                    None => destination(fixture).0,
                }
                .try_into()?
            )),
        "destination identity refused"
    );
    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;
    let sent = tls_transcript
        .sent()
        .iter()
        .filter(|r| r.typ == ContentType::ApplicationData)
        .map(|r| r.ciphertext.len())
        .sum::<usize>();
    let received = tls_transcript
        .recv()
        .iter()
        .filter(|r| r.typ == ContentType::ApplicationData)
        .map(|r| r.ciphertext.len())
        .sum::<usize>();
    handle.close();
    let mut socket = driver_task.await??;
    let request: AttestationRequest = read_frame(&mut socket).await?;
    let extension = execution
        .map(|binding| binding.extension(binding.domain()?))
        .transpose()?;
    if let Some(binding) = execution {
        let (issued, expires) = binding.window()?;
        let at = tls_transcript.time() as i64;
        ensure!(
            issued <= at && at < expires,
            "TLS session outside approval validity"
        );
    }
    // Synchronous KMS signing stays off Tokio's async worker threads.
    let attestation = tokio::task::spawn_blocking(move || -> Result<Attestation> {
        let mut config = AttestationConfig::builder();
        config.supported_signature_algs(vec![SignatureAlgId::SECP256R1]);
        let config = config.build()?;
        let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
            bail!("TLS 1.2 required")
        };
        let mut builder = Attestation::builder(&config).accept_request(request)?;
        // This field is supplied only by the admitted witness, never the prover.
        if let Some(extension) = extension {
            builder.extension(extension);
        }
        builder
            .connection_info(ConnectionInfo {
                time: tls_transcript.time(),
                version: tls_transcript.version(),
                transcript_length: TranscriptLength {
                    sent: sent as u32,
                    received: received as u32,
                },
            })
            .server_ephemeral_key(binding.server_ephemeral_key.clone())
            .transcript_commitments(verified.transcript_commitments);
        Ok(builder.build(&provider)?)
    })
    .await??;
    send_frame(&mut socket, &attestation).await?;
    socket.close().await?;
    Ok(())
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use tokio::io::AsyncReadExt as _;

    #[tokio::test]
    async fn session_timeout_aborts_spawned_task_and_closes_its_socket() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let mut peer = TcpStream::connect(listener.local_addr()?).await?;
        let (mut owned_socket, _) = listener.accept().await?;
        let task = tokio::spawn(async move {
            let mut byte = [0];
            // A stalled peer keeps this task alive until the guard aborts it.
            owned_socket.read_exact(&mut byte).await
        });
        let task_status = task.abort_handle();
        let result = tokio::time::timeout(Duration::from_millis(20), async {
            let _abort = AbortOnDrop(task.abort_handle());
            task.await
        })
        .await;
        assert!(result.is_err(), "the stalled operation must time out");

        let mut byte = [0];
        let read = tokio::time::timeout(Duration::from_secs(1), peer.read(&mut byte)).await??;
        assert_eq!(read, 0, "the aborted task must drop its socket");
        assert!(
            task_status.is_finished(),
            "the task must be reaped, not detached"
        );
        Ok(())
    }
}
