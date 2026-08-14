use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use h2::{Reason, RecvStream, SendStream};
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode, Uri, Version};

use crate::network::client_resolver::ClientResolver;
use crate::network::policy::ClientNetworkPolicy;
use crate::network::protocol::{NetworkError, NetworkErrorKind};
use crate::network::resolver_protocol::{
    MAX_RESOLVER_REQUEST_BODY_BYTES, MAX_RESOLVER_RESPONSE_BODY_BYTES, RESOLVER_CONTENT_TYPE,
    RESOLVER_REQUEST_AUTHORITY, RESOLVER_REQUEST_PATH, RESOLVER_REQUEST_SCHEME, ResolveOutcome,
    ResolveOutcomeBody, ResolveRequest, ResolveRequestBody, encode_resolve_outcome,
    encode_resolve_request,
};
use crate::network::session::{
    OperatorNetworkSession, map_h2_error, map_session_error, send_h2_data,
};

pub(super) const MAX_CONCURRENT_RESOLVER_REQUESTS: usize =
    crate::network::client_resolver::MAX_CONCURRENT_NATIVE_RESOLVER_LOOKUPS;

const RESOLVER_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(5);
const RESOLVER_RESPONSE_GRACE: Duration = Duration::from_secs(1);
const RESPONSE_CODE_SERVER_FAILURE: u8 = 2;

impl OperatorNetworkSession {
    pub(super) fn acquire_resolver_permit(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, NetworkError> {
        Arc::clone(&self.resolver_permits)
            .try_acquire_owned()
            .map_err(|_| NetworkError::resource_limit("network session resolver limit reached"))
    }

    pub(crate) async fn resolve(
        &self,
        request: ResolveRequest,
    ) -> Result<ResolveOutcome, NetworkError> {
        let _permit = self.acquire_resolver_permit()?;
        let encoded = encode_resolve_request(&request)
            .map_err(|error| protocol_error(format!("invalid resolver request: {error}")))?;
        let timeout = Duration::from_millis(u64::from(request.timeout_millis()))
            .saturating_add(RESOLVER_RESPONSE_GRACE);
        match tokio::time::timeout(timeout, self.resolve_over_stream(encoded)).await {
            Ok(result) => result,
            Err(_) => Err(NetworkError::new(
                NetworkErrorKind::TimedOut,
                format!("timed out resolving {} through the client", request.name()),
            )),
        }
    }

    async fn resolve_over_stream(&self, encoded: Vec<u8>) -> Result<ResolveOutcome, NetworkError> {
        let uri = resolver_uri()?;
        let http_request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_2)
            .uri(uri)
            .header(
                CONTENT_TYPE,
                HeaderValue::from_static(RESOLVER_CONTENT_TYPE),
            )
            .header(CONTENT_LENGTH, encoded.len())
            .body(())
            .map_err(|error| {
                protocol_error(format!("failed to build resolver request: {error}"))
            })?;
        let (response, send) = self.open_request(http_request, false).await?;
        let mut stream = ResolverStreamGuard::new(send);
        send_h2_data(stream.send(), Bytes::from(encoded), true)
            .await
            .map_err(map_session_error)?;
        let response = response.await.map_err(map_h2_error)?;
        if !response.status().is_success() {
            return Err(NetworkError::from_response(
                response.status(),
                response.headers(),
            ));
        }
        validate_resolver_response_head(&response)?;
        let expected_length = parse_content_length(
            response.headers(),
            MAX_RESOLVER_RESPONSE_BODY_BYTES,
            "resolver response",
        )?;
        let mut receive = response.into_body();
        let mut body = ResolveOutcomeBody::new();
        let mut received_length = 0_usize;
        while let Some(frame) = receive.data().await {
            let frame = frame.map_err(map_h2_error)?;
            received_length = received_length
                .checked_add(frame.len())
                .ok_or_else(|| protocol_error("resolver response body length overflow"))?;
            let push_result = body.push(&frame);
            receive
                .flow_control()
                .release_capacity(frame.len())
                .map_err(map_h2_error)?;
            push_result.map_err(|error| {
                protocol_error(format!("invalid resolver response body: {error}"))
            })?;
        }
        let trailers = receive.trailers().await.map_err(map_h2_error)?;
        if trailers.is_some() {
            return Err(protocol_error("resolver response must not carry trailers"));
        }
        validate_received_length(expected_length, received_length, "resolver response")?;
        let outcome = body
            .finish()
            .map_err(|error| protocol_error(format!("invalid resolver response body: {error}")))?;
        stream.finish();
        Ok(outcome)
    }
}

pub(super) fn is_resolver_request<B>(request: &Request<B>) -> bool {
    request.method() == Method::POST
}

pub(super) async fn handle_client_resolver_request(
    request: Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    resolver: Arc<ClientResolver>,
    policy: Arc<ClientNetworkPolicy>,
) -> Result<()> {
    if !policy.allows_resolver_stream() {
        let error =
            NetworkError::policy_denied("approved session does not permit client resolver streams");
        return reject_forbidden_resolver_stream(request, respond, error).await;
    }
    let expected_length = match validate_resolver_request_head(&request) {
        Ok(expected_length) => expected_length,
        Err(error) => {
            return reject_resolver_request(
                respond,
                StatusCode::BAD_REQUEST,
                NetworkError::new(NetworkErrorKind::Protocol, error.message),
            );
        }
    };
    let request = match tokio::time::timeout(
        RESOLVER_REQUEST_BODY_TIMEOUT,
        receive_resolver_request_body(request.into_body(), expected_length),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(ResolverRequestBodyError::Protocol(message))) => {
            return reject_resolver_request(
                respond,
                StatusCode::BAD_REQUEST,
                NetworkError::new(NetworkErrorKind::Protocol, message),
            );
        }
        Ok(Err(ResolverRequestBodyError::Transport(error))) => {
            if error.is_reset() {
                return Ok(());
            }
            return Err(error).context("resolver request body stream failed");
        }
        Err(_) => {
            return reject_resolver_request(
                respond,
                StatusCode::BAD_REQUEST,
                NetworkError::new(
                    NetworkErrorKind::Protocol,
                    "timed out receiving resolver request body",
                ),
            );
        }
    };
    if let Err(error) = policy.authorize_resolver_name(request.name()) {
        return reject_resolver_request(respond, StatusCode::FORBIDDEN, error);
    }
    let resolve_timeout = Duration::from_millis(u64::from(request.timeout_millis()));
    let outcome = tokio::select! {
        biased;
        reset = std::future::poll_fn(|context| respond.poll_reset(context)) => {
            reset.context("resolver request was cancelled by a broken HTTP/2 session")?;
            return Ok(());
        },
        outcome = tokio::time::timeout(resolve_timeout, resolver.resolve(&request)) => {
            outcome.unwrap_or_else(|_| server_failure())
        }
    };
    let encoded =
        encode_resolve_outcome(&outcome).context("client resolver produced an invalid outcome")?;
    let response = Response::builder()
        .status(StatusCode::OK)
        .version(Version::HTTP_2)
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static(RESOLVER_CONTENT_TYPE),
        )
        .header(CONTENT_LENGTH, encoded.len())
        .body(())
        .context("failed to build resolver response")?;
    let mut send = respond
        .send_response(response, false)
        .context("failed to send resolver response headers")?;
    send_h2_data(&mut send, Bytes::from(encoded), true)
        .await
        .context("failed to send resolver response body")
}

async fn reject_forbidden_resolver_stream(
    request: Request<RecvStream>,
    respond: h2::server::SendResponse<Bytes>,
    error: NetworkError,
) -> Result<()> {
    reject_resolver_request(respond, StatusCode::FORBIDDEN, error)?;
    let mut receive = request.into_body();
    let drain = async {
        while let Some(frame) = receive.data().await {
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) if error.is_reset() => return Ok(()),
                Err(error) => return Err(error).context("forbidden resolver request body failed"),
            };
            receive
                .flow_control()
                .release_capacity(frame.len())
                .context("failed to release forbidden resolver request capacity")?;
        }
        Ok(())
    };
    match tokio::time::timeout(RESOLVER_REQUEST_BODY_TIMEOUT, drain).await {
        Ok(result) => result,
        Err(_) => Ok(()),
    }
}

async fn receive_resolver_request_body(
    mut receive: RecvStream,
    expected_length: Option<usize>,
) -> Result<ResolveRequest, ResolverRequestBodyError> {
    let mut body = ResolveRequestBody::new();
    let mut received_length = 0_usize;
    while let Some(frame) = receive.data().await {
        let frame = frame.map_err(ResolverRequestBodyError::Transport)?;
        received_length = received_length.checked_add(frame.len()).ok_or_else(|| {
            ResolverRequestBodyError::Protocol("resolver request body length overflow".to_string())
        })?;
        let push_result = body.push(&frame);
        receive
            .flow_control()
            .release_capacity(frame.len())
            .map_err(ResolverRequestBodyError::Transport)?;
        push_result.map_err(|error| {
            ResolverRequestBodyError::Protocol(format!("invalid resolver request body: {error}"))
        })?;
    }
    let trailers = receive
        .trailers()
        .await
        .map_err(ResolverRequestBodyError::Transport)?;
    if trailers.is_some() {
        return Err(ResolverRequestBodyError::Protocol(
            "resolver request must not carry trailers".to_string(),
        ));
    }
    validate_received_length_value(expected_length, received_length, "resolver request")
        .map_err(ResolverRequestBodyError::Protocol)?;
    body.finish().map_err(|error| {
        ResolverRequestBodyError::Protocol(format!("invalid resolver request body: {error}"))
    })
}

fn validate_resolver_request_head<B>(
    request: &Request<B>,
) -> Result<Option<usize>, ResolverHeadError> {
    if request.method() != Method::POST
        || request.version() != Version::HTTP_2
        || request.extensions().get::<h2::ext::Protocol>().is_some()
        || request.uri().scheme_str() != Some(RESOLVER_REQUEST_SCHEME)
        || request.uri().authority().map(|value| value.as_str()) != Some(RESOLVER_REQUEST_AUTHORITY)
        || request.uri().path() != RESOLVER_REQUEST_PATH
        || request.uri().query().is_some()
    {
        return Err(ResolverHeadError::new("invalid resolver endpoint request"));
    }
    validate_content_type(request.headers(), "resolver request")?;
    parse_content_length_head(
        request.headers(),
        MAX_RESOLVER_REQUEST_BODY_BYTES,
        "resolver request",
    )
}

fn validate_resolver_response_head(response: &Response<RecvStream>) -> Result<(), NetworkError> {
    if response.version() != Version::HTTP_2 {
        return Err(protocol_error("resolver response is not HTTP/2"));
    }
    validate_content_type(response.headers(), "resolver response")
        .map_err(|error| protocol_error(error.message))
}

fn validate_content_type(
    headers: &HeaderMap,
    message_kind: &'static str,
) -> Result<(), ResolverHeadError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return Err(ResolverHeadError::new(format!(
            "{message_kind} is missing its content type"
        )));
    };
    if values.next().is_some() || value.as_bytes() != RESOLVER_CONTENT_TYPE.as_bytes() {
        return Err(ResolverHeadError::new(format!(
            "{message_kind} has an invalid content type"
        )));
    }
    Ok(())
}

fn parse_content_length(
    headers: &HeaderMap,
    maximum: usize,
    message_kind: &'static str,
) -> Result<Option<usize>, NetworkError> {
    parse_content_length_head(headers, maximum, message_kind)
        .map_err(|error| protocol_error(error.message))
}

fn parse_content_length_head(
    headers: &HeaderMap,
    maximum: usize,
    message_kind: &'static str,
) -> Result<Option<usize>, ResolverHeadError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some()
        || value.as_bytes().is_empty()
        || !value.as_bytes().iter().all(u8::is_ascii_digit)
    {
        return Err(ResolverHeadError::new(format!(
            "{message_kind} has an invalid content length"
        )));
    }
    let length = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or_else(|| {
            ResolverHeadError::new(format!("{message_kind} has an invalid content length"))
        })?;
    if length > maximum {
        return Err(ResolverHeadError::new(format!(
            "{message_kind} body is {length} bytes; the maximum is {maximum}"
        )));
    }
    Ok(Some(length))
}

fn validate_received_length(
    expected: Option<usize>,
    actual: usize,
    message_kind: &'static str,
) -> Result<(), NetworkError> {
    validate_received_length_value(expected, actual, message_kind).map_err(protocol_error)
}

fn validate_received_length_value(
    expected: Option<usize>,
    actual: usize,
    message_kind: &'static str,
) -> Result<(), String> {
    let Some(expected) = expected else {
        return Ok(());
    };
    if actual == expected {
        return Ok(());
    }
    Err(format!(
        "{message_kind} content length is {expected} bytes but its body is {actual} bytes"
    ))
}

fn resolver_uri() -> Result<Uri, NetworkError> {
    Uri::builder()
        .scheme(RESOLVER_REQUEST_SCHEME)
        .authority(RESOLVER_REQUEST_AUTHORITY)
        .path_and_query(RESOLVER_REQUEST_PATH)
        .build()
        .map_err(|error| protocol_error(format!("failed to build resolver URI: {error}")))
}

fn reject_resolver_request(
    mut respond: h2::server::SendResponse<Bytes>,
    status: StatusCode,
    error: NetworkError,
) -> Result<()> {
    let mut response = Response::builder()
        .status(status)
        .version(Version::HTTP_2)
        .body(())
        .context("failed to build resolver rejection response")?;
    error.write_headers(response.headers_mut());
    respond
        .send_response(response, true)
        .context("failed to reject resolver request")?;
    Ok(())
}

pub(super) fn reject_resolver_capacity(respond: h2::server::SendResponse<Bytes>) -> Result<()> {
    reject_resolver_request(
        respond,
        StatusCode::SERVICE_UNAVAILABLE,
        NetworkError::resource_limit("client resolver request limit reached"),
    )
}

fn protocol_error(message: impl Into<String>) -> NetworkError {
    NetworkError::new(NetworkErrorKind::Protocol, message)
}

fn server_failure() -> ResolveOutcome {
    ResolveOutcome::Failure {
        response_code: RESPONSE_CODE_SERVER_FAILURE,
    }
}

struct ResolverStreamGuard {
    send: Option<SendStream<Bytes>>,
}

impl ResolverStreamGuard {
    fn new(send: SendStream<Bytes>) -> Self {
        Self { send: Some(send) }
    }

    fn send(&mut self) -> &mut SendStream<Bytes> {
        self.send
            .as_mut()
            .expect("an active resolver stream owns its send handle")
    }

    fn finish(&mut self) {
        self.send.take();
    }
}

impl Drop for ResolverStreamGuard {
    fn drop(&mut self) {
        if let Some(send) = &mut self.send {
            send.send_reset(Reason::CANCEL);
        }
    }
}

struct ResolverHeadError {
    message: String,
}

impl ResolverHeadError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

enum ResolverRequestBodyError {
    Protocol(String),
    Transport(h2::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use bytes::Bytes;
    use h2::Reason;
    use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
    use http::{Method, Request, Response, StatusCode, Version};
    use tokio::io::duplex;
    use tokio::sync::mpsc;

    use super::{
        MAX_CONCURRENT_RESOLVER_REQUESTS, RESOLVER_CONTENT_TYPE, RESOLVER_REQUEST_AUTHORITY,
        RESOLVER_REQUEST_PATH, ResolveOutcome, ResolveRequest, encode_resolve_outcome,
        encode_resolve_request, handle_client_resolver_request, resolver_uri,
    };
    use crate::network::client_resolver::ClientResolver;
    use crate::network::policy::ClientNetworkPolicy;
    use crate::network::protocol::{NetworkErrorKind, NetworkTarget, ResolutionFamily};
    use crate::network::session::OperatorNetworkSession;
    use crate::{OfferedSession, SystemVpnPolicy, VpnScope};

    fn full_system_vpn_policy() -> Arc<ClientNetworkPolicy> {
        Arc::new(
            ClientNetworkPolicy::from_approved_session(&OfferedSession::Vpn {
                scope: VpnScope::System {
                    policy: SystemVpnPolicy::full_tunnel(),
                },
            })
            .unwrap(),
        )
    }

    async fn operator_session(
        flow_limit: usize,
        resolver_limit: usize,
    ) -> Result<(
        OperatorNetworkSession,
        mpsc::UnboundedReceiver<(Request<h2::RecvStream>, h2::server::SendResponse<Bytes>)>,
        tokio::task::JoinHandle<Result<()>>,
        tokio::task::JoinHandle<Result<()>>,
    )> {
        let (operator_io, client_io) = duplex(64 * 1024);
        let mut server_builder = h2::server::Builder::new();
        server_builder.enable_connect_protocol();
        let server_handshake = server_builder.handshake::<_, Bytes>(client_io);
        let operator_handshake = h2::client::handshake(operator_io);
        let (client_connection, operator) = tokio::try_join!(server_handshake, operator_handshake)?;
        let (requests, operator_connection) = operator;
        let operator_task = tokio::spawn(async move {
            operator_connection
                .await
                .context("operator H2 test connection failed")
        });
        let (requests_tx, requests_rx) = mpsc::unbounded_channel();
        let client_task = tokio::spawn(async move {
            let mut client_connection = client_connection;
            while let Some(request) = client_connection.accept().await {
                let request = request.context("client H2 test connection failed")?;
                if requests_tx.send(request).is_err() {
                    return Ok(());
                }
            }
            Ok(())
        });
        Ok((
            OperatorNetworkSession::from_test_transport(requests, flow_limit, resolver_limit),
            requests_rx,
            operator_task,
            client_task,
        ))
    }

    async fn send_fragmented_outcome(
        mut respond: h2::server::SendResponse<Bytes>,
        outcome: &ResolveOutcome,
    ) -> Result<()> {
        let encoded = encode_resolve_outcome(outcome)?;
        let encoded_length = encoded.len();
        let response = Response::builder()
            .status(StatusCode::OK)
            .version(Version::HTTP_2)
            .header(CONTENT_TYPE, RESOLVER_CONTENT_TYPE)
            .header(CONTENT_LENGTH, encoded.len())
            .body(())?;
        let mut send = respond.send_response(response, false)?;
        for (index, byte) in encoded.into_iter().enumerate() {
            send.send_data(Bytes::from(vec![byte]), index + 1 == encoded_length)?;
        }
        Ok(())
    }

    async fn consume_request_body(mut body: h2::RecvStream) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        while let Some(frame) = body.data().await {
            let frame = frame?;
            bytes.extend_from_slice(&frame);
            body.flow_control().release_capacity(frame.len())?;
        }
        Ok(bytes)
    }

    #[tokio::test]
    async fn resolver_and_tcp_share_one_h2_connection_with_independent_capacity() {
        let (session, mut requests, operator_task, client_task) =
            operator_session(1, 1).await.unwrap();
        let flow_permit = session.acquire_test_flow_permit();
        let expected_request = ResolveRequest::new("jira.example", 1, 1, 2_000).unwrap();
        let server_request = expected_request.clone();
        let server_task = tokio::spawn(async move {
            let (request, respond) = requests.recv().await.unwrap();
            assert_eq!(request.method(), Method::POST);
            assert_eq!(
                request.uri().authority().unwrap().as_str(),
                RESOLVER_REQUEST_AUTHORITY
            );
            assert_eq!(request.uri().path(), RESOLVER_REQUEST_PATH);
            let request_body = consume_request_body(request.into_body()).await.unwrap();
            assert_eq!(
                request_body,
                encode_resolve_request(&server_request).unwrap()
            );
            send_fragmented_outcome(respond, &ResolveOutcome::Positive { answer_ttl: 37 })
                .await
                .unwrap();

            let (request, mut respond) = requests.recv().await.unwrap();
            assert_eq!(request.method(), Method::CONNECT);
            let target = NetworkTarget::from_connect_uri(request.uri(), request.headers()).unwrap();
            assert_eq!(target.host, "jira.example");
            assert_eq!(target.port, 443);
            assert_eq!(target.resolution_family, ResolutionFamily::Ipv4);
            let response = Response::builder()
                .status(StatusCode::OK)
                .version(Version::HTTP_2)
                .body(())
                .unwrap();
            respond.send_response(response, true).unwrap();
        });

        assert_eq!(
            session.resolve(expected_request).await.unwrap(),
            ResolveOutcome::Positive { answer_ttl: 37 }
        );
        assert_eq!(session.resolver_permits.available_permits(), 1);
        drop(flow_permit);
        let tunnel = session
            .connect_tcp(
                NetworkTarget::new_with_resolution_family(
                    "jira.example",
                    443,
                    ResolutionFamily::Ipv4,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        drop(tunnel);

        server_task.await.unwrap();
        drop(session);
        operator_task.abort();
        client_task.abort();
    }

    #[tokio::test]
    async fn resolver_timeout_resets_stream_and_releases_its_permit() {
        let (session, mut requests, operator_task, client_task) =
            operator_session(1, 1).await.unwrap();
        let server_task = tokio::spawn(async move {
            let (request, mut respond) = requests.recv().await.unwrap();
            consume_request_body(request.into_body()).await.unwrap();
            let reason = std::future::poll_fn(|context| respond.poll_reset(context))
                .await
                .unwrap();
            assert_eq!(reason, Reason::CANCEL);
        });
        let request = ResolveRequest::new("slow.example", 1, 1, 100).unwrap();

        let error = tokio::time::timeout(Duration::from_secs(3), session.resolve(request))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind, NetworkErrorKind::TimedOut);
        assert_eq!(session.resolver_permits.available_permits(), 1);

        server_task.await.unwrap();
        drop(session);
        operator_task.abort();
        client_task.abort();
    }

    #[tokio::test]
    async fn malformed_resolver_response_resets_stream_and_releases_its_permit() {
        let (session, mut requests, operator_task, client_task) =
            operator_session(1, 1).await.unwrap();
        let server_task = tokio::spawn(async move {
            let (request, mut respond) = requests.recv().await.unwrap();
            consume_request_body(request.into_body()).await.unwrap();
            let response = Response::builder()
                .status(StatusCode::OK)
                .version(Version::HTTP_2)
                .header(CONTENT_TYPE, "application/octet-stream")
                .body(())
                .unwrap();
            let mut send = respond.send_response(response, false).unwrap();
            let reason = std::future::poll_fn(|context| send.poll_reset(context))
                .await
                .unwrap();
            assert_eq!(reason, Reason::CANCEL);
        });
        let request = ResolveRequest::new("malformed.example", 1, 1, 2_000).unwrap();

        let error = tokio::time::timeout(Duration::from_secs(3), session.resolve(request))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind, NetworkErrorKind::Protocol);
        assert_eq!(session.resolver_permits.available_permits(), 1);

        server_task.await.unwrap();
        drop(session);
        operator_task.abort();
        client_task.abort();
    }

    async fn client_handler_session() -> Result<(
        h2::client::SendRequest<Bytes>,
        tokio::task::JoinHandle<Result<()>>,
        tokio::task::JoinHandle<Result<()>>,
    )> {
        let (operator_io, client_io) = duplex(64 * 1024);
        let policy = full_system_vpn_policy();
        let server_task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(client_io).await?;
            while let Some(request) = connection.accept().await {
                let (request, respond) = request?;
                let policy = Arc::clone(&policy);
                tokio::spawn(async move {
                    handle_client_resolver_request(
                        request,
                        respond,
                        Arc::new(ClientResolver::from_system_configuration()),
                        policy,
                    )
                    .await
                    .unwrap();
                });
            }
            Ok(())
        });
        let (requests, connection) = h2::client::handshake(operator_io).await?;
        let client_task =
            tokio::spawn(
                async move { connection.await.context("client H2 test connection failed") },
            );
        Ok((requests, client_task, server_task))
    }

    async fn post_body(
        requests: &h2::client::SendRequest<Bytes>,
        body: &[u8],
        chunk_size: usize,
    ) -> Result<StatusCode> {
        let request = Request::builder()
            .method(Method::POST)
            .version(Version::HTTP_2)
            .uri(resolver_uri()?)
            .header(CONTENT_TYPE, RESOLVER_CONTENT_TYPE)
            .body(())?;
        let mut ready = requests.clone().ready().await?;
        let (response, mut send) = ready.send_request(request, false)?;
        let chunks = body.chunks(chunk_size).collect::<Vec<_>>();
        for (index, chunk) in chunks.iter().enumerate() {
            send.send_data(Bytes::copy_from_slice(chunk), index + 1 == chunks.len())?;
        }
        Ok(response.await?.status())
    }

    #[tokio::test]
    async fn client_accepts_arbitrary_data_boundaries_and_rejects_oversized_bodies() {
        let (requests, client_task, server_task) = client_handler_session().await.unwrap();
        let valid =
            encode_resolve_request(&ResolveRequest::new("jira.example", 1, 1, 2_000).unwrap())
                .unwrap();
        assert_eq!(
            post_body(&requests, &valid, 1).await.unwrap(),
            StatusCode::OK
        );
        assert_eq!(
            post_body(&requests, &[0; 268], 17).await.unwrap(),
            StatusCode::BAD_REQUEST
        );

        drop(requests);
        client_task.abort();
        server_task.abort();
    }

    #[test]
    fn resolver_capacity_is_reserved_separately_from_long_lived_flows() {
        assert_eq!(MAX_CONCURRENT_RESOLVER_REQUESTS, 64);
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "https://{RESOLVER_REQUEST_AUTHORITY}{RESOLVER_REQUEST_PATH}"
            ))
            .body(())
            .unwrap();
        assert!(super::is_resolver_request(&request));
    }
}
