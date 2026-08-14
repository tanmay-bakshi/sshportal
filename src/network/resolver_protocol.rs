use std::fmt;

pub(crate) const RESOLVER_REQUEST_SCHEME: &str = "https";
pub(crate) const RESOLVER_REQUEST_AUTHORITY: &str = "client.sshportal.invalid";
pub(crate) const RESOLVER_REQUEST_PATH: &str = "/.well-known/sshportal/network/resolve";
pub(crate) const RESOLVER_CONTENT_TYPE: &str = "application/vnd.sshportal.resolver.v1";

pub(crate) const MAX_RESOLVER_REQUEST_BODY_BYTES: usize = 267;
pub(crate) const MAX_RESOLVER_RESPONSE_BODY_BYTES: usize = 8;

const WIRE_VERSION: u8 = 1;
const MAX_NAME_TEXT_BYTES: usize = 253;
const MIN_TIMEOUT_MILLIS: u32 = 100;
const MAX_TIMEOUT_MILLIS: u32 = 30_000;

const OUTCOME_POSITIVE: u8 = 1;
const OUTCOME_NO_DATA: u8 = 2;
const OUTCOME_FAILURE: u8 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ResolveRequest {
    name: String,
    record_type: u16,
    record_class: u16,
    timeout_millis: u32,
}

impl ResolveRequest {
    pub(crate) fn new(
        name: impl Into<String>,
        record_type: u16,
        record_class: u16,
        timeout_millis: u32,
    ) -> Result<Self, ResolverProtocolError> {
        let request = Self {
            name: name.into(),
            record_type,
            record_class,
            timeout_millis,
        };
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn record_type(&self) -> u16 {
        self.record_type
    }

    pub(crate) fn record_class(&self) -> u16 {
        self.record_class
    }

    pub(crate) fn timeout_millis(&self) -> u32 {
        self.timeout_millis
    }

    fn validate(&self) -> Result<(), ResolverProtocolError> {
        validate_resolver_name(&self.name)?;
        if self.record_type == 0 {
            return Err(ResolverProtocolError::ReservedRecordType);
        }
        if self.record_class == 0 {
            return Err(ResolverProtocolError::ReservedRecordClass);
        }
        if !(MIN_TIMEOUT_MILLIS..=MAX_TIMEOUT_MILLIS).contains(&self.timeout_millis) {
            return Err(ResolverProtocolError::InvalidTimeout(self.timeout_millis));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResolveOutcome {
    Positive { answer_ttl: u32 },
    NoData,
    Failure { response_code: u8 },
}

impl ResolveOutcome {
    fn validate(&self) -> Result<(), ResolverProtocolError> {
        match self {
            Self::Positive { .. } | Self::NoData => Ok(()),
            Self::Failure { response_code } => validate_failure_code(*response_code),
        }
    }
}

pub(crate) fn encode_resolve_request(
    request: &ResolveRequest,
) -> Result<Vec<u8>, ResolverProtocolError> {
    request.validate()?;
    let mut output = Vec::with_capacity(12 + request.name.len());
    output.push(WIRE_VERSION);
    output.push(0);
    write_u16(&mut output, request.record_type);
    write_u16(&mut output, request.record_class);
    write_u32(&mut output, request.timeout_millis);
    write_name(&mut output, &request.name)?;
    debug_assert!(output.len() <= MAX_RESOLVER_REQUEST_BODY_BYTES);
    Ok(output)
}

pub(crate) fn decode_resolve_request(
    bytes: &[u8],
) -> Result<ResolveRequest, ResolverProtocolError> {
    if bytes.len() > MAX_RESOLVER_REQUEST_BODY_BYTES {
        return Err(ResolverProtocolError::BodyTooLong {
            length: bytes.len(),
            maximum: MAX_RESOLVER_REQUEST_BODY_BYTES,
        });
    }
    let mut decoder = Decoder::new(bytes);
    validate_version(decoder.read_u8()?)?;
    validate_reserved_flags(decoder.read_u8()?)?;
    let record_type = decoder.read_u16()?;
    let record_class = decoder.read_u16()?;
    let timeout_millis = decoder.read_u32()?;
    let name = decoder.read_name()?;
    decoder.finish()?;
    ResolveRequest::new(name, record_type, record_class, timeout_millis)
}

pub(crate) fn encode_resolve_outcome(
    outcome: &ResolveOutcome,
) -> Result<Vec<u8>, ResolverProtocolError> {
    outcome.validate()?;

    let mut output = Vec::with_capacity(MAX_RESOLVER_RESPONSE_BODY_BYTES);
    output.push(WIRE_VERSION);
    output.push(0);
    match outcome {
        ResolveOutcome::Positive { answer_ttl } => {
            output.push(OUTCOME_POSITIVE);
            output.push(0);
            write_u32(&mut output, *answer_ttl);
        }
        ResolveOutcome::NoData => {
            output.push(OUTCOME_NO_DATA);
            output.push(0);
            write_u32(&mut output, 0);
        }
        ResolveOutcome::Failure { response_code } => {
            output.push(OUTCOME_FAILURE);
            output.push(*response_code);
            write_u32(&mut output, 0);
        }
    }
    debug_assert_eq!(output.len(), MAX_RESOLVER_RESPONSE_BODY_BYTES);
    Ok(output)
}

pub(crate) fn decode_resolve_outcome(
    bytes: &[u8],
) -> Result<ResolveOutcome, ResolverProtocolError> {
    if bytes.len() > MAX_RESOLVER_RESPONSE_BODY_BYTES {
        return Err(ResolverProtocolError::BodyTooLong {
            length: bytes.len(),
            maximum: MAX_RESOLVER_RESPONSE_BODY_BYTES,
        });
    }

    let mut decoder = Decoder::new(bytes);
    validate_version(decoder.read_u8()?)?;
    validate_reserved_flags(decoder.read_u8()?)?;
    let outcome_kind = decoder.read_u8()?;
    let response_code = decoder.read_u8()?;
    let answer_ttl = decoder.read_u32()?;
    decoder.finish()?;

    let outcome = match outcome_kind {
        OUTCOME_POSITIVE => {
            validate_response_code(response_code, 0, outcome_kind)?;
            ResolveOutcome::Positive { answer_ttl }
        }
        OUTCOME_NO_DATA => {
            validate_response_code(response_code, 0, outcome_kind)?;
            validate_zero_ttl(answer_ttl, outcome_kind)?;
            ResolveOutcome::NoData
        }
        OUTCOME_FAILURE => {
            validate_failure_code(response_code)?;
            validate_zero_ttl(answer_ttl, outcome_kind)?;
            ResolveOutcome::Failure { response_code }
        }
        value => return Err(ResolverProtocolError::UnknownOutcome(value)),
    };
    outcome.validate()?;
    Ok(outcome)
}

#[derive(Debug)]
pub(crate) struct ResolveRequestBody {
    buffer: BoundedBody,
}

impl ResolveRequestBody {
    pub(crate) fn new() -> Self {
        Self {
            buffer: BoundedBody::new(MAX_RESOLVER_REQUEST_BODY_BYTES),
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), ResolverProtocolError> {
        self.buffer.push(chunk)
    }

    pub(crate) fn finish(self) -> Result<ResolveRequest, ResolverProtocolError> {
        decode_resolve_request(&self.buffer.bytes)
    }
}

#[derive(Debug)]
pub(crate) struct ResolveOutcomeBody {
    buffer: BoundedBody,
}

impl ResolveOutcomeBody {
    pub(crate) fn new() -> Self {
        Self {
            buffer: BoundedBody::new(MAX_RESOLVER_RESPONSE_BODY_BYTES),
        }
    }

    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), ResolverProtocolError> {
        self.buffer.push(chunk)
    }

    pub(crate) fn finish(self) -> Result<ResolveOutcome, ResolverProtocolError> {
        decode_resolve_outcome(&self.buffer.bytes)
    }
}

#[derive(Debug)]
struct BoundedBody {
    bytes: Vec<u8>,
    maximum: usize,
}

impl BoundedBody {
    fn new(maximum: usize) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
        }
    }

    fn push(&mut self, chunk: &[u8]) -> Result<(), ResolverProtocolError> {
        let length = self.bytes.len().checked_add(chunk.len()).ok_or(
            ResolverProtocolError::BodyTooLong {
                length: usize::MAX,
                maximum: self.maximum,
            },
        )?;
        if length > self.maximum {
            return Err(ResolverProtocolError::BodyTooLong {
                length,
                maximum: self.maximum,
            });
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }
}

fn validate_version(version: u8) -> Result<(), ResolverProtocolError> {
    if version == WIRE_VERSION {
        return Ok(());
    }
    Err(ResolverProtocolError::UnsupportedVersion(version))
}

fn validate_reserved_flags(flags: u8) -> Result<(), ResolverProtocolError> {
    if flags == 0 {
        return Ok(());
    }
    Err(ResolverProtocolError::ReservedFlags(flags))
}

fn validate_response_code(
    actual: u8,
    expected: u8,
    outcome: u8,
) -> Result<(), ResolverProtocolError> {
    if actual == expected {
        return Ok(());
    }
    Err(ResolverProtocolError::InvalidOutcomeResponseCode {
        outcome,
        response_code: actual,
    })
}

fn validate_failure_code(response_code: u8) -> Result<(), ResolverProtocolError> {
    if (1..=15).contains(&response_code) && response_code != 3 {
        return Ok(());
    }
    Err(ResolverProtocolError::InvalidFailureResponseCode(
        response_code,
    ))
}

fn validate_zero_ttl(ttl: u32, outcome: u8) -> Result<(), ResolverProtocolError> {
    if ttl == 0 {
        return Ok(());
    }
    Err(ResolverProtocolError::UnexpectedAnswerTtl { outcome, ttl })
}

pub(crate) fn validate_resolver_name(name: &str) -> Result<(), ResolverProtocolError> {
    if name == "." {
        return Ok(());
    }
    if name.is_empty() || !name.is_ascii() || name.len() > MAX_NAME_TEXT_BYTES {
        return Err(ResolverProtocolError::InvalidName(name.to_string()));
    }
    if name.ends_with('.') {
        return Err(ResolverProtocolError::InvalidName(name.to_string()));
    }

    let mut wire_length = 1;
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ResolverProtocolError::InvalidName(name.to_string()));
        }
        if label
            .bytes()
            .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b'\\')
        {
            return Err(ResolverProtocolError::InvalidName(name.to_string()));
        }
        wire_length += label.len() + 1;
    }
    if wire_length > 255 {
        return Err(ResolverProtocolError::InvalidName(name.to_string()));
    }
    Ok(())
}

fn write_name(output: &mut Vec<u8>, name: &str) -> Result<(), ResolverProtocolError> {
    validate_resolver_name(name)?;
    let length = u16::try_from(name.len())
        .map_err(|_| ResolverProtocolError::InvalidName(name.to_string()))?;
    write_u16(output, length);
    output.extend_from_slice(name.as_bytes());
    Ok(())
}

fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, ResolverProtocolError> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or(ResolverProtocolError::TruncatedBody)?;
        self.offset += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, ResolverProtocolError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, ResolverProtocolError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_name(&mut self) -> Result<String, ResolverProtocolError> {
        let length = usize::from(self.read_u16()?);
        if length > MAX_NAME_TEXT_BYTES {
            return Err(ResolverProtocolError::InvalidNameLength(length));
        }
        let bytes = self.read_bytes(length)?;
        let name = std::str::from_utf8(bytes)
            .map_err(|_| ResolverProtocolError::NameIsNotAscii)?
            .to_string();
        validate_resolver_name(&name)?;
        Ok(name)
    }

    fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], ResolverProtocolError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ResolverProtocolError::TruncatedBody)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(ResolverProtocolError::TruncatedBody)?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), ResolverProtocolError> {
        if self.offset == self.bytes.len() {
            return Ok(());
        }
        Err(ResolverProtocolError::TrailingData(
            self.bytes.len() - self.offset,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ResolverProtocolError {
    BodyTooLong { length: usize, maximum: usize },
    TruncatedBody,
    TrailingData(usize),
    UnsupportedVersion(u8),
    ReservedFlags(u8),
    InvalidName(String),
    InvalidNameLength(usize),
    NameIsNotAscii,
    ReservedRecordType,
    ReservedRecordClass,
    InvalidTimeout(u32),
    UnknownOutcome(u8),
    InvalidOutcomeResponseCode { outcome: u8, response_code: u8 },
    InvalidFailureResponseCode(u8),
    UnexpectedAnswerTtl { outcome: u8, ttl: u32 },
}

impl fmt::Display for ResolverProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BodyTooLong { length, maximum } => write!(
                formatter,
                "resolver message is {length} bytes; the maximum is {maximum}"
            ),
            Self::TruncatedBody => formatter.write_str("resolver message ends inside a field"),
            Self::TrailingData(length) => {
                write!(formatter, "resolver message has {length} trailing bytes")
            }
            Self::UnsupportedVersion(version) => {
                write!(formatter, "resolver wire version {version} is unsupported")
            }
            Self::ReservedFlags(flags) => {
                write!(
                    formatter,
                    "resolver message carries reserved flags 0x{flags:02x}"
                )
            }
            Self::InvalidName(name) => write!(formatter, "invalid resolver name `{name}`"),
            Self::InvalidNameLength(length) => {
                write!(formatter, "resolver name length {length} exceeds 253 bytes")
            }
            Self::NameIsNotAscii => formatter.write_str("resolver name is not valid ASCII text"),
            Self::ReservedRecordType => formatter.write_str("DNS record type zero is reserved"),
            Self::ReservedRecordClass => formatter.write_str("DNS record class zero is reserved"),
            Self::InvalidTimeout(timeout) => write!(
                formatter,
                "resolver timeout {timeout}ms is outside 100ms through 30000ms"
            ),
            Self::UnknownOutcome(outcome) => {
                write!(formatter, "unknown resolver outcome {outcome}")
            }
            Self::InvalidOutcomeResponseCode {
                outcome,
                response_code,
            } => write!(
                formatter,
                "resolver outcome {outcome} cannot carry DNS response code {response_code}"
            ),
            Self::InvalidFailureResponseCode(code) => {
                write!(
                    formatter,
                    "DNS response code {code} is not a resolver failure"
                )
            }
            Self::UnexpectedAnswerTtl { outcome, ttl } => write!(
                formatter,
                "resolver outcome {outcome} cannot carry answer TTL {ttl}"
            ),
        }
    }
}

impl std::error::Error for ResolverProtocolError {}

#[cfg(test)]
mod tests {
    use super::{
        MAX_RESOLVER_REQUEST_BODY_BYTES, MAX_RESOLVER_RESPONSE_BODY_BYTES, RESOLVER_CONTENT_TYPE,
        RESOLVER_REQUEST_AUTHORITY, RESOLVER_REQUEST_PATH, RESOLVER_REQUEST_SCHEME, ResolveOutcome,
        ResolveOutcomeBody, ResolveRequest, ResolveRequestBody, ResolverProtocolError,
        decode_resolve_outcome, decode_resolve_request, encode_resolve_outcome,
        encode_resolve_request,
    };

    fn request() -> ResolveRequest {
        ResolveRequest::new("Jira.Example", 1, 1, 10_000).unwrap()
    }

    #[test]
    fn request_round_trips_all_fields() {
        let original = request();
        let encoded = encode_resolve_request(&original).unwrap();
        let decoded = decode_resolve_request(&encoded).unwrap();

        assert_eq!(decoded, original);
        assert_eq!(decoded.name(), "Jira.Example");
        assert_eq!(decoded.record_type(), 1);
        assert_eq!(decoded.record_class(), 1);
        assert_eq!(decoded.timeout_millis(), 10_000);
    }

    #[test]
    fn h2_endpoint_identity_is_explicit_and_versioned() {
        assert_eq!(RESOLVER_REQUEST_SCHEME, "https");
        assert_eq!(RESOLVER_REQUEST_AUTHORITY, "client.sshportal.invalid");
        assert_eq!(
            RESOLVER_REQUEST_PATH,
            "/.well-known/sshportal/network/resolve"
        );
        assert_eq!(
            RESOLVER_CONTENT_TYPE,
            "application/vnd.sshportal.resolver.v1"
        );
    }

    #[test]
    fn every_outcome_round_trips_with_strict_semantics() {
        let outcomes = [
            ResolveOutcome::Positive { answer_ttl: 20 },
            ResolveOutcome::NoData,
            ResolveOutcome::Failure { response_code: 2 },
            ResolveOutcome::Failure { response_code: 5 },
        ];

        for outcome in outcomes {
            let encoded = encode_resolve_outcome(&outcome).unwrap();
            assert_eq!(decode_resolve_outcome(&encoded).unwrap(), outcome);
        }
    }

    #[test]
    fn chunked_body_accumulators_ignore_h2_data_boundaries() {
        let request = request();
        let request_bytes = encode_resolve_request(&request).unwrap();
        let mut request_body = ResolveRequestBody::new();
        for chunk in request_bytes.chunks(2) {
            request_body.push(chunk).unwrap();
        }
        assert_eq!(request_body.finish().unwrap(), request);

        let outcome = ResolveOutcome::Positive { answer_ttl: 20 };
        let outcome_bytes = encode_resolve_outcome(&outcome).unwrap();
        let mut outcome_body = ResolveOutcomeBody::new();
        for chunk in outcome_bytes.chunks(3) {
            outcome_body.push(chunk).unwrap();
        }
        assert_eq!(outcome_body.finish().unwrap(), outcome);
    }

    #[test]
    fn truncated_prefixes_and_trailing_bytes_are_rejected() {
        let request = request();
        let request_bytes = encode_resolve_request(&request).unwrap();
        for length in 0..request_bytes.len() {
            assert!(decode_resolve_request(&request_bytes[..length]).is_err());
        }
        let mut trailing_request = request_bytes;
        trailing_request.push(0);
        assert_eq!(
            decode_resolve_request(&trailing_request),
            Err(ResolverProtocolError::TrailingData(1))
        );

        let outcome = ResolveOutcome::NoData;
        let outcome_bytes = encode_resolve_outcome(&outcome).unwrap();
        for length in 0..outcome_bytes.len() {
            assert!(decode_resolve_outcome(&outcome_bytes[..length]).is_err());
        }
        let mut trailing_outcome = outcome_bytes;
        trailing_outcome.push(0);
        assert_eq!(
            decode_resolve_outcome(&trailing_outcome),
            Err(ResolverProtocolError::BodyTooLong {
                length: MAX_RESOLVER_RESPONSE_BODY_BYTES + 1,
                maximum: MAX_RESOLVER_RESPONSE_BODY_BYTES,
            })
        );
    }

    #[test]
    fn body_limits_are_enforced_while_streaming() {
        let mut request_body = ResolveRequestBody::new();
        let maximum_request = [0; MAX_RESOLVER_REQUEST_BODY_BYTES];
        request_body.push(&maximum_request).unwrap();
        assert!(matches!(
            request_body.push(&[0]),
            Err(ResolverProtocolError::BodyTooLong { .. })
        ));

        let mut outcome_body = ResolveOutcomeBody::new();
        let maximum_response = [0; MAX_RESOLVER_RESPONSE_BODY_BYTES];
        outcome_body.push(&maximum_response).unwrap();
        assert!(matches!(
            outcome_body.push(&[0]),
            Err(ResolverProtocolError::BodyTooLong { .. })
        ));
    }

    #[test]
    fn invalid_names_types_classes_and_timeouts_are_rejected() {
        for name in [
            "",
            "jira.example.",
            "jira..example",
            "jira example",
            "jira\\example",
            "jira\0example",
            "café.example",
            &format!("{}.example", "a".repeat(64)),
        ] {
            assert!(ResolveRequest::new(name, 1, 1, 10_000).is_err());
        }
        assert!(ResolveRequest::new("jira.example", 0, 1, 10_000).is_err());
        assert!(ResolveRequest::new("jira.example", 1, 0, 10_000).is_err());
        assert!(ResolveRequest::new("jira.example", 1, 1, 99).is_err());
        assert!(ResolveRequest::new("jira.example", 1, 1, 30_001).is_err());
        assert!(ResolveRequest::new(".", 1, 1, 10_000).is_ok());
    }

    #[test]
    fn malformed_headers_are_rejected_before_payload_interpretation() {
        let request = request();
        let encoded = encode_resolve_request(&request).unwrap();

        let mut version = encoded.clone();
        version[0] = 2;
        assert_eq!(
            decode_resolve_request(&version),
            Err(ResolverProtocolError::UnsupportedVersion(2))
        );

        let mut flags = encoded;
        flags[1] = 1;
        assert_eq!(
            decode_resolve_request(&flags),
            Err(ResolverProtocolError::ReservedFlags(1))
        );
    }

    #[test]
    fn decoder_rejects_invalid_wire_name_lengths_and_bytes() {
        let request = request();
        let encoded = encode_resolve_request(&request).unwrap();

        let mut overlong = encoded.clone();
        overlong[10..12].copy_from_slice(&254_u16.to_be_bytes());
        assert_eq!(
            decode_resolve_request(&overlong),
            Err(ResolverProtocolError::InvalidNameLength(254))
        );

        let mut non_ascii = encoded;
        non_ascii[12] = 0xff;
        assert_eq!(
            decode_resolve_request(&non_ascii),
            Err(ResolverProtocolError::NameIsNotAscii)
        );
    }

    #[test]
    fn outcome_code_and_ttl_combinations_are_canonical() {
        let nodata = encode_resolve_outcome(&ResolveOutcome::NoData).unwrap();

        let mut wrong_nodata_code = nodata.clone();
        wrong_nodata_code[3] = 3;
        assert!(matches!(
            decode_resolve_outcome(&wrong_nodata_code),
            Err(ResolverProtocolError::InvalidOutcomeResponseCode { .. })
        ));

        let mut wrong_nodata_ttl = nodata;
        wrong_nodata_ttl[7] = 1;
        assert!(matches!(
            decode_resolve_outcome(&wrong_nodata_ttl),
            Err(ResolverProtocolError::UnexpectedAnswerTtl { .. })
        ));

        for code in [0, 3, 16, 255] {
            assert!(
                encode_resolve_outcome(&ResolveOutcome::Failure {
                    response_code: code
                })
                .is_err()
            );
        }
    }

    #[test]
    fn response_wire_type_has_no_field_for_real_addresses() {
        let response =
            encode_resolve_outcome(&ResolveOutcome::Positive { answer_ttl: 60 }).unwrap();

        assert_eq!(response.len(), MAX_RESOLVER_RESPONSE_BODY_BYTES);
        assert_eq!(
            decode_resolve_outcome(&response).unwrap(),
            ResolveOutcome::Positive { answer_ttl: 60 }
        );
    }
}
