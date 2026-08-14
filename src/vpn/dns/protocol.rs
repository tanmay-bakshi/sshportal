use std::fmt;

use super::name::{DnsName, DnsNameBuilder, NameError};

const DNS_HEADER_LENGTH: usize = 12;
const MAX_DNS_MESSAGE_LENGTH: usize = u16::MAX as usize;
const DEFAULT_UDP_PAYLOAD_SIZE: usize = 512;
const MAX_COMPRESSION_POINTERS: usize = 128;

const FLAG_QR: u16 = 0x8000;
const FLAG_OPCODE: u16 = 0x7800;
const FLAG_AA: u16 = 0x0400;
const FLAG_TC: u16 = 0x0200;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;
const FLAG_Z: u16 = 0x0040;
const FLAG_CD: u16 = 0x0010;
const FLAG_RCODE: u16 = 0x000f;

pub(crate) const RESPONSE_FLAG_QR: u16 = FLAG_QR;
pub(crate) const RESPONSE_FLAG_TC: u16 = FLAG_TC;
pub(crate) const RESPONSE_FLAG_RD: u16 = FLAG_RD;
pub(crate) const RESPONSE_FLAG_RA: u16 = FLAG_RA;
pub(crate) const RESPONSE_FLAG_CD: u16 = FLAG_CD;

const TYPE_OPT: u16 = 41;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordType {
    A,
    Cname,
    Aaaa,
    Svcb,
    Https,
    Other(u16),
}

impl RecordType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::A,
            5 => Self::Cname,
            28 => Self::Aaaa,
            64 => Self::Svcb,
            65 => Self::Https,
            value => Self::Other(value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Cname => 5,
            Self::Aaaa => 28,
            Self::Svcb => 64,
            Self::Https => 65,
            Self::Other(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordClass {
    Internet,
    Other(u16),
}

impl RecordClass {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Internet,
            value => Self::Other(value),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            Self::Internet => 1,
            Self::Other(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResponseCode(u8);

impl ResponseCode {
    pub const NO_ERROR: Self = Self(0);
    pub const SERVER_FAILURE: Self = Self(2);
    pub const NOT_IMPLEMENTED: Self = Self(4);
    #[cfg(test)]
    pub const REFUSED: Self = Self(5);

    pub fn from_u8(value: u8) -> Result<Self, InvalidResponseCode> {
        if value > 15 {
            return Err(InvalidResponseCode(value));
        }
        Ok(Self(value))
    }

    pub fn to_u8(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    name: DnsName,
    record_type: RecordType,
    record_class: RecordClass,
}

impl Question {
    pub fn name(&self) -> &DnsName {
        &self.name
    }

    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    pub fn record_class(&self) -> RecordClass {
        self.record_class
    }

    pub(crate) fn encode(&self, output: &mut Vec<u8>) {
        self.name.encode_uncompressed(output);
        write_u16(output, self.record_type.to_u16());
        write_u16(output, self.record_class.to_u16());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsQuery {
    id: u16,
    question: Question,
    recursion_desired: bool,
    checking_disabled: bool,
    edns: Option<EdnsRequest>,
}

impl DnsQuery {
    pub fn parse_udp(message: &[u8]) -> Result<Self, ParseError> {
        parse_query(message)
    }

    pub fn parse_tcp_frame(frame: &[u8]) -> Result<Self, ParseError> {
        let message = unframe_tcp_message(frame).map_err(ParseError::TcpFrame)?;
        parse_query(message)
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn question(&self) -> &Question {
        &self.question
    }

    #[cfg(test)]
    pub fn recursion_desired(&self) -> bool {
        self.recursion_desired
    }

    #[cfg(test)]
    pub fn checking_disabled(&self) -> bool {
        self.checking_disabled
    }

    pub fn requested_udp_payload_size(&self) -> usize {
        self.edns
            .as_ref()
            .map(|edns| usize::from(edns.udp_payload_size).max(DEFAULT_UDP_PAYLOAD_SIZE))
            .unwrap_or(DEFAULT_UDP_PAYLOAD_SIZE)
    }

    pub fn uses_edns(&self) -> bool {
        self.edns.is_some()
    }

    #[cfg(test)]
    pub fn dnssec_ok(&self) -> bool {
        self.edns.as_ref().is_some_and(|edns| edns.dnssec_ok)
    }

    pub(crate) fn response_flags(&self, response_code: ResponseCode, truncated: bool) -> u16 {
        let mut flags = RESPONSE_FLAG_QR | RESPONSE_FLAG_RA | u16::from(response_code.to_u8());
        if self.recursion_desired {
            flags |= RESPONSE_FLAG_RD;
        }
        if self.checking_disabled {
            flags |= RESPONSE_FLAG_CD;
        }
        if truncated {
            flags |= RESPONSE_FLAG_TC;
        }
        flags
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EdnsRequest {
    udp_payload_size: u16,
    dnssec_ok: bool,
}

fn parse_query(message: &[u8]) -> Result<DnsQuery, ParseError> {
    if message.len() < DNS_HEADER_LENGTH {
        return Err(ParseError::MessageTooShort(message.len()));
    }
    if message.len() > MAX_DNS_MESSAGE_LENGTH {
        return Err(ParseError::MessageTooLong(message.len()));
    }

    let id = read_u16(message, 0)?;
    let flags = read_u16(message, 2)?;
    if flags & FLAG_QR != 0 {
        return Err(ParseError::NotAQuery);
    }
    let opcode = ((flags & FLAG_OPCODE) >> 11) as u8;
    if opcode != 0 {
        return Err(ParseError::UnsupportedOpcode(opcode));
    }
    if flags & FLAG_Z != 0 {
        return Err(ParseError::ReservedHeaderBitSet);
    }
    if flags & (FLAG_AA | FLAG_TC | FLAG_RA) != 0 {
        return Err(ParseError::ResponseOnlyHeaderBitSet);
    }
    if flags & FLAG_RCODE != 0 {
        return Err(ParseError::ResponseCodeInQuery((flags & FLAG_RCODE) as u8));
    }

    let question_count = read_u16(message, 4)?;
    let answer_count = read_u16(message, 6)?;
    let authority_count = read_u16(message, 8)?;
    let additional_count = read_u16(message, 10)?;
    if question_count != 1 {
        return Err(ParseError::QuestionCount(question_count));
    }
    if answer_count != 0 || authority_count != 0 {
        return Err(ParseError::UnexpectedQuerySections {
            answers: answer_count,
            authorities: authority_count,
        });
    }
    if additional_count > 1 {
        return Err(ParseError::TooManyAdditionalRecords(additional_count));
    }

    let (name, mut offset) = parse_name(message, DNS_HEADER_LENGTH)?;
    let record_type = RecordType::from_u16(read_u16(message, offset)?);
    offset += 2;
    let record_class = RecordClass::from_u16(read_u16(message, offset)?);
    offset += 2;

    let edns = if additional_count == 1 {
        let (record, next_offset) = parse_resource_record(message, offset)?;
        offset = next_offset;
        if record.record_type != TYPE_OPT {
            return Err(ParseError::UnexpectedAdditionalRecord(record.record_type));
        }
        if !record.name.is_root() {
            return Err(ParseError::OptNameIsNotRoot);
        }
        let extended_response_code = (record.ttl >> 24) as u8;
        if extended_response_code != 0 {
            return Err(ParseError::ExtendedResponseCodeInQuery(
                extended_response_code,
            ));
        }
        let version = ((record.ttl >> 16) & 0xff) as u8;
        if version != 0 {
            return Err(ParseError::UnsupportedEdnsVersion(version));
        }
        let edns_flags = record.ttl as u16;
        if edns_flags & !0x8000 != 0 {
            return Err(ParseError::ReservedEdnsFlagSet(edns_flags));
        }
        validate_edns_options(record.rdata)?;
        Some(EdnsRequest {
            udp_payload_size: record.record_class,
            dnssec_ok: edns_flags & 0x8000 != 0,
        })
    } else {
        None
    };

    if offset != message.len() {
        return Err(ParseError::TrailingData(message.len() - offset));
    }

    Ok(DnsQuery {
        id,
        question: Question {
            name,
            record_type,
            record_class,
        },
        recursion_desired: flags & FLAG_RD != 0,
        checking_disabled: flags & FLAG_CD != 0,
        edns,
    })
}

struct ResourceRecordView<'a> {
    name: DnsName,
    record_type: u16,
    record_class: u16,
    ttl: u32,
    rdata: &'a [u8],
}

fn parse_resource_record(
    message: &[u8],
    offset: usize,
) -> Result<(ResourceRecordView<'_>, usize), ParseError> {
    let (name, mut offset) = parse_name(message, offset)?;
    let record_type = read_u16(message, offset)?;
    offset += 2;
    let record_class = read_u16(message, offset)?;
    offset += 2;
    let ttl = read_u32(message, offset)?;
    offset += 4;
    let rdata_length = usize::from(read_u16(message, offset)?);
    offset += 2;
    let end = offset
        .checked_add(rdata_length)
        .ok_or(ParseError::TruncatedMessage)?;
    let rdata = message
        .get(offset..end)
        .ok_or(ParseError::TruncatedMessage)?;
    Ok((
        ResourceRecordView {
            name,
            record_type,
            record_class,
            ttl,
            rdata,
        },
        end,
    ))
}

fn validate_edns_options(mut options: &[u8]) -> Result<(), ParseError> {
    while !options.is_empty() {
        if options.len() < 4 {
            return Err(ParseError::MalformedEdnsOptions);
        }
        let option_length = usize::from(u16::from_be_bytes([options[2], options[3]]));
        let total_length = 4_usize
            .checked_add(option_length)
            .ok_or(ParseError::MalformedEdnsOptions)?;
        options = options
            .get(total_length..)
            .ok_or(ParseError::MalformedEdnsOptions)?;
    }
    Ok(())
}

pub(crate) fn parse_name(
    message: &[u8],
    start_offset: usize,
) -> Result<(DnsName, usize), ParseError> {
    let mut name = DnsNameBuilder::new();
    let mut cursor = start_offset;
    let mut next_offset = None;
    let mut followed_pointer_count = 0;

    loop {
        let length = *message.get(cursor).ok_or(ParseError::TruncatedMessage)?;
        if length & 0xc0 == 0xc0 {
            let second = *message
                .get(cursor + 1)
                .ok_or(ParseError::TruncatedMessage)?;
            let pointer = usize::from(u16::from(length & 0x3f) << 8 | u16::from(second));
            if pointer >= message.len() {
                return Err(ParseError::CompressionPointerOutOfBounds(pointer));
            }
            if pointer < DNS_HEADER_LENGTH || pointer >= cursor {
                return Err(ParseError::CompressionPointerIsNotPrior(pointer));
            }
            if followed_pointer_count >= MAX_COMPRESSION_POINTERS {
                return Err(ParseError::CompressionPointerChainTooLong);
            }
            followed_pointer_count += 1;
            next_offset.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(ParseError::UnsupportedLabelEncoding(length));
        }

        cursor += 1;
        if length == 0 {
            return Ok((name.finish(), next_offset.unwrap_or(cursor)));
        }

        let end = cursor
            .checked_add(usize::from(length))
            .ok_or(ParseError::TruncatedMessage)?;
        let label = message
            .get(cursor..end)
            .ok_or(ParseError::TruncatedMessage)?;
        name.push_label(label).map_err(ParseError::InvalidName)?;
        cursor = end;
    }
}

pub fn frame_tcp_message(message: &[u8]) -> Result<Vec<u8>, TcpFrameError> {
    let length =
        u16::try_from(message.len()).map_err(|_| TcpFrameError::MessageTooLong(message.len()))?;
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(message);
    Ok(frame)
}

pub fn unframe_tcp_message(frame: &[u8]) -> Result<&[u8], TcpFrameError> {
    if frame.len() < 2 {
        return Err(TcpFrameError::MissingLengthPrefix);
    }
    let declared_length = usize::from(u16::from_be_bytes([frame[0], frame[1]]));
    let actual_length = frame.len() - 2;
    if declared_length != actual_length {
        return Err(TcpFrameError::LengthMismatch {
            declared: declared_length,
            actual: actual_length,
        });
    }
    Ok(&frame[2..])
}

pub(crate) fn write_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn write_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn read_u16(message: &[u8], offset: usize) -> Result<u16, ParseError> {
    let bytes = message
        .get(offset..offset + 2)
        .ok_or(ParseError::TruncatedMessage)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(message: &[u8], offset: usize) -> Result<u32, ParseError> {
    let bytes = message
        .get(offset..offset + 4)
        .ok_or(ParseError::TruncatedMessage)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidResponseCode(pub u8);

impl fmt::Display for InvalidResponseCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "DNS response code {} exceeds the four-bit RCODE field",
            self.0
        )
    }
}

impl std::error::Error for InvalidResponseCode {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpFrameError {
    MissingLengthPrefix,
    LengthMismatch { declared: usize, actual: usize },
    MessageTooLong(usize),
}

impl fmt::Display for TcpFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLengthPrefix => {
                formatter.write_str("DNS-over-TCP frame has no length prefix")
            }
            Self::LengthMismatch { declared, actual } => write!(
                formatter,
                "DNS-over-TCP frame declares {declared} bytes but contains {actual}"
            ),
            Self::MessageTooLong(length) => write!(
                formatter,
                "DNS message is {length} bytes; a TCP frame can contain at most 65535"
            ),
        }
    }
}

impl std::error::Error for TcpFrameError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ParseError {
    MessageTooShort(usize),
    MessageTooLong(usize),
    TruncatedMessage,
    NotAQuery,
    UnsupportedOpcode(u8),
    ReservedHeaderBitSet,
    ResponseOnlyHeaderBitSet,
    ResponseCodeInQuery(u8),
    QuestionCount(u16),
    UnexpectedQuerySections { answers: u16, authorities: u16 },
    TooManyAdditionalRecords(u16),
    UnexpectedAdditionalRecord(u16),
    OptNameIsNotRoot,
    ExtendedResponseCodeInQuery(u8),
    UnsupportedEdnsVersion(u8),
    ReservedEdnsFlagSet(u16),
    MalformedEdnsOptions,
    TrailingData(usize),
    CompressionPointerOutOfBounds(usize),
    CompressionPointerIsNotPrior(usize),
    CompressionPointerChainTooLong,
    UnsupportedLabelEncoding(u8),
    InvalidName(NameError),
    TcpFrame(TcpFrameError),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooShort(length) => {
                write!(
                    formatter,
                    "DNS message is only {length} bytes; the header needs 12"
                )
            }
            Self::MessageTooLong(length) => {
                write!(
                    formatter,
                    "DNS message is {length} bytes; the maximum is 65535"
                )
            }
            Self::TruncatedMessage => formatter.write_str("DNS message ends inside a field"),
            Self::NotAQuery => formatter.write_str("DNS message has the response bit set"),
            Self::UnsupportedOpcode(opcode) => {
                write!(formatter, "DNS opcode {opcode} is not a standard query")
            }
            Self::ReservedHeaderBitSet => formatter.write_str("reserved DNS header bit is set"),
            Self::ResponseOnlyHeaderBitSet => {
                formatter.write_str("a response-only DNS header bit is set in a query")
            }
            Self::ResponseCodeInQuery(code) => {
                write!(formatter, "DNS query carries response code {code}")
            }
            Self::QuestionCount(count) => {
                write!(
                    formatter,
                    "DNS query has {count} questions; exactly one is required"
                )
            }
            Self::UnexpectedQuerySections {
                answers,
                authorities,
            } => write!(
                formatter,
                "DNS query carries {answers} answer and {authorities} authority records"
            ),
            Self::TooManyAdditionalRecords(count) => write!(
                formatter,
                "DNS query has {count} additional records; only one OPT record is accepted"
            ),
            Self::UnexpectedAdditionalRecord(record_type) => write!(
                formatter,
                "DNS query has additional record type {record_type}; only OPT is accepted"
            ),
            Self::OptNameIsNotRoot => formatter.write_str("EDNS OPT owner name is not the root"),
            Self::ExtendedResponseCodeInQuery(code) => {
                write!(
                    formatter,
                    "EDNS query carries extended response code {code}"
                )
            }
            Self::UnsupportedEdnsVersion(version) => {
                write!(formatter, "EDNS version {version} is unsupported")
            }
            Self::ReservedEdnsFlagSet(flags) => {
                write!(formatter, "EDNS query carries reserved flags 0x{flags:04x}")
            }
            Self::MalformedEdnsOptions => formatter.write_str("EDNS option data is malformed"),
            Self::TrailingData(length) => {
                write!(
                    formatter,
                    "DNS query has {length} unaccounted trailing bytes"
                )
            }
            Self::CompressionPointerOutOfBounds(offset) => {
                write!(
                    formatter,
                    "DNS compression pointer targets offset {offset} outside the message"
                )
            }
            Self::CompressionPointerIsNotPrior(offset) => write!(
                formatter,
                "DNS compression pointer targets offset {offset}, which is not a prior encoded name"
            ),
            Self::CompressionPointerChainTooLong => {
                formatter.write_str("DNS compression pointer chain exceeds the safety limit")
            }
            Self::UnsupportedLabelEncoding(value) => {
                write!(
                    formatter,
                    "DNS label begins with unsupported encoding byte 0x{value:02x}"
                )
            }
            Self::InvalidName(error) => write!(formatter, "invalid DNS name: {error}"),
            Self::TcpFrame(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName(error) => Some(error),
            Self::TcpFrame(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DnsQuery, ParseError, RecordClass, RecordType, TcpFrameError, frame_tcp_message,
        unframe_tcp_message,
    };

    fn query(flags: u16, question_count: u16, record_type: u16) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&0x1234_u16.to_be_bytes());
        message.extend_from_slice(&flags.to_be_bytes());
        message.extend_from_slice(&question_count.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.push(4);
        message.extend_from_slice(b"Jira");
        message.push(7);
        message.extend_from_slice(b"Example");
        message.push(0);
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message
    }

    fn append_opt(message: &mut Vec<u8>, payload_size: u16, ttl: u32, rdata: &[u8]) {
        message[10..12].copy_from_slice(&1_u16.to_be_bytes());
        message.push(0);
        message.extend_from_slice(&41_u16.to_be_bytes());
        message.extend_from_slice(&payload_size.to_be_bytes());
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        message.extend_from_slice(rdata);
    }

    #[test]
    fn parses_one_question_with_edns_and_query_flags() {
        let mut message = query(0x0130, 1, 28);
        append_opt(&mut message, 1232, 0x0000_8000, &[0, 10, 0, 2, 7, 9]);

        let parsed = DnsQuery::parse_udp(&message).unwrap();

        assert_eq!(parsed.id(), 0x1234);
        assert_eq!(parsed.question().name().to_ascii().unwrap(), "Jira.Example");
        assert_eq!(parsed.question().record_type(), RecordType::Aaaa);
        assert_eq!(parsed.question().record_class(), RecordClass::Internet);
        assert!(parsed.recursion_desired());
        assert!(parsed.checking_disabled());
        assert!(parsed.dnssec_ok());
        assert_eq!(parsed.requested_udp_payload_size(), 1232);
    }

    #[test]
    fn sub_512_edns_payloads_are_treated_as_512() {
        let mut message = query(0x0100, 1, 1);
        append_opt(&mut message, 128, 0, &[]);

        assert_eq!(
            DnsQuery::parse_udp(&message)
                .unwrap()
                .requested_udp_payload_size(),
            512
        );
    }

    #[test]
    fn rejects_invalid_headers_and_section_counts() {
        let cases = [
            (query(0x8100, 1, 1), ParseError::NotAQuery),
            (query(0x0900, 1, 1), ParseError::UnsupportedOpcode(1)),
            (query(0x0140, 1, 1), ParseError::ReservedHeaderBitSet),
            (query(0x0500, 1, 1), ParseError::ResponseOnlyHeaderBitSet),
            (query(0x0103, 1, 1), ParseError::ResponseCodeInQuery(3)),
            (query(0x0100, 0, 1), ParseError::QuestionCount(0)),
        ];

        for (message, expected) in cases {
            assert_eq!(DnsQuery::parse_udp(&message), Err(expected));
        }

        let mut sections = query(0x0100, 1, 1);
        sections[6..8].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            DnsQuery::parse_udp(&sections),
            Err(ParseError::UnexpectedQuerySections { answers: 1, .. })
        ));
    }

    #[test]
    fn rejects_truncation_trailing_data_and_invalid_compression() {
        assert_eq!(
            DnsQuery::parse_udp(&[0; 11]),
            Err(ParseError::MessageTooShort(11))
        );

        let mut trailing = query(0x0100, 1, 1);
        trailing.push(0xff);
        assert_eq!(
            DnsQuery::parse_udp(&trailing),
            Err(ParseError::TrailingData(1))
        );

        let mut out_of_bounds = query(0x0100, 1, 1);
        out_of_bounds.splice(12..26, [0xff, 0xff]);
        assert_eq!(
            DnsQuery::parse_udp(&out_of_bounds),
            Err(ParseError::CompressionPointerOutOfBounds(16383))
        );

        let mut non_prior = query(0x0100, 1, 1);
        non_prior.splice(12..26, [0xc0, 0x0c]);
        assert_eq!(
            DnsQuery::parse_udp(&non_prior),
            Err(ParseError::CompressionPointerIsNotPrior(12))
        );

        let mut reserved_encoding = query(0x0100, 1, 1);
        reserved_encoding[12] = 0x40;
        assert_eq!(
            DnsQuery::parse_udp(&reserved_encoding),
            Err(ParseError::UnsupportedLabelEncoding(0x40))
        );
    }

    #[test]
    fn validates_opt_record_shape_version_flags_and_options() {
        let mut unexpected = query(0x0100, 1, 1);
        append_opt(&mut unexpected, 1232, 0, &[]);
        let opt_type_offset = unexpected.len() - 10;
        unexpected[opt_type_offset..opt_type_offset + 2].copy_from_slice(&16_u16.to_be_bytes());
        assert_eq!(
            DnsQuery::parse_udp(&unexpected),
            Err(ParseError::UnexpectedAdditionalRecord(16))
        );

        let mut version = query(0x0100, 1, 1);
        append_opt(&mut version, 1232, 0x0001_0000, &[]);
        assert_eq!(
            DnsQuery::parse_udp(&version),
            Err(ParseError::UnsupportedEdnsVersion(1))
        );

        let mut reserved_flags = query(0x0100, 1, 1);
        append_opt(&mut reserved_flags, 1232, 1, &[]);
        assert_eq!(
            DnsQuery::parse_udp(&reserved_flags),
            Err(ParseError::ReservedEdnsFlagSet(1))
        );

        let mut malformed_options = query(0x0100, 1, 1);
        append_opt(&mut malformed_options, 1232, 0, &[0, 10, 0, 3, 1]);
        assert_eq!(
            DnsQuery::parse_udp(&malformed_options),
            Err(ParseError::MalformedEdnsOptions)
        );

        let mut non_root = query(0x0100, 1, 1);
        non_root[10..12].copy_from_slice(&1_u16.to_be_bytes());
        non_root.extend_from_slice(&[1, b'x', 0]);
        non_root.extend_from_slice(&41_u16.to_be_bytes());
        non_root.extend_from_slice(&1232_u16.to_be_bytes());
        non_root.extend_from_slice(&0_u32.to_be_bytes());
        non_root.extend_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            DnsQuery::parse_udp(&non_root),
            Err(ParseError::OptNameIsNotRoot)
        );

        let mut extended_code = query(0x0100, 1, 1);
        append_opt(&mut extended_code, 1232, 0x0100_0000, &[]);
        assert_eq!(
            DnsQuery::parse_udp(&extended_code),
            Err(ParseError::ExtendedResponseCodeInQuery(1))
        );
    }

    #[test]
    fn every_truncated_prefix_of_a_valid_query_is_rejected() {
        let mut message = query(0x0100, 1, 1);
        append_opt(&mut message, 1232, 0, &[0, 10, 0, 2, 7, 9]);

        for length in 0..message.len() {
            assert!(
                DnsQuery::parse_udp(&message[..length]).is_err(),
                "accepted a query truncated to {length} bytes"
            );
        }
        assert!(DnsQuery::parse_udp(&message).is_ok());
    }

    #[test]
    fn oversized_messages_and_expanded_names_are_rejected() {
        assert_eq!(
            DnsQuery::parse_udp(&vec![0; 65_536]),
            Err(ParseError::MessageTooLong(65_536))
        );

        let mut message = Vec::new();
        message.extend_from_slice(&0x1234_u16.to_be_bytes());
        message.extend_from_slice(&0x0100_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&[0; 6]);
        for byte in *b"abcd" {
            message.push(63);
            message.extend(std::iter::repeat_n(byte, 63));
        }
        message.push(0);
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());

        assert!(matches!(
            DnsQuery::parse_udp(&message),
            Err(ParseError::InvalidName(super::NameError::NameTooLong(_)))
        ));
    }

    #[test]
    fn response_codes_are_bounded_to_the_base_header_field() {
        for code in 0..=15 {
            assert_eq!(super::ResponseCode::from_u8(code).unwrap().to_u8(), code);
        }
        assert_eq!(
            super::ResponseCode::from_u8(16),
            Err(super::InvalidResponseCode(16))
        );
    }

    #[test]
    fn tcp_framing_requires_exactly_one_complete_message() {
        let message = query(0x0100, 1, 1);
        let frame = frame_tcp_message(&message).unwrap();

        assert_eq!(unframe_tcp_message(&frame).unwrap(), message);
        assert_eq!(DnsQuery::parse_tcp_frame(&frame).unwrap().id(), 0x1234);
        assert_eq!(
            unframe_tcp_message(&[0]),
            Err(TcpFrameError::MissingLengthPrefix)
        );

        let mut truncated = frame.clone();
        truncated.pop();
        assert!(matches!(
            unframe_tcp_message(&truncated),
            Err(TcpFrameError::LengthMismatch { .. })
        ));

        let mut extra = frame;
        extra.push(0);
        assert!(matches!(
            unframe_tcp_message(&extra),
            Err(TcpFrameError::LengthMismatch { .. })
        ));
    }
}
