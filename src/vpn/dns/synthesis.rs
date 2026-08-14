use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::mapping::SyntheticAddressMap;
use super::name::DnsName;
use super::protocol::{
    DnsQuery, RecordClass, RecordType, ResponseCode, TcpFrameError, frame_tcp_message, write_u16,
    write_u32,
};

const DNS_HEADER_LENGTH: usize = 12;
const DNS_UDP_MINIMUM_PAYLOAD: usize = 512;
const DNS_MESSAGE_MAXIMUM: usize = u16::MAX as usize;
const MAX_SYNTHETIC_TTL_SECONDS: u32 = 30;
const TYPE_OPT: u16 = 41;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// The client resolver observed data for the requested type. Real client-side
    /// addresses and aliases never cross into the synthesized response.
    Positive {
        synthetic_ttl: u32,
    },
    NoData,
    Failure(ResponseCode),
}

pub fn synthesize_response(
    query: &DnsQuery,
    resolution: Resolution,
    mappings: &mut SyntheticAddressMap,
) -> Result<DnsResponse, SynthesisError> {
    if query.question().record_class() != RecordClass::Internet {
        return Ok(DnsResponse::new(
            query.clone(),
            ResponseCode::NOT_IMPLEMENTED,
            Vec::new(),
        ));
    }

    let (response_code, positive_ttl) = match resolution {
        Resolution::Positive { synthetic_ttl } => (ResponseCode::NO_ERROR, Some(synthetic_ttl)),
        Resolution::NoData => (ResponseCode::NO_ERROR, None),
        Resolution::Failure(response_code) => {
            if response_code == ResponseCode::NO_ERROR {
                return Err(SynthesisError::NoErrorFailure);
            }
            return Ok(DnsResponse::new(query.clone(), response_code, Vec::new()));
        }
    };

    let mut answers = Vec::new();

    let Some(synthetic_ttl) = positive_ttl else {
        return Ok(DnsResponse::new(query.clone(), response_code, answers));
    };
    let synthetic_ttl = synthetic_ttl.min(MAX_SYNTHETIC_TTL_SECONDS);
    match query.question().record_type() {
        RecordType::A => match mappings.get_or_allocate_ipv4(query.question().name()) {
            Ok(address) => answers.push(Answer::Ipv4 {
                owner: query.question().name().clone(),
                address,
                ttl: synthetic_ttl,
            }),
            Err(_) => {
                return Ok(DnsResponse::new(
                    query.clone(),
                    ResponseCode::SERVER_FAILURE,
                    Vec::new(),
                ));
            }
        },
        RecordType::Aaaa => match mappings.get_or_allocate_ipv6(query.question().name()) {
            Ok(address) => answers.push(Answer::Ipv6 {
                owner: query.question().name().clone(),
                address,
                ttl: synthetic_ttl,
            }),
            Err(_) => {
                return Ok(DnsResponse::new(
                    query.clone(),
                    ResponseCode::SERVER_FAILURE,
                    Vec::new(),
                ));
            }
        },
        RecordType::Cname | RecordType::Svcb | RecordType::Https => {}
        RecordType::Other(_) => {
            return Ok(DnsResponse::new(
                query.clone(),
                ResponseCode::NOT_IMPLEMENTED,
                Vec::new(),
            ));
        }
    }

    Ok(DnsResponse::new(query.clone(), response_code, answers))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Answer {
    Ipv4 {
        owner: DnsName,
        address: Ipv4Addr,
        ttl: u32,
    },
    Ipv6 {
        owner: DnsName,
        address: Ipv6Addr,
        ttl: u32,
    },
}

impl Answer {
    fn encode(&self, output: &mut Vec<u8>) {
        match self {
            Self::Ipv4 {
                owner,
                address,
                ttl,
            } => {
                owner.encode_uncompressed(output);
                write_u16(output, RecordType::A.to_u16());
                write_u16(output, RecordClass::Internet.to_u16());
                write_u32(output, *ttl);
                write_u16(output, 4);
                output.extend_from_slice(&address.octets());
            }
            Self::Ipv6 {
                owner,
                address,
                ttl,
            } => {
                owner.encode_uncompressed(output);
                write_u16(output, RecordType::Aaaa.to_u16());
                write_u16(output, RecordClass::Internet.to_u16());
                write_u32(output, *ttl);
                write_u16(output, 16);
                output.extend_from_slice(&address.octets());
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsResponse {
    query: DnsQuery,
    response_code: ResponseCode,
    answers: Vec<Answer>,
}

impl DnsResponse {
    fn new(query: DnsQuery, response_code: ResponseCode, answers: Vec<Answer>) -> Self {
        Self {
            query,
            response_code,
            answers,
        }
    }

    #[cfg(test)]
    pub fn response_code(&self) -> ResponseCode {
        self.response_code
    }

    #[cfg(test)]
    pub fn answer_count(&self) -> usize {
        self.answers.len()
    }

    pub fn to_udp(&self, server_payload_limit: usize) -> Result<Vec<u8>, EncodeError> {
        let server_payload_limit =
            server_payload_limit.clamp(DNS_UDP_MINIMUM_PAYLOAD, DNS_MESSAGE_MAXIMUM);
        let payload_limit = self
            .query
            .requested_udp_payload_size()
            .min(server_payload_limit);
        let full = self.encode_message(false, true, payload_limit)?;
        if full.len() <= payload_limit {
            return Ok(full);
        }

        let truncated = self.encode_message(true, false, payload_limit)?;
        if truncated.len() > payload_limit {
            return Err(EncodeError::QuestionExceedsUdpPayload {
                message_length: truncated.len(),
                payload_limit,
            });
        }
        Ok(truncated)
    }

    pub fn to_tcp(&self) -> Result<Vec<u8>, EncodeError> {
        let payload_size = self
            .query
            .requested_udp_payload_size()
            .min(DNS_MESSAGE_MAXIMUM);
        let message = self.encode_message(false, true, payload_size)?;
        frame_tcp_message(&message).map_err(EncodeError::TcpFrame)
    }

    fn encode_message(
        &self,
        truncated: bool,
        include_answers: bool,
        edns_payload_size: usize,
    ) -> Result<Vec<u8>, EncodeError> {
        let answer_count = if include_answers {
            u16::try_from(self.answers.len())
                .map_err(|_| EncodeError::TooManyAnswers(self.answers.len()))?
        } else {
            0
        };
        let additional_count = u16::from(self.query.uses_edns());
        let mut message = Vec::with_capacity(DNS_HEADER_LENGTH + 256);
        write_u16(&mut message, self.query.id());
        write_u16(
            &mut message,
            self.query.response_flags(self.response_code, truncated),
        );
        write_u16(&mut message, 1);
        write_u16(&mut message, answer_count);
        write_u16(&mut message, 0);
        write_u16(&mut message, additional_count);
        self.query.question().encode(&mut message);
        if include_answers {
            for answer in &self.answers {
                answer.encode(&mut message);
            }
        }
        if self.query.uses_edns() {
            message.push(0);
            write_u16(&mut message, TYPE_OPT);
            write_u16(&mut message, edns_payload_size as u16);
            write_u32(&mut message, 0);
            write_u16(&mut message, 0);
        }
        if message.len() > DNS_MESSAGE_MAXIMUM {
            return Err(EncodeError::MessageTooLong(message.len()));
        }
        Ok(message)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SynthesisError {
    NoErrorFailure,
}

impl fmt::Display for SynthesisError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoErrorFailure => {
                formatter.write_str("a DNS failure result cannot carry the NOERROR response code")
            }
        }
    }
}

impl std::error::Error for SynthesisError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    TooManyAnswers(usize),
    MessageTooLong(usize),
    QuestionExceedsUdpPayload {
        message_length: usize,
        payload_limit: usize,
    },
    TcpFrame(TcpFrameError),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyAnswers(count) => {
                write!(
                    formatter,
                    "DNS response has {count} answers; the maximum is 65535"
                )
            }
            Self::MessageTooLong(length) => {
                write!(
                    formatter,
                    "DNS response is {length} bytes; the maximum is 65535"
                )
            }
            Self::QuestionExceedsUdpPayload {
                message_length,
                payload_limit,
            } => write!(
                formatter,
                "truncated DNS response is {message_length} bytes and exceeds its {payload_limit}-byte UDP limit"
            ),
            Self::TcpFrame(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TcpFrame(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::super::mapping::{Ipv4Pool, Ipv6Pool, SyntheticAddressMap};
    use super::super::name::DnsName;
    use super::super::protocol::{
        DnsQuery, RecordType, ResponseCode, parse_name, unframe_tcp_message,
    };
    use super::{Answer, DnsResponse, Resolution, SynthesisError, synthesize_response};

    struct ParsedAnswer {
        owner: DnsName,
        record_type: u16,
        ttl: u32,
        rdata: Vec<u8>,
    }

    struct ParsedResponse {
        flags: u16,
        answers: Vec<ParsedAnswer>,
        additional_count: u16,
    }

    fn query(record_type: u16, edns: bool) -> DnsQuery {
        let mut message = Vec::new();
        message.extend_from_slice(&0x9876_u16.to_be_bytes());
        message.extend_from_slice(&0x0130_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&0_u16.to_be_bytes());
        message.extend_from_slice(&u16::from(edns).to_be_bytes());
        message.push(4);
        message.extend_from_slice(b"Jira");
        message.push(7);
        message.extend_from_slice(b"Example");
        message.push(0);
        message.extend_from_slice(&record_type.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        if edns {
            message.push(0);
            message.extend_from_slice(&41_u16.to_be_bytes());
            message.extend_from_slice(&1232_u16.to_be_bytes());
            message.extend_from_slice(&0x0000_8000_u32.to_be_bytes());
            message.extend_from_slice(&0_u16.to_be_bytes());
        }
        DnsQuery::parse_udp(&message).unwrap()
    }

    fn mappings(maximum_allocations: usize) -> SyntheticAddressMap {
        SyntheticAddressMap::new(
            Some(
                Ipv4Pool::new(
                    "198.18.0.2".parse().unwrap(),
                    "198.18.0.8".parse().unwrap(),
                    maximum_allocations,
                    [],
                )
                .unwrap(),
            ),
            Some(
                Ipv6Pool::new(
                    "fd00::2".parse().unwrap(),
                    "fd00::8".parse().unwrap(),
                    maximum_allocations,
                    [],
                )
                .unwrap(),
            ),
        )
    }

    fn parse_response(message: &[u8]) -> ParsedResponse {
        let flags = u16::from_be_bytes([message[2], message[3]]);
        let question_count = u16::from_be_bytes([message[4], message[5]]);
        let answer_count = u16::from_be_bytes([message[6], message[7]]);
        let additional_count = u16::from_be_bytes([message[10], message[11]]);
        assert_eq!(question_count, 1);

        let (_, mut offset) = parse_name(message, 12).unwrap();
        offset += 4;
        let mut answers = Vec::new();
        for _ in 0..answer_count {
            let (owner, next) = parse_name(message, offset).unwrap();
            offset = next;
            let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
            offset += 4;
            let ttl = u32::from_be_bytes([
                message[offset],
                message[offset + 1],
                message[offset + 2],
                message[offset + 3],
            ]);
            offset += 4;
            let length = usize::from(u16::from_be_bytes([message[offset], message[offset + 1]]));
            offset += 2;
            let rdata = message[offset..offset + length].to_vec();
            offset += length;
            answers.push(ParsedAnswer {
                owner,
                record_type,
                ttl,
                rdata,
            });
        }
        ParsedResponse {
            flags,
            answers,
            additional_count,
        }
    }

    #[test]
    fn positive_a_response_flattens_aliases_to_the_original_name() {
        let query = query(RecordType::A.to_u16(), false);
        let mut mappings = mappings(8);
        let response = synthesize_response(
            &query,
            Resolution::Positive { synthetic_ttl: 20 },
            &mut mappings,
        )
        .unwrap();
        let encoded = response.to_udp(4096).unwrap();
        let parsed = parse_response(&encoded);

        assert_eq!(response.response_code(), ResponseCode::NO_ERROR);
        assert_eq!(response.answer_count(), 1);
        assert_eq!(parsed.answers[0].record_type, 1);
        assert_eq!(parsed.answers[0].owner.to_ascii().unwrap(), "Jira.Example");
        assert_eq!(parsed.answers[0].ttl, 20);
        assert_eq!(parsed.answers[0].rdata, [198, 18, 0, 2]);
        let original = DnsName::from_ascii("jira.example").unwrap();
        assert_eq!(
            mappings.name_for_address(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2))),
            Some(&original)
        );
    }

    #[test]
    fn positive_aaaa_response_uses_an_independent_stable_mapping() {
        let query = query(RecordType::Aaaa.to_u16(), false);
        let mut mappings = mappings(8);
        let response = synthesize_response(
            &query,
            Resolution::Positive { synthetic_ttl: 60 },
            &mut mappings,
        )
        .unwrap();
        let parsed = parse_response(&response.to_udp(4096).unwrap());

        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].record_type, 28);
        assert_eq!(parsed.answers[0].ttl, 30);
        assert_eq!(
            parsed.answers[0].rdata,
            "fd00::2".parse::<Ipv6Addr>().unwrap().octets()
        );
        assert_eq!(mappings.ipv4_len(), 0);
        assert_eq!(mappings.ipv6_len(), 1);
    }

    #[test]
    fn nodata_and_failure_rcodes_remain_distinct() {
        let query = query(RecordType::A.to_u16(), false);
        let mut mappings = mappings(8);

        let nodata = synthesize_response(&query, Resolution::NoData, &mut mappings).unwrap();
        let refused = synthesize_response(
            &query,
            Resolution::Failure(ResponseCode::REFUSED),
            &mut mappings,
        )
        .unwrap();

        assert_eq!(nodata.response_code(), ResponseCode::NO_ERROR);
        assert_eq!(nodata.answer_count(), 0);
        assert_eq!(refused.response_code(), ResponseCode::REFUSED);
        assert_eq!(mappings.ipv4_len(), 0);
    }

    #[test]
    fn cname_queries_are_alias_free_nodata() {
        let query = query(RecordType::Cname.to_u16(), false);
        let mut mappings = mappings(8);
        let response = synthesize_response(
            &query,
            Resolution::Positive { synthetic_ttl: 20 },
            &mut mappings,
        )
        .unwrap();

        assert_eq!(response.answer_count(), 0);
        assert_eq!(mappings.ipv4_len(), 0);
        assert_eq!(mappings.ipv6_len(), 0);
    }

    #[test]
    fn https_and_svcb_are_safe_nodata_and_never_leak_address_hints() {
        for record_type in [RecordType::Https, RecordType::Svcb] {
            let query = query(record_type.to_u16(), false);
            let mut mappings = mappings(8);
            let response = synthesize_response(
                &query,
                Resolution::Positive { synthetic_ttl: 30 },
                &mut mappings,
            )
            .unwrap();

            assert_eq!(response.response_code(), ResponseCode::NO_ERROR);
            assert_eq!(response.answer_count(), 0);
            assert_eq!(mappings.ipv4_len(), 0);
            assert_eq!(mappings.ipv6_len(), 0);
        }
    }

    #[test]
    fn synthetic_ttl_is_capped_without_raising_zero() {
        let query = query(RecordType::A.to_u16(), false);
        let capped = synthesize_response(
            &query,
            Resolution::Positive { synthetic_ttl: 120 },
            &mut mappings(8),
        )
        .unwrap();
        let zero = synthesize_response(
            &query,
            Resolution::Positive { synthetic_ttl: 0 },
            &mut mappings(8),
        )
        .unwrap();

        assert_eq!(
            parse_response(&capped.to_udp(4_096).unwrap()).answers[0].ttl,
            30
        );
        assert_eq!(
            parse_response(&zero.to_udp(4_096).unwrap()).answers[0].ttl,
            0
        );
    }

    #[test]
    fn unsupported_positive_types_are_not_misrepresented_as_nodata() {
        let query = query(15, false);
        let mut mappings = mappings(8);
        let response = synthesize_response(
            &query,
            Resolution::Positive { synthetic_ttl: 30 },
            &mut mappings,
        )
        .unwrap();

        assert_eq!(response.response_code(), ResponseCode::NOT_IMPLEMENTED);
        assert_eq!(response.answer_count(), 0);
        assert_eq!(mappings.ipv4_len(), 0);

        let nodata = synthesize_response(&query, Resolution::NoData, &mut mappings).unwrap();
        assert_eq!(nodata.response_code(), ResponseCode::NO_ERROR);
    }

    #[test]
    fn pool_exhaustion_is_visible_as_servfail_without_reuse() {
        let query = query(RecordType::A.to_u16(), false);
        let mut mappings = mappings(1);
        let first = synthesize_response(
            &query,
            Resolution::Positive { synthetic_ttl: 30 },
            &mut mappings,
        )
        .unwrap();
        let other_query_bytes = {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&0x1111_u16.to_be_bytes());
            bytes.extend_from_slice(&0x0100_u16.to_be_bytes());
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&[0; 6]);
            bytes.push(5);
            bytes.extend_from_slice(b"Other");
            bytes.push(7);
            bytes.extend_from_slice(b"Example");
            bytes.push(0);
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes.extend_from_slice(&1_u16.to_be_bytes());
            bytes
        };
        let other_query = DnsQuery::parse_udp(&other_query_bytes).unwrap();
        let exhausted = synthesize_response(
            &other_query,
            Resolution::Positive { synthetic_ttl: 30 },
            &mut mappings,
        )
        .unwrap();

        assert_eq!(first.response_code(), ResponseCode::NO_ERROR);
        assert_eq!(exhausted.response_code(), ResponseCode::SERVER_FAILURE);
        assert_eq!(exhausted.answer_count(), 0);
        assert_eq!(mappings.ipv4_len(), 1);
    }

    #[test]
    fn response_clears_ad_and_edns_do_while_preserving_rd_and_cd() {
        let query = query(RecordType::A.to_u16(), true);
        let mut mappings = mappings(8);
        let response = synthesize_response(&query, Resolution::NoData, &mut mappings).unwrap();
        let encoded = response.to_udp(1232).unwrap();
        let parsed = parse_response(&encoded);

        assert_eq!(parsed.flags & 0x8000, 0x8000);
        assert_eq!(parsed.flags & 0x0100, 0x0100);
        assert_eq!(parsed.flags & 0x0080, 0x0080);
        assert_eq!(parsed.flags & 0x0020, 0);
        assert_eq!(parsed.flags & 0x0010, 0x0010);
        assert_eq!(parsed.additional_count, 1);
        assert_eq!(
            &encoded[encoded.len() - 6..encoded.len() - 2],
            &[0, 0, 0, 0]
        );
    }

    #[test]
    fn udp_truncates_only_at_record_boundaries_and_tcp_retains_full_answer() {
        let query = query(RecordType::A.to_u16(), false);
        let long_label = "a".repeat(63);
        let answers = (0..10)
            .map(|index| Answer::Ipv4 {
                owner: DnsName::from_ascii(&format!("{long_label}.{index}.example")).unwrap(),
                address: Ipv4Addr::new(198, 18, 0, index + 2),
                ttl: 30,
            })
            .collect();
        let response = DnsResponse::new(query, ResponseCode::NO_ERROR, answers);

        let udp = response.to_udp(4096).unwrap();
        let udp_parsed = parse_response(&udp);
        assert!(udp.len() <= 512);
        assert_eq!(udp_parsed.flags & 0x0200, 0x0200);
        assert_eq!(udp_parsed.answers.len(), 0);

        let tcp = response.to_tcp().unwrap();
        let tcp_message = unframe_tcp_message(&tcp).unwrap();
        let tcp_parsed = parse_response(tcp_message);
        assert_eq!(tcp_parsed.flags & 0x0200, 0);
        assert_eq!(tcp_parsed.answers.len(), 10);
    }

    #[test]
    fn noerror_cannot_be_disguised_as_a_failure() {
        let query = query(RecordType::A.to_u16(), false);
        let mut mappings = mappings(8);

        assert_eq!(
            synthesize_response(
                &query,
                Resolution::Failure(ResponseCode::NO_ERROR),
                &mut mappings,
            ),
            Err(SynthesisError::NoErrorFailure)
        );
    }
}
