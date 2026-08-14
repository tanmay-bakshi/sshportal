use std::fmt;
use std::hash::{Hash, Hasher};

const MAX_LABEL_LENGTH: usize = 63;
const MAX_WIRE_NAME_LENGTH: usize = 255;

#[derive(Clone, Debug)]
pub struct DnsName {
    labels: Vec<Vec<u8>>,
}

pub(super) struct DnsNameBuilder {
    labels: Vec<Vec<u8>>,
    wire_len: usize,
}

impl DnsName {
    #[cfg(test)]
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    #[cfg(test)]
    pub fn from_ascii(value: &str) -> Result<Self, NameError> {
        if value == "." {
            return Ok(Self::root());
        }
        if value.is_empty() {
            return Err(NameError::EmptyTextName);
        }
        if !value.is_ascii() {
            return Err(NameError::NonAsciiText);
        }

        let value = value.strip_suffix('.').unwrap_or(value);
        if value.is_empty() {
            return Ok(Self::root());
        }

        let mut labels = Vec::new();
        for label in value.split('.') {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if label.len() > MAX_LABEL_LENGTH {
                return Err(NameError::LabelTooLong(label.len()));
            }
            if label
                .bytes()
                .any(|byte| !(0x21..=0x7e).contains(&byte) || byte == b'\\')
            {
                return Err(NameError::UnrepresentableText);
            }
            labels.push(label.as_bytes().to_vec());
        }
        Self::from_wire_labels(labels)
    }

    pub fn to_ascii(&self) -> Result<String, NameError> {
        if self.is_root() {
            return Ok(".".to_string());
        }

        let mut output = String::new();
        for (index, label) in self.labels.iter().enumerate() {
            if index > 0 {
                output.push('.');
            }
            for &byte in label {
                if !(0x21..=0x7e).contains(&byte) || byte == b'.' || byte == b'\\' {
                    return Err(NameError::UnrepresentableText);
                }
                output.push(char::from(byte));
            }
        }
        Ok(output)
    }

    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    pub(crate) fn ends_with_ascii_suffix(&self, suffix: &str) -> bool {
        let mut labels = self.labels.iter().rev();
        for suffix_label in suffix.rsplit('.') {
            let Some(label) = labels.next() else {
                return false;
            };
            if !label.eq_ignore_ascii_case(suffix_label.as_bytes()) {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    pub fn wire_len(&self) -> usize {
        self.labels
            .iter()
            .map(|label| label.len() + 1)
            .sum::<usize>()
            + 1
    }

    #[cfg(test)]
    pub(crate) fn from_wire_labels(labels: Vec<Vec<u8>>) -> Result<Self, NameError> {
        let mut builder = DnsNameBuilder::new();
        for label in labels {
            builder.push_owned_label(label)?;
        }
        Ok(builder.finish())
    }

    pub(crate) fn encode_uncompressed(&self, output: &mut Vec<u8>) {
        for label in &self.labels {
            output.push(label.len() as u8);
            output.extend_from_slice(label);
        }
        output.push(0);
    }
}

impl DnsNameBuilder {
    pub(super) fn new() -> Self {
        Self {
            labels: Vec::new(),
            wire_len: 1,
        }
    }

    pub(super) fn push_label(&mut self, label: &[u8]) -> Result<(), NameError> {
        self.validate_label(label)?;
        self.labels.push(label.to_vec());
        self.wire_len += label.len() + 1;
        Ok(())
    }

    pub(super) fn finish(self) -> DnsName {
        DnsName {
            labels: self.labels,
        }
    }

    #[cfg(test)]
    fn push_owned_label(&mut self, label: Vec<u8>) -> Result<(), NameError> {
        self.validate_label(&label)?;
        self.wire_len += label.len() + 1;
        self.labels.push(label);
        Ok(())
    }

    fn validate_label(&self, label: &[u8]) -> Result<(), NameError> {
        if label.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LENGTH {
            return Err(NameError::LabelTooLong(label.len()));
        }
        let wire_len = self.wire_len + label.len() + 1;
        if wire_len > MAX_WIRE_NAME_LENGTH {
            return Err(NameError::NameTooLong(wire_len));
        }
        Ok(())
    }
}

impl PartialEq for DnsName {
    fn eq(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self
                .labels
                .iter()
                .zip(&other.labels)
                .all(|(left, right)| left.eq_ignore_ascii_case(right))
    }
}

impl Eq for DnsName {}

impl Hash for DnsName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.labels.len().hash(state);
        for label in &self.labels {
            label.len().hash(state);
            for &byte in label {
                byte.to_ascii_lowercase().hash(state);
            }
        }
    }
}

impl fmt::Display for DnsName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return formatter.write_str(".");
        }

        for (index, label) in self.labels.iter().enumerate() {
            if index > 0 {
                formatter.write_str(".")?;
            }
            for &byte in label {
                match byte {
                    b'.' | b'\\' => write!(formatter, "\\{}", char::from(byte))?,
                    0x21..=0x7e => formatter.write_str(&char::from(byte).to_string())?,
                    _ => write!(formatter, "\\{byte:03}")?,
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NameError {
    #[cfg(test)]
    EmptyTextName,
    EmptyLabel,
    LabelTooLong(usize),
    NameTooLong(usize),
    #[cfg(test)]
    NonAsciiText,
    UnrepresentableText,
}

impl fmt::Display for NameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(test)]
            Self::EmptyTextName => formatter.write_str("a DNS name must not be empty"),
            Self::EmptyLabel => formatter.write_str("a DNS name contains an empty label"),
            Self::LabelTooLong(length) => {
                write!(
                    formatter,
                    "a DNS label is {length} bytes; the maximum is 63"
                )
            }
            Self::NameTooLong(length) => {
                write!(
                    formatter,
                    "a DNS name is {length} bytes on the wire; the maximum is 255"
                )
            }
            #[cfg(test)]
            Self::NonAsciiText => formatter.write_str(
                "textual DNS names must be ASCII; convert internationalized names to IDNA first",
            ),
            Self::UnrepresentableText => formatter.write_str(
                "the DNS name cannot be represented by the unescaped textual-name interface",
            ),
        }
    }
}

impl std::error::Error for NameError {}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{DnsName, NameError};

    #[test]
    fn textual_names_round_trip_and_accept_one_trailing_root_label() {
        let name = DnsName::from_ascii("Jira.Example.COM.").unwrap();

        assert_eq!(name.to_ascii().unwrap(), "Jira.Example.COM");
        assert_eq!(name.wire_len(), 18);
        assert_eq!(DnsName::from_ascii(".").unwrap(), DnsName::root());
    }

    #[test]
    fn name_identity_is_ascii_case_insensitive() {
        let upper = DnsName::from_ascii("JIRA.Example").unwrap();
        let lower = DnsName::from_ascii("jira.example").unwrap();
        let mut map = HashMap::new();
        map.insert(upper, 7);

        assert_eq!(map.get(&lower), Some(&7));
    }

    #[test]
    fn invalid_text_and_overlong_names_are_rejected() {
        assert_eq!(DnsName::from_ascii(""), Err(NameError::EmptyTextName));
        assert_eq!(
            DnsName::from_ascii("a..example"),
            Err(NameError::EmptyLabel)
        );
        assert_eq!(
            DnsName::from_ascii("café.example"),
            Err(NameError::NonAsciiText)
        );
        assert!(matches!(
            DnsName::from_ascii(&format!("{}.example", "a".repeat(64))),
            Err(NameError::LabelTooLong(64))
        ));
        assert!(matches!(
            DnsName::from_ascii(
                &[
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(62),
                ]
                .join(".")
            ),
            Err(NameError::NameTooLong(_))
        ));
    }

    #[test]
    fn maximum_length_wire_name_is_accepted_without_an_off_by_one() {
        let name = DnsName::from_wire_labels(vec![
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 61],
        ])
        .unwrap();

        assert_eq!(name.wire_len(), 255);
    }

    #[test]
    fn wire_names_can_be_compared_and_displayed_without_assuming_utf8() {
        let name = DnsName::from_wire_labels(vec![vec![b'a', b'.', 0xff]]).unwrap();

        assert_eq!(name.to_string(), "a\\.\\255");
        assert_eq!(name.to_ascii(), Err(NameError::UnrepresentableText));
    }
}
