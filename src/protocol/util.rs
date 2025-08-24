//! # MQTT Protocol Utilities
//!
//! This module provides utility functions for MQTT protocol handling, including:
//! - Variable byte integer length calculation
//! - Topic name and filter validation
//! - System topic detection
//!
//! These utilities are used throughout the codec for validating MQTT-specific
//! data structures and ensuring protocol compliance.
//!

/// Calculates the number of bytes required to encode a length value using MQTT's
/// variable byte integer encoding format.
///
/// MQTT uses a variable-length encoding scheme for remaining length values where
/// each byte encodes 7 bits of data with the most significant bit indicating
/// continuation. This function determines how many bytes are needed to encode
/// a given length value.
///
/// # Panics
///
/// Panics if the length exceeds the maximum allowed by MQTT specification
/// (268,435,455 bytes or ~256 MB).
///
/// # MQTT Specification Reference
///
/// This implements the variable byte integer encoding from MQTT specification
/// section 1.5.5.
///
/// # Example
///
/// ```
/// use mqute_codec::protocol::util;
///
/// assert_eq!(util::len_bytes(127), 1);    // Fits in 1 byte
/// assert_eq!(util::len_bytes(128), 2);    // Requires 2 bytes
/// assert_eq!(util::len_bytes(16383), 2);  // Maximum for 2 bytes
/// assert_eq!(util::len_bytes(16384), 3);  // Requires 3 bytes
/// ```
#[inline]
pub fn len_bytes(len: usize) -> usize {
    if len < 128 {
        1
    } else if len < 16_384 {
        2
    } else if len < 2_097_152 {
        3
    } else if len < 268_435_456 {
        4
    } else {
        panic!("Length of remaining bytes must be less than 28 bits")
    }
}

/// Validates whether a string is a valid MQTT topic name.
///
/// MQTT topic names must follow specific rules:
/// - Must not be empty
/// - Maximum length of 65,535 UTF-8 encoded bytes
/// - Must not contain null characters
/// - Must not contain wildcards (`+` or `#`)
/// - Can contain any other UTF-8 characters including `/` for hierarchy
///
/// # MQTT Specification Reference
///
/// Follows MQTT specification rules for topic names (section 4.7).
///
/// # Example
///
/// ```
/// use mqute_codec::protocol::util;
///
/// assert!(util::is_valid_topic_name("sensors/temperature"));
/// assert!(util::is_valid_topic_name("$SYS/monitor"));
/// assert!(!util::is_valid_topic_name("sensors/+")); // Contains wildcard
/// assert!(!util::is_valid_topic_name(""));          // Empty
/// ```
pub fn is_valid_topic_name<T: AsRef<str>>(name: T) -> bool {
    let name = name.as_ref();

    // Check minimum length and UTF-8 encoding length
    if name.is_empty() || name.len() > 65_535 {
        return false;
    }

    // Check for null character and wildcards (not allowed in topic names)
    if name.contains('\0') || name.contains('#') || name.contains('+') {
        return false;
    }

    true
}

/// Validates whether a string is a valid MQTT topic filter.
///
/// MQTT topic filters are used in subscriptions and can include wildcards:
/// - `+` (single-level wildcard) - matches one hierarchy level
/// - `#` (multi-level wildcard) - matches zero or more hierarchy levels
///
/// Validation rules:
/// - Must not be empty
/// - Maximum length of 65,535 UTF-8 encoded bytes
/// - Must not contain null characters
/// - Multi-level wildcard (`#`) must be the last character if present
/// - Multi-level wildcard must be preceded by `/` unless it's the only character
/// - Single-level wildcard (`+`) must occupy entire hierarchy levels
///
/// # MQTT Specification Reference
///
/// Follows MQTT specification rules for topic filters (section 4.7).
///
/// # Example
///
/// ```
/// use mqute_codec::protocol::util;
///
/// assert!(util::is_valid_topic_filter("sensors/+/temperature"));
/// assert!(util::is_valid_topic_filter("sensors/#"));
/// assert!(util::is_valid_topic_filter("sensors/+/temperature/#"));
/// assert!(!util::is_valid_topic_filter("sensors/temperature/#/ranking"));
/// assert!(!util::is_valid_topic_filter("sensors+"));
/// ```
pub fn is_valid_topic_filter<T: AsRef<str>>(filter: T) -> bool {
    let filter = filter.as_ref();

    // Check minimum length and UTF-8 encoding length
    if filter.is_empty() || filter.len() > 65_535 {
        return false;
    }

    // Check for null character
    if filter.contains('\0') {
        return false;
    }

    // Multi-level wildcard validation
    if let Some(pos) = filter.find('#') {
        // Multi-level wildcard must be last character
        if pos != filter.len() - 1 {
            return false;
        }

        // Multi-level wildcard must be preceded by separator or be alone
        if filter.len() > 1 {
            let preceding_char = filter.chars().nth(pos - 1).unwrap();
            if preceding_char != '/' {
                return false;
            }
        }

        // Check if # appears anywhere else
        if filter.matches('#').count() > 1 {
            return false;
        }
    }

    // Single-level wildcard validation
    if filter.contains('+') {
        // Split by levels to check each segment
        let levels: Vec<&str> = filter.split('/').collect();
        for level in levels {
            if level.contains('+') && level != "+" {
                return false;
            }
        }
    }

    true
}

/// Determines if a topic name represents a system topic.
///
/// MQTT system topics are reserved for broker-specific functionality and
/// typically start with the `$` character. Clients should generally avoid
/// publishing to system topics unless specifically documented by the broker.
///
/// # Example
///
/// ```
/// use mqute_codec::protocol::util;
///
/// assert!(util::is_system_topic("$SYS/monitor"));
/// assert!(!util::is_system_topic("sensors/temperature"));
/// ```
pub fn is_system_topic<T: AsRef<str>>(topic: T) -> bool {
    topic.as_ref().starts_with('$')
}

#[cfg(test)]
mod tests {
    use crate::protocol::util;

    #[test]
    fn test_valid_topic_names() {
        let topic_names = vec![
            "sport/tennis/player1",
            "sport/tennis/player1/ranking",
            "sport/tennis/player1/score/wimbledon",
            "sport",
            "sport/",
            "/",
            "Accounts payable",
            "/finance",
            "$SYS/monitor/Clients",
        ];

        for name in topic_names {
            assert!(util::is_valid_topic_name(name));
        }
    }

    #[test]
    fn test_invalid_topic_names() {
        let topic_names = vec![
            "",
            "sport/\0/tennis",
            "sport/tennis/player1/#",
            "sport+",
            "#",
            "sport/tennis#",
            "sport/tennis/#/ranking",
        ];

        for name in topic_names {
            assert!(!util::is_valid_topic_name(name));
        }
    }

    #[test]
    fn test_valid_topic_filters() {
        let filters = vec![
            "sport/tennis/player1/#",
            "sport/#",
            "#",
            "sport/tennis/#",
            "+",
            "+/tennis/#",
            "sport/+/player1",
            "/finance",
            "$SYS/#",
            "$SYS/monitor/+",
        ];

        for filter in filters {
            assert!(util::is_valid_topic_filter(filter));
        }
    }

    #[test]
    fn test_invalid_topic_filters() {
        let filters = vec!["sport/tennis#", "sport/tennis/#/ranking", "sport+", ""];

        for filter in filters {
            assert!(!util::is_valid_topic_filter(filter));
        }
    }
}
