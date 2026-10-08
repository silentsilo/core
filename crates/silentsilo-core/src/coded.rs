//! Error messages a client translates.
//!
//! An error stays a string: code that compares one, logs it or prints it
//! goes on working. One a person reads carries, after its English and an
//! ASCII unit separator, the key a client translates it by and, when it has
//! values, their JSON. The English comes first, so a log or an older client
//! still shows a sentence. Nothing here is written to disk: these are
//! messages, not formats.

use std::fmt::Display;

/// Never in a sentence, so never a false match.
pub const SEP: char = '\u{1f}';

/// A fixed message with its key, usable in a `const`.
#[macro_export]
macro_rules! coded {
    ($code:literal, $english:literal) => {
        concat!($english, "\u{1f}", $code)
    };
}

/// A message with values: `english` has them written in, `params` names
/// each one for the translation.
pub fn coded_with(code: &str, english: impl Display, params: &[(&str, &dyn Display)]) -> String {
    let params: Vec<String> = params
        .iter()
        .map(|(name, value)| {
            format!(
                "{}:{}",
                serde_json_string(name),
                serde_json_string(&value.to_string())
            )
        })
        .collect();
    format!("{english}{SEP}{code}{SEP}{{{}}}", params.join(","))
}

/// The English alone, for a place that shows the text as it is (a terminal,
/// a file).
pub fn english(message: &str) -> &str {
    message.split(SEP).next().unwrap_or(message)
}

/// A JSON string literal, without a JSON dependency here.
fn serde_json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_english_comes_first_and_the_key_after() {
        const FIXED: &str = coded!("err.silo_not_open", "That silo is not open.");
        assert_eq!(FIXED, "That silo is not open.\u{1f}err.silo_not_open");
        assert_eq!(english(FIXED), "That silo is not open.");

        let with = coded_with(
            "err.sign_in_first",
            "Sign in to \"Drive\" first.",
            &[("provider", &"Google \"Drive\"")],
        );
        let parts: Vec<&str> = with.split(SEP).collect();
        assert_eq!(parts[1], "err.sign_in_first");
        assert_eq!(parts[2], r#"{"provider":"Google \"Drive\""}"#);
        assert_eq!(english(&with), "Sign in to \"Drive\" first.");
    }
}
