//! The `[security]` section of `config.toml`: what Atuin keeps out of what it stores, on top of
//! its built-in rules.

use std::borrow::Cow;

use atuin_common::secrets::files::SensitiveFiles;
use atuin_common::secrets::{REDACT_BUDGET, RedactPattern, Redactor};
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Security {
    /// Regular expressions for credentials of your own, redacted wherever Atuin redacts: in the
    /// commands history keeps, in captured command output and in AI sessions. A pattern's `secret`
    /// group is what goes, where it names one (`api-key: (?<secret>\w+)`), else all it matches.
    /// A pattern given as `{ pattern = "...", replacement = "..." }` rewrites all it matches with
    /// its replacement instead (see [`RedactPattern`]).
    #[serde(deserialize_with = "redact_patterns", default, skip_serializing)]
    pub redact_patterns: Vec<RedactPattern>,

    /// Files of your own whose contents are credentials, on top of the built-in ones (`.env`,
    /// `~/.ssh/id_*`, `~/.aws/credentials`, ...): what an AI agent reads out of them or writes to
    /// them is not captured, nor the output of a command naming one. A glob without a `/` is
    /// matched against a file's name (`*.secret`); one with a `/` against its path
    /// (`~/work/creds/**`).
    #[serde(default)]
    pub sensitive_files: Vec<String>,
}

impl Security {
    /// Redaction with [`Self::redact_patterns`], and the built-in patterns while `builtin`
    /// (`secrets_filter`).
    #[must_use]
    pub fn redactor(&self, builtin: bool) -> Redactor {
        Redactor::new(self.redact_patterns.clone(), builtin)
    }

    /// `command` as history keeps it: with [`Self::redact_patterns`] applied, but not the built-in
    /// patterns, as a command they recognise is not kept at all (`secrets_filter`). `None` when
    /// that takes too long (see [`REDACT_BUDGET`]): then the command is better not kept.
    #[must_use]
    pub fn redact_command<'a>(&self, command: &'a str) -> Option<Cow<'a, str>> {
        self.redactor(false).redact_within(command, REDACT_BUDGET)
    }

    /// The files whose contents are credentials: the built-in ones, `key_path` (Atuin's own
    /// encryption key) and [`Self::sensitive_files`].
    #[must_use]
    pub fn sensitive_files(&self, key_path: &std::path::Path) -> SensitiveFiles {
        SensitiveFiles::new(&self.sensitive_files, &[key_path.to_path_buf()], dirs::home_dir())
    }
}

/// An entry of `redact_patterns`, as written in `config.toml`.
#[derive(Deserialize)]
#[serde(untagged, expecting = "a regular expression, or a table of `pattern` and `replacement`")]
enum RawRedactPattern {
    Plain(String),
    Replacing(RawReplacingPattern),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReplacingPattern {
    pattern: String,
    replacement: String,
}

/// Compiles `redact_patterns`, rejecting a replacement that refers to a group its pattern does not
/// have: it would quietly expand to nothing, keeping less than the user meant -- or, for a `$` meant
/// literally, rewriting a command into one that no longer runs as it did.
fn redact_patterns<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RedactPattern>, D::Error> {
    use serde::de::Error;

    Vec::<RawRedactPattern>::deserialize(deserializer)?
        .into_iter()
        .enumerate()
        .map(|(i, raw)| {
            let (pattern, replacement) = match raw {
                RawRedactPattern::Plain(pattern) => (pattern, None),
                RawRedactPattern::Replacing(RawReplacingPattern {
                    pattern,
                    replacement,
                }) => (pattern, Some(replacement)),
            };
            let regex = Regex::new(&pattern)
                .map_err(|e| D::Error::custom(format!("redact_patterns[{i}]: {e}")))?;
            match replacement {
                None => Ok(RedactPattern::new(regex)),
                Some(replacement) => RedactPattern::with_replacement(regex, replacement)
                    .map_err(|e| D::Error::custom(format!("redact_patterns[{i}]: {e}"))),
            }
        })
        .collect()
}
