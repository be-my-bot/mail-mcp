//! Message parsing and MIME handling
//!
//! Parses RFC822 messages using `mailparse`, extracts body text/HTML,
//! and handles attachments. Sanitizes HTML with `ammonia` and supports
//! optional PDF text extraction.

use std::collections::BTreeMap;

use mailparse::{DispositionType, MailHeader, ParsedMail};

use crate::errors::{AppError, AppResult};
use crate::models::AttachmentInfo;

/// Parsed message representation
///
/// Contains extracted headers, body content, and attachment metadata.
/// Bodies are truncated by caller to configured limits.
#[derive(Debug, Clone)]
pub struct ParsedMessage {
    /// Parsed Date header
    pub date: Option<String>,
    /// Parsed From header
    pub from: Option<String>,
    /// Parsed To header
    pub to: Option<String>,
    /// Parsed Cc header
    pub cc: Option<String>,
    /// Parsed Subject header
    pub subject: Option<String>,
    /// All headers as key-value pairs
    pub headers_all: Vec<(String, String)>,
    /// Plain text body (untruncated)
    pub body_text: Option<String>,
    /// Sanitized HTML body (untruncated)
    pub body_html_sanitized: Option<String>,
    /// Attachment metadata
    pub attachments: Vec<AttachmentInfo>,
}

/// Parse RFC822 message into structured representation
///
/// Extracts headers, body text/HTML, and attachment info. Sanitizes
/// HTML and optionally extracts text from PDF attachments.
///
/// # Parameters
///
/// - `raw`: RFC822 message bytes
/// - `body_max_chars`: Maximum characters for body text/HTML (caller truncates)
/// - `include_html`: Whether to include HTML body
/// - `extract_attachment_text`: Whether to extract text from PDFs
/// - `attachment_text_max_chars`: Maximum characters for extracted PDF text
///
/// # Errors
///
/// - `Internal` if `mailparse` fails
pub fn parse_message(
    raw: &[u8],
    body_max_chars: usize,
    include_html: bool,
    extract_attachment_text: bool,
    attachment_text_max_chars: usize,
) -> AppResult<ParsedMessage> {
    let parsed = mailparse::parse_mail(raw)
        .map_err(|e| AppError::Internal(format!("failed to parse RFC822 message: {e}")))?;

    let headers = parse_all_headers(raw)?;
    let mut body_text = None;
    let mut body_html = None;
    let mut attachments: Vec<(AttachmentInfo, Vec<u8>)> = Vec::new();

    walk_parts(
        &parsed,
        "1".to_owned(),
        &mut body_text,
        &mut body_html,
        &mut attachments,
        extract_attachment_text,
        attachment_text_max_chars,
    )?;

    let text = body_text.map(|t| truncate_chars(t, body_max_chars));
    let html = if include_html {
        body_html.map(|h| truncate_chars(h, body_max_chars))
    } else {
        None
    };

    let header_map = to_header_map(&headers);
    Ok(ParsedMessage {
        date: header_map.get("date").cloned(),
        from: header_map.get("from").cloned(),
        to: header_map.get("to").cloned(),
        cc: header_map.get("cc").cloned(),
        subject: header_map.get("subject").cloned(),
        headers_all: headers,
        body_text: text,
        body_html_sanitized: html,
        attachments: attachments.into_iter().map(|(info, _)| info).collect(),
    })
}

/// Walk MIME part tree recursively
///
/// Traverses all MIME parts to extract text/plain, text/html bodies,
/// and attachment metadata. Handles multipart structures correctly.
fn walk_parts(
    part: &ParsedMail<'_>,
    part_id: String,
    body_text: &mut Option<String>,
    body_html: &mut Option<String>,
    attachments: &mut Vec<(AttachmentInfo, Vec<u8>)>,
    extract_attachment_text: bool,
    attachment_text_max_chars: usize,
) -> AppResult<()> {
    if part.subparts.is_empty() {
        let ctype = part.ctype.mimetype.to_ascii_lowercase();
        let disp = part.get_content_disposition();
        let filename = attachment_filename(part, &disp.params);
        let is_attachment = disp.disposition == DispositionType::Attachment || filename.is_some();

        if !is_attachment {
            if ctype == "text/plain"
                && body_text.is_none()
                && let Ok(text) = part.get_body()
            {
                *body_text = Some(text);
            }

            if ctype == "text/html"
                && body_html.is_none()
                && let Ok(html) = part.get_body()
            {
                *body_html = Some(ammonia::clean(&html));
            }
        }

        if is_attachment {
            let raw_body = part
                .get_body_raw()
                .map_err(|e| AppError::Internal(format!("failed decoding attachment body: {e}")))?;
            let mut extracted_text = None;
            if extract_attachment_text
                && ctype == "application/pdf"
                && raw_body.len() <= 5_000_000
                && let Ok(text) = pdf_extract::extract_text_from_mem(&raw_body)
            {
                extracted_text = Some(truncate_chars(text, attachment_text_max_chars));
            }

            attachments.push((
                AttachmentInfo {
                    filename,
                    content_type: ctype,
                    size_bytes: raw_body.len(),
                    part_id,
                    extracted_text,
                },
                raw_body,
            ));
        }

        return Ok(());
    }

    for (idx, sub) in part.subparts.iter().enumerate() {
        let next_id = format!("{part_id}.{}", idx + 1);
        walk_parts(
            sub,
            next_id,
            body_text,
            body_html,
            attachments,
            extract_attachment_text,
            attachment_text_max_chars,
        )?;
    }
    Ok(())
}

/// A resolved attachment: metadata plus decoded part bytes
#[derive(Debug)]
pub struct ResolvedAttachment {
    /// Attachment metadata (part id, content type, filename, size)
    pub info: AttachmentInfo,
    /// Decoded part bytes
    pub bytes: Vec<u8>,
}

/// Resolve an attachment by `part_id` or `filename`
///
/// - `part_id` only: exact match on the synthetic MIME path (IMAP section
///   numbering, e.g. `1.2`). Any leaf part can be addressed, including
///   inline text parts.
/// - `filename` (with or without `part_id`): matched against the attachment
///   list — exact first, then case-insensitive. Zero matches is a `NotFound`
///   error, more than one is an `InvalidInput` ambiguity error, and a
///   `part_id` that disagrees with the match is rejected.
///
/// # Errors
///
/// - `Internal` if `mailparse` fails
/// - `NotFound` if nothing matches
/// - `InvalidInput` on ambiguous or contradictory selection
pub fn resolve_attachment(
    raw: &[u8],
    part_id: Option<&str>,
    filename: Option<&str>,
) -> AppResult<ResolvedAttachment> {
    let parsed = mailparse::parse_mail(raw)
        .map_err(|e| AppError::Internal(format!("failed to parse RFC822 message: {e}")))?;

    let mut leaves = Vec::new();
    collect_leaf_parts(&parsed, "1".to_owned(), &mut leaves);

    if let Some(filename) = filename {
        let mut matches: Vec<&LeafPart> = leaves
            .iter()
            .filter(|leaf| leaf.is_attachment && leaf.filename.as_deref() == Some(filename))
            .collect();
        if matches.is_empty() {
            matches = leaves
                .iter()
                .filter(|leaf| {
                    leaf.is_attachment
                        && leaf
                            .filename
                            .as_deref()
                            .is_some_and(|f| f.eq_ignore_ascii_case(filename))
                })
                .collect();
        }
        match matches.len() {
            0 => Err(AppError::NotFound(format!(
                "no attachment named '{filename}'"
            ))),
            1 => {
                let leaf = matches[0];
                if let Some(part_id) = part_id
                    && part_id != leaf.part_id
                {
                    return Err(AppError::InvalidInput(format!(
                        "part_id '{part_id}' does not match attachment '{filename}' (part {})",
                        leaf.part_id
                    )));
                }
                Ok(ResolvedAttachment {
                    info: leaf.to_attachment_info(),
                    bytes: leaf.bytes.clone(),
                })
            }
            n => Err(AppError::InvalidInput(format!(
                "filename '{filename}' matches {n} attachments (parts {}); select by part_id instead",
                matches
                    .iter()
                    .map(|m| m.part_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))),
        }
    } else if let Some(part_id) = part_id {
        let leaf = leaves
            .iter()
            .find(|leaf| leaf.part_id == part_id)
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "no message part '{part_id}' (available parts: {})",
                    leaves
                        .iter()
                        .map(|l| l.part_id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
        Ok(ResolvedAttachment {
            info: leaf.to_attachment_info(),
            bytes: leaf.bytes.clone(),
        })
    } else {
        Err(AppError::InvalidInput(
            "provide part_id or filename".to_owned(),
        ))
    }
}

/// A leaf MIME part with its section id and decoded bytes
struct LeafPart {
    part_id: String,
    content_type: String,
    filename: Option<String>,
    is_attachment: bool,
    bytes: Vec<u8>,
}

impl LeafPart {
    fn to_attachment_info(&self) -> AttachmentInfo {
        AttachmentInfo {
            filename: self.filename.clone(),
            content_type: self.content_type.clone(),
            size_bytes: self.bytes.len(),
            part_id: self.part_id.clone(),
            extracted_text: None,
        }
    }
}

/// Collect every leaf MIME part with its synthetic section id
fn collect_leaf_parts(part: &ParsedMail<'_>, part_id: String, out: &mut Vec<LeafPart>) {
    if part.subparts.is_empty() {
        let ctype = part.ctype.mimetype.to_ascii_lowercase();
        let disp = part.get_content_disposition();
        let filename = attachment_filename(part, &disp.params);
        let is_attachment = disp.disposition == DispositionType::Attachment || filename.is_some();
        let bytes = part.get_body_raw().unwrap_or_default();
        out.push(LeafPart {
            part_id,
            content_type: ctype,
            filename,
            is_attachment,
            bytes,
        });
        return;
    }

    for (idx, sub) in part.subparts.iter().enumerate() {
        collect_leaf_parts(sub, format!("{part_id}.{}", idx + 1), out);
    }
}

/// Extract attachment filename from part
///
/// Checks Content-Disposition parameter first, falls back to Content-Type
/// name parameter.
fn attachment_filename(
    part: &ParsedMail<'_>,
    disp_params: &BTreeMap<String, String>,
) -> Option<String> {
    disp_params
        .get("filename")
        .cloned()
        .or_else(|| part.ctype.params.get("name").cloned())
}

/// Return headers, either curated or all
///
/// If `include_all=true`, returns all headers. Otherwise, returns only
/// a safe subset (Date, From, To, Cc, Subject, Message-ID).
pub fn curated_headers(headers: &[(String, String)], include_all: bool) -> Vec<(String, String)> {
    if include_all {
        return headers.to_vec();
    }

    let allowed = ["date", "from", "to", "cc", "subject", "message-id"];
    headers
        .iter()
        .filter(|(k, _)| allowed.contains(&k.to_ascii_lowercase().as_str()))
        .cloned()
        .collect()
}

/// Parse header bytes into key-value pairs
pub fn parse_header_bytes(header_bytes: &[u8]) -> AppResult<Vec<(String, String)>> {
    let (headers, _) = mailparse::parse_headers(header_bytes)
        .map_err(|e| AppError::Internal(format!("failed to parse message headers: {e}")))?;
    Ok(to_tuples(headers))
}

/// Parse all headers from raw message
fn parse_all_headers(raw: &[u8]) -> AppResult<Vec<(String, String)>> {
    let (headers, _) = mailparse::parse_headers(raw)
        .map_err(|e| AppError::Internal(format!("failed to parse message headers: {e}")))?;
    Ok(to_tuples(headers))
}

/// Convert mailparse headers to key-value tuples
///
/// Extracts header keys and values using mailparse's `get_key()` and `get_value()`
/// methods, which handle encoding and whitespace normalization.
fn to_tuples(headers: Vec<MailHeader<'_>>) -> Vec<(String, String)> {
    headers
        .into_iter()
        .map(|h| (h.get_key(), h.get_value()))
        .collect()
}

/// Convert header tuples to case-insensitive map
///
/// Returns the first value for each header key (case-insensitive). If a header
/// appears multiple times, only the first value is retained. Keys are normalized
/// to lowercase for case-insensitive lookup.
fn to_header_map(headers: &[(String, String)]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (k, v) in headers {
        let key = k.to_ascii_lowercase();
        map.entry(key).or_insert_with(|| v.clone());
    }
    map
}

/// Truncate string to maximum characters (Unicode-aware)
///
/// Preserves complete characters, never splitting multi-byte sequences.
/// Extract plain text body from a parsed email message.
///
/// Walks the MIME parts and returns the first `text/plain` body found.
/// Returns `None` if no text/plain part exists.
pub fn extract_body_text(parsed: &mailparse::ParsedMail<'_>) -> Option<String> {
    if parsed.subparts.is_empty() {
        let ct = parsed.ctype.mimetype.to_ascii_lowercase();
        if ct == "text/plain" || ct == "text" {
            return parsed.get_body().ok();
        }
        return None;
    }
    for sub in &parsed.subparts {
        if let Some(text) = extract_body_text(sub) {
            return Some(text);
        }
    }
    None
}

pub fn truncate_chars(input: String, max_chars: usize) -> String {
    input.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::{curated_headers, parse_message, truncate_chars};

    /// Tests that Unicode strings are truncated by character, not byte.
    #[test]
    fn truncates_unicode_by_character() {
        let input = "a😀b😀c".to_owned();
        let out = truncate_chars(input, 4);
        assert_eq!(out, "a😀b😀");
    }

    /// Tests that `curated_headers` filters headers unless `include_all` is true.
    #[test]
    fn curated_headers_filters_unless_include_all() {
        let headers = vec![
            (
                "Date".to_owned(),
                "Wed, 1 Jan 2025 00:00:00 +0000".to_owned(),
            ),
            ("From".to_owned(), "sender@example.com".to_owned()),
            ("X-Custom".to_owned(), "value".to_owned()),
        ];

        let curated = curated_headers(&headers, false);
        assert_eq!(curated.len(), 2);
        assert!(curated.iter().any(|(k, _)| k.eq_ignore_ascii_case("date")));
        assert!(curated.iter().any(|(k, _)| k.eq_ignore_ascii_case("from")));

        let all = curated_headers(&headers, true);
        assert_eq!(all.len(), 3);
    }

    /// Tests parsing of a simple plain text message and verifies header and body extraction.
    #[test]
    fn parses_simple_plain_text_message() {
        let raw = b"From: sender@example.com\r\nTo: user@example.com\r\nSubject: Hi\r\nDate: Wed, 1 Jan 2025 00:00:00 +0000\r\n\r\nHello there";
        let parsed = parse_message(raw, 2000, false, false, 10000).expect("parse should succeed");

        assert_eq!(parsed.subject.as_deref(), Some("Hi"));
        assert_eq!(parsed.from.as_deref(), Some("sender@example.com"));
        assert_eq!(parsed.to.as_deref(), Some("user@example.com"));
        assert_eq!(parsed.body_text.as_deref(), Some("Hello there"));
        assert!(parsed.attachments.is_empty());
    }

    /// Build a nested multipart message: multipart/mixed wrapping a
    /// multipart/alternative (plain + html) and a PDF attachment.
    fn nested_multipart_raw() -> Vec<u8> {
        let boundary_inner = "alt-boundary";
        let boundary_outer = "mix-boundary";
        format!(
            "From: sender@example.com\r\n\
             To: user@example.com\r\n\
             Subject: Multipart\r\n\
             Date: Wed, 1 Jan 2025 00:00:00 +0000\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"{boundary_outer}\"\r\n\
             \r\n\
             --{boundary_outer}\r\n\
             Content-Type: multipart/alternative; boundary=\"{boundary_inner}\"\r\n\
             \r\n\
             --{boundary_inner}\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             plain body\r\n\
             --{boundary_inner}\r\n\
             Content-Type: text/html\r\n\
             \r\n\
             <p>html body</p>\r\n\
             --{boundary_inner}--\r\n\
             --{boundary_outer}\r\n\
             Content-Type: application/pdf\r\n\
             Content-Disposition: attachment; filename=\"report.pdf\"\r\n\
             \r\n\
             %PDF-1.4 fake bytes\r\n\
             --{boundary_outer}--\r\n"
        )
        .into_bytes()
    }

    /// Tests that `walk_parts` part ids line up with IMAP section numbering:
    /// children of the root get `1.1`, `1.2`, ... so `BODY.PEEK[<part_id>]`
    /// fetches the same part.
    #[test]
    fn part_ids_follow_imap_section_numbering() {
        let parsed = parse_message(&nested_multipart_raw(), 2000, false, false, 0)
            .expect("parse should succeed");

        assert_eq!(parsed.attachments.len(), 1);
        assert_eq!(parsed.attachments[0].part_id, "1.2");
        assert_eq!(
            parsed.attachments[0].filename.as_deref(),
            Some("report.pdf")
        );
    }

    /// Tests resolving an attachment by part id, including inline (non-attachment)
    /// leaf parts.
    #[test]
    fn resolves_attachment_by_part_id() {
        let raw = nested_multipart_raw();

        let resolved =
            super::resolve_attachment(&raw, Some("1.2"), None).expect("part 1.2 should resolve");
        assert_eq!(resolved.info.part_id, "1.2");
        assert_eq!(resolved.info.content_type, "application/pdf");
        assert_eq!(resolved.info.size_bytes, resolved.bytes.len());
        assert!(resolved.bytes.starts_with(b"%PDF-1.4"));

        // Inline text parts are addressable by part id too.
        let text = super::resolve_attachment(&raw, Some("1.1.1"), None)
            .expect("part 1.1.1 should resolve");
        assert_eq!(text.info.content_type, "text/plain");
        assert_eq!(text.bytes, b"plain body");
    }

    /// Tests filename resolution: exact, case-insensitive fallback, ambiguity,
    /// not-found, and part_id/filename contradiction.
    #[test]
    fn resolves_attachment_by_filename() {
        let raw = nested_multipart_raw();

        let resolved =
            super::resolve_attachment(&raw, None, Some("report.pdf")).expect("should resolve");
        assert_eq!(resolved.info.part_id, "1.2");

        let resolved = super::resolve_attachment(&raw, Some("1.2"), Some("REPORT.PDF"))
            .expect("case-insensitive match should resolve");
        assert_eq!(resolved.info.part_id, "1.2");

        let err = super::resolve_attachment(&raw, None, Some("missing.pdf"))
            .expect_err("missing filename must fail");
        assert!(err.to_string().contains("no attachment named"));

        let err = super::resolve_attachment(&raw, Some("1.1.1"), Some("report.pdf"))
            .expect_err("contradicting part_id must fail");
        assert!(err.to_string().contains("does not match"));
    }

    /// Tests that an ambiguous filename is rejected instead of guessing.
    #[test]
    fn rejects_ambiguous_filename() {
        let raw = b"From: sender@example.com\r\n\
             To: user@example.com\r\n\
             Subject: Dup\r\n\
             Date: Wed, 1 Jan 2025 00:00:00 +0000\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"b\"\r\n\
             \r\n\
             --b\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"data.bin\"\r\n\
             \r\n\
             AAAA\r\n\
             --b\r\n\
             Content-Type: application/octet-stream\r\n\
             Content-Disposition: attachment; filename=\"data.bin\"\r\n\
             \r\n\
             BBBB\r\n\
             --b--\r\n";

        let err =
            super::resolve_attachment(raw, None, Some("data.bin")).expect_err("must be ambiguous");
        assert!(err.to_string().contains("matches 2 attachments"));
    }
}
