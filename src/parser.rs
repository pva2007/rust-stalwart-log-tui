use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn parse(s: &str) -> Option<Level> {
        match s.to_ascii_uppercase().as_str() {
            "TRACE" => Some(Level::Trace),
            "DEBUG" => Some(Level::Debug),
            "INFO" => Some(Level::Info),
            "WARN" | "WARNING" => Some(Level::Warn),
            "ERROR" => Some(Level::Error),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Connect,
    AuthOk,
    AuthFail,
    Received,
    Queued,
    Delivered,
    Failed,
    Spam,
    Blocked,
    Throttled,
    Policy,
    Greylisted,
    Tls,
    Disconnect,
    Noise,
    Other,
}

impl Category {
    pub const ALL: [Category; 16] = [
        Category::Connect,
        Category::AuthOk,
        Category::AuthFail,
        Category::Received,
        Category::Queued,
        Category::Delivered,
        Category::Failed,
        Category::Spam,
        Category::Blocked,
        Category::Throttled,
        Category::Policy,
        Category::Greylisted,
        Category::Tls,
        Category::Disconnect,
        Category::Noise,
        Category::Other,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Connect => "Sessions (EHLO)",
            Category::AuthOk => "Auth success",
            Category::AuthFail => "Auth failures",
            Category::Received => "Received",
            Category::Queued => "Queued",
            Category::Delivered => "Delivered",
            Category::Failed => "Errors/Bounces",
            Category::Spam => "Spam",
            Category::Blocked => "Blocked/Banned",
            Category::Throttled => "Throttled",
            Category::Policy => "Policy (SPF/DKIM/DMARC)",
            Category::Greylisted => "Greylisted (def.)",
            Category::Tls => "TLS handshakes",
            Category::Disconnect => "Disconnects",
            Category::Noise => "Maintenance noise",
            Category::Other => "Other",
        }
    }

    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            Category::AuthOk | Category::Delivered => Color::Green,
            Category::AuthFail | Category::Failed | Category::Blocked | Category::Spam => Color::Red,
            Category::Throttled | Category::Policy | Category::Greylisted => Color::Yellow,
            Category::Noise => Color::DarkGray,
            Category::Connect | Category::Tls => Color::Cyan,
            _ => Color::Gray,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub ts: Option<DateTime<Utc>>,
    pub level: Level,
    /// Event name from the trailing `(event.name)` marker, e.g.
    /// `queue.message-queued`. Old-style line facilities land here too.
    pub event: Option<String>,
    /// Human-readable message part.
    pub message: String,
    /// Parsed `key = value` pairs after the event marker.
    pub kv: Vec<(String, String)>,
    pub category: Category,
    pub raw: String,
}

impl LogRecord {
    fn other(level: Level, raw: String) -> LogRecord {
        LogRecord {
            ts: None,
            level,
            event: None,
            message: raw.clone(),
            kv: Vec::new(),
            category: Category::Other,
            raw,
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.kv
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Timestamps at the start of a line: RFC 3339 (`2026-11-19T00:00:40Z`,
/// optional offset, with/without fraction) or bare epoch seconds.
/// Returns (Utc timestamp, index of next unconsumed token).
fn parse_timestamp(tokens: &[&str]) -> Option<(DateTime<Utc>, usize)> {
    let first = tokens.first()?;

    if first.len() >= 10 && first.as_bytes()[4] == b'-' {
        if let Ok(dt) = DateTime::parse_from_rfc3339(first) {
            return Some((dt.with_timezone(&Utc), 1));
        }
        // date only in first token, time in the next: `2026-11-19 23:12:04.123`
        if tokens.len() >= 2 {
            let joined = format!("{} {}", first.trim_end_matches('Z'), tokens[1]);
            if let Ok(naive) = NaiveDateTime::parse_from_str(&joined, "%Y-%m-%d %H:%M:%S%.f") {
                // no offset present: assume the log's local time
                let local = Local
                    .from_local_datetime(&naive)
                    .earliest()
                    .unwrap_or_else(Local::now);
                return Some((local.with_timezone(&Utc), 2));
            }
            if let Ok(dt) = DateTime::parse_from_str(&joined, "%Y-%m-%d %H:%M:%S%.f%z") {
                return Some((dt.with_timezone(&Utc), 2));
            }
        }
    }

    if let Ok(secs) = first.parse::<i64>()
        && (100_000_000..10_000_000_000).contains(&secs)
            && let Some(ts) = chrono::DateTime::from_timestamp(secs, 0) {
                return Some((ts, 1));
            }

    None
}

/// Stalwart events end the human message with `(event.name)` followed by
/// `key = value` pairs. Anchored on the *first* event-like marker so nested
/// event names inside `causedBy = ... { (mail-auth.dns-error) ... }` values
/// do not steal the match.
static EVENT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*([\s\S]*?)\s*\(([a-z][a-z0-9]*(?:[.-][a-z0-9]+)+)\)\s*([\s\S]*)$")
        .expect("event regex")
});

static IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(\d{1,3}\.){3}\d{1,3}\b").expect("ip regex")
});

/// Best-effort category for a known Stalwart event name.
pub fn category_from_event(event: &str) -> Option<Category> {
    let exact = |e: &str| -> Option<Category> {
        Some(match e {
            "auth.success" => Category::AuthOk,
            "auth.error" | "smtp.auth-not-allowed" | "smtp.relay-not-allowed" => Category::AuthFail,
            "smtp.ehlo" => Category::Connect,
            "smtp.mail-from" | "smtp.rcpt-to" | "message-ingest.duplicate" => Category::Received,
            "queue.message-queued" => Category::Queued,
            "message-ingest.spam" => Category::Spam,
            "security.ip-blocked" | "security.scan-ban" | "smtp.invalid-ehlo"
            | "smtp.vrfy-disabled" | "smtp.expn-disabled" => Category::Blocked,
            "smtp.rate-limit-exceeded" | "throttle.rate-limit-exceeded" => Category::Throttled,
            "smtp.rcpt-to-greylisted" => Category::Greylisted,
            "tls.handshake" => Category::Tls,
            "queue.message-delivered" | "queue.message-relayed" => Category::Delivered,
            "queue.message-failed" | "message-ingest.error" | "store.s3-error" => Category::Failed,
            "network.listen-start" => Category::Connect,
            "network.listen-stop" => Category::Disconnect,
            "server.startup" | "server.shutdown" | "queue.started" | "queue.stopped" => {
                Category::Noise
            }
            _ => return None,
        })
    };
    if let Some(c) = exact(event) {
        return Some(c);
    }

    let e = event;
    if e.starts_with("spf.")
        || e.starts_with("dkim.")
        || e.starts_with("dmarc.")
        || e.starts_with("iprev.")
        || e.starts_with("mail-auth.")
        || e.ends_with("spf-fail")
        || e.ends_with("dmarc-fail")
        || e.ends_with("dkim-fail")
    {
        return Some(Category::Policy);
    }
    if e.starts_with("task-manager.")
        || e.starts_with("telemetry.")
        || e.starts_with("store.blob-store")
        || e.starts_with("store.data-store")
        || e.starts_with("network.")
        || e.starts_with("server.")
        || e.starts_with("search-index.")
        || e.starts_with("registry.")
        || e.starts_with("resource.")
        || e.starts_with("spam.train-")
        || e == "spam.model-loaded"
        || e.starts_with("outgoing-report.")
    {
        return Some(Category::Noise);
    }
    if e.starts_with("security.") {
        return Some(Category::Blocked);
    }
    if e.starts_with("spam.") {
        return Some(Category::Spam);
    }
    None
}

/// Fallback classification by message text for unknown or old-style lines.
pub fn classify(event: Option<&str>, message: &str) -> Category {
    if let Some(ev) = event
        && let Some(c) = category_from_event(ev)
            && c != Category::Other
        {
            return c;
        }
    let hay = format!("{} {}", event.unwrap_or(""), message).to_ascii_lowercase();

    if hay.contains("authentication") {
        if hay.contains("failed") || hay.contains("failure") || hay.contains("error") {
            return Category::AuthFail;
        }
        if hay.contains("succes") || hay.contains("verified") {
            return Category::AuthOk;
        }
    }
    if hay.contains("auth") && (hay.contains("failed") || hay.contains("error")) {
        return Category::AuthFail;
    }
    if hay.contains("throttl") || hay.contains("rate limit") || hay.contains("too many") {
        return Category::Throttled;
    }
    if hay.contains("greylist") {
        return Category::Greylisted;
    }
    if hay.contains("spam") || hay.contains("virus") {
        return Category::Spam;
    }
    if hay.contains("dkim") || hay.contains("spf") || hay.contains("dmarc") {
        return Category::Policy;
    }
    if hay.contains("blocked") || hay.contains("banned") || hay.contains("invalid ehlo") {
        return Category::Blocked;
    }
    if hay.contains("relay failed")
        || hay.contains("delivery failed")
        || hay.contains("delivery failure")
        || hay.contains("bounce")
    {
        return Category::Failed;
    }
    if hay.contains("delivered") || hay.contains("message relayed") || hay.contains("completed successfully") {
        return Category::Delivered;
    }
    if hay.contains("queued") {
        return Category::Queued;
    }
    if (hay.contains("received") && hay.contains("message")) || hay.contains("received for delivery") {
        return Category::Received;
    }
    if hay.contains("starttls") || hay.contains("tls") {
        return Category::Tls;
    }
    if hay.contains("disconnected") || hay.contains("disconnect") || hay.contains("connection closed") {
        return Category::Disconnect;
    }
    if hay.contains("connection")
        && (hay.contains("from") || hay.contains("opened") || hay.contains("starting") || hay.contains("accepting"))
    {
        return Category::Connect;
    }
    Category::Other
}

/// Parse one log line. Unparseable lines are returned as an "Other" record at
/// Info level so nothing is silently dropped. Line shapes handled:
///
/// - Current Stalwart: `2026-11-19T00:00:40Z INFO <message> (<event>) k = v, ...`
/// - Older: `2026-11-19 10:00:01 INFO [<session>] <facility> <message>` or
///   bare epoch-seconds prefix.
pub fn parse_line(line: &str) -> LogRecord {
    let line = line.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return LogRecord::other(Level::Info, String::new());
    }

    let tokens: Vec<&str> = line.split_whitespace().collect();
    let ts = parse_timestamp(&tokens);
    let idx = ts.as_ref().map_or(0, |(_, n)| *n);

    let Some(level) = tokens.get(idx).and_then(|t| Level::parse(t)) else {
        return unknown_level_record(line);
    };
    let remainder = tokens[idx + 1..].join(" ");
    if remainder.is_empty() {
        let mut r = LogRecord::other(level, line.to_string());
        r.ts = ts.map(|(t, _)| t);
        return r;
    }

    let (message, event, kv_str) = match EVENT_RE.captures(&remainder) {
        Some(caps) => (
            caps.get(1).map_or("", |m| m.as_str()).trim().to_string(),
            caps.get(2).map(|m| m.as_str().to_string()),
            caps.get(3).map(|m| m.as_str()).unwrap_or(""),
        ),
        None => (remainder, None, ""),
    };

    let kv = parse_kv(kv_str);
    let category = classify(event.as_deref(), &message);

    LogRecord {
        ts: ts.map(|(t, _)| t),
        level,
        event,
        message,
        kv,
        category,
        raw: line.to_string(),
    }
}

fn unknown_level_record(line: &str) -> LogRecord {
    let mut level = Level::Info;
    for tok in line.split_whitespace() {
        if let Some(l) = Level::parse(tok) {
            level = l;
            break;
        }
    }
    LogRecord::other(level, line.to_string())
}

/// Split `a = 1, b = "two, three", c = ["x", "y"]` into pairs. Commas inside
/// quotes or brackets do not split.
fn parse_kv(s: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut depth = 0i32;

    for ch in s.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(ch);
            }
            '[' | '{' if !in_quotes => {
                depth += 1;
                cur.push(ch);
            }
            ']' | '}' if !in_quotes => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if !in_quotes && depth == 0 => {
                pairs.push(std::mem::take(&mut cur));
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        pairs.push(cur);
    }

    pairs
        .into_iter()
        .filter_map(|item| {
            let item = item.trim();
            if item.is_empty() {
                return None;
            }
            let (k, v) = item.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").expect("email regex")
});

/// Extract email addresses from a to/from style value like
/// `["a@b.c", "d@e.f"]` or `"a@b.c"` or bare `a@b.c`.
pub fn emails_in(value: &str) -> Vec<String> {
    EMAIL_RE
        .find_iter(value)
        .map(|m| m.as_str().to_ascii_lowercase())
        .collect()
}

/// Find client IPs anywhere in a text (used as a fallback when there is no
/// `remoteIp` key).
pub fn ips_in(text: &str) -> Vec<String> {
    IP_RE
        .find_iter(text)
        .map(|m| m.as_str().to_string())
        .filter(|ip| ip != "0.0.0.0")
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn parses_current_stalwart_format() {
        let r = parse_line(
            "2026-11-19T00:01:52Z INFO Queued message for delivery (queue.message-queued) listenerId = \"smtp\", localPort = 25, remoteIp = 167.89.48.242, remotePort = 15422, queueId = 341344700644505600, from = \"bounces+4558842-efa7-hotel=mager.sk@em7433.profi-pozicka.sk\", to = [\"hotel@mager.sk\"], size = 49391",
        );
        assert_eq!(r.level, Level::Info);
        assert_eq!(r.event.as_deref(), Some("queue.message-queued"));
        assert_eq!(r.category, Category::Queued);
        assert_eq!(r.message, "Queued message for delivery");
        assert_eq!(r.get("remoteIp"), Some("167.89.48.242"));
        assert_eq!(r.get("size"), Some("49391"));
        assert!(r.get("from").unwrap().contains("em7433.profi-pozicka.sk"));
        let tos = emails_in(r.get("to").unwrap());
        assert_eq!(tos, vec!["hotel@mager.sk".to_string()]);
    }

    #[test]
    fn parses_auth_error() {
        let r = parse_line(
            "2026-11-19T23:03:00Z ERROR Authentication error (auth.error) listenerId = \"imaps\", localPort = 993, remotePort = 55162, reason = \"Unsupported credentials type for OIDC backend\", causedBy = \"crates/directory/src/core/dispatch.rs:27\", remoteIp = 147.93.182.44, id = \"a001\"",
        );
        assert_eq!(r.level, Level::Error);
        assert_eq!(r.category, Category::AuthFail);
        assert_eq!(r.get("remoteIp"), Some("147.93.182.44"));
        assert_eq!(
            r.get("reason"),
            Some("\"Unsupported credentials type for OIDC backend\"")
        );
    }

    #[test]
    fn parses_dmarc_with_nested_parens() {
        let r = parse_line(
            "2026-11-19T23:02:32Z INFO DMARC check failed (smtp.dmarc-fail) listenerId = \"smtp\", localPort = 25, remoteIp = 167.89.48.242, remotePort = 53828, strict = false, domain = \"profi-pozicka.sk\", policy = \"none\", result = DMARC temporary error (dmarc.temp-error) { causedBy = DNS error (mail-auth.dns-error) { details = \"request timed out\" } }, elapsed = 15002ms",
        );
        assert_eq!(r.event.as_deref(), Some("smtp.dmarc-fail"));
        assert_eq!(r.category, Category::Policy);
        assert_eq!(r.message, "DMARC check failed");
        assert_eq!(r.get("domain"), Some("\"profi-pozicka.sk\""));
        assert!(r.get("result").unwrap().contains("temporary error"));
    }

    #[test]
    fn parses_old_space_separated_format() {
        let r = parse_line("2025-11-19 23:12:04 INFO [435214851] smtp.session connection from [192.0.2.10]:40000");
        assert_eq!(r.level, Level::Info);
        assert_eq!(r.category, Category::Connect);
        assert!(r.ts.is_some());
        assert!(r.ts.unwrap().year() >= 2025);
    }

    #[test]
    fn parses_epoch_timestamp() {
        let r = parse_line("1695829382 INFO core.shutdown Shutting down");
        assert_eq!(r.level, Level::Info);
        assert!(r.ts.is_some());
        assert!(r.ts.unwrap().year() >= 2023);
    }

    #[test]
    fn falls_back_gracefully() {
        let r = parse_line("<json>{\"weird\":\"line\"}");
        assert_eq!(r.level, Level::Info);
        assert_eq!(r.category, Category::Other);
        assert!(r.ts.is_none());
        assert_eq!(r.raw, "<json>{\"weird\":\"line\"}");
    }

    #[test]
    fn classifies_known_events() {
        assert_eq!(category_from_event("auth.success"), Some(Category::AuthOk));
        assert_eq!(category_from_event("security.ip-blocked"), Some(Category::Blocked));
        assert_eq!(category_from_event("smtp.rate-limit-exceeded"), Some(Category::Throttled));
        assert_eq!(category_from_event("message-ingest.spam"), Some(Category::Spam));
        assert_eq!(category_from_event("tls.handshake"), Some(Category::Tls));
        assert_eq!(category_from_event("spf.temp-error"), Some(Category::Policy));
        assert_eq!(category_from_event("mail-auth.dns-error"), Some(Category::Policy));
        assert_eq!(category_from_event("task-manager.task-scheduled"), Some(Category::Noise));
        assert_eq!(category_from_event("telemetry.metrics-collected"), Some(Category::Noise));
        assert_eq!(category_from_event("store.blob-store-purged"), Some(Category::Noise));
    }

    #[test]
    fn kv_split_respects_quotes_and_brackets() {
        let kv = parse_kv(
            "a = 1, b = \"two, three\", c = [\"x\", \"y\"], d = { e = 5 }, to = [\"p@q.rs\",\"s@t.us\"]",
        );
        assert_eq!(kv.len(), 5);
        assert_eq!(kv[1], ("b".to_string(), "\"two, three\"".to_string()));
        let to = kv.iter().find(|(k, _)| k == "to").unwrap();
        assert_eq!(
            emails_in(&to.1),
            vec!["p@q.rs".to_string(), "s@t.us".to_string()]
        );
    }

    #[test]
    fn ip_extraction() {
        assert_eq!(
            ips_in("remoteIp = 1.2.3.4 and 0.0.0.0 skip"),
            vec!["1.2.3.4".to_string()]
        );
    }
}
