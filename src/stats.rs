use crate::parser::{emails_in, ips_in, Category, Level, LogRecord};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet, VecDeque};

const BUCKET_SECONDS: u64 = 1;
pub const HISTORY_LEN: usize = 180;

// --- abuse-signal thresholds -------------------------------------------------
pub const SUSPECT_FAILS_HI: u64 = 20;
pub const SUSPECT_FAILS_LO: u64 = 5;
pub const BRUTE_USERS: usize = 10;
pub const MULTI_USERS: usize = 3;
pub const VARIED_REASONS: usize = 3;
pub const SPRAY_IPS: usize = 10;
/// Auth successes after this many recent failures "arm" the compromise
/// detector for subsequent outbound mail from the same IP.
pub const FAILS_TO_ARM: u32 = 3;
/// An entity first seen within this many minutes of the newest event counts
/// as "new".
pub const NEW_WINDOW_MIN: i64 = 24 * 60;
/// Bounds so hostile logs cannot balloon memory.
pub const MAX_TRACKED_USERS: usize = 100_000;
pub const MAX_REASONS_PER_IP: usize = 50;
/// Upper bound on distinct (sender, recipient) pairs kept for the mail
/// in/out table.
pub const MAX_MAIL_PAIRS: usize = 20_000;
/// Upper bound on unique message ids tracked for de-duplicated counting.
pub const MAX_QUEUE_TRACKED: usize = 250_000;

/// Per-client-IP authentication bookkeeping for the abuse view.
#[derive(Debug, Default)]
pub struct IpAuth {
    pub attempts: u32,
    pub ok: u32,
    /// Consecutive failed attempts since the last success.
    pub fails_since_ok: u32,
    /// Username -> attempts (present only when the log line names a user).
    pub users: HashMap<String, u32>,
    /// Failure-reason text -> attempts; repetitive reasons mean
    /// misconfiguration, varied reasons mean probing.
    pub reasons: HashMap<String, u32>,
    /// Minute at which a success followed enough failures (compromise fuse).
    pub armed_at: Option<i64>,
    /// Minute at which outbound mail followed the fuse.
    pub compromised: Option<i64>,
}

/// Per-minute flow counters for one stream of log events.
/// `inn` = Received, `out` = Queued + Delivered, `err` = Failed/Spam/Blocked/
/// Throttled, `blk` = Spam/Blocked/Policy/Throttled (junk-ish outcomes).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct MinutePoint {
    pub minute: i64,
    pub inn: u32,
    pub out: u32,
    pub err: u32,
    pub blk: u32,
}

/// Compact time series: at most one `MinutePoint` per calendar minute,
/// stored ascending. Cheap enough to keep per entity.
#[derive(Debug, Default)]
pub struct FlowHist {
    points: Vec<MinutePoint>,
}

impl FlowHist {
    fn bump(&mut self, minute: i64, inn: u32, out: u32, err: u32, blk: u32) {
        match self.points.last_mut() {
            Some(p) if p.minute == minute => {
                p.inn += inn;
                p.out += out;
                p.err += err;
                p.blk += blk;
            }
            Some(p) if p.minute > minute => {} // out-of-order older event: ignore
            _ => self.points.push(MinutePoint { minute, inn, out, err, blk }),
        }
        if self.points.len() > 50_000 {
            self.points.drain(..25_000);
        }
    }

    pub fn first_minute(&self) -> Option<i64> {
        self.points.first().map(|p| p.minute)
    }

    /// Sum of every point from `from_min` onward: (inn, out, err, blk).
    /// Only used in tests; the UI sums the aggregated bars instead.
    #[cfg(test)]
    pub fn totals_since(&self, from_min: i64) -> (u64, u64, u64, u64) {
        let mut inn = 0u64;
        let mut out = 0u64;
        let mut err = 0u64;
        let mut blk = 0u64;
        for p in &self.points {
            if p.minute >= from_min {
                inn += p.inn as u64;
                out += p.out as u64;
                err += p.err as u64;
                blk += p.blk as u64;
            }
        }
        (inn, out, err, blk)
    }

    /// Aggregate the stored minutes in `[from_min, to_min)` into
    /// `to_min - from_min / bar_minutes` bars (each tagged with its start
    /// minute). Bar values are sums of the underlying per-minute counters.
    pub fn window(&self, from_min: i64, to_min: i64, bar_minutes: usize) -> Vec<MinutePoint> {
        let bar_minutes = bar_minutes.max(1);
        let nbars = (((to_min - from_min).max(1) as usize) / bar_minutes).max(1);
        let mut bars: Vec<MinutePoint> = (0..nbars)
            .map(|i| MinutePoint { minute: from_min + (i * bar_minutes) as i64, ..Default::default() })
            .collect();
        for p in &self.points {
            if p.minute < from_min || p.minute >= to_min {
                continue;
            }
            let idx = (((p.minute - from_min) as usize) / bar_minutes).min(nbars - 1);
            let b = &mut bars[idx];
            b.inn += p.inn;
            b.out += p.out;
            b.err += p.err;
            b.blk += p.blk;
        }
        bars
    }

    /// Peak "recipients per unit" in `[from_min, to_min)`, where each stored
    /// point's `out` field holds an occurrences-per-minute count. Returns the
    /// peak along with the minute it happened.
    pub fn peak_per_unit(&self, from_min: i64, to_min: i64, unit_minutes: usize) -> Option<(i64, u32)> {
        let first = self.first_minute()?;
        let start = first.max(from_min);
        let end = to_min.max(start + 1);
        let unit = unit_minutes.max(1) as i64;
        // dense per-minute values in range are unnecessary: points are sparse,
        // so accumulate sums of range [m, m+unit) by walking the slice once
        // per candidate is too slow in theory but fine at these magnitudes;
        // instead: sliding sum over sorted points.
        let in_range: Vec<&MinutePoint> = self
            .points
            .iter()
            .filter(|p| p.minute >= start && p.minute < end)
            .collect();
        if in_range.is_empty() {
            return None;
        }
        // iterate window starts anchored at each point's minute, then use
        // two-pointer accumulation over the sorted points
        let mut best: Option<(i64, u32)> = None;
        let mut sum: u32 = 0;
        let mut lo = 0usize;
        for (hi, p) in in_range.iter().enumerate() {
            sum += p.out;
            let win_start = p.minute;
            while lo <= hi && in_range[lo].minute < win_start - (unit - 1) {
                sum -= in_range[lo].out;
                lo += 1;
            }
            if best.is_none_or(|(_, v)| sum > v) {
                best = Some((win_start, sum));
            }
        }
        best
    }

}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntityKind {
    Ip,
    Sender,
    Recipient,
}

impl EntityKind {
    pub fn prefix(self) -> &'static str {
        match self {
            EntityKind::Ip => "i:",
            EntityKind::Sender => "s:",
            EntityKind::Recipient => "r:",
        }
    }
}

const CAT_SLOTS: usize = 16;

/// Aggregated stats for one entity (a client IP, a sender address or a
/// recipient address): per-category totals, its own per-minute flow history,
/// a fan-out history (approximately distinct recipients per minute), and
/// peer counters.
#[derive(Debug)]
pub struct EntityDetail {
    pub kind: EntityKind,
    /// Totals indexed by position in `Category::ALL`.
    pub counts: [u64; CAT_SLOTS],
    /// Minute of the entity's earliest event.
    pub first_seen: Option<i64>,
    /// in/out/err/blk per minute for this entity's own events.
    pub hist: FlowHist,
    /// Approx. distinct recipients per minute (`out` field), for Ip/Sender.
    pub fanout: FlowHist,
    /// For fan-out bookkeeping: last minute each recipient was seen.
    rec_last: HashMap<String, i64>,
    /// Peers "on the from side": for Ip the senders seen on it, for Sender
    /// the source IPs (keys prefixed `ip:`), for Recipient the senders.
    pub peers_from: HashMap<String, u64>,
    /// Peers "on the to side": for Ip/Sender the recipients, for Recipient
    /// the source IPs (keys prefixed `ip:`).
    pub peers_to: HashMap<String, u64>,
}

impl EntityDetail {
    fn new(kind: EntityKind) -> EntityDetail {
        EntityDetail {
            kind,
            counts: [0; CAT_SLOTS],
            first_seen: None,
            hist: FlowHist::default(),
            fanout: FlowHist::default(),
            rec_last: HashMap::new(),
            peers_from: HashMap::new(),
            peers_to: HashMap::new(),
        }
    }

    pub fn cat_index(category: Category) -> usize {
        Category::ALL.iter().position(|c| *c == category).unwrap_or(CAT_SLOTS - 1)
    }

    fn count_category(&mut self, category: Category) {
        self.counts[Self::cat_index(category)] += 1;
    }
}

/// Which events count as mail flow (as opposed to sessions, TLS, noise...).
fn is_flow(category: Category) -> bool {
    matches!(category, Category::Received | Category::Queued | Category::Delivered | Category::Failed)
}

fn flow_flags(category: Category) -> (u32, u32, u32, u32) {
    match category {
        Category::Received => (1, 0, 0, 0),
        Category::Queued | Category::Delivered => (0, 1, 0, 0),
        Category::Failed => (0, 0, 1, 0),
        Category::Spam | Category::Blocked | Category::Throttled => (0, 0, 1, 1),
        Category::Policy => (0, 0, 0, 1),
        _ => (0, 0, 0, 0),
    }
}

/// True for events that represent a message leaving the system.
fn out_of(category: Category) -> bool {
    matches!(category, Category::Queued | Category::Delivered)
}

/// Extract the login/account name from an auth event, if the line names one.
fn auth_user(record: &LogRecord) -> Option<String> {
    for key in ["accountName", "account", "login", "username", "user"] {
        if let Some(v) = record.get(key) {
            return Some(v.trim_matches('"').to_string());
        }
    }
    None
}

// --- abuse signals -----------------------------------------------------------

/// One suspicious client IP with the flags that make it suspicious.
#[derive(Debug, Clone)]
pub struct Suspect {
    pub name: String,
    pub score: u32,
    pub attempts: u64,
    pub ok: u64,
    pub users: usize,
    pub top_reason: Option<String>,
    pub verdicts: Vec<&'static str>,
    pub compromised_at: Option<i64>,
}

/// An account that was attacked from `ips` distinct source IPs.
#[derive(Debug, Clone)]
pub struct AttackedAccount {
    pub name: String,
    pub ips: usize,
}

#[derive(Debug, Default)]
pub struct AbuseReport {
    pub suspects: Vec<Suspect>,
    pub accounts: Vec<AttackedAccount>,
}

/// Direction of a mail flow relative to the hosted domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailDir {
    In,
    Out,
    Local,
    Transit,
}

impl MailDir {
    pub fn as_str(&self) -> &'static str {
        match self {
            MailDir::In => "in",
            MailDir::Out => "out",
            MailDir::Local => "local",
            MailDir::Transit => "relay",
        }
    }

    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            MailDir::In => Color::Cyan,
            MailDir::Out => Color::Green,
            MailDir::Local => Color::Magenta,
            MailDir::Transit => Color::DarkGray,
        }
    }
}

/// One aggregated mail flow: sender -> recipient with its direction and
/// message count.
#[derive(Debug, Clone)]
pub struct MailPair {
    pub from: String,
    pub to: String,
    pub dir: MailDir,
    pub count: u64,
}

/// Domain part of an email address (lowercased by `emails_in`); for input
/// without an `@` the input itself is returned.
pub fn domain_of(addr: &str) -> String {
    addr.rsplit_once('@')
        .map(|(_, d)| d.to_string())
        .unwrap_or_else(|| addr.to_string())
}

#[derive(Debug, Default)]
pub struct Stats {
    pub total: u64,
    pub total_by_level: HashMap<Level, u64>,
    pub total_by_category: HashMap<Category, u64>,

    /// Events per 1-second bucket, oldest first. All events.
    pub history: VecDeque<u64>,
    /// Events per 1-second bucket excluding maintenance noise.
    pub history_active: VecDeque<u64>,
    bucket_start: Option<DateTime<Utc>>,
    bucket_count: u64,
    bucket_count_active: u64,

    pub top_ips: HashMap<String, u64>,
    pub top_senders: HashMap<String, u64>,
    pub top_recipients: HashMap<String, u64>,

    /// Aggregated mail flow per (sender, recipient) pair, from Queued and
    /// Delivered events.
    pub mail_pairs: HashMap<(String, String), u64>,
    /// Domains of mail stored into local mailboxes (message-ingest events):
    /// domain -> stored-message count. The "hosted" domains of this server.
    pub hosted_mailboxes: HashMap<String, u64>,
    /// Message ids already counted in the top sender/recipient lists and
    /// mail pairs, so one physical mail is counted once even though it
    /// produces several log lines (queued -> stored -> delivered).
    queue_seen: HashSet<String>,

    /// Per-minute in/out/err/blk flow for ALL events (key `EntityKind`-less).
    pub flow: FlowHist,
    /// Per-entity drill-down stats, keyed by `kind.prefix() + name`.
    pub details: HashMap<String, EntityDetail>,

    /// Authentication abuse bookkeeping per client IP.
    pub auth_ips: HashMap<String, IpAuth>,
    /// Username -> set of source IPs that attempted it.
    pub user_ips: HashMap<String, HashSet<String>>,

    /// Bytes received in messages (sum of `size` on queued/received events).
    pub bytes_seen: u64,

    /// Most recent WARN/ERROR raw lines.
    pub recent_problems: VecDeque<String>,

    pub first_ts: Option<DateTime<Utc>>,
    pub last_ts: Option<DateTime<Utc>>,
}

impl Stats {
    pub fn new() -> Stats {
        Stats::default()
    }

    pub fn ingest(&mut self, record: &LogRecord, now: DateTime<Utc>) {
        self.total += 1;
        *self.total_by_level.entry(record.level).or_default() += 1;
        *self.total_by_category.entry(record.category).or_default() += 1;

        if let Some(size) = record.get("size").and_then(|s| s.parse::<u64>().ok()) {
            self.bytes_seen = self.bytes_seen.saturating_add(size);
        }

        if matches!(record.level, Level::Warn | Level::Error) && !record.raw.trim().is_empty() {
            self.recent_problems.push_back(record.raw.clone());
            while self.recent_problems.len() > 200 {
                self.recent_problems.pop_front();
            }
        }

        // Structured fields first; fall back to regexing the message.
        let mut ip_keys: Vec<String> = Vec::new();
        if let Some(ip) = record.get("remoteIp") {
            *self.top_ips.entry(ip.to_string()).or_default() += 1;
            ip_keys.push(ip.to_string());
        } else {
            for ip in ips_in(&record.message) {
                ip_keys.push(ip.clone());
                *self.top_ips.entry(ip).or_default() += 1;
            }
        }

        let ts = record.ts.unwrap_or(now);
        let minute = ts.timestamp() / 60;

        // One physical mail produces several log lines that share its
        // queueId (accepted -> stored -> delivered). Count senders,
        // recipients and pairs once per message, at the first line seen.
        let qid = record.get("queueId").map(|q| q.to_string());
        let countable = match &qid {
            None => matches!(record.category, Category::Queued | Category::Delivered),
            Some(id) => {
                if self.queue_seen.contains(id) {
                    false
                } else {
                    if self.queue_seen.len() < MAX_QUEUE_TRACKED {
                        self.queue_seen.insert(id.clone());
                    }
                    true
                }
            }
        };

        let mut sender_key: Option<String> = None;
        if let Some(from) = record.get("from") {
            let emails = emails_in(from);
            let display = if emails.is_empty() { from } else { &emails[0] };
            sender_key = Some(display.to_string());
        }
        let recipients = record
            .get("to")
            .map(emails_in)
            .unwrap_or_default();
        if !recipients.is_empty() {
            if countable {
                for to in &recipients {
                    *self.top_recipients.entry(to.clone()).or_default() += 1;
                }
            }
        } else if countable && matches!(record.category, Category::Delivered | Category::Failed) {
            for email in emails_in(&record.message) {
                *self.top_recipients.entry(email.clone()).or_default() += 1;
            }
        }
        if countable
            && let Some(d) = sender_key.as_deref()
        {
            *self.top_senders.entry(d.to_string()).or_default() += 1;
        }

        self.track_mail(record, countable, sender_key.as_deref(), &recipients);

        if matches!(record.category, Category::AuthFail | Category::AuthOk) {
            self.track_auth(record, &ip_keys, minute);
        }
        self.track_entities(record, &ip_keys, sender_key.as_deref(), &recipients, minute);
        self.tighten_compromise(&ip_keys, minute, out_of(record.category));

        if self.first_ts.is_none() {
            self.first_ts = Some(ts);
        }
        // files are read in name order, so keep the maximum to reflect the
        // real most-recent event
        if self.last_ts.is_none_or(|old| ts > old) {
            self.last_ts = Some(ts);
        }

        let (inn, out, err, blk) = flow_flags(record.category);
        self.flow.bump(minute, inn, out, err, blk);

        self.roll_history(ts);
        self.bucket_count += 1;
        if record.category != Category::Noise {
            self.bucket_count_active += 1;
        }
    }

    /// Track sender->recipient mail flow (for the mail in/out table) and
    /// detect the hosted domains (local mailbox ingest events). `fresh`
    /// marks the first log line of a physical message.
    fn track_mail(
        &mut self,
        record: &LogRecord,
        fresh: bool,
        sender_key: Option<&str>,
        recipients: &[String],
    ) {
        if recipients.is_empty() {
            return;
        }
        // message-ingest.* = message stored into a local mailbox, so its
        // recipient domains are hosted on this server.
        if record.event.as_deref().is_some_and(|e| e.starts_with("message-ingest")) {
            for to in recipients {
                *self.hosted_mailboxes.entry(domain_of(to)).or_default() += 1;
            }
        }
        if !fresh {
            return;
        }
        let Some(from) = sender_key else { return };
        // Queued = acceptance of a message (in to local, out via submission),
        // Delivered = remote delivery of a local message (out).
        if !matches!(record.category, Category::Queued | Category::Delivered) {
            return;
        }
        for to in recipients {
            let pair = (from.to_string(), to.clone());
            if self.mail_pairs.len() < MAX_MAIL_PAIRS {
                *self.mail_pairs.entry(pair).or_default() += 1;
            } else if let Some(c) = self.mail_pairs.get_mut(&pair) {
                *c += 1;
            }
        }
    }

    /// Hosted domains with their stored-mail counts, most active first.
    pub fn hosted_domains(&self) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .hosted_mailboxes
            .iter()
            .map(|(d, c)| (d.clone(), *c))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Top sender->recipient pairs, optionally restricted to mail touching
    /// one of the given hosted domains (`domains` empty selects everything,
    /// like `None`). Direction is derived from the hosted-domain set:
    /// recipient hosted = in, sender hosted = out, both = local.
    pub fn top_mail_pairs(&self, n: usize, domains: Option<&[String]>) -> Vec<MailPair> {
        let sel: Option<HashSet<&str>> = domains.map(|ds| ds.iter().map(|s| s.as_str()).collect());
        let mut rows: Vec<MailPair> = self
            .mail_pairs
            .iter()
            .filter(|((f, t), _)| {
                let fd = domain_of(f);
                let td = domain_of(t);
                self.hosted_mailboxes.contains_key(&fd) || self.hosted_mailboxes.contains_key(&td)
            })
            .filter(|((f, t), _)| {
                sel.as_ref().is_none_or(|s| {
                    s.contains(domain_of(f).as_str()) || s.contains(domain_of(t).as_str())
                })
            })
            .map(|((f, t), c)| {
                let fd = self.hosted_mailboxes.contains_key(&domain_of(f));
                let td = self.hosted_mailboxes.contains_key(&domain_of(t));
                let dir = match (fd, td) {
                    (false, true) => MailDir::In,
                    (true, false) => MailDir::Out,
                    (true, true) => MailDir::Local,
                    (false, false) => MailDir::Transit,
                };
                MailPair {
                    from: f.clone(),
                    to: t.clone(),
                    dir,
                    count: *c,
                }
            })
            .collect();
        rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.from.cmp(&b.from)));
        rows.truncate(n);
        rows
    }

    /// Update the per-entity drill-down stats: per-entity counters and flow
    /// history, plus peer relations (client↔sender/recipients,
    /// sender↔recipients/source-IPs, recipient↔senders/source-IPs).
    fn track_entities(
        &mut self,
        record: &LogRecord,
        ip_keys: &[String],
        sender_key: Option<&str>,
        recipients: &[String],
        minute: i64,
    ) {
        let category = record.category;
        let (inn, out, err, blk) = flow_flags(category);
        let flow_event = is_flow(category);
        let source_ip = ip_keys.first().map(|ip| format!("ip:{ip}"));

        for ip in ip_keys {
            let d = self.details.entry(EntityKind::Ip.prefix().to_string() + ip).or_insert_with(|| EntityDetail::new(EntityKind::Ip));
            d.count_category(category);
            if d.first_seen.is_none_or(|m| minute < m) {
                d.first_seen = Some(minute);
            }
            d.hist.bump(minute, inn, out, err, blk);
            if flow_event {
                if let Some(from) = sender_key {
                    *d.peers_from.entry(from.to_string()).or_default() += 1;
                }
                for r in recipients {
                    *d.peers_to.entry(r.clone()).or_default() += 1;
                    // fan-out: approximately distinct recipients per minute
                    let fanout_rec = d.rec_last.get(r) != Some(&minute);
                    if fanout_rec {
                        d.rec_last.insert(r.clone(), minute);
                        d.fanout.bump(minute, 0, 1, 0, 0);
                    }
                }
            }
        }

        if let Some(from) = sender_key {
            let d = self.details.entry(EntityKind::Sender.prefix().to_string() + from).or_insert_with(|| EntityDetail::new(EntityKind::Sender));
            d.count_category(category);
            if d.first_seen.is_none_or(|m| minute < m) {
                d.first_seen = Some(minute);
            }
            d.hist.bump(minute, inn, out, err, blk);
            if flow_event {
                if let Some(ip) = &source_ip {
                    *d.peers_from.entry(ip.clone()).or_default() += 1;
                }
                for r in recipients {
                    *d.peers_to.entry(r.clone()).or_default() += 1;
                    let fanout_rec = d.rec_last.get(r) != Some(&minute);
                    if fanout_rec && (out > 0 || inn > 0) {
                        d.rec_last.insert(r.clone(), minute);
                        d.fanout.bump(minute, 0, 1, 0, 0);
                    }
                }
            }
        }

        for r in recipients {
            let d = self.details.entry(EntityKind::Recipient.prefix().to_string() + r).or_insert_with(|| EntityDetail::new(EntityKind::Recipient));
            d.count_category(category);
            if d.first_seen.is_none_or(|m| minute < m) {
                d.first_seen = Some(minute);
            }
            d.hist.bump(minute, inn, out, err, blk);
            if flow_event {
                if let Some(from) = sender_key {
                    *d.peers_from.entry(from.to_string()).or_default() += 1;
                }
                if let Some(ip) = &source_ip {
                    *d.peers_to.entry(ip.clone()).or_default() += 1;
                }
            }
        }
    }

    /// Authentication bookkeeping per client IP: attempt/success counts,
    /// usernames and failure reasons where the log names them, and the
    /// brute-force-then-success "fuse" for the compromise detector.
    fn track_auth(&mut self, record: &LogRecord, ip_keys: &[String], minute: i64) {
        let ok = record.category == Category::AuthOk;
        let user = auth_user(record);
        for ip in ip_keys {
            let a = self.auth_ips.entry(ip.clone()).or_default();
            a.attempts += 1;
            if ok {
                a.ok += 1;
                if a.fails_since_ok >= FAILS_TO_ARM && a.armed_at.is_none() {
                    a.armed_at = Some(minute);
                }
                a.fails_since_ok = 0;
            } else {
                a.fails_since_ok += 1;
                if let Some(u) = user.as_deref() {
                    if let Some(users) = self.user_ips.get_mut(u) {
                        users.insert(ip.clone());
                    } else if self.user_ips.len() < MAX_TRACKED_USERS {
                        self.user_ips.insert(u.to_string(), HashSet::from([ip.clone()]));
                    }
                    if a.users.len() < MAX_TRACKED_USERS {
                        *a.users.entry(u.to_string()).or_default() += 1;
                    }
                }
                if a.reasons.len() < MAX_REASONS_PER_IP
                    && let Some(reason) = record.get("reason")
                {
                    *a.reasons.entry(reason.to_string()).or_default() += 1;
                }
            }
        }
    }

    /// Close the compromise fuse: outbound mail from an armed IP.
    fn tighten_compromise(&mut self, ip_keys: &[String], minute: i64, out: bool) {
        if !out {
            return;
        }
        for ip in ip_keys {
            if let Some(a) = self.auth_ips.get_mut(ip)
                && let Some(arm) = a.armed_at
                && minute >= arm
                && a.compromised.is_none()
            {
                a.compromised = Some(minute);
            }
        }
    }

    fn roll_history(&mut self, ts: DateTime<Utc>) {
        let bucket = bucket_of(ts);
        match self.bucket_start {
            // still inside the current bucket
            Some(start) if bucket <= start => {}
            Some(start) => {
                let mut cur = start;
                while cur < bucket {
                    self.history.push_back(self.bucket_count);
                    self.history_active.push_back(self.bucket_count_active);
                    self.bucket_count = 0;
                    self.bucket_count_active = 0;
                    if self.history.len() > HISTORY_LEN {
                        self.history.pop_front();
                        self.history_active.pop_front();
                    }
                    cur += chrono::Duration::seconds(BUCKET_SECONDS as i64);
                }
                self.bucket_start = Some(bucket);
            }
            None => self.bucket_start = Some(bucket),
        }
    }

    pub fn level_count(&self, level: Level) -> u64 {
        self.total_by_level.get(&level).copied().unwrap_or(0)
    }

    pub fn category_count(&self, category: Category) -> u64 {
        self.total_by_category.get(&category).copied().unwrap_or(0)
    }

    pub fn history_snapshot(&self, hide_noise: bool) -> Vec<u64> {
        let (history, last) = if hide_noise {
            (&self.history_active, self.bucket_count_active)
        } else {
            (&self.history, self.bucket_count)
        };
        let mut v: Vec<u64> = history.iter().copied().collect();
        v.push(last);
        v
    }

    /// Top-n of a count map, sorted by count desc then key.
    pub fn top_n_ext(map: &HashMap<String, u64>, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = map.iter().map(|(k, c)| (k.clone(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    pub fn top_n(&self, map: &HashMap<String, u64>, n: usize) -> Vec<(String, u64)> {
        Self::top_n_ext(map, n)
    }

    pub fn detail(&self, kind: EntityKind, name: &str) -> Option<&EntityDetail> {
        self.details.get(&(kind.prefix().to_string() + name))
    }

    /// Economic scoring of one client IP from its auth and flow stats.
    fn suspect_of<'a>(&'a self, ip: &str, a: Option<&'a IpAuth>) -> Option<Suspect> {
        let d = self.detail(EntityKind::Ip, ip)?;
        let cat = |c: Category| d.counts[EntityDetail::cat_index(c)];
        let tout = cat(Category::Queued) + cat(Category::Delivered);
        let tok = cat(Category::AuthOk);
        let tblk = cat(Category::Spam) + cat(Category::Blocked) + cat(Category::Policy) + cat(Category::Throttled);
        let last_min = self.minute_span().1;
        let new_active = d.first_seen.is_some_and(|fs| fs >= last_min - NEW_WINDOW_MIN)
            && (tok > 0 || tout > 0);

        let (attempts, ok, users, reasons, top_reason, compromised) = match a {
            Some(a) => (
                a.attempts as u64,
                a.ok as u64,
                a.users.len(),
                a.reasons.len(),
                a.reasons
                    .iter()
                    .max_by_key(|(_, c)| **c)
                    .map(|(k, _)| k.clone())
                    .or_else(|| a.users.keys().next().cloned()),
                a.compromised,
            ),
            None => (
                0,
                tok,
                0,
                0,
                None,
                None,
            ),
        };

        let mut verdicts: Vec<&'static str> = Vec::new();
        let mut score = 0u32;
        if attempts >= SUSPECT_FAILS_HI {
            score += 2;
        } else if attempts >= SUSPECT_FAILS_LO {
            score += 1;
        }
        if users >= BRUTE_USERS {
            score += 2;
            verdicts.push("brute force (many users)");
        } else if users >= MULTI_USERS {
            score += 1;
            verdicts.push("multiple users");
        }
        if reasons >= VARIED_REASONS {
            score += 1;
            verdicts.push("varied failure reasons");
        }
        if compromised.is_some() {
            score += 3;
            verdicts.push("compromised");
        }
        if new_active {
            score += 2;
            verdicts.push("new + active");
        }
        if tblk > 0 {
            score += 1;
            verdicts.push("junk/blocked");
        }
        if score == 0 {
            return None;
        }
        Some(Suspect {
            name: ip.to_string(),
            score,
            attempts,
            ok,
            users,
            top_reason,
            verdicts,
            compromised_at: compromised,
        })
    }

    /// Full abuse view: suspicious IPs (score-sorted) and attacked accounts.
    pub fn abuse_report(&self) -> AbuseReport {
        let ips: HashSet<&str> = self
            .auth_ips
            .keys()
            .map(|s| s.as_str())
            .chain(self.details.keys().filter_map(|k| k.strip_prefix("i:")))
            .collect();
        let mut suspects: Vec<Suspect> = ips
            .into_iter()
            .filter_map(|ip| self.suspect_of(ip, self.auth_ips.get(ip)))
            .collect();
        suspects.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));

        let mut accounts: Vec<AttackedAccount> = self
            .user_ips
            .iter()
            .filter(|(_, ips)| ips.len() >= SPRAY_IPS)
            .map(|(u, ips)| AttackedAccount { name: u.clone(), ips: ips.len() })
            .collect();
        accounts.sort_by(|a, b| b.ips.cmp(&a.ips).then_with(|| a.name.cmp(&b.name)));

        AbuseReport { suspects, accounts }
    }

    /// Abuse flags for a single entity, for the drill-down view.
    pub fn suspect_for(&self, name: &str) -> Option<Suspect> {
        self.suspect_of(name, self.auth_ips.get(name))
    }

    /// Anchor minutes for window charts: (first, last) event minute.
    pub fn minute_span(&self) -> (i64, i64) {
        let last = self.last_ts.map(|t| t.timestamp() / 60).unwrap_or_else(|| Utc::now().timestamp() / 60);
        let first = self.first_ts.map(|t| t.timestamp() / 60).unwrap_or(last);
        (first, last)
    }
}

fn bucket_of(ts: DateTime<Utc>) -> DateTime<Utc> {
    // truncate to the second boundary via timestamp
    chrono::DateTime::from_timestamp(ts.timestamp(), 0).unwrap_or(ts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_line;

    fn dt(secs: i64) -> DateTime<Utc> {
        chrono::DateTime::from_timestamp(secs, 0).unwrap()
    }

    #[test]
    fn ingests_real_format_line() {
        let mut s = Stats::new();
        s.ingest(
            &parse_line(
                "2026-11-19T00:01:52Z INFO Queued message for delivery (queue.message-queued) listenerId = \"smtp\", remoteIp = 167.89.48.242, from = \"sender@example.com\", to = [\"hotel@mager.sk\"], size = 49391",
            ),
            dt(1_800_000_000),
        );
        assert_eq!(s.total, 1);
        assert_eq!(s.category_count(Category::Queued), 1);
        assert!(s.top_ips.contains_key("167.89.48.242"));
        assert!(s.top_senders.contains_key("sender@example.com"));
        assert!(s.top_recipients.contains_key("hotel@mager.sk"));
        assert_eq!(s.bytes_seen, 49391);
        assert_eq!(s.recent_problems.len(), 0);
    }

    #[test]
    fn problems_collects_warn_error() {
        let mut s = Stats::new();
        s.ingest(
            &parse_line(
                "2026-11-19T23:03:00Z ERROR Authentication error (auth.error) remoteIp = 147.93.182.44",
            ),
            dt(1_800_000_000),
        );
        assert_eq!(s.recent_problems.len(), 1);
        assert_eq!(s.level_count(Level::Error), 1);
        assert!(s.top_ips.contains_key("147.93.182.44"));
    }

    #[test]
    fn history_is_bounded() {
        let mut s = Stats::new();
        for i in 0..1000 {
            s.ingest(
                &parse_line(&format!(
                    "2026-11-19 10:00:{:02} INFO [1] smtp.session connection from [192.0.2.{}]:1",
                    i % 60,
                    i % 200
                )),
                Utc::now(),
            );
        }
        assert!(s.history.len() <= HISTORY_LEN + 1);
        assert_eq!(s.total, 1000);
    }

    #[test]
    fn epoch_timestamps_roll_history() {
        let mut s = Stats::new();
        for (i, secs) in [1_800_000_000u64, 1_800_000_002, 1_800_000_005].into_iter().enumerate() {
            s.ingest(
                &parse_line(&format!("{secs} INFO [1] smtp.ehlo test")),
                dt(1_800_000_006 + i as i64),
            );
        }
        // open buckets between events: :000, :001, :002.., one per second
        assert_eq!(s.history.len(), 5);
        assert_eq!(s.history[0], 1);
        assert_eq!(s.history[2], 1);
    }

    #[test]
    fn flow_hist_windows_and_peaks() {
        let mut h = FlowHist::default();
        h.bump(100, 1, 2, 0, 0);
        h.bump(101, 0, 1, 0, 0);
        h.bump(200, 0, 5, 0, 0);
        let bars = h.window(100, 110, 2);
        assert_eq!(bars.len(), 5);
        assert_eq!(bars[0].minute, 100);
        assert_eq!(bars[0].inn, 1);
        // bar 0 covers minutes 100 and 101
        assert_eq!(bars[0].out, 3);
        assert_eq!(bars[1].out, 0);
        assert_eq!(bars[4].out, 0);
        // any 60-minute window around minute 200 sees the 5 out events
        assert_eq!(h.peak_per_unit(0, 1000, 60), Some((200, 5)));
        assert_eq!(h.totals_since(150), (0, 5, 0, 0));
    }

    #[test]
    fn entities_track_peers_and_fanout() {
        let mut s = Stats::new();
        let line_from = |from: &str, to: &str, ip: &str| {
            parse_line(&format!(
                "2026-11-19T10:00:{:02}Z INFO Queued message for delivery (queue.message-queued) remoteIp = {ip}, from = \"{from}\", to = [\"{to}\"]",
                0
            ))
        };
        s.ingest(&line_from("a@x.com", "r1@y.com", "1.2.3.4"), dt(1_800_000_000));
        s.ingest(&line_from("a@x.com", "r2@y.com", "1.2.3.4"), dt(1_800_000_001));

        let ip = s.detail(EntityKind::Ip, "1.2.3.4").unwrap();
        assert_eq!(ip.counts[EntityDetail::cat_index(Category::Queued)], 2);
        assert_eq!(ip.peers_from.get("a@x.com"), Some(&2));
        assert_eq!(ip.peers_to.get("r1@y.com"), Some(&1));
        // two distinct recipients in one minute -> fan-out 2
        assert_eq!(ip.fanout.totals_since(0), (0, 2, 0, 0));

        let sender = s.detail(EntityKind::Sender, "a@x.com").unwrap();
        assert_eq!(sender.peers_to.get("r2@y.com"), Some(&1));
        assert!(sender.peers_from.contains_key("ip:1.2.3.4"));

        let recip = s.detail(EntityKind::Recipient, "r1@y.com").unwrap();
        assert_eq!(recip.peers_from.get("a@x.com"), Some(&1));
        assert!(recip.peers_to.contains_key("ip:1.2.3.4"));
        assert_eq!(s.flow.totals_since(0), (0, 2, 0, 0));
    }

    #[test]
    fn flow_hist_caps_memory() {
        let mut h = FlowHist::default();
        for m in 0..60_000i64 {
            h.bump(m, 1, 0, 0, 0);
        }
        assert!(h.first_minute().unwrap() >= 10_000);
    }

    #[test]
    fn abuse_brute_force_and_spray() {
        let mut s = Stats::new();
        // one IP guessing 12 different usernames -> brute force
        for i in 0..12 {
            s.ingest(
                &parse_line(&format!(
                    "2026-11-19T10:{:02}:00Z ERROR Authentication error (auth.error) remoteIp = 9.9.9.9, accountName = \"user{i}@x.com\"",
                    i % 60
                )),
                dt(1_800_000_000),
            );
        }
        // 12 IPs attacking one account -> spray entry for that user
        for i in 0..12 {
            s.ingest(
                &parse_line(&format!(
                    "2026-11-19T10:{:02}:00Z ERROR Authentication error (auth.error) remoteIp = 10.0.0.{i}, accountName = \"victim@x.com\"",
                    i % 60
                )),
                dt(1_800_000_000),
            );
        }
        let report = s.abuse_report();
        let brute = report.suspects.iter().find(|s| s.name == "9.9.9.9").unwrap();
        assert_eq!(brute.users, 12);
        assert!(brute.verdicts.contains(&"brute force (many users)"));
        assert!(brute.score >= 2);

        let victim = report.accounts.iter().find(|a| a.name == "victim@x.com").unwrap();
        assert_eq!(victim.ips, 12);
        assert!(report.accounts.iter().all(|a| a.ips >= SPRAY_IPS));
    }

    #[test]
    fn abuse_compromise_detector() {
        let mut s = Stats::new();
        let line = |event: &str, ip: &str, extra: &str, sec: u32| {
            parse_line(&format!(
                "2026-11-19T10:00:{:02}Z {} ({}) remoteIp = {ip}{extra}",
                sec % 60,
                if event.starts_with("auth") { "ERROR" } else { "INFO" },
                event
            ))
        };
        // 3 failures then a success then outbound mail -> compromised
        for i in 0..3 {
            s.ingest(&line("auth.error", "7.7.7.7", ", reason = \"bad password\"", i), dt(1_800_000_000));
        }
        s.ingest(&line("auth.success", "7.7.7.7", ", accountName = \"admin\"", 4), dt(1_800_000_000));
        s.ingest(
            &line("queue.message-queued", "7.7.7.7", ", from = \"a@b.co\"", 5),
            dt(1_800_000_000),
        );
        let report = s.abuse_report();
        let susp = report.suspects.iter().find(|s| s.name == "7.7.7.7").unwrap();
        assert!(susp.compromised_at.is_some());
        assert!(susp.verdicts.contains(&"compromised"));
        // compromise alone is the heaviest single signal
        assert!(susp.score >= 3);
    }

    #[test]
    fn abuse_not_triggered_without_volume() {
        let mut s = Stats::new();
        // one or two stray failures must not create a suspect
        s.ingest(
            &parse_line("2026-11-19T10:00:00Z ERROR Authentication error (auth.error) remoteIp = 4.4.4.4, reason = \"bad password\""),
            dt(1_800_000_000),
        );
        s.ingest(
            &parse_line("2026-11-19T10:01:00Z ERROR Authentication error (auth.error) remoteIp = 4.4.4.4, reason = \"bad password\""),
            dt(1_800_000_000),
        );
        assert!(s.abuse_report().suspects.is_empty());
    }

    #[test]
    fn abuse_repetitive_reason_scores_low() {
        let mut s = Stats::new();
        // config-noise pattern: a single IP, identical reason, no users
        for i in 0..40 {
            s.ingest(
                &parse_line(&format!(
                    "2026-11-19T10:{:02}:00Z ERROR Authentication error (auth.error) remoteIp = 171.43.138.222, reason = \"Unsupported credentials type for OIDC backend\"",
                    i % 60
                )),
                dt(1_800_000_000),
            );
        }
        let report = s.abuse_report();
        let susp = report.suspects.iter().find(|s| s.name == "171.43.138.222").unwrap();
        // base fail signal (+2) but no multi-user/varied-reason escalation
        assert_eq!(susp.score, 2);
        assert_eq!(susp.users, 0);
        assert!(susp.top_reason.as_deref().unwrap_or("").contains("OIDC"));
    }

    #[test]
    fn watcher_skips_binary_and_reads_bz2() -> anyhow::Result<()> {
        use crate::watcher::FolderWatcher;
        use std::fs;
        use std::process::Command;

        let tmp = tempfile::tempdir()?;
        // binary junk (like a tar) is skipped without poisoning stats
        let tar = tmp.path().join("stalwart-log2-tar");
        fs::write(&tar, b"\x00garbage\x00data\x00")?;
        // a bz2 archive is decompressed transparently (built with the
        // system bzip2 CLI so no extra dependency is needed)
        let plain = tmp.path().join("plain.log");
        fs::write(&plain, b"2026-11-19T10:00:00Z INFO [1] smtp.session connection from [1.2.3.4]:1\n")?;
        let bz2 = tmp.path().join("stalwart.2026-11-19.log.bz2");
        let ok = Command::new("bzip2").args(["-kf", &plain.to_string_lossy()]).status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            fs::rename(plain.with_extension("log.bz2"), &bz2)?;
        } else {
            fs::write(&bz2, b"")?; // no bzip2 available: only test the binary skip
        }

        let mut w = FolderWatcher::new(tmp.path(), Some("stalwart".into()))?;
        let r = w.poll()?;
        assert_eq!(r.files_seen, 2);
        if ok {
            // only the bz2 line is parsed; the tar contributes nothing
            assert_eq!(r.records.len(), 1);
            assert!(r.records[0].message.contains("connection from"));
        } else {
            assert_eq!(r.records.len(), 0);
        }
        // second poll: both are known, nothing new
        let r = w.poll()?;
        assert_eq!(r.records.len(), 0);
        assert!(!fs::read(&bz2).unwrap().is_empty());
        Ok(())
    }

    #[test]
    fn hosted_domains_and_mail_pairs() {
        let mut s = Stats::new();
        // inbound spam queued for a local mailbox (-> hosted detection below)
        s.ingest(
            &parse_line(
                "2026-11-19T00:01:52Z INFO Queued message for delivery (queue.message-queued) remoteIp = 167.89.48.242, from = \"bounces+x@em7433.profi-pozicka.sk\", to = [\"hotel@mager.sk\"]",
            ),
            dt(1_800_000_000),
        );
        // local mailbox ingest identifies the hosted domain
        s.ingest(
            &parse_line(
                "2026-11-19T00:01:53Z INFO Message stored (message-ingest.message-stored) queueName = \"local\", from = \"b+x@em7433.profi-pozicka.sk\", to = [\"hotel@mager.sk\"]",
            ),
            dt(1_800_000_000),
        );
        // outbound delivery from a hosted domain
        s.ingest(
            &parse_line(
                "2026-11-19T00:37:28Z INFO Message delivered (delivery.delivered) remoteIp = 1.2.3.4, from = \"info@mager.sk\", to = [\"zakaznik@terasport.cz\"]",
            ),
            dt(1_800_000_000),
        );

        assert_eq!(s.hosted_domains(), vec![("mager.sk".to_string(), 1)]);
        let pairs = s.top_mail_pairs(10, None);
        assert_eq!(pairs.len(), 2);
        let in_pair = pairs.iter().find(|p| p.to.ends_with("@mager.sk")).unwrap();
        assert_eq!(in_pair.dir, MailDir::In);
        let out_pair = pairs.iter().find(|p| p.from.ends_with("@mager.sk")).unwrap();
        assert_eq!(out_pair.dir, MailDir::Out);
        // filter: only pairs touching the selected domain
        let filtered = s.top_mail_pairs(10, Some(&["mager.sk".to_string()]));
        assert_eq!(filtered.len(), 2);
        let filtered = s.top_mail_pairs(10, Some(&["other.example".to_string()]));
        assert!(filtered.is_empty());
    }

    #[test]
    fn mail_pairs_local_and_respect_hosted_only() {
        let mut s = Stats::new();
        s.ingest(
            &parse_line(
                "2026-11-19T10:00:00Z INFO Message stored (message-ingest.message-stored) queueName = \"local\", from = \"x@cdn21.de\", to = [\"postmaster@cdn21.de\"]",
            ),
            dt(1_800_000_000),
        );
        // relay attempt external -> external: pair must not appear
        s.ingest(
            &parse_line(
                "2026-11-19T10:01:00Z INFO Queued message for delivery (queue.message-queued) remoteIp = 5.6.7.8, from = \"a@spam.example\", to = [\"b@elsewhere.example\"]",
            ),
            dt(1_800_000_000),
        );
        // local: hosted -> hosted
        s.ingest(
            &parse_line(
                "2026-11-19T10:02:00Z INFO Queued message for delivery (queue.message-queued) remoteIp = 172.19.0.6, from = \"x@cdn21.de\", to = [\"hotel@mager.sk\"]",
            ),
            dt(1_800_000_000),
        );
        s.ingest(
            &parse_line(
                "2026-11-19T10:02:10Z INFO Message stored (message-ingest.message-stored) queueName = \"local\", from = \"x@cdn21.de\", to = [\"hotel@mager.sk\"]",
            ),
            dt(1_800_000_000),
        );
        let hosted: std::collections::HashSet<String> =
            s.hosted_domains().into_iter().map(|(d, _)| d).collect();
        assert!(hosted.contains("cdn21.de") && hosted.contains("mager.sk"));
        let pairs = s.top_mail_pairs(10, None);
        assert!(pairs.iter().all(|p| p.dir != MailDir::Transit));
        // hosted -> hosted queued mail is "local"
        assert_eq!(pairs.iter().find(|p| p.from == "x@cdn21.de").unwrap().dir, MailDir::Local);
    }

    #[test]
    fn message_counted_once_per_queue_id() {
        let mut s = Stats::new();
        let line = |event: &str, extra: &str| {
            parse_line(&format!(
                "2026-11-19T10:00:00Z INFO {event} {extra}, queueId = 341344700644505600, from = \"x@spam.example\", to = [\"hotel@mager.sk\"]",
            ))
        };
        // same message travelling: queued -> stored -> duplicate notice
        s.ingest(
            &line("Queued message for delivery (queue.message-queued)", "remoteIp = 1.2.3.4"),
            dt(1_800_000_000),
        );
        s.ingest(
            &line("Message stored (message-ingest.message-stored)", "queueName = \"local\""),
            dt(1_800_000_000),
        );
        s.ingest(
            &line("Skipping duplicate message (message-ingest.duplicate)", "queueName = \"local\""),
            dt(1_800_000_000),
        );
        assert_eq!(s.top_recipients.get("hotel@mager.sk"), Some(&1));
        assert_eq!(s.top_senders.get("x@spam.example"), Some(&1));
        // exactly one in-pair
        assert_eq!(s.top_mail_pairs(10, None).len(), 1);
        assert_eq!(s.queue_seen.len(), 1);
        // outbound: relayed delivery shares the qid -> no double count
        s.ingest(
            &parse_line(
                "2026-11-19T10:01:00Z INFO Message delivered (delivery.delivered) queueId = 341344700644505600, from = \"x@spam.example\", to = [\"hotel@mager.sk\"], hostname = \"mx.remote.example\"",
            ),
            dt(1_800_000_000),
        );
        assert_eq!(s.top_recipients.get("hotel@mager.sk"), Some(&1));
    }

    /// Integration check against the real log files shipped in `sample/`.
    /// Note: the numbers are pinned to the current contents of the folder
    /// (plain text files 2026-10-18 .. 2026-11-19, ~51.7k events). If the
    /// sample data is updated, adjust the expected numbers or drop them.
    #[test]
    fn parses_entire_real_sample_folder() {
        let dir = std::path::Path::new("sample");
        if !dir.is_dir() {
            return;
        }
        let mut w = crate::watcher::FolderWatcher::new(dir, Some("stalwart".into())).unwrap();
        let result = w.poll().unwrap();

        let mut s = Stats::new();
        for r in &result.records {
            s.ingest(r, dt(1_800_000_000));
        }
        // every non-empty line must have been ingested exactly once
        let non_empty = result.records.iter().filter(|r| !r.raw.is_empty()).count();
        assert_eq!(s.total, non_empty as u64);
        assert!(
            s.total > 30_000,
            "sample folder unexpectedly small: {}",
            s.total
        );
        assert!(s.category_count(Category::AuthFail) > 100);
        assert!(s.category_count(Category::Tls) > 50);
        // the newest event in the folder
        let last = s.last_ts.expect("last_ts");
        assert_eq!(
            last.timestamp(),
            chrono::DateTime::parse_from_rfc3339("2026-11-19T23:05:56Z")
                .unwrap()
                .timestamp()
        );
        // 2026-10-18T00:00:15Z is the oldest event in the folder
        let first = s.first_ts.expect("first_ts");
        assert!(first.timestamp() <= chrono::DateTime::parse_from_rfc3339("2026-10-18T03:00:00Z").unwrap().timestamp());
    }
}
