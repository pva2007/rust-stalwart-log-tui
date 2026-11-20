use crate::parser::{emails_in, ips_in, Category, Level, LogRecord};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};

const BUCKET_SECONDS: u64 = 1;
pub const HISTORY_LEN: usize = 180;

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

    /// Per-minute in/out/err/blk flow for ALL events (key `EntityKind`-less).
    pub flow: FlowHist,
    /// Per-entity drill-down stats, keyed by `kind.prefix() + name`.
    pub details: HashMap<String, EntityDetail>,

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

        let mut sender_key: Option<String> = None;
        if let Some(from) = record.get("from") {
            let emails = emails_in(from);
            let display = if emails.is_empty() { from } else { &emails[0] };
            sender_key = Some(display.to_string());
            *self.top_senders.entry(display.to_string()).or_default() += 1;
        }
        let recipients = record
            .get("to")
            .map(emails_in)
            .unwrap_or_default();
        if !recipients.is_empty() {
            for to in &recipients {
                *self.top_recipients.entry(to.clone()).or_default() += 1;
            }
        } else if matches!(record.category, Category::Delivered | Category::Failed) {
            for email in emails_in(&record.message) {
                *self.top_recipients.entry(email.clone()).or_default() += 1;
            }
        }

        let ts = record.ts.unwrap_or(now);
        self.track_entities(record, &ip_keys, sender_key.as_deref(), &recipients, ts);

        if self.first_ts.is_none() {
            self.first_ts = Some(ts);
        }
        // files are read in name order, so keep the maximum to reflect the
        // real most-recent event
        if self.last_ts.is_none_or(|old| ts > old) {
            self.last_ts = Some(ts);
        }

        let minute = ts.timestamp() / 60;
        let (inn, out, err, blk) = flow_flags(record.category);
        self.flow.bump(minute, inn, out, err, blk);

        self.roll_history(ts);
        self.bucket_count += 1;
        if record.category != Category::Noise {
            self.bucket_count_active += 1;
        }
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
        ts: DateTime<Utc>,
    ) {
        let minute = ts.timestamp() / 60;
        let category = record.category;
        let (inn, out, err, blk) = flow_flags(category);
        let flow_event = is_flow(category);
        let source_ip = ip_keys.first().map(|ip| format!("ip:{ip}"));

        for ip in ip_keys {
            let d = self.details.entry(EntityKind::Ip.prefix().to_string() + ip).or_insert_with(|| EntityDetail::new(EntityKind::Ip));
            d.count_category(category);
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

    /// Integration check against the real log files shipped in `sample/`.
    /// Numbers cross-checked with grep on 2026-11-14..19: 15284 non-empty
    /// lines; 2393 auth-failure events (auth.error + auth-not-allowed +
    /// relay-not-allowed); 201 tls.handshake.
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
        assert_eq!(s.total, 15284);
        assert_eq!(s.category_count(Category::AuthFail), 2393);
        assert_eq!(s.category_count(Category::Tls), 201);
        assert!(s.top_ips.contains_key("167.89.48.242"));
        assert!(s.top_recipients.contains_key("hotel@mager.sk"));
        // 2026-11-19T23:05:56Z is the newest event in the folder
        let last = s.last_ts.expect("last_ts");
        assert_eq!(last.timestamp(), {
            // rough epoch for 2026-11-19T23:05:56Z
            chrono::DateTime::parse_from_rfc3339("2026-11-19T23:05:56Z").unwrap().timestamp()
        });
    }
}
