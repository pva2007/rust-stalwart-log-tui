use crate::dns::DnsCache;
use crate::parser::LogRecord;
use crate::settings::Settings;
use crate::stats::{EntityKind, FlowHist, MailPair, MinutePoint, Stats};
use crate::watcher::FolderWatcher;
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::PathBuf;

const RECENT_LEN: usize = 300;

/// Windows for flow charts: (label, minutes; 0 = since first event).
pub const WIN_PRESETS: [(&str, i64); 5] =
    [("5m", 5), ("1h", 60), ("6h", 360), ("24h", 1440), ("all", 0)];

enum Overlay {
    None,
    Settings,
    Abuse,
    Domains,
}

pub struct App {
    pub folder: PathBuf,
    pub poll_ms: u64,
    pub watcher: FolderWatcher,
    pub stats: Stats,
    pub recent: VecDeque<LogRecord>,
    pub paused: bool,
    pub started_at: DateTime<Utc>,
    pub last_poll_at: Option<DateTime<Utc>>,
    pub status: String,
    pub files_seen: usize,
    pub quit: bool,
    pub settings: Settings,
    pub settings_path: PathBuf,
    pub dns: DnsCache,
    /// Settings overlay: which row is selected.
    pub settings_row: usize,
    overlay: Overlay,
    dns_requested: HashSet<IpAddr>,

    /// Abuse/signals view: which suspect row is selected.
    pub abuse_row: usize,
    /// Domain filter picker: which row is selected (0 = "all").
    pub domain_row: usize,

    /// Top-list selection: 0 = client IPs, 1 = senders, 2 = recipients.
    pub sel_panel: usize,
    pub sel_row: usize,
    /// Open drill-down entity (kind + raw key).
    pub detail: Option<(EntityKind, String)>,
    /// Index into `WIN_PRESETS` for the mail-flow panel and the drill-down.
    pub flow_win: usize,
    pub detail_win: usize,
}

impl App {
    pub fn new(
        folder: PathBuf,
        poll_ms: u64,
        pattern: Option<String>,
        settings: Settings,
        settings_path: PathBuf,
    ) -> Result<App> {
        let watcher = FolderWatcher::new(&folder, pattern)?;
        let dns = DnsCache::new(settings.dns_cache_hours);
        Ok(App {
            folder,
            poll_ms,
            watcher,
            stats: Stats::new(),
            recent: VecDeque::new(),
            paused: false,
            started_at: Utc::now(),
            last_poll_at: None,
            status: "starting".to_string(),
            files_seen: 0,
            quit: false,
            settings,
            settings_path,
            dns,
            settings_row: 0,
            overlay: Overlay::None,
            dns_requested: HashSet::new(),
            abuse_row: 0,
            domain_row: 0,
            sel_panel: 0,
            sel_row: 0,
            detail: None,
            flow_win: 2,
            detail_win: 3,
        })
    }

    /// Read existing log data and ingest it; runs once before the UI loop
    /// starts so the first frame already shows historical stats.
    pub fn load_initial(&mut self) {
        self.poll_once("initial load");
    }

    pub fn poll_once(&mut self, label: &str) {
        match self.watcher.poll() {
            Ok(result) => {
                let now = Utc::now();
                for record in &result.records {
                    if record.raw.is_empty() {
                        continue;
                    }
                    self.stats.ingest(record, now);
                    self.recent.push_back(record.clone());
                    while self.recent.len() > RECENT_LEN {
                        self.recent.pop_front();
                    }
                }
                self.files_seen = result.files_seen;
                self.status = format!(
                    "{}: {} new from {}/{} files",
                    label,
                    result.records.len(),
                    self.files_seen,
                    self.folder.display()
                );
                self.last_poll_at = Some(now);
            }
            Err(e) => {
                self.status = format!("poll error: {e}");
            }
        }
    }

    /// Resolve hostnames only for the IPs shown in the Top panel; call once
    /// per UI tick. Resolving every IP seen in the logs would flood the
    /// single worker thread (many IPs have no PTR record, each costing a
    /// full timeout).
    pub const DNS_TOP_N: usize = 30;

    fn queue_top_dns(&mut self) {
        for (ip_str, _count) in self.stats.top_n(&self.stats.top_ips, Self::DNS_TOP_N) {
            if let Ok(ip) = ip_str.parse::<IpAddr>()
                && self.dns_requested.insert(ip)
            {
                self.dns.ensure(ip);
            }
        }
    }

    pub fn events_per_second(&self) -> u64 {
        let history = self.stats.history_snapshot(self.settings.hide_noise);
        history.last().copied().unwrap_or(0)
    }

    pub fn clear_stats(&mut self) {
        self.stats = Stats::new();
        self.recent.clear();
        self.status = "stats cleared".to_string();
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        self.status = if self.paused { "paused".to_string() } else { "resumed".to_string() };
    }

    // --- settings overlay ---

    pub fn show_settings(&mut self) {
        self.overlay = Overlay::Settings;
        self.settings_row = 0;
    }

    pub fn close_settings(&mut self) {
        self.overlay = Overlay::None;
    }

    pub fn settings_open(&self) -> bool {
        matches!(self.overlay, Overlay::Settings)
    }

    /// Number of mutable settings shown in the overlay.
    pub const SETTINGS_ROWS: usize = 4;

    pub fn settings_down(&mut self) {
        self.settings_row = (self.settings_row + 1) % Self::SETTINGS_ROWS;
    }

    pub fn settings_up(&mut self) {
        self.settings_row = (self.settings_row + Self::SETTINGS_ROWS - 1) % Self::SETTINGS_ROWS;
    }

    /// Apply a change to the selected setting; `direction` is +1 / -1.
    pub fn settings_change(&mut self, direction: i8) {
        let s = &mut self.settings;
        match self.settings_row {
            0 => {
                s.show_hostnames = !s.show_hostnames;
                if s.show_hostnames {
                    // queue names for the IPs we already know
                    self.queue_top_dns();
                }
            }
            1 => {
                s.hide_noise = !s.hide_noise;
            }
            2 => {
                s.cycle_time_format(direction < 0);
            }
            _ => {
                s.dns_cache_hours = (s.dns_cache_hours as i64 + direction as i64 * 12)
                    .clamp(1, 720) as u64;
                self.dns.invalidate();
            }
        }
        self.persist_settings();
    }

    fn persist_settings(&mut self) {
        if let Err(e) = self.settings.save(&self.settings_path) {
            self.status = format!("settings save failed: {e}");
        }
    }

    // --- domain filter picker ---

    pub fn show_domains(&mut self) {
        self.overlay = Overlay::Domains;
        self.domain_row = 0;
    }

    pub fn close_domains(&mut self) {
        self.overlay = Overlay::None;
    }

    pub fn domains_open(&self) -> bool {
        matches!(self.overlay, Overlay::Domains)
    }

    /// Picker rows: first row is "all domains" (empty selection).
    pub fn domain_rows(&self) -> Vec<(String, u64)> {
        vec![("(all domains)".to_string(), self.stats.mail_pairs.len() as u64)]
            .into_iter()
            .chain(self.stats.hosted_domains())
            .collect()
    }

    pub fn domains_move(&mut self, delta: i8) {
        let len = self.domain_rows().len();
        if len == 0 {
            return;
        }
        let row = self.domain_row as i64 + delta as i64;
        self.domain_row = row.rem_euclid(len as i64) as usize;
    }

    /// Toggle the selected domain in the filter; the "all" row clears it.
    /// Persists the settings.
    pub fn domain_toggle(&mut self) {
        if self.domain_row == 0 {
            self.settings.domains.clear();
        } else {
            let rows = self.domain_rows();
            if let Some((name, _)) = rows.get(self.domain_row) {
                let name = name.clone();
                if let Some(pos) = self.settings.domains.iter().position(|d| *d == name) {
                    self.settings.domains.swap_remove(pos);
                } else {
                    self.settings.domains.push(name);
                }
            }
        }
        self.persist_settings();
    }

    /// Whether the pairs view is restricted to selected domains.
    pub fn domain_filter_active(&self) -> bool {
        !self.settings.domains.is_empty()
    }

    /// Top sender->recipient rows honoring the domain filter (row cap).
    pub fn mail_pairs(&self, n: usize) -> Vec<MailPair> {
        let domains = self.domain_filter_active().then(|| self.settings.domains.clone());
        self.stats.top_mail_pairs(n, domains.as_deref())
    }

    // --- abuse / signals view ---

    pub fn show_abuse(&mut self) {
        self.overlay = Overlay::Abuse;
        self.abuse_row = 0;
    }

    pub fn close_abuse(&mut self) {
        self.overlay = Overlay::None;
    }

    pub fn abuse_open(&self) -> bool {
        matches!(self.overlay, Overlay::Abuse)
    }

    pub fn abuse_move(&mut self, delta: i8) {
        let len = self.stats.abuse_report().suspects.len();
        if len == 0 {
            self.abuse_row = 0;
            return;
        }
        let row = self.abuse_row as i64 + delta as i64;
        self.abuse_row = row.clamp(0, len as i64 - 1) as usize;
    }

    /// Open the drill-down for the selected suspect. Returns false when the
    /// list is empty or the row is out of range.
    pub fn open_abuse_detail(&mut self) -> bool {        let suspects = self.stats.abuse_report().suspects;
        let Some(s) = suspects.get(self.abuse_row) else {
            return false;
        };
        let name = s.name.clone();
        if let Ok(ip) = name.parse()
            && self.settings.show_hostnames
            && self.dns_requested.insert(ip)
        {
            self.dns.ensure(ip);
        }
        self.detail = Some((EntityKind::Ip, name));
        self.overlay = Overlay::None;
        true
    }

    /// Write the current suspect list (IP, score, verdicts, top reason) to
    /// `suspects-<timestamp>.txt` in the working directory, one record per
    /// line with comment lines starting `#`. Returns a status message.
    pub fn export_suspects(&mut self) -> String {
        let report = self.stats.abuse_report();
        if report.suspects.is_empty() {
            return "abuse export: no suspects to export".to_string();
        }
        let path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join(format!(
            "suspects-{}.txt",
            Utc::now().format("%Y%m%d-%H%M%S")
        ));
        let mut out = format!(
            "# stalwart-log abuse export {} (folder: {})\n# ip\tscore\tattempts\tok\tusers\tverdicts\ttop_reason\n",
            Utc::now().to_rfc3339(),
            self.folder.display()
        );
        for s in &report.suspects {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                s.name,
                s.score,
                s.attempts,
                s.ok,
                s.users,
                s.verdicts.join(","),
                truncate_reason(s.top_reason.as_deref().unwrap_or("-"), 80),
            ));
        }
        match std::fs::write(&path, &out) {
            Ok(_) => format!("exported {} suspect IPs to {}", report.suspects.len(), path.display()),
            Err(e) => format!("abuse export failed: {e}"),
        }
    }

    /// Poll DNS answers and refresh the cache; call once per UI tick.
    pub fn tick_dns(&mut self) {
        if self.settings.show_hostnames {
            // re-request names for top IPs that came in while disabled
            self.queue_top_dns();
        }
        self.dns.drain();
    }

    // --- selection / drill-down ---

    /// The currently rendered top list for `panel` (0 IPs, 1 senders, 2
    /// recipients); selection and Enter act on the same ordering as the UI.
    pub fn panel_entries(&self, panel: usize) -> Vec<(String, u64)> {
        match panel {
            0 => self.stats.top_n(&self.stats.top_ips, 12),
            1 => self.stats.top_n(&self.stats.top_senders, 10),
            _ => self.stats.top_n(&self.stats.top_recipients, 10),
        }
    }

    pub fn panel_kind(&self, panel: usize) -> EntityKind {
        match panel {
            0 => EntityKind::Ip,
            1 => EntityKind::Sender,
            _ => EntityKind::Recipient,
        }
    }

    pub fn cycle_panel(&mut self) {
        self.sel_panel = (self.sel_panel + 1) % 3;
        self.sel_row = 0;
    }

    pub fn select_panel(&mut self, panel: usize) {
        self.sel_panel = panel % 3;
        self.sel_row = 0;
    }

    pub fn sel_move(&mut self, delta: i8) {
        let len = self.panel_entries(self.sel_panel).len();
        if len == 0 {
            self.sel_row = 0;
            return;
        }
        let row = self.sel_row as i64 + delta as i64;
        self.sel_row = row.clamp(0, len as i64 - 1) as usize;
    }

    /// Open the drill-down view for the selected entry. Returns false when
    /// the selected panel has no rows.
    pub fn open_detail(&mut self) -> bool {
        let entries = self.panel_entries(self.sel_panel);
        let Some((key, _)) = entries.get(self.sel_row) else {
            return false;
        };
        let kind = self.panel_kind(self.sel_panel);
        if kind == EntityKind::Ip
            && self.settings.show_hostnames
            && let Ok(ip) = key.parse()
            && self.dns_requested.insert(ip)
        {
            self.dns.ensure(ip);
        }
        self.detail = Some((kind, key.clone()));
        true
    }

    pub fn close_detail(&mut self) {
        self.detail = None;
    }

    pub fn cycle_flow_win(&mut self) {
        self.flow_win = (self.flow_win + 1) % WIN_PRESETS.len();
    }

    pub fn cycle_detail_win(&mut self) {
        self.detail_win = (self.detail_win + 1) % WIN_PRESETS.len();
    }

    /// Bars for the main mail-flow panel: (window label, per-bar points).
    pub fn flow_window(&self, nbars: usize) -> (&'static str, Vec<MinutePoint>) {
        self.detail_window_hist(&self.stats.flow, self.flow_win, nbars)
    }

    /// Bars for the drill-down timeline of an entity's own flow history.
    pub fn detail_window(&self, hist: &FlowHist, nbars: usize) -> (&'static str, Vec<MinutePoint>) {
        self.detail_window_hist(hist, self.detail_win, nbars)
    }

    fn detail_window_hist(
        &self,
        hist: &FlowHist,
        win: usize,
        nbars: usize,
    ) -> (&'static str, Vec<MinutePoint>) {
        let (first, last) = self.stats.minute_span();
        let (label, mins) = WIN_PRESETS[win];
        let end = last + 1;
        let from = if mins == 0 { first } else { (end - mins).max(first) };
        let bar = ((end - from).max(1) as usize / nbars).max(1);
        (label, hist.window(from, end, bar))
    }

    /// Display name for an entity: hostnames for IPs when resolving is on.
    pub fn entity_label(&self, kind: EntityKind, key: &str) -> String {
        if kind == EntityKind::Ip && self.settings.show_hostnames && let Ok(ip) = key.parse() {
            return match self.dns.get(ip, Utc::now()) {
                Some(h) => h.to_string(),
                None => key.to_string(),
            };
        }
        key.to_string()
    }
}

/// Shorten a reason string for export lines: hard-cut to `max` characters plus
/// an ellipsis marker.
fn truncate_reason(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let cut: String = s.chars().take(max.saturating_sub(3)).collect();
    format!("{cut}...")
}
