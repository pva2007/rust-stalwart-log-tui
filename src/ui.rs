use crate::app::App;
use crate::parser::{Category, Level};
use crate::stats::{HISTORY_LEN, EntityKind, MinutePoint};
use chrono::{DateTime, Utc};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph, Sparkline},
};

fn level_color(level: Level) -> Color {
    match level {
        Level::Trace => Color::DarkGray,
        Level::Debug => Color::Cyan,
        Level::Info => Color::Green,
        Level::Warn => Color::Yellow,
        Level::Error => Color::Red,
    }
}

fn human_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

fn uptime(start: DateTime<Utc>, now: DateTime<Utc>) -> String {
    let s = (now - start).num_seconds().max(0);
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

pub fn draw(f: &mut Frame, app: &App) {
    let now = Utc::now();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(10),   // body
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    draw_header(f, app, chunks[0], now);

    if app.abuse_open() {
        draw_abuse(f, app, chunks[1]);
        draw_footer(f, app, chunks[2]);
        if app.settings_open() {
            draw_settings(f, app, f.area());
        }
        return;
    }

    if app.detail.is_some() {
        draw_detail(f, app, chunks[1]);
        draw_footer(f, app, chunks[2]);
        if app.settings_open() {
            draw_settings(f, app, f.area());
        }
        return;
    }

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(55), // throughput + flow + levels + categories
            Constraint::Percentage(45), // top lists + problems
        ])
        .split(chunks[1]);

    let left = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6), // throughput sparkline
            Constraint::Length(8), // mail flow (in/out/err)
            Constraint::Length(6), // level gauges
            Constraint::Length(7), // event categories (3 columns, 5 rows)
            Constraint::Min(0),    // mail in/out (sender -> recipient)
        ])
        .split(body[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(35), // top ips
            Constraint::Percentage(32), // senders | recipients
            Constraint::Min(0),         // recent problems
        ])
        .split(body[1]);

    draw_throughput(f, app, left[0]);
    draw_mail_flow(f, app, left[1]);
    draw_levels(f, app, left[2]);
    draw_categories(f, app, left[3]);
    draw_mail_pairs(f, app, left[4]);
    let interactive = !app.settings_open();
    draw_top_ips(f, app, right[0], interactive);
    draw_top_addresses(f, app, right[1], interactive);
    draw_problems(f, app, right[2]);
    draw_footer(f, app, chunks[2]);

    if app.settings_open() {
        draw_settings(f, app, f.area());
    }
    if app.domains_open() {
        draw_domains(f, app, f.area());
    }
}

fn draw_domains(f: &mut Frame, app: &App, area: Rect) {
    let rows = app.domain_rows();
    let width = 50u16.min(area.width.saturating_sub(4)).max(20);
    let height = (rows.len() as u16 + 4).min(area.height);
    let popup = centered_rect(area, width, height);

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, (name, count))| {
            let selected = i == app.domain_row;
            let active = if i == 0 {
                app.settings.domains.is_empty()
            } else {
                app.settings.domains.contains(name)
            };
            let style = if selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {}  ", if selected { ">" } else { " " }), style),
                Span::styled(format!("[{}] ", if active { "x" } else { " " }), style),
                Span::styled(format!("{:<26}", truncate(name, 26)), style),
                Span::styled(format!("{:>7} msgs ", human_count(*count)), style),
            ]))
        })
        .collect();

    let help = Line::from(Span::styled(
        " up/down select, enter/space toggle, empty selection = all, d/Esc close  ",
        Style::default().fg(Color::DarkGray),
    ));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Hosted domain filter ")
        .style(Style::default().bg(Color::Black));
    let list = List::new(items).block(block);
    f.render_widget(ratatui::widgets::Clear, popup);
    f.render_widget(list, popup);

    let help_area = Rect {
        x: popup.x,
        y: popup.y + popup.height - 1,
        width: popup.width,
        height: 1,
    };
    f.render_widget(Paragraph::new(help), help_area);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect, now: DateTime<Utc>) {
    let paused_style = if app.paused {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let line = Line::from(vec![
        Span::styled(
            " Stalwart Log Analyzer ",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::raw("│ "),
        Span::styled(format!("events: {}", human_count(app.stats.total)), Style::default().fg(Color::Cyan)),
        Span::raw(" │ "),
        Span::styled(format!("eps: {}", app.events_per_second()), Style::default().fg(Color::Green)),
        Span::raw(" │ "),
        Span::styled(format!("data: {}", human_bytes(app.stats.bytes_seen)), Style::default().fg(Color::Magenta)),
        Span::raw(" │ "),
        Span::styled(format!("uptime: {}", uptime(app.started_at, now)), Style::default().fg(Color::Cyan)),
        Span::raw(" │ "),
        Span::styled(if app.paused { "PAUSED" } else { "live" }, paused_style),
    ]);
    let last_ts = app
        .stats
        .last_ts
        .map(|t| format_time(app, t))
        .unwrap_or_else(|| "-".to_string());
    let p = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" {} ── last event: {} ", app.folder.display(), last_ts)),
    );
    f.render_widget(p, area);
}

fn draw_throughput(f: &mut Frame, app: &App, area: Rect) {
    let data: Vec<u64> = app.stats.history_snapshot(app.settings.hide_noise);
    let title = if app.settings.hide_noise {
        format!(" Throughput (mail events/s, last {HISTORY_LEN}s, noise hidden) ")
    } else {
        format!(" Throughput (events/s, last {HISTORY_LEN}s) ")
    };
    let spark = Sparkline::default()
        .block(Block::default().borders(Borders::ALL).title(title))
        .data(&data)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(spark, area);
}

/// Main-screen mail-flow chart: per-bar in / out / error-rate for the
/// selected window (press `t` to change).
fn draw_mail_flow(f: &mut Frame, app: &App, area: Rect) {
    let nbars = (area.width.saturating_sub(2) / 3).max(10) as usize;
    let (label, bars) = app.flow_window(nbars);

    let sum = |bars: &[MinutePoint], field: fn(&MinutePoint) -> u32| -> u64 {
        bars.iter().map(|b| field(b) as u64).sum()
    };
    let tin = sum(&bars, |b| b.inn);
    let tout = sum(&bars, |b| b.out);
    let terr = sum(&bars, |b| b.err);
    let err_pct = {
        let base = tin + tout + terr;
        if base == 0 { 0.0 } else { terr as f64 / base as f64 * 100.0 }
    };

    // shared scale so `in` and `out` bars are comparable
    let scale = |bars: &[MinutePoint], field: fn(&MinutePoint) -> u32| -> Vec<u64> {
        let max = bars.iter().map(field).max().unwrap_or(0).max(1) as u64;
        bars.iter().map(|b| (field(b) as f64 / max as f64 * 8.0) as u64).collect()
    };
    let in_data = scale(&bars, |b| b.inn);
    let out_data = scale(&bars, |b| b.out);
    let err_data: Vec<u64> = bars
        .iter()
        .map(|b| {
            let base = (b.inn + b.out + b.err) as f64;
            if base == 0.0 { 0 } else { (b.err as f64 / base * 8.0) as u64 }
        })
        .collect();

    let title = format!(
        " Mail flow last {} │ in {} out {} err {} ({:.1}%) │ t change ",
        label,
        human_count(tin),
        human_count(tout),
        human_count(terr),
        err_pct
    );
    f.render_widget(
        Block::default().borders(Borders::ALL).title(title),
        area,
    );
    let col = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .horizontal_margin(1)
        .split(area);
    let label_row = area.y + area.height - 2;
    for (i, (data, name, color)) in [
        (&in_data, "in (received)", Color::Cyan),
        (&out_data, "out (queued/deliv.)", Color::Green),
        (&err_data, "err/junk share", Color::Red),
    ]
    .into_iter()
    .enumerate()
    {
        f.render_widget(
            Sparkline::default().data(data).style(Style::default().fg(color)),
            Rect {
                y: area.y + 1,
                height: area.height.saturating_sub(3),
                ..col[i]
            },
        );
        f.render_widget(
            Paragraph::new(Span::styled(name, Style::default().fg(color)))
                .alignment(ratatui::layout::Alignment::Center),
            Rect { y: label_row, height: 1, ..col[i] },
        );
    }
}

fn draw_levels(f: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Ratio(1, 5); 5])
        .margin(1)
        .split(area);

    for (i, level) in [Level::Error, Level::Warn, Level::Info, Level::Debug, Level::Trace]
        .into_iter()
        .enumerate()
    {
        let count = app.stats.level_count(level);
        let ratio = if app.stats.total > 0 {
            (count as f64 / app.stats.total as f64).clamp(0.0, 1.0)
        } else {
            0.0
        };
        let label = format!("{:<8} {:>8}", level, human_count(count));
        let gauge = Gauge::default()
            .block(Block::default())
            .ratio(ratio)
            .gauge_style(Style::default().fg(level_color(level)).bg(Color::Black))
            .label(label);
        f.render_widget(gauge, rows[i]);
    }
}

fn draw_categories(f: &mut Frame, app: &App, area: Rect) {
    let max = Category::ALL
        .iter()
        .map(|c| app.stats.category_count(*c))
        .max()
        .unwrap_or(1)
        .max(1);

    // compact: three columns of five rows so the panel stays slim
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .split(area);

    let make_items = |cats: &[Category], width: u16| -> Vec<ListItem<'static>> {
        let name_w = width.saturating_sub(7).clamp(8, 20) as usize;
        cats.iter()
            .map(|c| {
                let count = app.stats.category_count(*c);
                let mark = if count as f64 / max as f64 > 0.66 {
                    "██"
                } else if count > 0 {
                    "█ "
                } else {
                    "  "
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:<nw$}", truncate(c.as_str(), name_w), nw = name_w),
                        Style::default().fg(Color::Gray),
                    ),
                    Span::styled(mark, Style::default().fg(c.color())),
                    Span::styled(format!("{:>5}", human_count(count)), Style::default().fg(Color::White)),
                ]))
            })
            .collect()
    };
    let cats = Category::ALL;
    let parts = |col: usize| -> Vec<ListItem> {
        let start = col * cats.len().div_ceil(3);
        let end = ((col + 1) * cats.len().div_ceil(3)).min(cats.len());
        make_items(&cats[start..end], cols[col].width.saturating_sub(2))
    };

    f.render_widget(
        List::new(parts(0)).block(Block::default().borders(Borders::LEFT | Borders::TOP | Borders::BOTTOM).title(" Event categories ")),
        cols[0],
    );
    f.render_widget(
        List::new(parts(1)).block(Block::default().borders(Borders::TOP | Borders::BOTTOM)),
        cols[1],
    );
    f.render_widget(
        List::new(parts(2)).block(Block::default().borders(Borders::RIGHT | Borders::TOP | Borders::BOTTOM)),
        cols[2],
    );
}

/// Table of mail flows sender -> recipient (from Queued/Delivered events),
/// optionally restricted by the domain filter (key `d`).
fn draw_mail_pairs(f: &mut Frame, app: &App, area: Rect) {
    let rows = app.mail_pairs(200);
    let inner_w = area.width.saturating_sub(6).max(20) as usize;
    let addr_w = (inner_w.saturating_sub(34) / 2).clamp(16, 44);

    let mut items: Vec<ListItem> = Vec::new();
    if rows.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "  no mail flow events (Queued/Delivered) match the filter",
            Style::default().fg(Color::DarkGray),
        ))));
    } else {
        let max = rows.first().map(|p| p.count).unwrap_or(1).max(1);
        let time_w = 16usize;
        let bar_max = inner_w
            .saturating_sub(addr_w * 2 + 12 + time_w + 2)
            .clamp(0, 20);
        for p in &rows {
            let bar_len = ((p.count as f64 / max as f64) * bar_max as f64) as usize;
            let bar = if bar_max > 0 { "█".repeat(bar_len.max(1)) } else { String::new() };
            let seen = chrono::DateTime::from_timestamp(p.last_seen * 60, 0)
                .map(|t| format_time(app, t))
                .unwrap_or_default();
            items.push(ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<6}", p.dir.as_str()), Style::default().fg(p.dir.color())),
                Span::styled(format!("{:<aw$}", truncate(&p.from, addr_w), aw = addr_w), Style::default().fg(Color::Gray)),
                Span::styled("→ ", Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:<aw$}", truncate(&p.to, addr_w), aw = addr_w), Style::default().fg(Color::Gray)),
                Span::styled(format!("{:>5} ", human_count(p.count)), Style::default().fg(Color::White)),
                Span::styled(format!("{:<tw$} ", truncate(&seen, time_w), tw = time_w), Style::default().fg(Color::DarkGray)),
                Span::styled(bar, Style::default().fg(p.dir.color())),
            ])));
        }
    }

    let filter = if app.domain_filter_active() {
        let doms = &app.settings.domains;
        format!(" [filter: {}{}]", doms[0], if doms.len() > 1 { format!(" +{}", doms.len() - 1) } else { String::new() })
    } else {
        " [all domains, newest first]".to_string()
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(Span::styled(" Mail in/out (sender → recipient) ", Style::default().fg(Color::Gray)))
            .title(Span::styled(
                format!("{:>width$}", filter, width = (area.width as usize).saturating_sub(38)),
                Style::default().fg(Color::DarkGray),
            )),
    );
    f.render_widget(list, area);
}

fn draw_top_ips(f: &mut Frame, app: &App, area: Rect, interactive: bool) {
    let now = Utc::now();
    let entries = app.panel_entries(0);
    let display: Vec<(String, u64)> = entries
        .into_iter()
        .map(|(ip_str, count)| {
            let shown = match ip_str.parse::<std::net::IpAddr>() {
                Ok(ip) if app.settings.show_hostnames => {
                    app.dns.get(ip, now).map(String::from).unwrap_or(ip_str)
                }
                _ => ip_str,
            };
            (shown, count)
        })
        .collect();
    let max_w = area.width.saturating_sub(16).max(8) as usize;
    let sel = if interactive && app.sel_panel == 0 { Some(app.sel_row) } else { None };
    let items: Vec<ListItem> = with_bars(&display, max_w, Color::Cyan, sel);
    let title = format!(
        " Top client IPs [1] {} ",
        if app.settings.show_hostnames {
            format!("(resolving... {} pending)", app.dns.pending_count())
        } else {
            "(remoteIp)".to_string()
        }
    );
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(list, area);
}

fn draw_top_addresses(f: &mut Frame, app: &App, area: Rect, interactive: bool) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let senders = app.panel_entries(1);
    let recipients = app.panel_entries(2);
    let w = cols[0].width.saturating_sub(16).max(8) as usize;
    let sel_s = if interactive && app.sel_panel == 1 { Some(app.sel_row) } else { None };
    let sel_r = if interactive && app.sel_panel == 2 { Some(app.sel_row) } else { None };

    let list = List::new(with_bars(&senders, w, Color::Green, sel_s))
        .block(Block::default().borders(Borders::ALL).title(" Top senders (from) [2] "));
    f.render_widget(list, cols[0]);
    let list = List::new(with_bars(&recipients, w, Color::Magenta, sel_r))
        .block(Block::default().borders(Borders::ALL).title(" Top recipients (to) [3] "));
    f.render_widget(list, cols[1]);
}

fn with_bars(
    entries: &[(String, u64)],
    width: usize,
    color: Color,
    selected: Option<usize>,
) -> Vec<ListItem<'static>> {
    let max_count = entries.first().map(|(_, c)| *c).unwrap_or(1).max(1);
    let bar_max = width.saturating_sub(30).clamp(3, 24).max(3);

    entries
        .iter()
        .enumerate()
        .map(|(i, (k, v))| {
            let bar_len = ((*v as f64 / max_count as f64) * bar_max as f64) as usize;
            let bar = "█".repeat(bar_len.max(1));
            let mut style = Style::default();
            if Some(i) == selected {
                style = style.fg(Color::Black).bg(color).add_modifier(Modifier::BOLD);
            } else {
                style = style.fg(color);
            }
            let mark = if Some(i) == selected { "> " } else { "  " };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{mark}{:<27} ", truncate(k, 27)), style),
                Span::styled(bar, style),
                Span::styled(format!("{:>6}", human_count(*v)), style),
            ]))
        })
        .collect()
}

fn draw_problems(f: &mut Frame, app: &App, area: Rect) {
    let items: Vec<ListItem> = app
        .stats
        .recent_problems
        .iter()
        .rev()
        .map(|line| {
            let r = crate::parser::parse_line(line);
            let ts = r
                .ts
                .map(|t| format_time(app, t))
                .unwrap_or_else(|| "-".to_string());
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<7}", ts), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{:<6}", r.level), Style::default().fg(level_color(r.level))),
                Span::styled(
                    format!("{:<26} ", truncate(r.event.as_deref().unwrap_or("-"), 26)),
                    Style::default().fg(Color::Gray),
                ),
                Span::styled(
                    truncate(&r.message, area.width.saturating_sub(46) as usize),
                    Style::default(),
                ),
            ]))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" Recent problems ({} warn/error) ", app.stats.recent_problems.len())),
    );
    f.render_widget(list, area);
}

/// Full-screen drill-down for one entity (client IP, sender or recipient):
/// totals, abuse indicators, timeline chart and peer lists.
fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some((kind, key)) = app.detail.as_ref() else { return };
    let Some(detail) = app.stats.detail(*kind, key) else { return };

    let label = app.entity_label(*kind, key);
    let (title, kind_word) = match detail.kind {
        EntityKind::Ip => (format!(" Client: {label} "), "client"),
        EntityKind::Sender => (format!(" Sender: {label} "), "sender"),
        EntityKind::Recipient => (format!(" Recipient: {label} "), "recipient"),
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // summary + risk
            Constraint::Min(6),    // timeline charts
            Constraint::Length(10), // peer lists
        ])
        .split(area);
    let block = Block::default().borders(Borders::ALL).title(title);
    f.render_widget(block, area);

    // --- summary + risk indicators ---
    let cat = |c: Category| detail.counts[crate::stats::EntityDetail::cat_index(c)];
    let tin = cat(Category::Received);
    let tout = cat(Category::Queued) + cat(Category::Delivered);
    let terr = cat(Category::Failed) + cat(Category::Spam) + cat(Category::Blocked) + cat(Category::Throttled);
    let tblk = cat(Category::Spam) + cat(Category::Blocked) + cat(Category::Policy) + cat(Category::Throttled);
    let tauth = cat(Category::AuthFail);
    let tpol = cat(Category::Policy);

    let (first, last) = app.stats.minute_span();
    let (fan_min, fan_hr) = match detail.kind {
        EntityKind::Sender | EntityKind::Ip => (
            detail.fanout.peak_per_unit(first, last + 1, 1),
            detail.fanout.peak_per_unit(first, last + 1, 60),
        ),
        _ => (None, None),
    };
    let events = tin + tout + terr + tpol;
    let junk_pct = if events > 0 { tblk as f64 / events as f64 * 100.0 } else { 0.0 };

    let mut lines = vec![
        Line::from(vec![
            Span::raw(" events: "),
            Span::styled(human_count(detail.counts.iter().sum()), Style::default().fg(Color::White)),
            Span::raw("   in: "),
            Span::styled(human_count(tin), Style::default().fg(Color::Cyan)),
            Span::raw("   out: "),
            Span::styled(human_count(tout), Style::default().fg(Color::Green)),
            Span::raw("   errors: "),
            Span::styled(human_count(terr), Style::default().fg(Color::Red)),
            Span::raw("   junk/policy: "),
            Span::styled(format!("{} ({:.0}%)", human_count(tblk), junk_pct), Style::default().fg(Color::Red)),
        ]),
    ];
    // abuse indicators
    if fan_min.is_some() || fan_hr.is_some() {
        let fm = fan_min.map(|(m, v)| format_peak(m, v, app)).unwrap_or_else(|| "-".to_string());
        let fh = fan_hr.map(|(m, v)| format_peak(m, v, app)).unwrap_or_else(|| "-".to_string());
        let hot = fan_hr.map(|(_, v)| v).unwrap_or(0);
        let style = if hot > 50 {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else if hot > 20 {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        lines.push(Line::from(vec![
            Span::raw(" fan-out: "),
            Span::styled(
                format!(
                    "peak {} recipients/min, peak {} recipients/h  <- distinct recipients; high values suggest spam/mass mailing",
                    fm, fh
                ),
                style,
            ),
        ]));
    }
    if tauth > 0 {
        lines.push(Line::from(vec![
            Span::raw(" auth failures from this "),
            Span::raw(if detail.kind == EntityKind::Ip { "IP: " } else { "entity: " }),
            Span::styled(human_count(tauth), Style::default().fg(if tauth > 50 { Color::Red } else { Color::Yellow })),
            Span::styled("  <- possible password spraying / brute force", Style::default().fg(Color::DarkGray)),
        ]));
    }
    // abuse signals for client IPs
    if detail.kind == EntityKind::Ip
        && let Some(susp) = app.stats.suspect_for(key)
    {
        let mut spans = vec![
            Span::raw(" signals: "),
            Span::styled(format!("score {}", susp.score), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(format!(" ({})", susp.verdicts.join(", ")), Style::default().fg(if susp.score >= 5 { Color::Red } else { Color::Yellow })),
        ];
        if let Some(m) = susp.compromised_at {
            let when = chrono::DateTime::from_timestamp(m * 60, 0)
                .map(|t| format_time(app, t))
                .unwrap_or_default();
            spans.push(Span::styled(format!("  COMPROMISED: outbound mail after failed logins at {when}"), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)));
        }
        lines.push(Line::from(spans));
    }
    f.render_widget(
        Paragraph::new(ratatui::text::Text::from(lines)),
        Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width.saturating_sub(2),
            height: rows[0].height - 2,
        },
    );

    // --- timeline ---
    let nbars = area.width.saturating_sub(4).max(10) as usize;
    let (wlabel, bars) = app.detail_window(&detail.hist, nbars);
    let scale = |field: fn(&MinutePoint) -> u32| -> Vec<u64> {
        let max = bars.iter().map(field).max().unwrap_or(0).max(1) as u64;
        bars.iter().map(|b| (field(b) as f64 / max as f64 * 8.0) as u64).collect()
    };
    let tl_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .horizontal_margin(1)
        .split(rows[1]);
    f.render_widget(
        Block::default()
            .borders(Borders::TOP)
            .title(Span::styled(
                format!(" timeline last {wlabel} (t changes window) "),
                Style::default().fg(Color::DarkGray),
            )),
        rows[1],
    );
    for (i, (field, name, color)) in [
        ((|b: &MinutePoint| b.inn) as fn(&MinutePoint) -> u32, "in (received)", Color::Cyan),
        ((|b: &MinutePoint| b.out) as fn(&MinutePoint) -> u32, "out (queued/deliv.)", Color::Green),
        ((|b: &MinutePoint| b.err) as fn(&MinutePoint) -> u32, "err/junk", Color::Red),
    ]
    .into_iter()
    .enumerate()
    {
        let data = scale(field);
        let cell = Rect {
            y: rows[1].y + 1,
            height: rows[1].height.saturating_sub(2),
            ..tl_layout[i]
        };
        f.render_widget(
            Sparkline::default().data(&data).style(Style::default().fg(color)),
            cell,
        );
        f.render_widget(
            Paragraph::new(Span::styled(name, Style::default().fg(color)))
                .alignment(ratatui::layout::Alignment::Center),
            Rect { y: rows[1].y + rows[1].height - 1, height: 1, ..tl_layout[i] },
        );
    }

    // --- peers ---
    let peers = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(rows[2]);
    let (from_title, from_map, to_title, to_map) = match detail.kind {
        EntityKind::Ip => (
            " senders seen on this client ",
            &detail.peers_from,
            " recipients ",
            &detail.peers_to,
        ),
        EntityKind::Sender => (
            " source IPs ",
            &detail.peers_from,
            " recipients ",
            &detail.peers_to,
        ),
        EntityKind::Recipient => (
            " senders ",
            &detail.peers_from,
            " source IPs ",
            &detail.peers_to,
        ),
    };
    let strip = |(k, v): (String, u64)| -> (String, u64) {
        (k.strip_prefix("ip:").unwrap_or(&k).to_string(), v)
    };
    let w = peers[0].width.saturating_sub(14).max(8) as usize;
    let from_entries: Vec<(String, u64)> =
        crate::stats::Stats::top_n_ext(from_map, 8).into_iter().map(strip).collect();
    let to_entries: Vec<(String, u64)> =
        crate::stats::Stats::top_n_ext(to_map, 8).into_iter().map(strip).collect();
    f.render_widget(
        List::new(with_bars(&from_entries, w, Color::Green, None))
            .block(Block::default().borders(Borders::ALL).title(from_title)),
        peers[0],
    );
    f.render_widget(
        List::new(with_bars(&to_entries, w, Color::Magenta, None))
            .block(Block::default().borders(Borders::ALL).title(to_title)),
        peers[1],
    );

    let help = Line::from(Span::styled(
        format!(" {kind_word} view - esc/enter back, t window, q quit  "),
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(
        Paragraph::new(help),
        Rect {
            y: area.y + area.height.saturating_sub(1),
            height: 1,
            ..area
        },
    );
}

fn format_peak(minute: i64, count: u32, app: &App) -> String {
    let ts = chrono::DateTime::<Utc>::from_timestamp(minute * 60, 0)
        .map(|t| format_time(app, t))
        .unwrap_or_default();
    format!("{count} @ {ts}")
}
/// Patterns containing an explicit styling suffix `Z` are rendered in UTC,
/// everything else in local time.
fn format_time(app: &App, ts: DateTime<Utc>) -> String {
    let fmt = &app.settings.time_format;
    if fmt.ends_with('Z') {
        ts.format(fmt).to_string()
    } else {
        ts.with_timezone(&chrono::Local).format(fmt).to_string()
    }
}

fn draw_abuse(f: &mut Frame, app: &App, area: Rect) {
    let report = app.stats.abuse_report();
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(6),    // suspects
            Constraint::Length(9), // spray targets
        ])
        .split(area);
    let inner_w = layout[0].width.saturating_sub(2) as usize;

    let mut items: Vec<ListItem> = Vec::new();
    items.push(ListItem::new(Line::from(Span::styled(
        format!(
            "  {:>3}  {:>4} {:>6} {:>3}  {:<26}{:<5}",
            "sc", "fail", "ok", "usr", "signals / top failure reason", ""
        ),
        Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD),
    ))));
    if report.suspects.is_empty() {
        items.push(ListItem::new(Line::from(Span::styled(
            "  no suspicious activity detected",
            Style::default().fg(Color::Green),
        ))));
    }
    for (i, s) in report.suspects.iter().enumerate() {
        let selected = i == app.abuse_row;
        let base = if selected {
            Style::default().fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let score_style = if selected {
            base
        } else if s.score >= 5 || s.compromised_at.is_some() {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Yellow)
        };
        let head = format!(
            "{} {:>3}  {:>4} {:>6} {:>3}  ",
            if selected { ">" } else { " " },
            s.score,
            s.attempts,
            s.ok,
            s.users,
        );
        let mut spans = vec![
            Span::styled(head, base),
            Span::styled(truncate(&s.name, 24), base),
            Span::raw("  "),
            Span::styled(format!("{:<40}", truncate(&s.verdicts.join(", "), 40)), score_style),
        ];
        if let Some(r) = &s.top_reason {
            spans.push(Span::styled(
                format!(" {}", truncate(r, inner_w.saturating_sub(100).clamp(12, 50))),
                base,
            ));
        }
        items.push(ListItem::new(Line::from(spans)));
    }
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Abuse & security signals (a / Esc closes, Enter = drill down) "),
    );
    f.render_widget(list, layout[0]);

    let mut acc_items: Vec<ListItem> = Vec::new();
    if report.accounts.is_empty() {
        acc_items.push(ListItem::new(Line::from(Span::styled(
            "  no account targeted from many IPs",
            Style::default().fg(Color::DarkGray),
        ))));
    }
    for a in &report.accounts {
        acc_items.push(ListItem::new(Line::from(vec![
            Span::styled(format!(" {:<40} ", truncate(&a.name, 40)), Style::default().fg(Color::Red)),
            Span::styled(
                format!("attacked from {} client IPs", a.ips),
                Style::default().fg(Color::Yellow),
            ),
        ])));
    }
    let list = List::new(acc_items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Account spray (one account, many source IPs) "),
    );
    f.render_widget(list, layout[1]);
}

fn draw_settings(f: &mut Frame, app: &App, area: Rect) {
    let rows = [
        ("Show hostnames instead of IPs", if app.settings.show_hostnames { "on" } else { "off" }.to_string()),
        ("Hide maintenance noise in throughput", if app.settings.hide_noise { "on" } else { "off" }.to_string()),
        ("Time/date format", app.settings.time_format_display()),
        ("Hostname cache duration", format!("{} h", app.settings.dns_cache_hours)),
    ];

    let width = 62u16.min(area.width.saturating_sub(4)).max(20);
    let height = (rows.len() as u16 + 4).min(area.height);
    let popup = centered_rect(area, width, height);

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, (label, value))| {
            let selected = i == app.settings_row;
            let style = if selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {}  ", if selected { ">" } else { " " }), style),
                Span::styled(format!("{:<38}", label), style),
                Span::styled(format!("{:>18} ", value), style),
            ]))
        })
        .collect();

    let help = Line::from(Span::styled(
        " up/down select, left/right or enter change, q quit, s/Esc close  ",
        Style::default().fg(Color::DarkGray),
    ));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Settings ")
        .style(Style::default().bg(Color::Black));
    let list = List::new(items).block(block);
    f.render_widget(ratatui::widgets::Clear, popup);
    f.render_widget(list.clone(), popup);

    let help_area = Rect {
        x: popup.x,
        y: popup.y + popup.height - 1,
        width: popup.width,
        height: 1,
    };
    f.render_widget(Paragraph::new(help), help_area);
}

fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect::new(x, y, width, height)
}fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let chip = Style::default().fg(Color::Black).bg(Color::Cyan);
    let mut spans = vec![
        Span::styled(" q ", chip),
        Span::raw(" quit   "),
        Span::styled(" space ", chip),
        Span::raw(" pause   "),
        Span::styled(" c ", chip),
        Span::raw(" clear   "),
        Span::styled(" r ", chip),
        Span::raw(" repoll   "),
        Span::styled(" s ", chip),
        Span::raw(" settings   "),
        Span::styled(" a ", chip),
        Span::raw(" abuse   "),
        Span::styled(" d ", chip),
        Span::raw(" domains   "),
    ];
    (!app.abuse_open() && app.detail.is_none())
        .then(|| {
            spans.extend([
                Span::styled(" tab/1-3 ", chip),
                Span::raw(" panel   "),
                Span::styled(" j/k ", chip),
                Span::raw(" select   "),
                Span::styled(" enter ", chip),
                Span::raw(" detail   "),
            ]);
        });
    spans.extend([
        Span::styled(" t ", chip),
        Span::raw(" window   "),
        Span::styled(format!(" {} ", app.status), Style::default().fg(Color::DarkGray)),
    ]);
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max > 3 {
        let keep = max - 3;
        let mut out: String = s.chars().take(keep).collect();
        out.push_str("...");
        out
    } else {
        s.chars().take(max).collect()
    }
}
