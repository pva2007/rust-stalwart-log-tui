# stalwart-log

A terminal UI (Rust + ratatui) that analyzes **Stalwart mailserver** logs from a
folder of log files and shows live stats as new data arrives.

## Run

```sh
cargo run --release            # reads ./logs by default
cargo run --release /var/opt/stalwart-mail/logs
cargo run --release sample     # try with the bundled sample
```

Options:

| Flag | Meaning |
| --- | --- |
| `FOLDER` (positional) | Folder containing the log files (default `./logs`) |
| `-p, --pattern` | Only follow files whose name contains this substring |
| `-i, --poll-ms` | Folder polling interval in ms (default 500) |

Keys: `q`/`Esc` quit, `space` pause/resume, `c` clear stats, `r` force re-poll.

## What it shows

- **Header**: total events, events/s, data volume, last event time, live/paused state
- **Throughput**: events-per-second sparkline (last 180 s)
- **Levels**: ERROR / WARN / INFO / DEBUG / TRACE gauges
- **Event categories**: sessions, auth success/failures, received, queued,
  delivered, bounces, spam, blocked/banned, throttled, policy (SPF/DKIM/DMARC),
  TLS, maintenance noise
- **Top IPs / senders / recipients**: from structured `remoteIp`, `from`, `to` fields
- **Recent problems**: latest WARN/ERROR raw lines

## Log format

The parser is built around the current Stalwart tracing format (verified
against real server logs in `sample/`):

```
2026-11-19T00:01:52Z INFO Queued message for delivery (queue.message-queued) listenerId = "smtp", localPort = 25, remoteIp = 167.89.48.242, remotePort = 15422, queueId = 341344700644505600, from = "bounces+...@em7433.profi-pozicka.sk", to = ["hotel@mager.sk"], size = 49391, ...
```

That is `<RFC3339 timestamp> <LEVEL> <human message> (<event.name>) <key = value pairs>`.
The event name drives classification; `key = value` pairs are parsed (quote-
and bracket-aware) and used for stats: `remoteIp` → Top client IPs, `from` →
Top senders, `to` → Top recipients, `size` → data volume. Older shapes are
also handled: spaced timestamps, optional `[session-id]`, bare epoch seconds.
Lines with no recognizable event are classified by message text and kept as
"Other"/fallback instead of being dropped.

Maintenance chatter (`task-manager.*`, `telemetry.*`, `store.*` purges,
`server.*`/`network.*`, spam training) is grouped into a **Maintenance noise**
category so it does not drown the mail statistics.

## Charts and drill-down

- **Mail flow panel** (main screen): three sparklines — received (in),
  queued+delivered (out) and the error/junk share per time bar. Press `t` to
  cycle the window: 5m → 1h → 6h → 24h → all.
- **Selection**: `Tab` or `1`/`2`/`3` picks a Top panel, `j`/`k` move the
  selection, `Enter` opens the drill-down for that entry (darkened/reverse-
  highlighted row).
- **Drill-down view** per client IP / sender / recipient shows:
  - totals: events, in, out, errors, junk/policy share;
  - abuse indicators: fan-out (approx. distinct recipients per minute and per
    hour — high values suggest a compromised account mass-mailing spam),
    auth-failure count (possible brute force / password spraying);
  - timeline sparklines (in / out / err, `t` cycles the window);
  - peer lists: for a client IP the senders and recipients seen on it, for a
    sender its source IPs and recipients, for a recipient its senders and
    source IPs. `Esc`/`Enter` goes back.

Under the hood each entity keeps its own per-minute flow history (coalesced)
plus peer counters, so drill-downs reflect the whole loaded history and stay
live as new events arrive.

## Mail in/out and the domain filter

The **Event categories** panel is followed by a **Mail in/out (sender →
recipient)** table: the top mail flows with their direction relative to the
domains hosted on the server — `in` (delivery to a hosted mailbox), `out`
(sent from a hosted domain to the outside), `local` (hosted → hosted).
Pairs are aggregated from Queued/Delivered events and ordered by their
most recent activity, newest first (total volume is shown as a column
and breaks ties).

Both Top panels and the mail in/out table count **messages, not log lines**:
one physical mail (identified by its unique `queueId`) passes through TCP →
RCPT → queued → stored/delivered and is counted exactly once.

Hosted domains are detected from the logs themselves: every message stored
into a local mailbox (`message-ingest.*` events) contributes its recipient
domain. Press `d` to open the hosted-domain filter — tick one or many
domains (or leave everything unticked for all), and the mail in/out table
restricts itself to flows touching the selection. The filter persists in
`stalwart-log.toml` as `domains = [...]` (empty list = all).

## Abuse & security signals

Press `a` to open the abuse screen. It scores client IPs from their auth
behaviour and marks them with signals: `junk/blocked` (blocked or junk events),
`brute force` (one IP, many usernames), `account spray` (one account attacked
from many IPs), `compromised` (auth failures followed by a success and
outbound mail from the same IP), `new + active` and
`protocol probe (single reason)` (many failures, no usernames, always the
same error — typically probing a login protocol rather than guessing
passwords; informative only, does not raise the score).

- **failure trend**: when the newest day with failures passes a threshold
  (10+), a highlighted line shows that day's fail count, how many source IPs
  saw their first-ever failure on it and the previous daily peak — a sudden
  jump from a quiet baseline to many failures from fresh IPs is the fingerprint
  of a starting distributed scan.
- **`Enter`** drills down into a suspect (same view as a selected client IP).
- **`e`** exports the current suspect list to `suspects-<timestamp>.txt` in
  the working directory (tab-separated: ip, score, attempts, ok, users,
  verdicts, top reason).

## Settings

Press `s` to open the settings overlay. Navigate with `j`/`k` (or arrow keys),
change with Enter/Space or the arrow keys, close with `s` or `Esc`; changes
are saved immediately.

| Setting | What it does |
| --- | --- |
| Show hostnames | Reverse-DNS lookups of client IPs; the Top IPs panel shows hostnames instead of addresses. Queries run on a background worker for the top 30 IPs only and are cached (default 24 h). |
| Hide noise | Exclude maintenance chatter from the throughput sparkline. |
| Time format | Cycles through five timestamp formats (chrono strftime patterns; patterns ending in `Z` render UTC, others local time). |
| DNS cache | Reverse-DNS cache lifetime in hours (1–720). |

Settings persist to `stalwart-log.toml` in the working directory — or the path
given with `--config`:

```toml
show_hostnames = false
hide_noise = false
time_format = "%H:%M:%S"
dns_cache_hours = 24
domains = []
```

## Sample data

`sample/` contains real log files from a running Stalwart server
(`stalwart.2026-11-14` … `stalwart.2026-11-19`, ~15k events/day-scale mix).
An integration test (`stats::tests::parses_entire_real_sample_folder`,
skipped when `sample/` is absent) cross-checks parsing counts against those
files.

## Layout

```
src/
  main.rs      entry point, terminal setup/teardown, key handling
  cli.rs       clap CLI definition
  parser.rs    line -> LogRecord (timestamp, level, session, facility, category)
  stats.rs     live aggregation: level/category totals, 1s buckets, top lists
  watcher.rs   folder poller: append tailing, new files, rotation handling
  app.rs       shared state wired parser/watcher/stats
  ui.rs        ratatui drawing
sample/        example log to try immediately
```

Tests: `cargo test`
