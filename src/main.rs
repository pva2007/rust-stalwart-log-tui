mod app;
mod cli;
mod dns;
mod parser;
mod settings;
mod stats;
mod ui;
mod watcher;

mod term {
    use crossterm::event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind,
    };
    use crossterm::execute;
    use crossterm::terminal::{
        EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
    };
    use ratatui::{Terminal, backend::CrosstermBackend};
    use std::io;
    use std::time::{Duration, Instant};

    use crate::app::App;
    use crate::cli::Cli;
    use crate::ui;

    pub type Tui = Terminal<CrosstermBackend<io::Stdout>>;

    pub fn setup() -> std::io::Result<Tui> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        Terminal::new(CrosstermBackend::new(stdout))
    }

    pub fn teardown(terminal: &mut Tui) -> std::io::Result<()> {
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;
        Ok(())
    }

    /// Main UI loop. Returns when the user quits; `App` (and its watcher)
    /// are dropped on scope exit. Errors before the loop starts (e.g. a
    /// missing log folder) are returned so main can tear the terminal down.
    pub fn run(cli: &Cli, terminal: &mut Tui) -> anyhow::Result<()> {
        let settings = crate::settings::Settings::load_or_create(&cli.config);
        let mut app = App::new(
            cli.folder.clone(),
            cli.poll_ms,
            cli.pattern.clone(),
            settings,
            cli.config.clone(),
        )?;
        app.load_initial();

        let poll_interval = Duration::from_millis(app.poll_ms.max(50));
        let mut last_poll = Instant::now();
        let tick = Duration::from_millis(100);

        loop {
            if terminal.draw(|f| ui::draw(f, &app)).is_err() {
                break;
            }
            if app.quit {
                break;
            }

            if handle_events(tick, &mut app) {
                break;
            }
            app.tick_dns();

            if !app.paused && last_poll.elapsed() >= poll_interval {
                app.poll_once("tick");
                last_poll = Instant::now();
            }
        }
        Ok(())
    }

    /// Poll keyboard events for at most `timeout`; returns true to quit.
    fn handle_events(timeout: Duration, app: &mut App) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                return false;
            }
            if event::poll(remaining).unwrap_or(false)
                && let Ok(Event::Key(key)) = event::read()
                    && key.kind == KeyEventKind::Press {
                        return dispatch_key(key.code, app);
                    }
        }
    }

    /// Returns true when the app should quit.
    fn dispatch_key(code: KeyCode, app: &mut App) -> bool {
        if app.settings_open() {
            match code {
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    app.quit = true;
                    return true;
                }
                KeyCode::Esc | KeyCode::Char('s') => app.close_settings(),
                KeyCode::Down | KeyCode::Char('j') => app.settings_down(),
                KeyCode::Up | KeyCode::Char('k') => app.settings_up(),
                KeyCode::Enter | KeyCode::Char(' ') => app.settings_change(1),
                KeyCode::Left => app.settings_change(-1),
                KeyCode::Right => app.settings_change(1),
                _ => {}
            }
            return app.quit;
        }
        if app.domains_open() {
            match code {
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    app.quit = true;
                    return true;
                }
                KeyCode::Esc | KeyCode::Char('d') => app.close_domains(),
                KeyCode::Down | KeyCode::Char('j') => app.domains_move(1),
                KeyCode::Up | KeyCode::Char('k') => app.domains_move(-1),
                KeyCode::Enter | KeyCode::Char(' ') => app.domain_toggle(),
                KeyCode::Char('s') => app.show_settings(),
                _ => {}
            }
            return app.quit;
        }
        if app.abuse_open() {
            match code {
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    app.quit = true;
                    return true;
                }
                KeyCode::Esc | KeyCode::Char('a') => app.close_abuse(),
                KeyCode::Down | KeyCode::Char('j') => app.abuse_move(1),
                KeyCode::Up | KeyCode::Char('k') => app.abuse_move(-1),
                KeyCode::Enter => {
                    app.open_abuse_detail();
                }
                KeyCode::Char('s') => app.show_settings(),
                KeyCode::Char(' ') => app.toggle_pause(),
                _ => {}
            }
            return app.quit;
        }
        if app.detail.is_some() {
            // drill-down view: navigation-free page, Esc/Enter closes
            match code {
                KeyCode::Char('q') | KeyCode::Char('Q') => {
                    app.quit = true;
                    return true;
                }
                KeyCode::Esc | KeyCode::Enter | KeyCode::Backspace => app.close_detail(),
                KeyCode::Char('t') | KeyCode::Left | KeyCode::Right => app.cycle_detail_win(),
                KeyCode::Char('a') => {
                    app.close_detail();
                    app.show_abuse();
                }
                KeyCode::Char('d') => {
                    app.close_detail();
                    app.show_domains();
                }
                KeyCode::Char('s') => app.show_settings(),
                KeyCode::Char(' ') => app.toggle_pause(),
                _ => {}
            }
            return app.quit;
        }
        match code {
            KeyCode::Char('q') | KeyCode::Esc => {
                app.quit = true;
                return true;
            }
            KeyCode::Char(' ') => app.toggle_pause(),
            KeyCode::Char('c') => app.clear_stats(),
            KeyCode::Char('r') => app.poll_once("manual"),
            KeyCode::Char('s') => app.show_settings(),
            KeyCode::Char('a') => app.show_abuse(),
            KeyCode::Char('d') => app.show_domains(),
            KeyCode::Char('t') => app.cycle_flow_win(),
            KeyCode::Tab => app.cycle_panel(),
            KeyCode::Char('1') => app.select_panel(0),
            KeyCode::Char('2') => app.select_panel(1),
            KeyCode::Char('3') => app.select_panel(2),
            KeyCode::Down | KeyCode::Char('j') => app.sel_move(1),
            KeyCode::Up | KeyCode::Char('k') => app.sel_move(-1),
            KeyCode::Enter => {
                app.open_detail();
            }
            _ => {}
        }
        app.quit
    }
}

use anyhow::Result;
use clap::Parser as _;

fn main() -> Result<()> {
    let cli = crate::cli::Cli::parse();
    let mut terminal = term::setup()?;
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            term::run(&cli, &mut terminal)
        }));
    term::teardown(&mut terminal).ok();
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}
