use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// User-tunable settings, persisted to a TOML file and editable from the
/// in-app settings overlay (`s`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    /// Reverse-resolve client IPs and show hostnames instead of IPs where
    /// a PTR record exists.
    pub show_hostnames: bool,
    /// Exclude maintenance-noise events (task scheduler, metrics, purges)
    /// from the throughput chart and events/s number.
    pub hide_noise: bool,
    /// chrono strftime pattern used for timestamps in the header and the
    /// problems panel. One of [`Settings::TIME_FORMATS`].
    pub time_format: String,
    /// How long a resolved (or failed) hostname is trusted, in hours.
    pub dns_cache_hours: u64,
    /// Hosted domains selected in the domain filter (`d`). Empty list =
    /// no restriction (all domains).
    #[serde(default)]
    pub domains: Vec<String>,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            show_hostnames: false,
            hide_noise: true,
            time_format: Settings::TIME_FORMATS[0].to_string(),
            dns_cache_hours: 24,
            domains: Vec::new(),
        }
    }
}

impl Settings {
    /// Preset strftime patterns cycled through in the overlay.
    pub const TIME_FORMATS: [&'static str; 5] = [
        "%Y-%m-%d %H:%M:%S",
        "%H:%M:%S",
        "%d.%m.%Y %H:%M",
        "%Y-%m-%dT%H:%M:%SZ",
        "%a %d %b %H:%M",
    ];

    pub fn load(path: &Path) -> Result<Settings> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading settings {}", path.display()))?;
        let s = toml::from_str(&text)
            .with_context(|| format!("parsing settings {}", path.display()))?;
        Ok(s)
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self).context("serializing settings")?;
        std::fs::write(path, text)
            .with_context(|| format!("writing settings {}", path.display()))?;
        Ok(())
    }

    /// Load from `path` if it exists, otherwise return defaults (and try to
    /// write the file once so users discover where settings live).
    pub fn load_or_create(path: &Path) -> Settings {
        match Settings::load(path) {
            Ok(s) => s,
            Err(_) => {
                let s = Settings::default();
                let _ = s.save(path);
                s
            }
        }
    }

    pub fn cycle_time_format(&mut self, back: bool) {
        let idx = Self::TIME_FORMATS
            .iter()
            .position(|f| *f == self.time_format)
            .unwrap_or(0);
        let len = Self::TIME_FORMATS.len();
        let new_idx = if back {
            (idx + len - 1) % len
        } else {
            (idx + 1) % len
        };
        self.time_format = Self::TIME_FORMATS[new_idx].to_string();
    }

    /// Human-readable description of the current format for the overlay.
    pub fn time_format_display(&self) -> String {
        self.time_format.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_preserves_values() {
        let tmp = TempDir::new().unwrap();
        let path = PathBuf::from(tmp.path()).join("settings.toml");
        let s = Settings {
            show_hostnames: true,
            hide_noise: false,
            time_format: "%H:%M:%S".into(),
            dns_cache_hours: 6,
            domains: vec!["example.com".into()],
        };
        s.save(&path).unwrap();
        let loaded = Settings::load(&path).unwrap();
        assert_eq!(loaded, s);
    }

    #[test]
    fn load_or_create_writes_defaults() {
        let tmp = TempDir::new().unwrap();
        let path = PathBuf::from(tmp.path()).join("sub").join("settings.toml");
        // parent dir missing -> load fails silently, defaults returned
        let s = Settings::load_or_create(&path);
        assert_eq!(s, Settings::default());
    }

    #[test]
    fn time_format_cycles() {
        let mut s = Settings::default();
        let first = s.time_format.clone();
        s.cycle_time_format(false);
        assert_ne!(s.time_format, first);
        s.cycle_time_format(true);
        assert_eq!(s.time_format, first);
    }
}
