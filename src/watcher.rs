use crate::parser::LogRecord;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Watches a folder of log files by polling: reads appended data from known
/// files, picks up newly created files, and handles truncation/rotation
/// (offset resets when a file shrinks). No external watch dependency needed.
#[derive(Debug)]
pub struct FolderWatcher {
    dir: PathBuf,
    /// Optional substring a file name must contain to be followed.
    pattern: Option<String>,
    offsets: HashMap<PathBuf, u64>,
    /// Incomplete trailing bytes per file (last line without newline yet).
    partial: HashMap<PathBuf, String>,
}

#[derive(Debug, Default)]
pub struct PollResult {
    pub records: Vec<LogRecord>,
    pub files_seen: usize,
}

impl FolderWatcher {
    pub fn new(dir: impl Into<PathBuf>, pattern: Option<String>) -> Result<FolderWatcher> {
        let dir = dir.into();
        if !dir.is_dir() {
            anyhow::bail!("log folder does not exist or is not a directory: {}", dir.display());
        }
        Ok(FolderWatcher {
            dir,
            pattern,
            offsets: HashMap::new(),
            partial: HashMap::new(),
        })
    }

    /// Read one full snapshot (used at startup so the TUI immediately
    /// reflects the log history already present in the folder).
    pub fn poll(&mut self) -> Result<PollResult> {
        let mut result = PollResult::default();
        let entries = fs::read_dir(&self.dir)
            .with_context(|| format!("reading folder {}", self.dir.display()))?;

        let mut seen: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with('.') {
                    continue;
                }
                if let Some(pattern) = &self.pattern
                    && !name.contains(pattern.as_str()) {
                        continue;
                    }
            }
            seen.push(path.clone());
        }
        result.files_seen = seen.len();

        // Drop tracking for files that disappeared.
        self.offsets.retain(|p, _| seen.contains(p));
        self.partial.retain(|p, _| seen.contains(p));

        seen.sort();
        for path in seen {
            match self.read_appends(&path) {
                Ok(records) => result.records.extend(records),
                Err(e) => {
                    // never fail the whole poll because one file vanished
                    eprintln!("watcher: skipping {}: {e}", path.display());
                }
            }
        }
        Ok(result)
    }

    fn read_appends(&mut self, path: &Path) -> Result<Vec<LogRecord>> {
        let mut records = Vec::new();

        let size = fs::metadata(path)?.len();
        let offset = *self.offsets.get(path).unwrap_or(&0);

        // File was rotated/truncated: start from the beginning again.
        let (mut file, offset) = if size < offset {
            (fs::File::open(path)?, 0)
        } else {
            let mut f = fs::File::open(path)?;
            f.seek(SeekFrom::Start(offset))?;
            (f, offset)
        };

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        let new_offset = offset + buf.len() as u64;
        self.offsets.insert(path.to_path_buf(), new_offset);

        let carry = self.partial.remove(path).unwrap_or_default();
        let mut data = carry.into_bytes();
        data.extend_from_slice(&buf);

        // Split into fully terminated lines and the trailing unterminated
        // chunk (kept for the next poll).
        let (complete, remainder) = match data.iter().rposition(|&b| b == b'\n') {
            Some(i) => {
                let rem = data.split_off(i + 1);
                (data, rem)
            }
            None => (Vec::new(), data),
        };
        if !remainder.is_empty() {
            self.partial.insert(
                path.to_path_buf(),
                String::from_utf8_lossy(&remainder).into_owned(),
            );
        }

        for line in complete.split(|&b| b == b'\n') {
            let line = String::from_utf8_lossy(line);
            let line = line.trim_end_matches('\r');
            if line.is_empty() {
                continue;
            }
            records.push(crate::parser::parse_line(line));
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tails_and_detects_rotation() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().to_path_buf();
        let file = dir.join("stalwart.log");
        fs::write(&file, "2025-11-19 10:00:00 INFO [1] smtp.session connection from [1.2.3.4]:1\n")?;

        let mut w = FolderWatcher::new(&dir, None)?;
        let r = w.poll()?;
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.files_seen, 1);

        // no new data -> nothing
        let r = w.poll()?;
        assert_eq!(r.records.len(), 0);

        // append
        fs::write(&file, "2025-11-19 10:00:00 INFO [1] smtp.session connection from [1.2.3.4]:1\n2025-11-19 10:00:01 INFO [1] queue.message Message delivered to a@b.c\n")?;
        let r = w.poll()?;
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.records[0].category, crate::parser::Category::Delivered);

        // rotation (shrink)
        fs::write(&file, "short\n")?;
        let r = w.poll()?;
        assert_eq!(r.records.len(), 1);
        assert_eq!(r.records[0].message, "short");

        // pattern filter
        let mut w2 = FolderWatcher::new(&dir, Some("missing-file".into()))?;
        let r2 = w2.poll()?;
        assert_eq!(r2.files_seen, 0);

        Ok(())
    }

    #[test]
    fn handles_partial_lines() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let file = tmp.path().join("stalwart.log");
        fs::write(&file, "2025-11-19 10:00:00 INFO [1] smtp.session conn")?;

        let mut w = FolderWatcher::new(tmp.path(), None)?;
        let r = w.poll()?;
        assert_eq!(r.records.len(), 0);

        fs::write(&file, "2025-11-19 10:00:00 INFO [1] smtp.session connection from [1.2.3.4]:1\n")?;
        let r = w.poll()?;
        assert_eq!(r.records.len(), 1);
        assert!(r.records[0].message.contains("connection from"));
        Ok(())
    }

    #[test]
    fn picks_up_new_files() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut w = FolderWatcher::new(tmp.path(), None)?;
        let r = w.poll()?;
        assert_eq!(r.files_seen, 0);

        fs::write(tmp.path().join("stalwart-2025-11-19.log"), "2025-11-19 10:00:00 INFO [1] smtp.session connection from [1.2.3.4]:1\n")?;
        let r = w.poll()?;
        assert_eq!(r.files_seen, 1);
        assert_eq!(r.records.len(), 1);
        Ok(())
    }
}
