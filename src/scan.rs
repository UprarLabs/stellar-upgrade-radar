//! Directory walking and per-file context construction.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

/// A text file handed to every rule, with a repo-relative path, its raw content,
/// and pre-split lines (1-indexed when enumerated). `abs_path` is the canonical
/// on-disk path (when known) so file-anchored rules can consult sibling files
/// such as a `Cargo.lock`; it is `None` for synthetic in-memory contexts.
pub struct FileCtx {
    pub rel_path: String,
    pub content: String,
    pub lines: Vec<String>,
    pub abs_path: Option<PathBuf>,
}

impl FileCtx {
    /// Build a context from in-memory source; used by unit tests.
    pub fn from_source(rel_path: &str, content: &str) -> Self {
        Self {
            rel_path: rel_path.to_string(),
            content: content.to_string(),
            lines: content.lines().map(|l| l.to_string()).collect(),
            abs_path: None,
        }
    }

    fn from_path(root: &Path, path: &Path) -> Option<Self> {
        let bytes = fs::read(path).ok()?;
        if is_binary(&bytes) {
            return None;
        }
        let content = String::from_utf8(bytes).ok()?;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let abs = path.canonicalize().ok();
        let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        Some(Self {
            rel_path: rel,
            content,
            lines,
            abs_path: abs,
        })
    }
}

/// Recursively collect readable text files under `root`, skipping VCS and build
/// directories. Symlinks are not followed; unreadable entries are skipped.
pub fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(ft) = entry.file_type() else { continue };
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if is_skipped_dir(&name) {
                    continue;
                }
                stack.push(path);
            } else if ft.is_file() {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Build a `FileCtx` for a discovered path, relative to `root`.
pub fn context_for(root: &Path, path: &Path) -> Option<FileCtx> {
    FileCtx::from_path(root, path)
}

fn is_skipped_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".venv" | "venv" | "dist" | "build" | ".hermes"
    )
}

/// A NUL byte in the first 8 KiB marks the file as binary and it is not scanned.
fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

/// Read a file path into a `FileCtx` regardless of the discovery walk; used by
/// the CLI when a single file (not a directory) is passed.
pub fn context_for_single(path: &Path) -> Option<FileCtx> {
    let parent = path.parent().unwrap_or(Path::new("."));
    FileCtx::from_path(parent, path)
}

/// Convenience: read raw bytes of a file, used nowhere critical but handy in tests.
pub fn read_to_string(path: &Path) -> Option<String> {
    let mut s = String::new();
    fs::File::open(path).ok()?.read_to_string(&mut s).ok()?;
    Some(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_source_splits_lines() {
        let ctx = FileCtx::from_source("a.rs", "one\ntwo\n");
        assert_eq!(ctx.lines.len(), 2);
        assert_eq!(ctx.lines[1], "two");
    }

    #[test]
    fn from_source_has_no_abs_path() {
        let ctx = FileCtx::from_source("a.rs", "hi\n");
        assert!(ctx.abs_path.is_none());
    }

    #[test]
    fn binary_detection() {
        assert!(is_binary(&[0x00, 0x01, 0x02]));
        assert!(!is_binary(b"plain text"));
    }

    #[test]
    fn skips_build_dirs() {
        assert!(is_skipped_dir("target"));
        assert!(is_skipped_dir(".git"));
        assert!(!is_skipped_dir("src"));
    }
}
