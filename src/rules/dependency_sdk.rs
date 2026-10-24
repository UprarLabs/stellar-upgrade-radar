//! SUR-1002 (non-Rust ecosystems): JS/TS, Python, Go, Elixir SDK readiness.
//!
//! Evidence policy:
//! - A finding is emitted only for a *detected* Stellar SDK dependency, and the
//!   readiness verdict is derived from a version that can be **proven**: a
//!   lockfile resolution is preferred; a manifest range alone is never treated
//!   as the resolved version.
//! - Readiness thresholds are the first releases whose *official* release notes
//!   state Protocol 30 (CAP-84/CAP-88) support. Where no such release exists
//!   (Python, Elixir) the status is `Unknown` — we never guess a minimum.
//! - This rule reports the SDK version, not application runtime/on-chain
//!   compatibility; application-level W-address handling is SUR-1001's scope.
//!
//! Lockfiles are read as evidence and findings are attributed to the manifest,
//! so a lockfile never double-reports with its manifest.

use std::path::Path;

use crate::report::{Confidence, Finding, Kind, Severity};
use crate::scan::FileCtx;

const JS_RELEASE: &str = "https://github.com/stellar/js-stellar-sdk/releases/tag/v17.3.0";
const JS_LTS_RELEASE: &str = "https://github.com/stellar/js-stellar-sdk/releases/tag/v16.4.0";
const GO_RELEASE: &str = "https://github.com/stellar/go-stellar-sdk/releases/tag/v0.8.0";
const PY_CHANGELOG: &str = "https://github.com/StellarCN/py-stellar-base/blob/main/CHANGELOG.md";
const ELIXIR_RELEASES: &str = "https://github.com/kommitters/stellar_sdk/releases";
const UPGRADE_GUIDE: &str = "https://stellar.org/blog/developers/bell-protocol-30-upgrade-guide";

/// Verified first Protocol 30 releases (official release notes).
const JS_FIRST: &str = "v16.4.0 (LTS) or v17.3.0";
const GO_FIRST: &str = "v0.8.0";

/// Readiness of a detected SDK version against verified Protocol 30 releases.
#[derive(Debug, PartialEq)]
pub(crate) enum Readiness {
    /// Version is at or above a verified Protocol 30 release.
    Ready,
    /// Version predates the first verified Protocol 30 release.
    Predates { first: &'static str },
    /// No verified threshold applies (unknown major line, or no evidence).
    Unknown,
}

pub(crate) fn scan(ctx: &FileCtx) -> Vec<Finding> {
    let name = Path::new(&ctx.rel_path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match name {
        "package.json" => js::scan(ctx),
        "pyproject.toml" | "requirements.txt" => python::scan(ctx),
        "go.mod" => go::scan(ctx),
        "mix.exs" => elixir::scan(ctx),
        // Lockfiles are evidence sources only; findings point at the manifest.
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn sibling(ctx: &FileCtx, name: &str) -> Option<String> {
    let base = ctx.abs_path.as_ref()?.parent()?;
    std::fs::read_to_string(base.join(name)).ok()
}

/// Find a lockfile by walking up from the manifest directory, bounded to a
/// project root (a `.git` directory) and a small depth so a monorepo package can
/// resolve the root lockfile without sweeping the filesystem.
fn nearest_file(ctx: &FileCtx, name: &str) -> Option<String> {
    let base = ctx.abs_path.as_ref()?.parent()?;
    let mut dir = Some(base);
    let mut depth = 0usize;
    while let Some(d) = dir {
        let p = d.join(name);
        if p.is_file() {
            if let Ok(s) = std::fs::read_to_string(&p) {
                return Some(s);
            }
        }
        if d.join(".git").exists() {
            break;
        }
        dir = d.parent();
        depth += 1;
        if depth > 6 {
            break;
        }
    }
    None
}

fn parse_major_minor(ver: &str) -> Option<(u32, u32)> {
    let v = ver.trim().trim_start_matches('v');
    let core: String = v
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut it = core.split('.');
    let major: u32 = it.next()?.parse().ok()?;
    let minor: u32 = it.next().unwrap_or("0").parse().unwrap_or(0);
    Some((major, minor))
}

/// A requirement is an exact pin if it is a bare semver with no range operator.
fn is_exact_pin(req: &str) -> bool {
    let r = req.trim();
    if r.is_empty() || r.contains(['^', '~', '>', '<', '*', '=', ' ', ',', '|', 'x']) {
        return false;
    }
    r.trim_start_matches('v')
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_digit())
}

/// The lowest version a constraint can resolve to (`^17.3.0`, `~> 0.23`,
/// `>=16.0.0`, `0.8.0` -> the version; `*` / `<17` -> `None`).
fn lower_bound(req: &str) -> Option<String> {
    let r = req
        .trim()
        .trim_start_matches(['^', '~', '>', '=', ' ', '\'', '"'])
        .trim_start_matches('v');
    let v: String = r
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Resolve a readiness verdict, preferring a lockfile resolution; a manifest
/// constraint is only trusted when it *guarantees* an outcome (exact pin, or a
/// lower bound that already satisfies the threshold). Ranges are never assumed
/// to resolve to the version they are written with.
fn verdict(
    declared: &str,
    resolved: &Option<String>,
    readiness: impl Fn(&str) -> Readiness,
) -> (Readiness, String, &'static str) {
    if let Some(v) = resolved {
        let r = if is_prerelease(v) {
            Readiness::Unknown
        } else {
            readiness(v)
        };
        return (r, v.clone(), "resolved in the lockfile");
    }
    if is_exact_pin(declared) {
        let r = if is_prerelease(declared) {
            Readiness::Unknown
        } else {
            readiness(declared)
        };
        return (
            r,
            declared.to_string(),
            "declared in the manifest (no lockfile found)",
        );
    }
    if let Some(lb) = lower_bound(declared) {
        if matches!(readiness(&lb), Readiness::Ready) && !is_prerelease(declared) {
            return (
                Readiness::Ready,
                lb,
                "declared constraint lower bound (no lockfile found)",
            );
        }
    }
    (
        Readiness::Unknown,
        declared.to_string(),
        "declared constraint (no lockfile; the resolved version is not provable)",
    )
}

fn quoted_after(s: &str) -> Option<String> {
    let q = s.chars().find(|c| *c == '"' || *c == '\'')?;
    let rest = &s[s.find(q)? + 1..];
    let end = rest.find(q)?;
    if end == 0 {
        None
    } else {
        Some(rest[..end].to_string())
    }
}

/// Return the text following the dependency name when it appears as an element
/// of a dependency array (`["stellar-sdk>=1.0", ...]`), with a word boundary
/// before it and a version separator after it.
fn array_dep_rest<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let mut from = 0usize;
    while let Some(pos) = line[from..].find(key) {
        let p = from + pos;
        let before_ok = p == 0 || {
            let b = line[..p].chars().last().unwrap();
            !b.is_alphanumeric() && b != '-' && b != '_' && b != '.'
        };
        let after = &line[p + key.len()..];
        let a0 = after.chars().next();
        let after_ok = a0.is_none()
            || matches!(
                a0.unwrap(),
                '=' | '>' | '<' | '~' | '!' | ' ' | '"' | '\'' | ',' | ';' | ']'
            );
        if before_ok && after_ok {
            return Some(after);
        }
        from = p + key.len();
    }
    None
}

/// Extract the version from the text following a Python dependency name,
/// skipping extras (`[dev]`), range operators and markers.
fn python_version_after(rest: &str) -> String {
    let mut s = rest.trim();
    if let Some(stripped) = s.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            s = stripped[end + 1..].trim_start();
        }
    }
    let s = s.trim_start_matches(|c: char| {
        c.is_whitespace() || matches!(c, '=' | '>' | '<' | '~' | '!' | '"' | '\'')
    });
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
        .collect()
}
/// Extract a `version` value from a line (JSON `"version": "x"` or TOML
/// `version = "x"`), tolerating a leading `:`/`=` and quotes.
fn version_in_line(line: &str) -> Option<String> {
    let idx = line.find("version")?;
    let rest = line[idx + "version".len()..].trim_start();
    let rest = rest.trim_start_matches([':', '=', '"', '\'', ' ']);
    let v: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
        .collect();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Extract a JSON string value for `"<key>"` anywhere in `content`
/// (`"key": "value"`), used for nested package.json dependency objects.
fn json_value_after(content: &str, key: &str) -> Option<String> {
    let kq = format!("\"{key}\"");
    for line in content.lines() {
        let Some(kpos) = line.find(&kq) else { continue };
        let after = &line[kpos + kq.len()..];
        let Some(colon) = after.find(':') else {
            continue;
        };
        if let Some(v) = quoted_after(after[colon + 1..].trim_start()) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Result of resolving a dependency version from a lockfile.
enum LockResult {
    NotFound,
    One(String),
    /// More than one distinct version was found for the marker (ambiguous).
    Ambiguous,
}

/// Resolve the SDK version from a lockfile across several markers. Collects
/// distinct versions within a few lines after each marker so multiple
/// resolutions (monorepo / nested installs) are detected rather than silently
/// taking the first.
fn resolve_lock(content: &str, markers: &[&str]) -> LockResult {
    let lines: Vec<&str> = content.lines().collect();
    let mut found: Vec<String> = Vec::new();
    for marker in markers {
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(marker) {
                continue;
            }
            for l in lines.iter().skip(i).take(4) {
                if let Some(v) = version_in_line(l) {
                    if !found.contains(&v) {
                        found.push(v);
                    }
                }
            }
        }
    }
    match found.len() {
        0 => LockResult::NotFound,
        1 => LockResult::One(found.remove(0)),
        _ => LockResult::Ambiguous,
    }
}

/// True for a Go pseudo-version (`vX.Y.Z-0.YYYYMMDDHHMMSS-hash` / `vX.0.0-…`).
/// Readiness cannot be inferred from the embedded timestamp.
fn is_pseudo_version(ver: &str) -> bool {
    let mut run = 0usize;
    for c in ver.chars() {
        if c.is_ascii_digit() {
            run += 1;
            if run >= 14 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// True for a semver prerelease (`17.3.0-rc.1`, `1.0.0-beta`, `v0.8.0-rc.1`).
/// A prerelease must not be treated as Ready merely because its numeric part
/// meets the stable threshold — its readiness is not provable from the version.
fn is_prerelease(ver: &str) -> bool {
    let v = ver
        .trim()
        .trim_start_matches('v')
        .trim_start_matches(['^', '~', '>', '=', ' ', '\'', '"']);
    let core_end = v
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(v.len());
    let core = &v[..core_end];
    let rest = &v[core_end..];
    if core.is_empty() || !rest.starts_with('-') {
        return false;
    }
    rest.chars().any(|c| c.is_ascii_alphabetic())
}

/// Find `marker` in the content and return the first `version` value within the
/// following few lines (covers JSON/TOML/YAML lockfile layouts).
fn lock_version(content: &str, marker: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains(marker) {
            continue;
        }
        for l in lines.iter().skip(i).take(4) {
            if let Some(v) = version_in_line(l) {
                return Some(v);
            }
        }
    }
    None
}

/// A `go.mod`/`go.sum` style module reference: the module token followed by a
/// `vX.Y.Z` version, anywhere on the line (`require mod vX.Y.Z`, `\tmod vX.Y.Z
/// // indirect`, or a bare `mod vX.Y.Z`).
fn go_module_version(content: &str, module: &str) -> Option<String> {
    for line in content.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        let mut from = 0usize;
        while let Some(pos) = t[from..].find(module) {
            let p = from + pos;
            let after = &t[p + module.len()..];
            // Require a path boundary so `github.com/stellar/go` does not match
            // `github.com/stellar/go-stellar-sdk`.
            let boundary = after.is_empty() || after.starts_with(char::is_whitespace);
            if boundary {
                let tok = after.split_whitespace().next().unwrap_or("");
                if tok.starts_with('v') {
                    return Some(tok.to_string());
                }
            }
            from = p + module.len();
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn finding(
    ctx: &FileCtx,
    line_no: usize,
    raw: &str,
    explanation: String,
    recommendation: String,
    severity: Severity,
    confidence: Confidence,
    kind: Kind,
    sources: &[&str],
    limitations: &str,
) -> Finding {
    Finding::new(
        "SUR-1002",
        "Stellar SDK dependency predates Protocol 30",
        severity,
        confidence,
        kind,
        &ctx.rel_path,
    )
    .location(line_no, None, Some(raw))
    .explanation(&explanation)
    .recommendation(&recommendation)
    .sources(sources)
    .limitations(limitations)
}

/// Resolve the effective version: a lockfile value when present, otherwise the
/// manifest declaration (only meaningful when it is an exact pin).
fn effective<'a>(declared: &'a str, resolved: &'a Option<String>) -> (String, &'static str) {
    match resolved {
        Some(v) => (v.clone(), "resolved in the lockfile"),
        None if is_exact_pin(declared) => (
            declared.to_string(),
            "declared in the manifest (no lockfile found)",
        ),
        None => (
            declared.to_string(),
            "declared in the manifest (no lockfile found; range cannot be resolved)",
        ),
    }
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript
// ---------------------------------------------------------------------------

mod js {
    use super::*;

    const CURRENT: &str = "@stellar/stellar-sdk";
    const LEGACY: &str = "stellar-sdk";

    pub(crate) fn scan(ctx: &FileCtx) -> Vec<Finding> {
        let mut out = Vec::new();
        for key in [CURRENT, LEGACY] {
            let Some((line_no, declared)) = find_package_json_dep(&ctx.content, key) else {
                continue;
            };
            let raw = ctx.lines[line_no - 1].clone();
            let lock = lockfile(ctx);
            let mut ambiguous = false;
            let resolved: Option<String> = match &lock {
                Some(LockResult::One(v)) => Some(v.clone()),
                Some(LockResult::Ambiguous) => {
                    ambiguous = true;
                    None
                }
                Some(LockResult::NotFound) | None => None,
            };
            let (mut verdict, mut ver, mut provenance) = verdict(&declared, &resolved, readiness);
            if ambiguous {
                verdict = Readiness::Unknown;
                ver = declared.clone();
                provenance = "lockfile lists multiple resolutions (ambiguous)";
            }
            match verdict {
                Readiness::Ready => {}
                Readiness::Predates { first } => out.push(finding(
                    ctx,
                    line_no,
                    &raw,
                    format!("`{key}` is {ver} ({provenance}), older than the first Protocol 30 JavaScript SDK release ({first}). An older SDK may fail to decode Protocol 30 ledgers (CAP-88) and lacks the CAP-84 W-address parser."),
                    format!("Upgrade @stellar/stellar-sdk to {first} and handle W (muxed contract) addresses in your own address validation (see SUR-1001)."),
                    Severity::Medium,
                    Confidence::High,
                    Kind::Static,
                    &[JS_RELEASE, JS_LTS_RELEASE, UPGRADE_GUIDE],
                    "SDK-version observation only; application-level compatibility is not asserted.",
                )),
                Readiness::Unknown => out.push(unknown_finding(ctx, line_no, &raw, key, &ver, provenance)),
            }
        }
        out
    }

    fn find_package_json_dep(content: &str, key: &str) -> Option<(usize, String)> {
        let kq = format!("\"{key}\"");
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") || t.starts_with('*') {
                continue;
            }
            let Some(kpos) = t.find(&kq) else { continue };
            let after = &t[kpos + kq.len()..];
            let Some(colon) = after.find(':') else {
                continue;
            };
            let value = after[colon + 1..].trim_start();
            if value.starts_with('{') {
                // Nested object (non-standard deps form): read its "version".
                return json_value_after(&t[kpos..], "version").map(|v| (i + 1, v));
            }
            if let Some(v) = quoted_after(value) {
                if !v.is_empty() {
                    return Some((i + 1, v));
                }
            }
        }
        None
    }

    fn lockfile(ctx: &FileCtx) -> Option<LockResult> {
        for name in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"] {
            let Some(content) = nearest_file(ctx, name) else {
                continue;
            };
            let markers: &[&str] = if name == "package-lock.json" {
                &[
                    "node_modules/@stellar/stellar-sdk",
                    "\"@stellar/stellar-sdk\"",
                ]
            } else {
                &["@stellar/stellar-sdk@"]
            };
            match resolve_lock(&content, markers) {
                LockResult::NotFound => continue,
                other => return Some(other),
            }
        }
        None
    }

    fn readiness(ver: &str) -> Readiness {
        match parse_major_minor(ver) {
            Some((16, m)) if m >= 4 => Readiness::Ready,
            Some((17, m)) if m >= 3 => Readiness::Ready,
            Some((16, _)) | Some((17, _)) => Readiness::Predates { first: JS_FIRST },
            Some((mj, _)) if mj < 16 => Readiness::Predates { first: JS_FIRST },
            _ => Readiness::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Python
// ---------------------------------------------------------------------------

mod python {
    use super::*;

    const KEY: &str = "stellar-sdk";

    pub(crate) fn scan(ctx: &FileCtx) -> Vec<Finding> {
        let name = Path::new(&ctx.rel_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        let requirements = name == "requirements.txt";
        let Some((line_no, declared)) = find_python_dep(&ctx.content, requirements) else {
            return Vec::new();
        };
        let raw = ctx.lines[line_no - 1].clone();
        let resolved = lockfile_version(ctx);
        let (ver, provenance) = effective(&declared, &resolved);
        // No released Python SDK carries Protocol 30 (support is "Pending").
        vec![unknown_finding(ctx, line_no, &raw, KEY, &ver, provenance)]
    }

    /// Find the `stellar-sdk` dependency in a *dependency context* — never an
    /// arbitrary substring. A project or package **name** such as
    /// `my-stellar-sdk-app` must not be treated as the dependency.
    fn find_python_dep(content: &str, requirements: bool) -> Option<(usize, String)> {
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let rest: Option<&str> = if requirements {
                // requirements.txt: the requirement starts the line.
                t.strip_prefix(KEY)
            } else if let Some(r0) = t.strip_prefix(KEY) {
                // pyproject [tool.poetry.dependencies]: `stellar-sdk = "..."`.
                let r = r0.trim_start();
                if r.starts_with('=') || r.starts_with('{') {
                    Some(r)
                } else {
                    None
                }
            } else if t.contains('[') && t.contains(']') {
                // pyproject [project] dependencies array: `["stellar-sdk>=…"]`.
                array_dep_rest(t, KEY)
            } else {
                None
            };
            let Some(rest) = rest else { continue };
            return Some((i + 1, python_version_after(rest)));
        }
        None
    }

    fn lockfile_version(ctx: &FileCtx) -> Option<String> {
        for name in ["poetry.lock", "uv.lock"] {
            if let Some(content) = sibling(ctx, name) {
                if let Some(v) = lock_version(&content, KEY) {
                    return Some(v);
                }
            }
        }
        if let Some(content) = sibling(ctx, "Pipfile.lock") {
            // Pipfile.lock nests the version under "version": "==x.y.z".
            if let Some(v) = lock_version(&content, KEY) {
                let v = v.trim_start_matches('=').to_string();
                return Some(v);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

mod go {
    use super::*;

    const MODULE: &str = "github.com/stellar/go-stellar-sdk";
    /// The Go monorepo. The Bell guide points to `go-stellar-sdk` for the Go
    /// SDK; no verified Protocol 30 release threshold is established for this
    /// module, so it is reported as manual-review rather than a guessed minimum.
    const MODULE_ALT: &str = "github.com/stellar/go";

    pub(crate) fn scan(ctx: &FileCtx) -> Vec<Finding> {
        let mut out = Vec::new();
        if let Some((line_no, declared)) = find_go_dep(&ctx.content, MODULE) {
            let raw = ctx.lines[line_no - 1].clone();
            out.extend(go_finding(
                ctx,
                line_no,
                &raw,
                MODULE,
                &declared,
                &ctx.content,
            ));
        }
        if let Some((line_no, _)) = find_go_dep(&ctx.content, MODULE_ALT) {
            let raw = ctx.lines[line_no - 1].clone();
            out.push(unknown_finding(
                ctx,
                line_no,
                &raw,
                MODULE_ALT,
                "",
                "detected in go.mod (no verified Protocol 30 release threshold)",
            ));
        }
        out
    }

    fn go_finding(
        ctx: &FileCtx,
        line_no: usize,
        raw: &str,
        module: &str,
        declared: &str,
        content: &str,
    ) -> Vec<Finding> {
        let replace = go_replace(content, module);
        let (verdict, ver, provenance) = match replace {
            Replace::Version(v) => {
                if is_prerelease(&v) {
                    (
                        Readiness::Unknown,
                        v,
                        "replace target is a prerelease (readiness not provable)",
                    )
                } else {
                    (readiness(&v), v, "resolved via replace directive")
                }
            }
            Replace::Path => (
                Readiness::Unknown,
                declared.to_string(),
                "replaced by a local/path module (version not provable)",
            ),
            Replace::None => {
                if is_pseudo_version(declared) {
                    (
                        Readiness::Unknown,
                        declared.to_string(),
                        "pseudo-version (protocol readiness is not inferable from the timestamp)",
                    )
                } else if is_prerelease(declared) {
                    (
                        Readiness::Unknown,
                        declared.to_string(),
                        "prerelease (protocol readiness is not provable from the version)",
                    )
                } else {
                    (
                        readiness(declared),
                        declared.to_string(),
                        "required in go.mod (authoritative for the build)",
                    )
                }
            }
        };
        match verdict {
            Readiness::Ready => Vec::new(),
            Readiness::Predates { first } => vec![finding(
                ctx,
                line_no,
                raw,
                format!("{module} is {ver} ({provenance}), older than the first Protocol 30 Go SDK release ({first}). The Protocol 30 Go SDK carries CAP-84/CAP-88 XDR and muxed contract (W) address support."),
                format!("Upgrade {module} to {first} and handle W (muxed contract) addresses in your own address validation (see SUR-1001)."),
                Severity::Medium,
                Confidence::High,
                Kind::Static,
                &[GO_RELEASE, UPGRADE_GUIDE],
                "SDK-version observation only; application-level compatibility is not asserted.",
            )],
            Readiness::Unknown => vec![unknown_finding(ctx, line_no, raw, module, &ver, provenance)],
        }
    }

    fn find_go_dep(content: &str, module: &str) -> Option<(usize, String)> {
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.starts_with("//") {
                continue;
            }
            if let Some(v) = go_module_version(&format!("{t}\n"), module) {
                return Some((i + 1, v));
            }
        }
        None
    }

    fn readiness(ver: &str) -> Readiness {
        match parse_major_minor(ver) {
            Some((0, m)) if m >= 8 => Readiness::Ready,
            Some((0, _)) => Readiness::Predates { first: GO_FIRST },
            _ => Readiness::Unknown,
        }
    }
}

/// A `replace` directive outcome for a module.
enum Replace {
    None,
    Version(String),
    /// Replaced by a local path or another source with no usable version.
    Path,
}

/// Parse `replace` directives for `module` (single-line and `replace ( … )`
/// block forms). Returns the first matching directive.
fn go_replace(content: &str, module: &str) -> Replace {
    let mut in_block = false;
    for line in content.lines() {
        let t = line.trim();
        if in_block {
            if t.starts_with(')') {
                in_block = false;
                continue;
            }
            if let Some(r) = parse_replace(t, module) {
                return r;
            }
            continue;
        }
        if t.starts_with("replace (") {
            in_block = true;
            continue;
        }
        if let Some(rest) = t.strip_prefix("replace ") {
            if let Some(r) = parse_replace(rest, module) {
                return r;
            }
        }
    }
    Replace::None
}

fn parse_replace(rest: &str, module: &str) -> Option<Replace> {
    let (left, right) = rest.split_once("=>")?;
    if left.trim() != module {
        return None;
    }
    // Target is either `<module> vX.Y.Z` or a local path / other source.
    let last = right.split_whitespace().last().unwrap_or("");
    if last.starts_with('v') && last.len() > 1 {
        Some(Replace::Version(last.to_string()))
    } else {
        Some(Replace::Path)
    }
}

// ---------------------------------------------------------------------------
// Elixir
// ---------------------------------------------------------------------------

mod elixir {
    use super::*;

    const APP: &str = "stellar_sdk";

    pub(crate) fn scan(ctx: &FileCtx) -> Vec<Finding> {
        let Some((line_no, declared)) = find_mix_dep(&ctx.content) else {
            return Vec::new();
        };
        let raw = ctx.lines[line_no - 1].clone();
        let resolved = mix_lock_version(ctx);
        let (ver, provenance) = effective(&declared, &resolved);
        // No verified Protocol 30 release for the Elixir SDK.
        vec![unknown_finding(ctx, line_no, &raw, APP, &ver, provenance)]
    }

    fn find_mix_dep(content: &str) -> Option<(usize, String)> {
        for (i, line) in content.lines().enumerate() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let prefix = format!(":{APP},");
            let Some(pos) = t.find(&prefix) else {
                continue;
            };
            let rest = t[pos + prefix.len()..].trim_start();
            // A git/path/branch source carries no hex version: report unknown
            // rather than surfacing the URL/path as a "version".
            if is_mix_source_dep(rest) {
                return Some((i + 1, String::new()));
            }
            if let Some(v) = quoted_after(rest) {
                if !v.is_empty() {
                    return Some((i + 1, v));
                }
            }
        }
        None
    }

    fn mix_lock_version(ctx: &FileCtx) -> Option<String> {
        let content = sibling(ctx, "mix.lock")?;
        for line in content.lines() {
            if !(line.contains(&format!(":{APP}")) || line.contains(&format!("\"{APP}\""))) {
                continue;
            }
            // git/path entries (`{:git, "url", ...}` / `{:path, "..."}`) have no
            // hex version to report.
            if let Some(entry) = line.find(['{', '"']) {
                let entry = &line[entry..];
                if entry.starts_with("{:git") || entry.starts_with("{:path") {
                    return Some(String::new());
                }
            }
            if let Some(pos) = line.find(&format!(":{APP}")) {
                let rest = &line[pos + APP.len() + 1..];
                if let Some(v) = quoted_after(rest) {
                    if !v.is_empty() {
                        return Some(v);
                    }
                }
            }
        }
        None
    }
}

/// True when an Elixir dependency requirement is a source (git/path/branch/tag)
/// reference with no version.
fn is_mix_source_dep(rest: &str) -> bool {
    let r = rest.trim_start();
    [
        "github:", "git:", "path:", "github ", "git ", "path ", "branch:", "tag:", "ref:",
    ]
    .iter()
    .any(|p| r.starts_with(p))
}

// ---------------------------------------------------------------------------
// Shared unknown-status finding
// ---------------------------------------------------------------------------

fn unknown_finding(
    ctx: &FileCtx,
    line_no: usize,
    raw: &str,
    key: &str,
    ver: &str,
    provenance: &str,
) -> Finding {
    let shown = if ver.is_empty() {
        "version not determinable".to_string()
    } else {
        format!("version {ver}")
    };
    finding(
        ctx,
        line_no,
        raw,
        format!(
            "`{key}` detected ({shown}, {provenance}), but no verified Protocol 30 (CAP-84/CAP-88) release threshold could be established for this ecosystem. Readiness cannot be asserted from the version alone; verify against the SDK's Protocol 30 support."
        ),
        "Confirm the SDK's Protocol 30 (CAP-84 W addresses, CAP-88 ledger header) support against its release notes before relying on it.".to_string(),
        Severity::Low,
        Confidence::Low,
        Kind::ManualReview,
        &[UPGRADE_GUIDE, JS_RELEASE, GO_RELEASE, PY_CHANGELOG, ELIXIR_RELEASES],
        "Manual review: no verified Protocol 30 minimum version is available for this ecosystem.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::FileCtx;

    fn ctx(file: &str, src: &str) -> FileCtx {
        FileCtx::from_source(file, src)
    }

    // ---- JS ----

    #[test]
    fn js_ready_versions_are_not_flagged() {
        for src in [
            "[dependencies]\n\"@stellar/stellar-sdk\": \"17.3.0\"\n",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"^17.3.0\"\n",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"16.4.1\"\n",
        ] {
            assert!(js::scan(&ctx("package.json", src)).is_empty(), "src: {src}");
        }
    }

    #[test]
    fn js_old_version_is_medium_static() {
        let f = js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"16.3.1\"\n",
        ));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].kind, Kind::Static);
        assert!(f[0].explanation.contains("16.3.1"));
    }

    #[test]
    fn js_protocol28_line_is_predates() {
        // v17.0.0 is "Protocol 28", not Protocol 30.
        let f = js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"17.0.0\"\n",
        ));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn js_legacy_package_name_detected() {
        let f = js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"stellar-sdk\": \"15.0.0\"\n",
        ));
        assert_eq!(f.len(), 1);
        assert!(f[0].explanation.contains("stellar-sdk"));
    }

    #[test]
    fn js_comment_line_ignored() {
        let src = "// \"@stellar/stellar-sdk\": \"16.0.0\"\n\"@stellar/stellar-sdk\": \"17.3.0\"\n";
        assert!(js::scan(&ctx("package.json", src)).is_empty());
    }

    // ---- Python ----

    #[test]
    fn python_dependency_is_manual_review_not_defect() {
        for (file, src) in [
            ("requirements.txt", "stellar-sdk==16.1.1\n"),
            ("requirements.txt", "stellar-sdk>=16.4.0\n"),
            (
                "requirements.txt",
                "stellar-sdk==16.1.1; python_version >= \"3.9\"\n",
            ),
            (
                "pyproject.toml",
                "[project]\ndependencies = [\"stellar-sdk>=16.0.0\"]\n",
            ),
            (
                "pyproject.toml",
                "[tool.poetry.dependencies]\nstellar-sdk = \"^16.1\"\n",
            ),
        ] {
            let f = python::scan(&ctx(file, src));
            assert_eq!(f.len(), 1, "file={file} src: {src}");
            assert_eq!(f[0].kind, Kind::ManualReview);
            assert_eq!(f[0].severity, Severity::Low);
        }
    }

    #[test]
    fn python_project_name_is_not_a_dependency() {
        // A project/package *name* containing the substring must not be flagged.
        for src in [
            "[project]\nname = \"my-stellar-sdk-app\"\nversion = \"0.1.0\"\n",
            "[project]\nname = \"stellar-sdk\"\n",
            "[project]\ndependencies = [\"my-stellar-sdk-app>=1.0\"]\n",
        ] {
            assert!(
                python::scan(&ctx("pyproject.toml", src)).is_empty(),
                "must not flag a name: {src}"
            );
        }
        // A valid dependency in the same file is still detected.
        let src =
            "[project]\nname = \"my-stellar-sdk-app\"\ndependencies = [\"stellar-sdk>=16.0.0\"]\n";
        let f = python::scan(&ctx("pyproject.toml", src));
        assert_eq!(f.len(), 1, "valid dep must still be detected");
    }

    #[test]
    fn python_comment_ignored() {
        let src = "# stellar-sdk==16.0.0\nstellar-sdk==16.1.1\n";
        let f = python::scan(&ctx("requirements.txt", src));
        assert_eq!(f.len(), 1);
        assert!(f[0]
            .snippet
            .as_deref()
            .unwrap_or_default()
            .contains("stellar-sdk==16.1.1"));
    }

    // ---- Go ----

    #[test]
    fn go_ready_version_not_flagged() {
        let src = "module example\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.8.0\n";
        assert!(go::scan(&ctx("go.mod", src)).is_empty());
    }

    #[test]
    fn go_old_version_is_medium_static() {
        let src = "module example\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.7.3\n";
        let f = go::scan(&ctx("go.mod", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
        assert_eq!(f[0].kind, Kind::Static);
        assert!(f[0].explanation.contains("v0.7.3"));
    }

    #[test]
    fn go_indirect_require_detected() {
        let src = "require (\n\tgithub.com/stellar/go-stellar-sdk v0.7.3 // indirect\n)\n";
        let f = go::scan(&ctx("go.mod", src));
        assert_eq!(f.len(), 1);
    }

    #[test]
    fn go_comment_ignored() {
        let src = "// github.com/stellar/go-stellar-sdk v0.7.3\nrequire github.com/stellar/go-stellar-sdk v0.8.0\n";
        assert!(go::scan(&ctx("go.mod", src)).is_empty());
    }

    // ---- Elixir ----

    #[test]
    fn elixir_dependency_is_manual_review() {
        let src = "defp deps do\n  [\n    {:stellar_sdk, \"~> 0.23\"},\n  ]\nend\n";
        let f = elixir::scan(&ctx("mix.exs", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
        assert_eq!(f[0].severity, Severity::Low);
    }

    #[test]
    fn elixir_comment_ignored() {
        let src = "# {:stellar_sdk, \"~> 0.22\"}\n{:stellar_sdk, \"~> 0.23\"}\n";
        let f = elixir::scan(&ctx("mix.exs", src));
        assert_eq!(f.len(), 1);
    }

    // ---- helpers ----

    #[test]
    fn parse_major_minor_handles_v_prefix() {
        assert_eq!(parse_major_minor("v0.8.0"), Some((0, 8)));
        assert_eq!(parse_major_minor("17.3.0-rc.1"), Some((17, 3)));
        assert_eq!(parse_major_minor("not-a-version"), None);
    }

    #[test]
    fn is_exact_pin_distinguishes_ranges() {
        assert!(is_exact_pin("16.4.1"));
        assert!(is_exact_pin("0.8.0"));
        assert!(!is_exact_pin("^17.3.0"));
        assert!(!is_exact_pin(">=16.0.0"));
        assert!(!is_exact_pin(""));
    }

    #[test]
    fn version_in_line_json_and_toml() {
        assert_eq!(
            version_in_line("  \"version\": \"17.3.0\",").as_deref(),
            Some("17.3.0")
        );
        assert_eq!(
            version_in_line("version = \"16.1.1\"").as_deref(),
            Some("16.1.1")
        );
    }

    #[test]
    fn lock_version_finds_marker() {
        let lock = "[[package]]\nname = \"stellar-sdk\"\nversion = \"16.1.1\"\n";
        assert_eq!(lock_version(lock, "stellar-sdk").as_deref(), Some("16.1.1"));
    }

    #[test]
    fn go_module_version_extracts() {
        let gomod = "require github.com/stellar/go-stellar-sdk v0.8.0\n";
        assert_eq!(
            go_module_version(gomod, "github.com/stellar/go-stellar-sdk").as_deref(),
            Some("v0.8.0")
        );
    }

    #[test]
    fn js_readiness_thresholds() {
        assert_eq!(js_readiness("16.4.0"), Readiness::Ready);
        assert_eq!(
            js_readiness("16.3.1"),
            Readiness::Predates { first: JS_FIRST }
        );
        assert_eq!(js_readiness("17.3.0"), Readiness::Ready);
        assert_eq!(
            js_readiness("17.0.0"),
            Readiness::Predates { first: JS_FIRST }
        );
        assert_eq!(js_readiness("18.0.0"), Readiness::Unknown);
    }

    #[test]
    fn go_readiness_thresholds() {
        assert_eq!(go_readiness("0.8.0"), Readiness::Ready);
        assert_eq!(
            go_readiness("0.7.3"),
            Readiness::Predates { first: GO_FIRST }
        );
        assert_eq!(go_readiness("1.0.0"), Readiness::Unknown);
    }

    #[test]
    fn go_replace_with_version_is_used() {
        let src = "module m\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.7.3\n\nreplace github.com/stellar/go-stellar-sdk => github.com/stellar/go-stellar-sdk v0.9.0\n";
        assert!(
            go::scan(&ctx("go.mod", src)).is_empty(),
            "replace to v0.9.0 must be Ready"
        );
    }

    #[test]
    fn go_replace_block_with_version_is_used() {
        let src = "module m\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.7.3\n\nreplace (\n\tgithub.com/stellar/go-stellar-sdk => github.com/stellar/go-stellar-sdk v0.9.0\n)\n";
        assert!(go::scan(&ctx("go.mod", src)).is_empty());
    }

    #[test]
    fn go_replace_to_path_is_unknown() {
        let src = "module m\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.7.3\n\nreplace github.com/stellar/go-stellar-sdk => ../local/sdk\n";
        let f = go::scan(&ctx("go.mod", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
    }

    #[test]
    fn go_pseudo_version_is_unknown() {
        let src = "module m\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.0.0-20260101000000-abcdef123456\n";
        let f = go::scan(&ctx("go.mod", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
    }

    #[test]
    fn go_monorepo_module_is_manual_review() {
        let src = "module m\n\ngo 1.25\n\nrequire github.com/stellar/go v0.0.0-20260101000000-abcdef123456\n";
        let f = go::scan(&ctx("go.mod", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
        assert!(f[0].explanation.contains("github.com/stellar/go"));
    }

    #[test]
    fn go_require_block_detected() {
        let src =
            "module m\n\ngo 1.25\n\nrequire (\n\tgithub.com/stellar/go-stellar-sdk v0.7.3\n)\n";
        let f = go::scan(&ctx("go.mod", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Medium);
    }

    #[test]
    fn go_alt_module_not_confused_with_sdk() {
        // A require of go-stellar-sdk must not also produce an alt-module finding.
        let src = "module m\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.7.3\n";
        let f = go::scan(&ctx("go.mod", src));
        assert_eq!(
            f.len(),
            1,
            "only the SDK module, not the monorepo path: {f:?}"
        );
    }

    #[test]
    fn js_nested_object_extracts_version() {
        let ready =
            "{ \"dependencies\": { \"@stellar/stellar-sdk\": { \"version\": \"17.3.0\" } } }\n";
        assert!(js::scan(&ctx("package.json", ready)).is_empty());
        let old =
            "{ \"dependencies\": { \"@stellar/stellar-sdk\": { \"version\": \"16.3.1\" } } }\n";
        let f = js::scan(&ctx("package.json", old));
        assert_eq!(f.len(), 1);
        assert!(
            f[0].explanation.contains("16.3.1"),
            "must cite the nested version: {f:?}"
        );
    }

    #[test]
    fn elixir_git_dep_has_no_version() {
        let src = "defp deps do\n  [\n    {:stellar_sdk, github: \"kommitters/stellar_sdk\"},\n  ]\nend\n";
        let f = elixir::scan(&ctx("mix.exs", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
        assert!(
            !f[0].explanation.contains("kommitters/stellar_sdk"),
            "must not show a URL as the version"
        );
    }

    #[test]
    fn elixir_hex_dep_version_kept() {
        let src = "defp deps do\n  [\n    {:stellar_sdk, \"~> 0.23\"},\n  ]\nend\n";
        let f = elixir::scan(&ctx("mix.exs", src));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
    }

    #[test]
    fn is_prerelease_detects_suffix() {
        assert!(is_prerelease("17.3.0-rc.1"));
        assert!(is_prerelease("16.3.0-rc.1"));
        assert!(is_prerelease("v0.8.0-rc.1"));
        assert!(is_prerelease("^17.3.0-rc.1"));
        assert!(!is_prerelease("17.3.0"));
        assert!(!is_prerelease("16.4.0"));
        assert!(!is_prerelease("0.8.0"));
    }

    #[test]
    fn js_prerelease_is_not_ready() {
        // At the threshold: prerelease must be Unknown, not Ready.
        let at = js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"17.3.0-rc.1\"\n",
        ));
        assert_eq!(at.len(), 1, "prerelease must not be silently Ready: {at:?}");
        assert_eq!(at[0].kind, Kind::ManualReview);
        assert_eq!(at[0].severity, Severity::Low);

        // Below the threshold: also Unknown (no inference from the number).
        let below = js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"16.3.0-rc.1\"\n",
        ));
        assert_eq!(below.len(), 1);
        assert_eq!(below[0].kind, Kind::ManualReview);

        // A prerelease resolved in the lockfile is also Unknown.
        // (covered end-to-end by the js_prerelease fixture)
    }

    #[test]
    fn js_prerelease_range_constraint_is_not_ready() {
        let f = js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"^17.3.0-rc.1\"\n",
        ));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
    }

    #[test]
    fn js_stable_threshold_unchanged() {
        // Stable behaviour must not change.
        assert!(js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"17.3.0\"\n",
        ))
        .is_empty());
        assert!(js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"16.4.1\"\n",
        ))
        .is_empty());
        let old = js::scan(&ctx(
            "package.json",
            "[dependencies]\n\"@stellar/stellar-sdk\": \"16.3.1\"\n",
        ));
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].severity, Severity::Medium);
    }

    #[test]
    fn go_prerelease_is_unknown() {
        let f = go::scan(&ctx(
            "go.mod",
            "module m\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.8.0-rc.1\n",
        ));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, Kind::ManualReview);
        // Stable threshold unchanged.
        assert!(go::scan(&ctx(
            "go.mod",
            "module m\n\ngo 1.25\n\nrequire github.com/stellar/go-stellar-sdk v0.8.0\n",
        ))
        .is_empty());
    }

    fn js_readiness(ver: &str) -> Readiness {
        match parse_major_minor(ver) {
            Some((16, m)) if m >= 4 => Readiness::Ready,
            Some((17, m)) if m >= 3 => Readiness::Ready,
            Some((16, _)) | Some((17, _)) => Readiness::Predates { first: JS_FIRST },
            Some((mj, _)) if mj < 16 => Readiness::Predates { first: JS_FIRST },
            _ => Readiness::Unknown,
        }
    }

    fn go_readiness(ver: &str) -> Readiness {
        match parse_major_minor(ver) {
            Some((0, m)) if m >= 8 => Readiness::Ready,
            Some((0, _)) => Readiness::Predates { first: GO_FIRST },
            _ => Readiness::Unknown,
        }
    }
}
