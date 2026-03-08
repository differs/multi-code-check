use crate::model::{DiscoverProject, Finding, ProjectSummary, ScanReport, ScanSummary, Severity};
use crate::rules::Rule;
use anyhow::{Context, Result, anyhow};
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use walkdir::{DirEntry, WalkDir};

const PROJECT_MARKERS: &[&str] = &[
    "cargo.toml",
    "package.json",
    "pyproject.toml",
    "requirements.txt",
    "go.mod",
    "pubspec.yaml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gemfile",
    "composer.json",
    "mix.exs",
    "project.clj",
];

const DEFAULT_IGNORE_PATTERNS: &[&str] = &[
    "**/.git/",
    "**/target/",
    "**/node_modules/",
    "**/dist/",
    "**/build/",
    "**/out/",
    "**/.dart_tool/",
    "**/coverage/",
    "**/artifacts/",
    "**/venv/",
    "**/.venv/",
    "**/__pycache__/",
    "**/.idea/",
    "**/.vscode/",
];

const MAX_FILE_SIZE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub root: PathBuf,
    pub max_depth: usize,
    pub max_findings: usize,
    pub include_hidden: bool,
    pub case_insensitive: bool,
    pub ignore_file_paths: Vec<PathBuf>,
    pub use_gitignore: bool,
}

#[derive(Debug, Clone)]
struct DiscoveredProject {
    path: PathBuf,
    markers: Vec<String>,
}

#[derive(Debug)]
struct FindingCollector {
    limit: usize,
    findings: Vec<Finding>,
    dropped: usize,
}

#[derive(Debug)]
struct IgnoreMatcher {
    include_hidden: bool,
    gitignore: Gitignore,
}

impl IgnoreMatcher {
    fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        self.gitignore
            .matched_path_or_any_parents(path, is_dir)
            .is_ignore()
    }
}

impl FindingCollector {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            findings: Vec::new(),
            dropped: 0,
        }
    }

    fn push(&mut self, finding: Finding) {
        if self.findings.len() < self.limit {
            self.findings.push(finding);
        } else {
            self.dropped += 1;
        }
    }

    fn len(&self) -> usize {
        self.findings.len()
    }
}

pub fn run_scan(options: &ScanOptions, rules: &[Rule]) -> Result<ScanReport> {
    let root = normalize_path(&options.root)?;
    let root_matcher = build_ignore_matcher(&root, &root, options)?;
    let projects = discover_projects(&root, options.max_depth, &root_matcher)?;

    let mut collector = FindingCollector::new(options.max_findings.max(1));
    let mut project_summaries = Vec::new();
    let mut total_files = 0usize;

    for project in &projects {
        let visible_before = collector.len();
        let project_matcher = build_ignore_matcher(&root, &project.path, options)?;
        let summary = scan_project(
            project,
            &root,
            options,
            rules,
            &project_matcher,
            &mut collector,
        )?;
        total_files += summary.file_count;

        let mut summary = summary;
        summary.finding_count_visible = collector.len().saturating_sub(visible_before);
        project_summaries.push(summary);
    }

    let severity_breakdown = build_severity_breakdown(&collector.findings);

    Ok(ScanReport {
        root: root.display().to_string(),
        generated_at_unix: now_unix(),
        loaded_rules: rules.len(),
        projects: project_summaries,
        findings: collector.findings,
        summary: ScanSummary {
            total_projects: projects.len(),
            total_files,
            visible_findings: severity_breakdown.values().sum::<usize>(),
            dropped_findings: collector.dropped,
            severity_breakdown,
        },
    })
}

pub fn discover_for_output(
    root: &Path,
    max_depth: usize,
    include_hidden: bool,
    ignore_file_paths: &[PathBuf],
    use_gitignore: bool,
) -> Result<Vec<DiscoverProject>> {
    let normalized = normalize_path(root)?;
    let options = ScanOptions {
        root: normalized.clone(),
        max_depth,
        max_findings: 1,
        include_hidden,
        case_insensitive: true,
        ignore_file_paths: ignore_file_paths.to_vec(),
        use_gitignore,
    };
    let matcher = build_ignore_matcher(&normalized, &normalized, &options)?;
    let projects = discover_projects(&normalized, max_depth, &matcher)?;
    Ok(projects
        .into_iter()
        .map(|p| DiscoverProject {
            name: p
                .path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("root")
                .to_string(),
            path: p.path.display().to_string(),
            markers: p.markers,
        })
        .collect::<Vec<_>>())
}

pub fn render_text_report(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("multi-code-check report\n");
    out.push_str("=======================\n");
    out.push_str(&format!("root: {}\n", report.root));
    out.push_str(&format!(
        "projects: {}  files: {}  findings: {} (dropped: {})\n",
        report.summary.total_projects,
        report.summary.total_files,
        report.summary.visible_findings,
        report.summary.dropped_findings
    ));
    out.push_str("severity: ");
    for (k, v) in &report.summary.severity_breakdown {
        out.push_str(&format!("{}={} ", k, v));
    }
    out.push('\n');

    out.push_str("\nprojects:\n");
    for p in &report.projects {
        out.push_str(&format!(
            "- {} | files={} | findings={} | markers={}\n",
            p.path,
            p.file_count,
            p.finding_count_visible,
            p.markers.join(",")
        ));
    }

    out.push_str("\nfindings (top 50):\n");
    for (idx, f) in report.findings.iter().take(50).enumerate() {
        let line = f
            .line
            .map(|x| x.to_string())
            .unwrap_or_else(|| "-".to_string());
        out.push_str(&format!(
            "{}. [{}] {}:{} {} - {}\n",
            idx + 1,
            f.severity.as_str(),
            f.file,
            line,
            f.rule_id,
            f.message
        ));
    }

    out
}

fn scan_project(
    project: &DiscoveredProject,
    workspace_root: &Path,
    options: &ScanOptions,
    rules: &[Rule],
    ignore_matcher: &IgnoreMatcher,
    collector: &mut FindingCollector,
) -> Result<ProjectSummary> {
    let mut file_count = 0usize;
    let mut language_breakdown = BTreeMap::<String, usize>::new();

    let mut has_tests = false;
    let mut has_readme = false;
    let mut has_ci_workflow = false;

    for entry in WalkDir::new(&project.path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| should_visit(e, ignore_matcher))
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if metadata.len() > MAX_FILE_SIZE_BYTES {
            collector.push(Finding {
                severity: Severity::Low,
                project: project.path.display().to_string(),
                file: relativize(entry.path(), workspace_root),
                line: None,
                language: "unknown".to_string(),
                rule_id: "quality.large_file".to_string(),
                message: format!("File is larger than {} bytes", MAX_FILE_SIZE_BYTES),
                snippet: None,
            });
            continue;
        }

        let language = detect_language(entry.path());
        *language_breakdown.entry(language.clone()).or_insert(0) += 1;
        file_count += 1;

        if is_readme(entry.path()) {
            has_readme = true;
        }
        if is_test_path(entry.path()) {
            has_tests = true;
        }
        if is_ci_workflow_file(entry.path()) {
            has_ci_workflow = true;
        }

        let content = match read_text(entry.path()) {
            Some(c) => c,
            None => continue,
        };

        for (line_index, line) in content.lines().enumerate() {
            check_general_line_quality(
                project,
                workspace_root,
                entry.path(),
                &language,
                line,
                line_index + 1,
                collector,
                options.case_insensitive,
            );

            for rule in rules {
                if !rule.applies_to_language(&language) {
                    continue;
                }
                if rule.matches_line(line, options.case_insensitive) {
                    collector.push(Finding {
                        severity: rule.severity,
                        project: project.path.display().to_string(),
                        file: relativize(entry.path(), workspace_root),
                        line: Some(line_index + 1),
                        language: language.clone(),
                        rule_id: rule.id.clone(),
                        message: format!("{} (source: {})", rule.message, rule.source),
                        snippet: Some(line.trim().chars().take(220).collect::<String>()),
                    });
                }
            }
        }
    }

    let mut quality_notes = Vec::new();
    if !has_readme {
        quality_notes.push("README missing".to_string());
        collector.push(Finding {
            severity: Severity::Low,
            project: project.path.display().to_string(),
            file: relativize(&project.path, workspace_root),
            line: None,
            language: "meta".to_string(),
            rule_id: "quality.missing_readme".to_string(),
            message: "Project root has no README".to_string(),
            snippet: None,
        });
    }
    if !has_tests {
        quality_notes.push("tests missing".to_string());
        collector.push(Finding {
            severity: Severity::Medium,
            project: project.path.display().to_string(),
            file: relativize(&project.path, workspace_root),
            line: None,
            language: "meta".to_string(),
            rule_id: "quality.missing_tests".to_string(),
            message: "No obvious test files or tests directory found".to_string(),
            snippet: None,
        });
    }
    if !has_ci_workflow {
        quality_notes.push("ci workflow missing".to_string());
        collector.push(Finding {
            severity: Severity::Info,
            project: project.path.display().to_string(),
            file: relativize(&project.path, workspace_root),
            line: None,
            language: "meta".to_string(),
            rule_id: "quality.missing_ci".to_string(),
            message: "No .github/workflows/*.yml detected in this project".to_string(),
            snippet: None,
        });
    }

    Ok(ProjectSummary {
        name: project
            .path
            .file_name()
            .and_then(|x| x.to_str())
            .unwrap_or("root")
            .to_string(),
        path: project.path.display().to_string(),
        markers: project.markers.clone(),
        file_count,
        language_breakdown,
        finding_count_visible: 0,
        quality_notes,
    })
}

fn check_general_line_quality(
    project: &DiscoveredProject,
    workspace_root: &Path,
    file: &Path,
    language: &str,
    line: &str,
    line_number: usize,
    collector: &mut FindingCollector,
    case_insensitive: bool,
) {
    if line.ends_with(' ') || line.ends_with('\t') {
        collector.push(Finding {
            severity: Severity::Low,
            project: project.path.display().to_string(),
            file: relativize(file, workspace_root),
            line: Some(line_number),
            language: language.to_string(),
            rule_id: "quality.trailing_whitespace".to_string(),
            message: "Trailing whitespace".to_string(),
            snippet: Some(line.trim_end().chars().take(220).collect::<String>()),
        });
    }

    if line.chars().count() > 140 {
        collector.push(Finding {
            severity: Severity::Info,
            project: project.path.display().to_string(),
            file: relativize(file, workspace_root),
            line: Some(line_number),
            language: language.to_string(),
            rule_id: "quality.long_line".to_string(),
            message: "Line length exceeds 140 characters".to_string(),
            snippet: Some(line.trim().chars().take(220).collect::<String>()),
        });
    }

    if contains_case(line, "todo", case_insensitive)
        || contains_case(line, "fixme", case_insensitive)
        || contains_case(line, "hack", case_insensitive)
    {
        collector.push(Finding {
            severity: Severity::Info,
            project: project.path.display().to_string(),
            file: relativize(file, workspace_root),
            line: Some(line_number),
            language: language.to_string(),
            rule_id: "quality.todo_marker".to_string(),
            message: "TODO/FIXME/HACK marker found".to_string(),
            snippet: Some(line.trim().chars().take(220).collect::<String>()),
        });
    }
}

fn discover_projects(
    root: &Path,
    max_depth: usize,
    ignore_matcher: &IgnoreMatcher,
) -> Result<Vec<DiscoveredProject>> {
    let mut found = BTreeMap::<PathBuf, BTreeSet<String>>::new();

    for entry in WalkDir::new(root)
        .follow_links(false)
        .max_depth(max_depth)
        .into_iter()
        .filter_entry(|e| should_visit(e, ignore_matcher))
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_dir() {
            if entry
                .file_name()
                .to_str()
                .map(|x| x.eq_ignore_ascii_case(".git"))
                .unwrap_or(false)
            {
                if let Some(parent) = entry.path().parent() {
                    found
                        .entry(parent.to_path_buf())
                        .or_default()
                        .insert(".git".to_string());
                }
            }
            continue;
        }

        if !entry.file_type().is_file() {
            continue;
        }

        let file_name = entry
            .file_name()
            .to_str()
            .map(|x| x.to_ascii_lowercase())
            .unwrap_or_default();

        if PROJECT_MARKERS.iter().any(|m| file_name == *m) {
            if let Some(parent) = entry.path().parent() {
                found
                    .entry(parent.to_path_buf())
                    .or_default()
                    .insert(file_name.clone());
            }
        }
    }

    if found.is_empty() {
        found.insert(
            root.to_path_buf(),
            BTreeSet::from(["fallback_root".to_string()]),
        );
    }

    Ok(found
        .into_iter()
        .map(|(path, markers)| DiscoveredProject {
            path,
            markers: markers.into_iter().collect::<Vec<_>>(),
        })
        .collect::<Vec<_>>())
}

fn should_visit(entry: &DirEntry, ignore_matcher: &IgnoreMatcher) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let name = entry.file_name().to_string_lossy();
    if !ignore_matcher.include_hidden && name.starts_with('.') {
        return false;
    }
    !ignore_matcher.is_ignored(entry.path(), entry.file_type().is_dir())
}

fn build_ignore_matcher(
    scan_root: &Path,
    project_root: &Path,
    options: &ScanOptions,
) -> Result<IgnoreMatcher> {
    let mut builder = GitignoreBuilder::new(project_root);

    for pattern in DEFAULT_IGNORE_PATTERNS {
        builder
            .add_line(None, pattern)
            .map_err(|e| anyhow!("invalid builtin ignore pattern '{pattern}': {e}"))?;
    }

    let ignore_files = collect_ignore_files(scan_root, project_root, options)?;
    for ignore_file in ignore_files {
        if let Some(err) = builder.add(&ignore_file) {
            return Err(anyhow!(
                "failed to load ignore file '{}': {}",
                ignore_file.display(),
                err
            ));
        }
    }

    let gitignore = builder
        .build()
        .map_err(|e| anyhow!("failed to build ignore matcher: {e}"))?;

    Ok(IgnoreMatcher {
        include_hidden: options.include_hidden,
        gitignore,
    })
}

fn collect_ignore_files(
    scan_root: &Path,
    project_root: &Path,
    options: &ScanOptions,
) -> Result<Vec<PathBuf>> {
    let mut files = BTreeSet::new();

    if options.use_gitignore {
        for candidate in [
            scan_root.join(".gitignore"),
            scan_root.join(".mccignore"),
            project_root.join(".gitignore"),
            project_root.join(".mccignore"),
        ] {
            if candidate.is_file() {
                files.insert(candidate);
            }
        }
    }

    for raw in &options.ignore_file_paths {
        let resolved = if raw.is_absolute() {
            raw.clone()
        } else {
            scan_root.join(raw)
        };

        if resolved.is_file() {
            files.insert(resolved);
            continue;
        }

        if resolved.is_dir() {
            for entry in WalkDir::new(&resolved)
                .follow_links(false)
                .into_iter()
                .filter_map(|x| x.ok())
            {
                if !entry.file_type().is_file() {
                    continue;
                }
                if is_ignore_file(entry.path()) {
                    files.insert(entry.path().to_path_buf());
                }
            }
            continue;
        }

        return Err(anyhow!(
            "ignore path does not exist: {}",
            resolved.display()
        ));
    }

    Ok(files.into_iter().collect::<Vec<_>>())
}

fn is_ignore_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|x| x.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if lower == ".gitignore" || lower == ".mccignore" {
        return true;
    }
    path.extension()
        .and_then(|x| x.to_str())
        .map(|x| x.eq_ignore_ascii_case("ignore"))
        .unwrap_or(false)
}

fn detect_language(path: &Path) -> String {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "rs" => "rust",
        "js" | "mjs" | "cjs" | "jsx" => "javascript",
        "ts" | "tsx" => "typescript",
        "vue" => "vue",
        "svelte" => "svelte",
        "py" => "python",
        "go" => "go",
        "dart" => "dart",
        "java" => "java",
        "kt" | "kts" => "kotlin",
        "swift" => "swift",
        "rb" => "ruby",
        "php" => "php",
        "sh" | "bash" | "zsh" => "shell",
        "sql" => "sql",
        "c" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "cs" => "csharp",
        "scala" => "scala",
        "lua" => "lua",
        "json" => "json",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        "md" | "markdown" => "markdown",
        _ => "unknown",
    }
    .to_string()
}

fn contains_case(haystack: &str, needle: &str, case_insensitive: bool) -> bool {
    if case_insensitive {
        haystack
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
    } else {
        haystack.contains(needle)
    }
}

fn read_text(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    if bytes.iter().any(|b| *b == 0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn is_readme(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|x| x.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower == "readme" || lower.starts_with("readme.")
}

fn is_test_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_ascii_lowercase();
    path_str.contains("/tests/")
        || path_str.ends_with("_test.rs")
        || path_str.ends_with("_test.py")
        || path_str.contains(".spec.")
        || path_str.contains(".test.")
}

fn is_ci_workflow_file(path: &Path) -> bool {
    let path_str = path.to_string_lossy().to_ascii_lowercase();
    path_str.contains(".github/workflows/")
        && (path_str.ends_with(".yml") || path_str.ends_with(".yaml"))
}

fn build_severity_breakdown(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for finding in findings {
        *out.entry(finding.severity.as_str().to_string())
            .or_insert(0) += 1;
    }
    out
}

fn relativize(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn normalize_path(path: &Path) -> Result<PathBuf> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to get current dir")?
            .join(path)
    };
    Ok(abs)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|x| x.as_secs())
        .unwrap_or(0)
}
