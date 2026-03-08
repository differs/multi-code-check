use crate::model::Severity;
use anyhow::{Context, Result, anyhow};
use regex::{Regex, RegexBuilder};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const DEFAULT_RULES_MD: &str = include_str!("../rules/default_rules.md");

#[derive(Clone, Debug)]
enum RuleMatcher {
    Contains {
        pattern: String,
        pattern_lower: String,
    },
    Regex {
        sensitive: Regex,
        insensitive: Regex,
    },
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub severity: Severity,
    pub languages: Vec<String>,
    pub message: String,
    pub ignore_case: bool,
    pub source: String,
    matcher: RuleMatcher,
}

impl Rule {
    pub fn applies_to_language(&self, language: &str) -> bool {
        self.languages
            .iter()
            .any(|x| x == "*" || x.eq_ignore_ascii_case(language))
    }

    pub fn matches_line(&self, line: &str, global_case_insensitive: bool) -> bool {
        let effective_ignore_case = global_case_insensitive || self.ignore_case;
        match &self.matcher {
            RuleMatcher::Contains {
                pattern,
                pattern_lower,
            } => {
                if effective_ignore_case {
                    line.to_ascii_lowercase().contains(pattern_lower)
                } else {
                    line.contains(pattern)
                }
            }
            RuleMatcher::Regex {
                sensitive,
                insensitive,
            } => {
                if effective_ignore_case {
                    insensitive.is_match(line)
                } else {
                    sensitive.is_match(line)
                }
            }
        }
    }
}

#[derive(Debug)]
struct RuleBuilder {
    id: Option<String>,
    severity: Option<Severity>,
    languages: Option<Vec<String>>,
    kind: Option<String>,
    pattern: Option<String>,
    message: Option<String>,
    ignore_case: Option<bool>,
    enabled: Option<bool>,
}

impl RuleBuilder {
    fn new() -> Self {
        Self {
            id: None,
            severity: None,
            languages: None,
            kind: None,
            pattern: None,
            message: None,
            ignore_case: None,
            enabled: None,
        }
    }

    fn build(
        self,
        source: &str,
        index: usize,
        default_languages: &[String],
    ) -> Result<Option<Rule>> {
        let enabled = self.enabled.unwrap_or(true);
        if !enabled {
            return Ok(None);
        }

        let id = self
            .id
            .ok_or_else(|| anyhow!("rule block #{index} missing 'id' ({source})"))?;
        let severity = self.severity.unwrap_or(Severity::Medium);
        let languages = self.languages.filter(|x| !x.is_empty()).unwrap_or_else(|| {
            if default_languages.is_empty() {
                vec!["*".to_string()]
            } else {
                default_languages.to_vec()
            }
        });
        let kind = self.kind.unwrap_or_else(|| "contains".to_string());
        let pattern = self
            .pattern
            .ok_or_else(|| anyhow!("rule '{id}' missing 'pattern' ({source})"))?;
        let message = self
            .message
            .unwrap_or_else(|| format!("Rule '{id}' matched pattern '{pattern}'"));
        let ignore_case = self.ignore_case.unwrap_or(true);

        let matcher = match kind.to_ascii_lowercase().as_str() {
            "contains" => RuleMatcher::Contains {
                pattern_lower: pattern.to_ascii_lowercase(),
                pattern,
            },
            "regex" => {
                let sensitive = RegexBuilder::new(&pattern)
                    .case_insensitive(false)
                    .build()
                    .with_context(|| format!("invalid regex for rule '{id}' in {source}"))?;
                let insensitive = RegexBuilder::new(&pattern)
                    .case_insensitive(true)
                    .build()
                    .with_context(|| format!("invalid regex for rule '{id}' in {source}"))?;
                RuleMatcher::Regex {
                    sensitive,
                    insensitive,
                }
            }
            other => return Err(anyhow!("unsupported rule type '{other}' in {source}")),
        };

        Ok(Some(Rule {
            id,
            severity,
            languages,
            message,
            ignore_case,
            source: source.to_string(),
            matcher,
        }))
    }
}

#[derive(Clone, Debug)]
struct RuleFile {
    path: PathBuf,
    inferred_languages: Vec<String>,
}

pub fn load_rules(extra_rule_paths: &[PathBuf]) -> Result<Vec<Rule>> {
    let mut all = parse_rules_from_markdown(
        DEFAULT_RULES_MD,
        "builtin:rules/default_rules.md",
        &extract_default_languages_from_markdown(DEFAULT_RULES_MD),
    )?;

    for file in expand_markdown_paths(extra_rule_paths)? {
        let text = fs::read_to_string(&file.path)
            .with_context(|| format!("failed reading rule markdown: {}", file.path.display()))?;
        let mut defaults = file.inferred_languages;
        let file_declared = extract_default_languages_from_markdown(&text);
        if !file_declared.is_empty() {
            defaults = file_declared;
        }
        let parsed = parse_rules_from_markdown(&text, &file.path.display().to_string(), &defaults)?;
        all.extend(parsed);
    }

    if all.is_empty() {
        return Err(anyhow!("no rules loaded"));
    }
    Ok(all)
}

fn expand_markdown_paths(paths: &[PathBuf]) -> Result<Vec<RuleFile>> {
    let mut out = Vec::new();
    for path in paths {
        if path.is_file() {
            if is_markdown(path) {
                out.push(RuleFile {
                    path: path.clone(),
                    inferred_languages: infer_default_languages_from_path(path),
                });
            }
            continue;
        }
        if path.is_dir() {
            for entry in WalkDir::new(path)
                .follow_links(false)
                .into_iter()
                .filter_map(|x| x.ok())
            {
                if entry.file_type().is_file() && is_markdown(entry.path()) {
                    out.push(RuleFile {
                        path: entry.path().to_path_buf(),
                        inferred_languages: infer_default_languages_from_path(entry.path()),
                    });
                }
            }
            continue;
        }
        return Err(anyhow!("rule path does not exist: {}", path.display()));
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path);
    Ok(out)
}

fn is_markdown(path: &Path) -> bool {
    path.extension()
        .and_then(|x| x.to_str())
        .map(|x| x.eq_ignore_ascii_case("md") || x.eq_ignore_ascii_case("markdown"))
        .unwrap_or(false)
}

fn parse_rules_from_markdown(
    markdown: &str,
    source: &str,
    default_languages: &[String],
) -> Result<Vec<Rule>> {
    let blocks = extract_rule_blocks(markdown, source)?;
    let mut rules = Vec::new();
    for (index, block) in blocks.iter().enumerate() {
        let builder = parse_rule_block(block);
        if let Some(rule) = builder.build(source, index + 1, default_languages)? {
            rules.push(rule);
        }
    }
    Ok(rules)
}

fn extract_rule_blocks(markdown: &str, source: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut current = String::new();

    for line in markdown.lines() {
        let trimmed = line.trim();
        if !in_block {
            if let Some(tag) = trimmed.strip_prefix("```") {
                let tag = tag.trim().to_ascii_lowercase();
                if tag == "rule" || tag == "mcc-rule" {
                    in_block = true;
                    current.clear();
                }
            }
            continue;
        }

        if trimmed.starts_with("```") {
            out.push(current.clone());
            current.clear();
            in_block = false;
            continue;
        }

        current.push_str(line);
        current.push('\n');
    }

    if in_block {
        return Err(anyhow!("unterminated ```rule block in {source}"));
    }

    Ok(out)
}

fn parse_rule_block(block: &str) -> RuleBuilder {
    let mut builder = RuleBuilder::new();
    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"').trim_matches('\'');

        match key.as_str() {
            "id" => builder.id = Some(value.to_string()),
            "severity" => builder.severity = Severity::from_str(value),
            "languages" => {
                let langs = value
                    .split(',')
                    .filter_map(|x| canonical_language(x.trim()))
                    .collect::<Vec<_>>();
                if !langs.is_empty() {
                    builder.languages = Some(langs);
                }
            }
            "type" => builder.kind = Some(value.to_string()),
            "pattern" => builder.pattern = Some(value.to_string()),
            "message" => builder.message = Some(value.to_string()),
            "ignore_case" => builder.ignore_case = parse_bool(value),
            "enabled" => builder.enabled = parse_bool(value),
            _ => {}
        }
    }
    builder
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Some(true),
        "false" | "no" | "0" | "off" => Some(false),
        _ => None,
    }
}

fn extract_default_languages_from_markdown(markdown: &str) -> Vec<String> {
    let mut result = Vec::new();
    for line in markdown.lines().take(32) {
        let lower = line.to_ascii_lowercase();
        if let Some(pos) = lower.find("default_languages:") {
            let raw = &line[pos + "default_languages:".len()..];
            for token in raw
                .trim()
                .trim_end_matches("-->")
                .split(',')
                .map(|x| x.trim())
            {
                if let Some(lang) = canonical_language(token) {
                    result.push(lang);
                }
            }
            break;
        }
    }
    dedup_sorted(result)
}

fn infer_default_languages_from_path(path: &Path) -> Vec<String> {
    let mut langs = Vec::new();

    if let Some(stem) = path.file_stem().and_then(|x| x.to_str()) {
        langs.extend(infer_from_text(stem));
    }

    if let Some(parent) = path.parent() {
        for component in parent.components() {
            let text = component.as_os_str().to_string_lossy();
            langs.extend(infer_from_text(&text));
        }
    }

    dedup_sorted(langs)
}

fn infer_from_text(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter_map(canonical_language)
        .collect::<Vec<_>>()
}

fn dedup_sorted(items: Vec<String>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for item in items {
        set.insert(item);
    }
    set.into_iter().collect::<Vec<_>>()
}

fn canonical_language(raw: &str) -> Option<String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }

    let mapped = match normalized.as_str() {
        "*" | "all" | "any" => "*",
        "rust" | "rs" => "rust",
        "javascript" | "js" | "node" => "javascript",
        "typescript" | "ts" | "tsx" => "typescript",
        "vue" => "vue",
        "svelte" => "svelte",
        "python" | "py" => "python",
        "go" | "golang" => "go",
        "dart" => "dart",
        "java" => "java",
        "kotlin" | "kt" => "kotlin",
        "swift" => "swift",
        "ruby" | "rb" => "ruby",
        "php" => "php",
        "shell" | "sh" | "bash" | "zsh" => "shell",
        "sql" => "sql",
        "cpp" | "c++" | "cc" | "cxx" => "cpp",
        "c" => "c",
        "csharp" | "c#" | "cs" => "csharp",
        "scala" => "scala",
        "lua" => "lua",
        "json" => "json",
        "yaml" | "yml" => "yaml",
        "toml" => "toml",
        "markdown" | "md" => "markdown",
        _ => return None,
    };

    Some(mapped.to_string())
}
