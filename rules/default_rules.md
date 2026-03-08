# multi-code-check default rules

这些规则使用 ` ```rule ` 代码块定义。

```rule
id: generic_no_silent_fallback_default
severity: high
languages: *
type: contains
pattern: fallback to default
message: Avoid silent fallback to default; fail-fast with explicit error.
ignore_case: true
```

```rule
id: generic_no_silent_fallback_mem
severity: high
languages: *
type: contains
pattern: fallback to mem
message: Avoid silent fallback to memory backend; surface storage failures.
ignore_case: true
```

```rule
id: rust_no_unwrap
severity: high
languages: rust
type: contains
pattern: unwrap(
message: Avoid unwrap in production path; propagate Result with context.
ignore_case: true
```

```rule
id: rust_no_todo_macro
severity: high
languages: rust
type: contains
pattern: todo!(
message: Remove todo! macro in production path.
ignore_case: true
```

```rule
id: ts_no_ts_ignore
severity: high
languages: typescript
type: contains
pattern: @ts-ignore
message: Avoid @ts-ignore; fix typing issue or use safe narrowing.
ignore_case: true
```

```rule
id: js_no_debugger
severity: medium
languages: javascript, typescript
type: contains
pattern: debugger
message: Remove debugger statements from committed code.
ignore_case: true
```

```rule
id: python_no_bare_except
severity: high
languages: python
type: regex
pattern: ^\s*except\s*:\s*$
message: Bare except masks root causes; catch explicit exception types.
ignore_case: true
```

```rule
id: go_no_fmt_println
severity: low
languages: go
type: contains
pattern: fmt.Println(
message: Prefer structured logging over fmt.Println in non-demo code.
ignore_case: true
```
