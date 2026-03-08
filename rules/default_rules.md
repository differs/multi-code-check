# multi-code-check built-in rules

默认规则覆盖常见前后端语言；规则命中时会输出 `rule_id` 与来源。

## Global

```rule
id: global_no_silent_fallback_default
severity: high
languages: *
type: regex
pattern: (?i)fall\s*back\b[\s:=-]*(to[\s:=-]*)?default\b
message: Avoid silent fallback to default; fail-fast with explicit error.
ignore_case: true
```

```rule
id: global_no_silent_fallback_mem
severity: high
languages: *
type: regex
pattern: (?i)fall\s*back\b[\s:=-]*(to[\s:=-]*)?(mem(ory)?|in[\s_-]*memory)\b
message: Avoid silent fallback to memory backend; surface storage failures.
ignore_case: true
```

```rule
id: global_silent_degrade_keyword
severity: medium
languages: *
type: regex
pattern: (?i)\b(silent|silently)\b.{0,30}\b(fallback|degrad(e|ed|ing)|downgrad(e|ed|ing))\b
message: Potential silent degrade/fallback path; verify fail-fast behavior.
ignore_case: true
```

```rule
id: global_hardcoded_bearer_token
severity: high
languages: *
type: regex
pattern: (?i)bearer\s+[a-z0-9\-_]{20,}
message: Possible hardcoded bearer token.
ignore_case: true
```

## Frontend: JavaScript / TypeScript / Vue / React

```rule
id: js_no_eval
severity: high
languages: javascript,typescript
type: contains
pattern: eval(
message: Avoid eval(); it introduces code injection risk.
ignore_case: true
```

```rule
id: js_no_new_function
severity: high
languages: javascript,typescript
type: contains
pattern: new Function(
message: Avoid dynamic Function constructor in application code.
ignore_case: true
```

```rule
id: js_no_document_write
severity: medium
languages: javascript,typescript
type: contains
pattern: document.write(
message: Avoid document.write; unsafe and blocks rendering.
ignore_case: true
```

```rule
id: js_no_innerhtml_assignment
severity: high
languages: javascript,typescript
type: regex
pattern: (?i)\.innerhtml\s*=
message: innerHTML assignment may cause XSS; sanitize or avoid.
ignore_case: true
```

```rule
id: js_debugger_statement
severity: medium
languages: javascript,typescript
type: contains
pattern: debugger
message: Remove debugger statements from committed code.
ignore_case: true
```

```rule
id: js_console_log
severity: low
languages: javascript,typescript
type: contains
pattern: console.log(
message: Prefer structured logger over console.log in production path.
ignore_case: true
```

```rule
id: ts_no_ts_ignore
severity: high
languages: typescript
type: contains
pattern: @ts-ignore
message: Avoid @ts-ignore; fix typing issue or use proper type narrowing.
ignore_case: true
```

```rule
id: ts_no_ts_nocheck
severity: high
languages: typescript
type: contains
pattern: @ts-nocheck
message: Avoid @ts-nocheck; this disables type safety for entire file.
ignore_case: true
```

```rule
id: ts_explicit_any
severity: medium
languages: typescript
type: regex
pattern: :\s*any\b
message: Avoid broad any type in critical path.
ignore_case: true
```

```rule
id: react_dangerously_set_inner_html
severity: high
languages: javascript,typescript
type: contains
pattern: dangerouslySetInnerHTML
message: Review sanitization for dangerouslySetInnerHTML usage.
ignore_case: true
```

```rule
id: vue_v_html
severity: high
languages: vue
type: regex
pattern: (?i)\bv-html\b
message: v-html can introduce XSS; sanitize input strictly.
ignore_case: true
```

```rule
id: node_child_process_exec
severity: high
languages: javascript,typescript
type: contains
pattern: child_process.exec(
message: child_process.exec is risky; prefer spawn with strict args.
ignore_case: true
```

## Backend: Rust

```rule
id: rust_no_unwrap_prod
severity: high
languages: rust
type: contains
pattern: unwrap(
message: Avoid unwrap in production path; propagate Result with context.
ignore_case: true
exclude_path: (^|/)(tests?|benches?|examples?|mocks?|fixtures?)/|(_test|_bench)\.rs$
```

```rule
id: rust_no_unwrap_test
severity: medium
languages: rust
type: contains
pattern: unwrap(
message: unwrap in test/bench code should still be intentional and reviewed.
ignore_case: true
include_path: (^|/)(tests?|benches?|examples?|mocks?|fixtures?)/|(_test|_bench)\.rs$
```

```rule
id: rust_no_expect_prod
severity: medium
languages: rust
type: contains
pattern: expect(
message: Review expect usage; avoid panic in production path.
ignore_case: true
exclude_path: (^|/)(tests?|benches?|examples?|mocks?|fixtures?)/|(_test|_bench)\.rs$
```

```rule
id: rust_no_expect_test
severity: low
languages: rust
type: contains
pattern: expect(
message: expect in test/bench code is lower risk but should include clear context.
ignore_case: true
include_path: (^|/)(tests?|benches?|examples?|mocks?|fixtures?)/|(_test|_bench)\.rs$
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
id: rust_unsafe_block
severity: medium
languages: rust
type: regex
pattern: \bunsafe\s*\{
message: Review unsafe block for invariants and memory safety.
ignore_case: true
```

## Backend: Python

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
id: python_eval_exec
severity: high
languages: python
type: regex
pattern: \b(eval|exec)\s*\(
message: eval/exec is dangerous on untrusted input.
ignore_case: true
```

```rule
id: python_subprocess_shell_true
severity: high
languages: python
type: regex
pattern: subprocess\.[a-z_]+\([^\)]*shell\s*=\s*true
message: subprocess with shell=True can be command injection prone.
ignore_case: true
```

```rule
id: python_print_debug
severity: low
languages: python
type: contains
pattern: print(
message: Prefer structured logging over print in backend services.
ignore_case: true
```

## Backend: Go

```rule
id: go_panic_call
severity: medium
languages: go
type: contains
pattern: panic(
message: panic should be exceptional; prefer explicit error propagation.
ignore_case: true
```

```rule
id: go_fmt_println
severity: low
languages: go
type: contains
pattern: fmt.Println(
message: Prefer structured logger in production path.
ignore_case: true
```

```rule
id: go_http_listen_and_serve
severity: medium
languages: go
type: contains
pattern: http.ListenAndServe(
message: Ensure server timeouts and graceful shutdown are configured.
ignore_case: true
```

## Backend: Java / Kotlin / C# / PHP / Ruby

```rule
id: java_runtime_exec
severity: high
languages: java,kotlin
type: contains
pattern: Runtime.getRuntime().exec(
message: Runtime exec may lead to command injection risks.
ignore_case: true
```

```rule
id: java_system_out
severity: low
languages: java
type: contains
pattern: System.out.println(
message: Prefer structured logging in server code.
ignore_case: true
```

```rule
id: kotlin_println
severity: low
languages: kotlin
type: regex
pattern: \bprintln\s*\(
message: Prefer structured logging in server code.
ignore_case: true
```

```rule
id: csharp_process_start
severity: high
languages: csharp
type: contains
pattern: Process.Start(
message: Validate command arguments to avoid command injection.
ignore_case: true
```

```rule
id: csharp_console_write_line
severity: low
languages: csharp
type: contains
pattern: Console.WriteLine(
message: Prefer structured logging in backend services.
ignore_case: true
```

```rule
id: php_eval
severity: high
languages: php
type: regex
pattern: \beval\s*\(
message: eval in PHP is dangerous; avoid dynamic code execution.
ignore_case: true
```

```rule
id: php_var_dump
severity: low
languages: php
type: contains
pattern: var_dump(
message: Remove debug var_dump in production code.
ignore_case: true
```

```rule
id: ruby_eval
severity: high
languages: ruby
type: regex
pattern: \beval\s*\(
message: eval in Ruby can introduce code injection risk.
ignore_case: true
```

```rule
id: ruby_puts
severity: low
languages: ruby
type: regex
pattern: \bputs\s+
message: Prefer structured logger in service code.
ignore_case: true
```

## DevOps / Shell / SQL

```rule
id: shell_curl_pipe_sh
severity: high
languages: shell
type: regex
pattern: curl\s+[^\n\|]+\|\s*(sh|bash|zsh)
message: Avoid piping remote scripts directly to shell.
ignore_case: true
```

```rule
id: shell_wget_pipe_sh
severity: high
languages: shell
type: regex
pattern: wget\s+[^\n\|]+\|\s*(sh|bash|zsh)
message: Avoid piping downloaded scripts directly to shell.
ignore_case: true
```

```rule
id: shell_sudo_usage
severity: medium
languages: shell
type: regex
pattern: \bsudo\b
message: Review sudo usage in automation scripts.
ignore_case: true
```

```rule
id: sql_select_star
severity: low
languages: sql
type: regex
pattern: \bselect\s+\*
message: Avoid SELECT * in critical queries.
ignore_case: true
```
