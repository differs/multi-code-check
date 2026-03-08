# Rule Authoring Guide

`multi-code-check` 规则以 Markdown 管理，规则块使用 ` ```rule `。

## 1) 规则块格式

````markdown
```rule
id: ts_no_ts_ignore
severity: high
languages: typescript
type: contains
pattern: @ts-ignore
message: Avoid @ts-ignore.
ignore_case: true
enabled: true
```
````

字段：
- `id`（必填）：规则 ID，建议唯一
- `severity`：`high|medium|low|info`
- `languages`：逗号分隔；支持 `*`
- `type`：`contains` 或 `regex`
- `pattern`（必填）：匹配表达式
- `message`：命中提示
- `ignore_case`：是否忽略大小写（默认 true）
- `enabled`：`false` 表示禁用

## 2) 按语言拆分多个文件

推荐目录：

```text
rules/
  rust.md
  python.md
  frontend/
    javascript.md
    typescript.md
```

当规则块未写 `languages:` 时：
- 会自动从文件名推断（如 `rust.md` -> `rust`）
- 会自动从父目录推断（如 `frontend/typescript.md` -> `typescript`）

语言别名示例：
- `rs -> rust`
- `py -> python`
- `js -> javascript`
- `ts -> typescript`

## 3) 文件级默认语言

可在 Markdown 前部声明：

```markdown
<!-- default_languages: rust,typescript -->
```

此声明会作为该文件规则块的默认语言。

## 4) contains vs regex

`contains`：
- 简单字符串匹配
- 可读性高，推荐优先使用

`regex`：
- 复杂模式匹配
- 注意转义和性能

## 5) 示例

### Rust 示例

````markdown
```rule
id: rust_no_unwrap
severity: high
type: contains
pattern: unwrap(
message: Avoid unwrap in production path.
```
````

### Python 正则示例

````markdown
```rule
id: python_no_bare_except
severity: high
languages: python
type: regex
pattern: ^\s*except\s*:\s*$
message: Bare except masks root causes.
```
````

## 6) 运行时加载

```bash
cargo run -- scan --root /path/workspaces --rules ./rules
```

`--rules` 可重复传入多个文件或目录。
