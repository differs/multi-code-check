# multi-code-check

`multi-code-check` 是一个 Rust 实现的 MCP 服务，做多项目代码质量巡检。

功能：
- 自动发现指定目录下项目（`.git` + 常见 manifest 标记）
- 按文件后缀识别语言
- 大小写无关检查（可配置）
- 规则从 Markdown 加载
- 支持“按语言拆分多个规则文件”
- 提供 MCP tools：`multi_code_check.scan`、`multi_code_check.discover_projects`

## Build

```bash
cargo build --release
```

## One-shot Scan

```bash
# 扫描当前目录
cargo run -- scan --root .

# 输出 JSON
cargo run -- scan --root /root/workspaces --json

# 加载额外规则（文件或目录，可重复）
cargo run -- scan --root /root/workspaces \
  --rules ./rules \
  --rules /path/to/custom/rules
```

## MCP Mode

```bash
cargo run -- mcp --root /root/workspaces
```

MCP 客户端配置示例：

```json
{
  "mcpServers": {
    "multi-code-check": {
      "command": "/root/workspaces/multi-code-check/target/release/multi-code-check",
      "args": ["mcp", "--root", "/root/workspaces"]
    }
  }
}
```

## Markdown 规则格式

规则必须写在 fenced code block：

````markdown
```rule
id: rust_no_unwrap
severity: high
languages: rust
type: contains
pattern: unwrap(
message: Avoid unwrap in production path.
ignore_case: true
```
````

支持字段：
- `id`：规则 ID（必填）
- `severity`：`high|medium|low|info`
- `languages`：逗号分隔，例如 `rust,typescript`；可写 `*`
- `type`：`contains` 或 `regex`
- `pattern`：匹配表达式（必填）
- `message`：命中后提示
- `ignore_case`：是否忽略大小写
- `enabled`：`false` 时禁用该规则

## 按语言拆分多个规则文件

支持这两种方式：

1. 文件名/目录名推断语言（无需每条规则重复写 `languages`）
- 例如：
  - `rules/rust.md`
  - `rules/python/security.md`
  - `rules/typescript/strict.md`

2. 在 Markdown 顶部写默认语言声明

```markdown
<!-- default_languages: rust,typescript -->
```

如果规则块里写了 `languages:`，会覆盖文件默认语言。
