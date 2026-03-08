# multi-code-check

`multi-code-check` 是一个可直接作为 MCP 使用的多项目代码巡检器（Rust 实现）。

核心能力：
- 自动发现目录下项目（`.git` + 常见 manifest）
- 按文件后缀识别编程语言并做语言专项检查
- 规则大小写无关匹配（默认开启，可关闭）
- 规则从 Markdown 加载（支持按语言拆分多个规则文件）
- 支持 `gitignore` 风格忽略（自动 `.gitignore/.mccignore` + 自定义 ignore 文件）
- MCP tools：`multi_code_check.scan`、`multi_code_check.discover_projects`

## 1. 快速开始（git clone 即可）

```bash
git clone git@github.com:differs/multi-code-check.git
cd multi-code-check
cargo build --release
```

最小扫描：

```bash
cargo run -- scan --root /path/to/workspaces
```

输出 JSON：

```bash
cargo run -- scan --root /path/to/workspaces --json
```

## 2. 忽略目录/文件（gitignore 语法）

默认行为：
- 自动读取扫描根目录与项目目录下的 `.gitignore`、`.mccignore`
- 内置忽略：`.git`、`target`、`node_modules`、`dist`、`build`、`coverage` 等

手动追加 ignore 文件或目录：

```bash
cargo run -- scan --root /path/to/workspaces \
  --ignore-file /path/to/global.ignore \
  --ignore-file /path/to/ignore-folder
```

关闭自动 `.gitignore/.mccignore` 读取：

```bash
cargo run -- scan --root /path/to/workspaces --use-gitignore false
```

`.mccignore` 示例：

```gitignore
# 目录
**/generated/
**/mock/

# 文件
**/*.snap
**/*.min.js

# 保留某目录（gitignore 规则支持反选）
!apps/web/src/**
```

## 3. 规则编写（Markdown）

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
enabled: true
```
````

字段说明：
- `id`：规则唯一标识（必填）
- `severity`：`high|medium|low|info`
- `languages`：逗号分隔，支持 `*`
- `type`：`contains` 或 `regex`
- `pattern`：匹配表达式（必填）
- `message`：命中提示
- `ignore_case`：是否忽略大小写
- `enabled`：`false` 表示禁用该规则

## 4. 按语言拆分多个规则文件

支持按目录加载多个规则文件：

```bash
cargo run -- scan --root /path/to/workspaces --rules ./rules
```

推荐结构：

```text
rules/
  rust.md
  python.md
  frontend/
    typescript.md
    vue.md
```

推断机制：
- 规则块未写 `languages:` 时，自动从文件名/父目录名推断语言
- 也可在 Markdown 顶部显式声明：

```markdown
<!-- default_languages: rust,typescript -->
```

如果规则块内写了 `languages:`，会覆盖文件级默认语言。

## 5. 内置规则覆盖语言

内置规则文件：`rules/default_rules.md`，覆盖常见前后端语言：
- Frontend：`javascript`、`typescript`、`vue`（含 React 常见风险）
- Backend：`rust`、`python`、`go`、`java`、`kotlin`、`csharp`、`php`、`ruby`
- Ops/DB：`shell`、`sql`

适合 clone 后直接开箱使用；你也可以在此基础上追加团队规则包。

## 6. MCP 模式

启动 MCP（stdio）：

```bash
cargo run -- mcp --root /path/to/workspaces
```

客户端配置示例：

```json
{
  "mcpServers": {
    "multi-code-check": {
      "command": "/abs/path/multi-code-check/target/release/multi-code-check",
      "args": [
        "mcp",
        "--root",
        "/path/to/workspaces",
        "--rules",
        "/abs/path/multi-code-check/rules"
      ]
    }
  }
}
```

可调用工具：
- `multi_code_check.scan`
- `multi_code_check.discover_projects`

`scan` 支持参数：`root`、`max_depth`、`max_findings`、`include_hidden`、`case_insensitive`、`use_gitignore`、`ignore_file_paths`、`rule_paths`。

## 7. 规则文档

- 规则写法：`rules/README.md`
- 内置规则：`rules/default_rules.md`
