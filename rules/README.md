# Rule Authoring (Markdown)

`multi-code-check` 从 Markdown 文件加载规则。

## 推荐目录结构（按语言拆分）

```text
rules/
  rust.md
  python.md
  typescript/
    strict.md
    security.md
```

说明：
- 当规则块未写 `languages:` 时，会自动根据文件名或父目录名推断默认语言。
- 支持别名：`rs -> rust`、`py -> python`、`ts -> typescript`、`js -> javascript`。

## 单条规则格式

````markdown
```rule
id: ts_no_ts_ignore
severity: high
type: contains
pattern: @ts-ignore
message: Avoid @ts-ignore.
ignore_case: true
```
````

可选字段：
- `languages:`：覆盖文件默认语言，支持逗号分隔
- `type:`：`contains` 或 `regex`
- `enabled:`：`false` 表示临时禁用

## 文件级默认语言（可选）

```markdown
<!-- default_languages: rust,typescript -->
```

当文件顶部出现该声明时，会覆盖路径推断结果。
