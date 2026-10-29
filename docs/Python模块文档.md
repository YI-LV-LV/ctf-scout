# ctf-scout Python 模块文档

本文档对应 `ctf-scout 0.1.0`，说明各模块的公开类、函数、数据流与扩展方法。模块同时提供 pydoc HTML 版本，入口见 [pydoc/index.html](pydoc/index.html)。

## 1. 包结构

```text
ctf_scout/
├── __init__.py          __version__
├── __main__.py          python -m ctf_scout 入口
├── cli.py               命令行解析与扫描编排
├── agent.py             任务队列智能体
├── scope.py             目标解析与授权校验
├── http.py              HTTP 客户端与 HTML 解析
├── models.py            Finding / ServiceInfo / WebTarget / Context
├── report.py            控制台与三种报告
├── llm.py               OpenAI 兼容接口分析
├── wordlists.py         敏感路径与证据路径集合
└── tools/
    ├── recon.py         端口扫描与服务指纹
    ├── web.py           Web 指纹、枚举与技术栈检查
    ├── checks.py        被动检查与主动验证
    └── services.py      服务提示与未授权验证
```

## 2. `ctf_scout.models`

### 2.1 常量

```python
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {...}   # 中文等级名
SEVERITY_WEIGHT = {"critical": 50, "high": 20, "medium": 8, "low": 2, "info": 0}
```

### 2.2 `Finding`

```python
@dataclass
class Finding:
    title: str
    severity: str
    category: str
    target: str
    evidence: str
    suggestion: str = ""
    ctf_hint: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]
```

字段说明：

| 字段 | 说明 |
| --- | --- |
| `title` | 发现标题，用于去重 |
| `severity` | `critical` / `high` / `medium` / `low` / `info` |
| `category` | 分类，如敏感路径、主动探测、服务暴露 |
| `target` | 具体 URL 或 `host:port` |
| `evidence` | 状态码、响应头、正文片段等证据 |
| `suggestion` | 下一步或处置建议 |
| `ctf_hint` | CTF 利用思路，与 suggestion 相同时报告只显示一次 |
| `tags` | 攻击路径推理标签 |

### 2.3 `ServiceInfo`

```python
@dataclass
class ServiceInfo:
    port: int
    service: str = "unknown"
    banner: str = ""
    product: str = ""
    is_http: bool = False
    scheme: str = ""
```

### 2.4 `WebTarget`

```python
@dataclass
class WebTarget:
    url: str
    scheme: str
    host: str
    port: int
    status: int = 0
    final_url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[str] = field(default_factory=list)
    title: str = ""
    body: str = ""
    body_len: int = 0
    technologies: list[str] = field(default_factory=list)
    meta_generator: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    baseline_404_len: int = -1
    skip_enum: bool = False

    @property
    def base_url(self) -> str
```

`headers` 的键统一为小写；多条 `Set-Cookie` 以换行合并。

### 2.5 `Context`

```python
@dataclass
class Context:
    input_target: str
    target_host: str
    target_port: int
    scheme: str
    base_path: str
    resolved_ip: str
    is_private: bool
    authorized: bool
    options: dict[str, Any]
    open_ports: dict[int, ServiceInfo]
    web_targets: list[WebTarget]
    findings: list[Finding]
    discovered_paths: dict[str, str]
    robots_paths: list[str]
    attack_paths: list[str]
    commands: list[str]
    ai_analysis: str
    logs: list[str]
    started_at: float
    finished_at: float
```

方法：

| 方法 | 说明 |
| --- | --- |
| `log(message, level="info")` | 写入带时间戳的日志 |
| `add(finding) -> bool` | 去重并合并 Finding |
| `severity_counts() -> dict[str, int]` | 各等级数量 |
| `risk_score() -> int` | 0-100 加权评分 |
| `sorted_findings() -> list[Finding]` | 按严重度排序 |
| `elapsed` | 扫描耗时属性 |
| `to_dict()` | 完整上下文序列化 |

`add()` 的合并规则：

- `title` 与 `target` 相同视为同一条。
- 新等级更高时升级原条目。
- 证据去重后追加，最长 800 字符。
- 合并 tags。

## 3. `ctf_scout.scope`

### 3.1 `ScopeError`

继承 `ValueError`，表示目标或参数校验失败。

### 3.2 `Target`

```python
@dataclass
class Target:
    original: str
    scheme: str
    host: str
    port: int
    base_path: str
    resolved_ip: str
    is_private: bool
```

### 3.3 `parse_target(raw, default_scheme="http") -> Target`

支持：

- `host`
- `host:port`
- `http://host[:port][/path][?query]`
- `https://host[:port][/path]`

行为：

- 未写协议默认 `http`。
- URL 中的路径与查询串保存到 `base_path`。
- 通过 `socket.getaddrinfo` 解析 IPv4。
- 拒绝 IPv6、未指定地址、组播、广播。
- `is_private` 覆盖私网、回环、链路本地。

异常：`ScopeError`。

### 3.4 `require_authorization(target, authorized_flag) -> None`

- 私网/本机目标直接通过。
- 公网目标要求 `authorized_flag=True`，否则抛出 `ScopeError`。

### 3.5 `parse_ports(spec) -> list[int]`

解析 `80,443,8000-9000`，返回排序去重后的端口列表。范围自动纠正起止顺序，校验 1-65535。

## 4. `ctf_scout.http`

### 4.1 `Response`

```python
@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    raw_len: int
    error: str = ""

    @property
    def ok(self) -> bool   # status != 0
```

`status == 0` 表示网络错误，具体原因在 `error`。

### 4.2 `request(...) -> Response`

```python
request(
    url: str,
    method: str = "GET",
    timeout: float = 8.0,
    allow_redirects: bool = True,
    max_body: int = 512 * 1024,
    extra_headers: dict[str, str] | None = None,
) -> Response
```

行为：

- 使用标准库 `urllib.request`。
- 自签名 HTTPS 不校验证书。
- 手动处理最多 3 次重定向。
- 只跟随同主机重定向。
- 4xx/5xx 通过 `HTTPError` 捕获并保留响应体。
- 自动按 `Content-Type` 的 charset 解码，失败回退 UTF-8。

### 4.3 辅助函数

| 函数 | 说明 |
| --- | --- |
| `header(headers, name)` | 大小写不敏感读取响应头 |
| `build_base_url(scheme, host, port, path="/")` | 拼接 URL，自动省略默认端口 |
| `same_host(url, host)` | 判断 URL 主机是否一致 |
| `query_urls(web, limit=6)` | 从页面链接与 GET 表单收集带参 URL |
| `first_param(url)` | 返回第一个查询参数 `(name, value)` |
| `replace_param(url, name, value)` | 替换指定参数并保留其他参数 |

### 4.4 `PageParser` / `parse_html`

`PageParser` 继承 `html.parser.HTMLParser`，收集：

- `title`
- `forms`：action、method、inputs
- `links`、`scripts`
- `meta_generator`
- `comments`

```python
parse_html(body: str) -> PageParser
```

解析异常会被忽略，适合畸形 HTML。

### 4.5 `normalize_text(text)`

压缩空白并转小写，用于软 404 比较与证据片段。

## 5. `ctf_scout.tools.recon`

### 5.1 常量

- `PORT_SERVICES: dict[int, str]`
- `COMMON_PORTS: list[int]`
- `HTTP_PORTS: set[int]`
- `HTTPS_PORTS: set[int]`

### 5.2 `scan_ports(...)`

```python
scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 0.7,
    workers: int = 200,
    progress=None,
) -> list[int]
```

线程池 TCP connect 扫描，返回排序后的开放端口。`progress(done, total, open_ports)` 可选。

### 5.3 `probe_service(host, port, timeout=1.2) -> ServiceInfo`

- HTTP 端口发送 `HEAD /`。
- Redis 发送 `PING`，Memcached 发送 `stats`。
- MySQL/SSH 读取主动 Banner。
- 其他端口先读后发空行。
- 根据 Banner 识别 OpenSSH、Apache、nginx、Tomcat、MySQL、Redis 等产品。

## 6. `ctf_scout.tools.web`

### 6.1 `PathHit`

```python
@dataclass
class PathHit:
    path: str
    url: str
    status: int
    length: int
    content_type: str
    title: str
    snippet: str
    body: str
    location: str
```

### 6.2 `probe_web(url, scheme, host, port, timeout) -> WebTarget | None`

抓取首页，填充响应头、Cookie、标题、表单、链接、脚本、注释与技术栈。网络失败返回 `None`。

### 6.3 `detect_technologies(web) -> list[str]`

识别：

- 服务器：nginx、Apache、IIS、Tomcat、Python http.server
- 语言/框架：PHP、ASP.NET、Java、Spring Boot、Django、Laravel、ThinkPHP、Express、Next.js、Nuxt
- CMS/面板：WordPress、phpMyAdmin、Jenkins、GitLab、Nacos、Druid、Grafana
- API/数据：Swagger UI、Elasticsearch、Kibana
- 前端库：jQuery、React、Vue.js、Bootstrap

### 6.4 `enum_paths(...)`

```python
enum_paths(
    web: WebTarget,
    timeout: float,
    workers: int = 8,
    progress=None,
) -> tuple[list[Finding], dict[str, PathHit], list[str]]
```

返回值：

1. `findings`：命中敏感路径的发现。
2. `hits`：`path -> PathHit`。
3. `robots_paths`：robots.txt 中的 Disallow/Allow 路径。

关键逻辑：

- 随机路径生成软 404 基线。
- 基线 401/403 时直接返回空结果。
- 状态码一致且长度/文本相似时视为软 404。
- 目录浏览特征提升为中危。
- 401/403 命中降级为 low/info 并标注“受保护”。
- 证据包含状态、类型、大小、标题、Location 与片段。

### 6.5 `tech_checks(web, hits, timeout) -> list[Finding]`

按技术栈执行：

| 技术栈 | 检查 |
| --- | --- |
| WordPress | 登录页、XML-RPC、REST 用户枚举 |
| Spring Boot | heapdump、env、actuator |
| Swagger/OpenAPI | v3/v2 api-docs、swagger-resources、接口数量与示例 |
| Jenkins | `/script`、`/manage` |
| Nacos | `/nacos/` 控制台 |
| Elasticsearch | `/_cat/indices?v` |

### 6.6 `fetch_extra_paths(web, paths, timeout) -> list[Finding]`

跟进 robots 路径，命中 200/30x/401/403 时生成低危或信息发现。

## 7. `ctf_scout.tools.checks`

### 7.1 常量

- `FLAG_PATTERN`：`flag{...}`、`ctf{...}` 等格式。
- `SQL_ERRORS`：常见数据库报错特征。
- `SKIP_PARAMS`：动作型参数，主动验证跳过。
- `LFI_PARAMS`：文件包含相关参数名。
- `REDIRECT_PARAMS`：跳转相关参数名。

### 7.2 `passive_checks(web, timeout) -> list[Finding]`

检查项：

- 缺少 CSP / X-Frame-Options / X-Content-Type-Options / Referrer-Policy / Permissions-Policy / HSTS
- Server 与 X-Powered-By 版本泄露
- Cookie 缺少 HttpOnly / Secure
- 目录浏览
- Apache/nginx/IIS/Tomcat 默认页
- Spring Whitelabel、Python Traceback、Django DisallowedHost、Laravel Whoops
- 页面直接出现 flag
- HTML 注释中的敏感关键字

### 7.3 `active_checks(web, timeout) -> list[Finding]`

检查项：

- CORS 反射与 `Access-Control-Allow-Credentials`
- OPTIONS 返回的 PUT/DELETE/TRACE/PATCH
- 报错 SQL 注入
- 反射型 XSS
- Linux/Windows LFI
- 开放重定向

请求数量受 `query_urls(limit=6)` 与首个命中即停止控制。

## 8. `ctf_scout.tools.services`

### 8.1 `SERVICE_HINTS`

端口到 `(标题, 严重度, 建议)` 的映射，覆盖 FTP、SSH、Telnet、SMTP、SMB、MySQL、PostgreSQL、Redis、Memcached、Docker、MongoDB、WebLogic、Nacos、RabbitMQ 等。

### 8.2 `passive_service_findings(ctx) -> list[Finding]`

只针对非 HTTP 端口生成服务暴露提示。

### 8.3 `active_service_checks(ctx, timeout) -> list[Finding]`

只读验证：

| 服务 | 请求 |
| --- | --- |
| FTP | `anonymous` 登录 |
| Redis | `PING` |
| Memcached | `stats` |
| Docker | `GET /version` |
| Elasticsearch | `GET /_cat/indices?v` |
| CouchDB | `GET /_all_dbs` |

## 9. `ctf_scout.agent`

### 9.1 `Agent`

```python
Agent(
    ctx: Context,
    progress: Callable[[str], None] | None = None,
    max_steps: int = 1000,
)
```

公开方法：

| 方法 | 说明 |
| --- | --- |
| `enqueue(kind, payload=None)` | 追加任务，按类型 + payload 去重 |
| `run()` | 执行队列并收尾 |

内部任务处理函数命名为 `_task_<kind>`，新增任务类型时按此约定扩展。

任务失败会写入 `ctx.logs` 并继续执行后续任务。

### 9.2 攻击路径与命令

`_build_attack_paths()` 根据 tags 生成：

- flag 泄露
- 源码/配置泄露
- 未授权服务
- SQLi
- LFI
- 后台入口
- API 暴露
- 目录浏览
- 上传点
- XSS
- 开放重定向
- CORS

`_build_commands()` 生成 nmap、git-dumper、sqlmap、curl、wpscan、redis-cli、docker、ssh-audit 等建议命令，最多 8 条，仅打印不执行。

## 10. `ctf_scout.report`

| 函数 | 说明 |
| --- | --- |
| `print_summary(ctx, color=True)` | 控制台摘要 |
| `render_markdown(ctx) -> str` | Markdown 报告 |
| `render_json(ctx) -> str` | 结构化 JSON |
| `render_html(ctx) -> str` | 自包含 HTML |
| `write_reports(ctx, output_dir, formats) -> dict[str, str]` | 写文件并返回路径 |

`formats` 取值：`all`、`md`、`json`、`html`。

## 11. `ctf_scout.llm`

### `review(ctx) -> str`

读取环境变量：

- `CTF_SCOUT_LLM_API_KEY` 或 `OPENAI_API_KEY`
- `CTF_SCOUT_LLM_BASE_URL`
- `CTF_SCOUT_LLM_MODEL`

向 `${base_url}/chat/completions` 发送侦察摘要，返回 Markdown 文本。未配置 Key 或请求失败时抛出 `RuntimeError`，CLI 会捕获并跳过。

## 12. `ctf_scout.cli`

| 函数 | 说明 |
| --- | --- |
| `build_parser() -> argparse.ArgumentParser` | 构建 `scan` 子命令与参数 |
| `main(argv=None) -> int` | 程序主入口 |
| `run_scan(args) -> int` | 执行一次扫描 |

退出码：

| 码 | 含义 |
| --- | --- |
| `0` | 成功 |
| `1` | 扫描过程异常或未知命令 |
| `2` | 参数、目标或授权校验失败 |
| `130` | 用户中断 |

## 13. 扩展示例

### 13.1 自定义路径

```python
# ctf_scout/wordlists.py
PATHS["internal/"] = ("low", "内部目录暴露", "检查内部接口与调试页面。")
```

### 13.2 自定义检查

```python
# ctf_scout/tools/checks.py
def passive_checks(web: WebTarget, timeout: float) -> list[Finding]:
    findings = []
    ...
    if "x-debug" in web.headers:
        findings.append(
            _finding(
                "调试响应头暴露",
                "low",
                "信息泄露",
                web.url,
                "响应头包含 x-debug",
                "关闭调试响应头。",
                "",
                ["debug"],
            )
        )
    return findings
```

### 13.3 自定义服务

```python
# ctf_scout/tools/services.py
SERVICE_HINTS[9999] = ("示例服务暴露", "info", "使用示例客户端连接。")
```

### 13.4 自定义报告字段

`render_json()` 的 `_json_payload()` 中追加字段，HTML/Markdown 按需同步。

## 14. 类型与数据流

```text
str target
  -> scope.Target
  -> Context
  -> Agent
       -> tools.recon.ServiceInfo
       -> tools.web.WebTarget
       -> models.Finding
  -> llm.review(str)
  -> report.write_reports(dict[str, str])
```

所有工具函数都接收 `Context` 或 `WebTarget`，返回 `Finding` 列表，避免跨模块共享可变状态。

## 15. 版本与兼容性

- 最低 Python 3.10。
- 仅使用标准库。
- 公开 API 在 0.1.x 内保持稳定；内部 `_task_*` 与 `_render_*` 不属于稳定接口。
