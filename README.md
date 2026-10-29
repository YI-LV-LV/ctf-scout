# ctf-scout

面向授权 CTF 比赛、靶场和自有资产的自动化漏洞侦察智能体。纯 Python 标准库实现，零第三方依赖。

> 仅用于你拥有明确授权的目标。本项目不包含 exploit、口令爆破、webshell 上传或任何破坏性操作。

## 特性

- **智能体调度**：基于任务队列的“规划 → 执行 → 根据结果追加任务”流程，发现新技术栈后自动追加定向检查。
- **资产侦察**：TCP 端口扫描、Banner 抓取、服务与中间件指纹识别。
- **Web 发现**：页面指纹、61 条敏感路径枚举、robots.txt 路径自动跟进。
- **被动检查**：安全响应头、Cookie 属性、目录浏览、默认页、调试堆栈、HTML 注释、flag 格式匹配。
- **主动验证（可选）**：报错 SQL 注入、反射型 XSS、LFI、开放重定向、CORS、危险 HTTP 方法。
- **未授权服务验证（可选）**：FTP 匿名登录、Redis、Docker API、Memcached、Elasticsearch、CouchDB。
- **攻击路径推理**：按严重度输出 CTF 攻击链建议和可手工执行的验证命令。
- **多格式报告**：Markdown、JSON、自包含 HTML。
- **可选 LLM 分析**：兼容 OpenAI Chat Completions 接口。
- **授权保护**：公网目标必须显式确认授权；重定向仅跟随同主机；主动验证全部为只读/低风险请求。

## 环境要求

- Python 3.10+
- 无第三方依赖

## 快速开始

```bash
git clone <repository-url>
cd ctf-scout

# 直接运行
python -m ctf_scout scan http://10.10.10.5:8080

# 或安装为命令
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e .
ctf-scout scan http://10.10.10.5:8080
```

## 常用示例

```bash
# 被动侦察：只做指纹与敏感路径检查
python -m ctf_scout scan http://10.10.10.5:8080

# 主动验证：额外发送少量低风险测试请求
python -m ctf_scout scan http://10.10.10.5:8080 --active

# 全端口扫描并生成三种格式报告
python -m ctf_scout scan 10.10.10.5 --full --active --format all

# 指定端口范围
python -m ctf_scout scan 10.10.10.5 --ports 80,443,8000-9000

# 公网 CTF 靶机：必须显式确认授权
python -m ctf_scout scan https://target.ctf.com --authorized --active

# 只输出控制台摘要，不写文件
python -m ctf_scout scan 10.10.10.5 --format none
```

## 参数说明

| 参数 | 说明 |
| --- | --- |
| `target` | 支持 `host`、`host:port`、`http(s)://host[:port][/path]` |
| `--ports` | 自定义端口，如 `80,443,8000-9000`；默认扫描常见端口 |
| `--full` | 扫描 1-65535 全端口 |
| `--timeout` | HTTP 请求超时秒数，默认 8 |
| `--connect-timeout` | TCP 连接超时秒数，默认 0.7 |
| `--threads` | 端口扫描并发数，默认 200 |
| `--active` | 启用低风险主动验证 |
| `--authorized` | 确认已获得公网目标的测试授权 |
| `--llm` | 调用 OpenAI 兼容接口生成辅助分析 |
| `--format` | `all` / `md` / `json` / `html` / `none` |
| `--output` | 报告目录，默认 `./reports` |
| `--no-color` | 禁用彩色输出 |
| `--quiet` | 只输出最终摘要 |
| `--max-steps` | 智能体最大任务步数，默认 1000 |

## 报告

默认写入 `./reports/<host>_<port>_<timestamp>.{md,json,html}`：

- **Markdown**：适合归档、提交 Writeup 前整理。
- **JSON**：包含端口、Web 指纹、Finding、路径命中、日志，便于二次处理。
- **HTML**：自包含深色主题页面，可直接用浏览器打开。

报告可能包含账号、密钥、flag 等敏感信息，请勿公开分享。

## 主动验证内容

启用 `--active` 后会额外发送少量只读请求：

| 检查 | 请求方式 |
| --- | --- |
| 报错 SQL 注入 | 参数值追加单引号，观察数据库报错特征 |
| 反射型 XSS | 参数注入 SVG 标记，检查是否原样回显 |
| LFI | 参数注入路径穿越，检查系统文件特征 |
| 开放重定向 | 参数注入外部 URL，检查 Location |
| CORS | 带 Origin 的 GET 请求 |
| 危险方法 | OPTIONS 请求 |
| Redis 未授权 | `PING` |
| Docker API 未授权 | `GET /version` |
| Elasticsearch 未授权 | `GET /_cat/indices?v` |
| Memcached 未授权 | `stats` |
| CouchDB 未授权 | `GET /_all_dbs` |
| FTP 匿名 | `anonymous` 登录 |

所有请求都不会写入目标数据或执行命令。

## 可选 LLM 分析

```bash
# Windows PowerShell
$env:CTF_SCOUT_LLM_API_KEY="your-key"
$env:CTF_SCOUT_LLM_BASE_URL="https://api.openai.com/v1"
$env:CTF_SCOUT_LLM_MODEL="gpt-4o-mini"

python -m ctf_scout scan http://10.10.10.5:8080 --active --llm
```

兼容 OpenAI 风格的 `/chat/completions` 接口。启用后会将侦察摘要发送到所配置的服务。

## 项目结构

```
ctf-scout/
├── ctf_scout/
│   ├── __main__.py          # python -m ctf_scout 入口
│   ├── cli.py               # 参数解析与流程编排
│   ├── agent.py             # 任务队列智能体与攻击路径推理
│   ├── scope.py             # 目标解析与授权校验
│   ├── http.py              # HTTP 客户端与 HTML 解析
│   ├── models.py            # Finding / Context 等数据模型
│   ├── report.py            # 控制台、Markdown、JSON、HTML 报告
│   ├── llm.py               # 可选 LLM 分析
│   ├── wordlists.py         # 敏感路径字典
│   └── tools/
│       ├── recon.py         # 端口扫描与服务指纹
│       ├── web.py           # Web 指纹、路径枚举、技术栈检查
│       ├── checks.py        # 被动泄露检查与主动验证
│       └── services.py      # 非 Web 服务提示与未授权验证
├── docs/                    # 使用、架构与 Python 模块文档
├── LICENSE                  # MIT
├── pyproject.toml
├── .gitignore
└── README.md
```

详见 [使用文档](docs/使用文档.md)、[架构说明](docs/架构说明.md) 和 [Python 模块文档](docs/Python模块文档.md)。

## 扩展

新增敏感路径：编辑 `ctf_scout/wordlists.py` 中的 `PATHS`，格式为：

```python
"path": ("severity", "标题", "CTF 利用思路")
```

新增主动检查：在 `ctf_scout/tools/checks.py` 的 `active_checks()` 中追加逻辑，返回 `Finding`。

新增服务提示：编辑 `ctf_scout/tools/services.py` 中的 `SERVICE_HINTS`。

新增技术栈定向检查：在 `ctf_scout/tools/web.py` 的 `tech_checks()` 中按指纹追加。

## 安全与授权

- 本工具只应用于你拥有明确授权的 CTF 比赛、靶场或自有资产。
- 私网/本机目标可直接扫描；公网目标必须传入 `--authorized`。
- HTTP 重定向仅跟随同主机，避免意外访问第三方资产。
- 工具不会执行 exploit、命令执行、文件写入或口令爆破。
- 报告中的验证命令需要人工判断后手动执行。

## 已知限制

- 规则驱动，存在误报与漏报，不能替代人工验证。
- 不处理登录态、POST 表单、验证码与复杂业务逻辑。
- 不支持 IPv6 目标。
- `--full` 全端口扫描耗时取决于目标网络。
- 风险评分是严重度加权启发式，仅用于排序参考。

## 许可证

[MIT](LICENSE)
