"""被动信息泄露检查与低风险主动验证。"""

from __future__ import annotations

import re

from ..http import first_param, header, query_urls, replace_param, request
from ..models import Finding, WebTarget

FLAG_PATTERN = re.compile(
    r"(flag|ctf|nssctf|ctfhub|hgame|moectf|dasctf|actf|sekaictf|n1ctf)\{[^}\n]{1,120}\}",
    re.I,
)
SQL_ERRORS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate[",
    "postgresql query failed",
    "pg_query",
    "sqlite error",
    "ora-0",
    "mysqli",
    "syntax error",
    "mysql_fetch",
)
SKIP_PARAMS = {
    "logout",
    "delete",
    "remove",
    "destroy",
    "reset",
    "create",
    "update",
    "save",
    "submit",
}
LFI_PARAMS = {
    "file",
    "page",
    "path",
    "include",
    "inc",
    "template",
    "tpl",
    "view",
    "doc",
    "folder",
    "lang",
    "load",
    "read",
    "download",
    "filename",
    "module",
}
REDIRECT_PARAMS = {"url", "redirect", "next", "return", "returnurl", "goto", "link", "dest", "target"}


def _finding(
    title: str,
    severity: str,
    category: str,
    target: str,
    evidence: str,
    suggestion: str = "",
    hint: str = "",
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        category=category,
        target=target,
        evidence=evidence,
        suggestion=suggestion,
        ctf_hint=hint,
        tags=tags or [],
    )


def passive_checks(web: WebTarget, timeout: float) -> list[Finding]:
    """不改变目标状态的检查。"""
    findings: list[Finding] = []
    body_l = web.body.lower()

    absent = []
    for key, label in (
        ("content-security-policy", "Content-Security-Policy"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ):
        if not header(web.headers, key):
            absent.append(label)
    if web.scheme == "https" and not header(web.headers, "strict-transport-security"):
        absent.append("Strict-Transport-Security")
    if absent:
        findings.append(
            _finding(
                "缺少常见安全响应头",
                 "low" if len(absent) >= 3 else "info",
                "安全配置",
                web.url,
                "缺少: " + "、".join(absent),
                "这些响应头不是直接漏洞，但会放大 XSS、点击劫持与降级攻击的影响。",
                "CTF 中通常不是主要考点，可忽略并优先验证业务接口。",
                ["hardening"],
            )
        )

    server = header(web.headers, "server")
    powered = header(web.headers, "x-powered-by")
    version_bits = []
    if server and re.search(r"\d", server):
        version_bits.append(f"Server: {server}")
    if powered:
        version_bits.append(f"X-Powered-By: {powered}")
    if version_bits:
        findings.append(
            _finding(
                "服务端版本信息暴露",
                "low",
                "信息泄露",
                web.url,
                " | ".join(version_bits),
                "结合版本号检索已知 CVE；生产环境应关闭版本回显。",
                "版本号可直接用于 searchsploit 与 CVE 匹配。",
                ["version", "fingerprint"],
            )
        )

    cookie_issues = []
    for cookie in web.cookies:
        name = cookie.split("=", 1)[0].strip()
        lower = cookie.lower()
        if "httponly" not in lower:
            cookie_issues.append(f"{name} 缺少 HttpOnly")
        if web.scheme == "https" and "secure" not in lower:
            cookie_issues.append(f"{name} 缺少 Secure")
    if cookie_issues:
        findings.append(
            _finding(
                "Cookie 缺少安全属性",
                "low",
                "安全配置",
                web.url,
                "；".join(cookie_issues[:5]),
                "敏感 Cookie 应设置 HttpOnly、Secure 与 SameSite。",
                "若存在 XSS，缺少 HttpOnly 的会话 Cookie 可被直接读取。",
                ["cookie"],
            )
        )

    if "index of /" in body_l or "directory listing for" in body_l:
        findings.append(
            _finding(
                "目录浏览开启",
                "medium",
                "信息泄露",
                web.url,
                "页面出现目录索引特征（Index of / 或 Directory listing）",
                "关闭目录浏览；检查目录内是否包含备份、源码与上传文件。",
                "目录浏览常直接暴露备份文件、源码甚至 flag。",
                ["dirlisting"],
            )
        )

    default_pages = (
        ("apache2 ubuntu default page", "Apache2 默认页"),
        ("test page for the apache http server", "Apache 测试页"),
        ("welcome to nginx", "Nginx 默认页"),
        ("iis windows server", "IIS 默认页"),
        ("which is the default tomcat", "Tomcat 默认页"),
        ("tomcat manager", "Tomcat 管理页"),
    )
    for needle, title in default_pages:
        if needle in body_l:
            findings.append(
                _finding(
                    f"{title}暴露",
                    "low",
                    "默认配置",
                    web.url,
                    f"页面命中默认页特征: {needle}",
                    "确认中间件版本并检索对应历史漏洞；默认页通常意味着应用尚未正式部署。",
                    "默认页可用于确认中间件类型，再结合版本找 CVE。",
                    ["middleware", "default-page"],
                )
            )
            break

    if "whitelabel error page" in body_l:
        findings.append(
            _finding(
                "Spring Boot 默认错误页暴露",
                "low",
                "信息泄露",
                web.url,
                "页面出现 Whitelabel Error Page",
                "触发不同异常观察是否泄露堆栈；重点检查 Actuator 端点。",
                "Spring 靶场通常伴随 Actuator 或 SpEL 注入考点。",
                ["spring", "error-page"],
            )
        )

    if "traceback (most recent call last)" in body_l:
        findings.append(
            _finding(
                "Python 异常堆栈泄露",
                "medium",
                "信息泄露",
                web.url,
                "页面包含 Python Traceback",
                "修复调试模式；从堆栈中提取绝对路径、框架版本与代码片段。",
                "堆栈可直接暴露源码路径与未过滤参数。",
                ["debug", "traceback"],
            )
        )
    if "disallowedhost" in body_l:
        findings.append(
            _finding(
                "Django 调试页面泄露",
                "medium",
                "信息泄露",
                web.url,
                "页面包含 DisallowedHost 调试信息",
                "关闭 DEBUG；调试页会泄露 SECRET_KEY、SQL 与全部配置。",
                "Django DEBUG 页面是经典敏感信息泄露点。",
                ["django", "debug"],
            )
        )
    if "whoops!" in body_l and "laravel" in body_l:
        findings.append(
            _finding(
                "Laravel 调试页面泄露",
                "medium",
                "信息泄露",
                web.url,
                "页面出现 Whoops 调试页",
                "关闭 APP_DEBUG；从堆栈中提取环境变量、数据库口令与代码路径。",
                "Laravel Whoops 页面可泄露 APP_KEY 与数据库凭据。",
                ["laravel", "debug"],
            )
        )

    match = FLAG_PATTERN.search(web.body)
    if match:
        findings.append(
            _finding(
                "页面中疑似直接出现 flag",
                "critical",
                "Flag 泄露",
                web.url,
                f"匹配到: {match.group(0)[:120]}",
                "立即核对 flag 格式并提交；检查该页面是否还有其他泄露。",
                "部分简单题目会把 flag 直接放在首页、注释或静态文件中。",
                ["flag"],
            )
        )

    keywords = ("flag", "todo", "admin", "password", "passwd", "secret", "hint", "backup", "debug")
    interesting = []
    for comment in web.comments:
        if any(word in comment.lower() for word in keywords):
            interesting.append(comment)
    if interesting:
        findings.append(
            _finding(
                "HTML 注释包含敏感提示",
                "info",
                "信息泄露",
                web.url,
                " | ".join(interesting[:2])[:400],
                "检查注释中的路径、账号、TODO 与备份提示。",
                "出题人常把提示或 flag 藏在 HTML 注释里。",
                ["comment", "hint"],
            )
        )

    return findings


def active_checks(web: WebTarget, timeout: float) -> list[Finding]:
    """低风险主动验证，可能产生少量额外请求。"""
    findings: list[Finding] = []
    urls = query_urls(web, limit=6)
    tested_sqli: set[str] = set()

    cors = request(
        web.url,
        timeout=min(timeout, 6.0),
        extra_headers={"Origin": "https://ctf-scout.example"},
        max_body=64 * 1024,
    )
    acao = header(cors.headers, "access-control-allow-origin")
    acac = header(cors.headers, "access-control-allow-credentials").lower()
    if acao == "https://ctf-scout.example" and acac == "true":
        findings.append(
            _finding(
                "CORS 反射任意源且允许携带凭据",
                "high",
                "安全配置",
                web.url,
                "Access-Control-Allow-Origin 反射请求 Origin，且 Allow-Credentials: true",
                "限制可信来源白名单；该配置可被跨域读取登录态数据。",
                "CTF 中可结合 XSS 或恶意站点读取用户敏感接口。",
                ["cors"],
            )
        )
    elif acao == "*":
        findings.append(
            _finding(
                "CORS 允许任意来源",
                "info",
                "安全配置",
                web.url,
                "Access-Control-Allow-Origin: *",
                "若接口返回敏感数据，应收紧为可信来源白名单。",
                "若接口无需凭据但数据敏感，仍可能被跨域读取。",
                ["cors"],
            )
        )

    options = request(web.url, method="OPTIONS", timeout=min(timeout, 6.0), max_body=32 * 1024)
    allow = header(options.headers, "allow")
    risky = [m for m in ("PUT", "DELETE", "TRACE", "PATCH") if m in {x.strip().upper() for x in allow.split(",")}]
    if risky:
        findings.append(
            _finding(
                "HTTP 方法配置过宽",
                "low",
                "安全配置",
                web.url,
                f"Allow: {allow}",
                "仅开放业务需要的方法；TRACE 应禁用。",
                "PUT/DELETE 可能允许直接改写或删除资源。",
                ["http-method"],
            )
        )

    for url in urls:
        param = first_param(url)
        if not param:
            continue
        name, value = param
        if name.lower() in SKIP_PARAMS or name.lower() in tested_sqli:
            continue
        tested_sqli.add(name.lower())
        baseline = request(url, timeout=min(timeout, 6.0), max_body=128 * 1024)
        if baseline.status == 0:
            continue
        payload_url = replace_param(url, name, f"{value}'")
        probe = request(payload_url, timeout=min(timeout, 6.0), max_body=128 * 1024)
        if probe.status == 0:
            continue
        probe_l = probe.body.lower()
        baseline_l = baseline.body.lower()
        hit = next((sig for sig in SQL_ERRORS if sig in probe_l and sig not in baseline_l), "")
        if hit:
            findings.append(
                _finding(
                    "疑似 SQL 注入（报错回显）",
                    "high",
                    "主动探测",
                    payload_url,
                    f"参数 {name} 追加单引号后出现数据库报错特征: {hit}",
                    "使用 sqlmap 在授权范围内验证，注意控制 level/risk 与请求频率。",
                    "报错注入可直接拼接 UNION 或 extractvalue 读取 flag 表。",
                    ["sqli"],
                )
            )
            break

    if urls:
        url = urls[0]
        param = first_param(url)
        if param and param[0].lower() not in SKIP_PARAMS:
            name, value = param
            marker = "ctfscout<svg/onload=alert(1)>"
            xss_url = replace_param(url, name, marker)
            baseline = request(url, timeout=min(timeout, 6.0), max_body=128 * 1024)
            probe = request(xss_url, timeout=min(timeout, 6.0), max_body=128 * 1024)
            if probe.status and marker in probe.body and marker not in baseline.body:
                findings.append(
                    _finding(
                        "参数原样回显，疑似反射型 XSS",
                        "medium",
                        "主动探测",
                        xss_url,
                        f"参数 {name} 的 SVG 标签被原样反射到响应体",
                        "手工确认上下文与过滤规则；尝试绕过 WAF 或编码限制。",
                        "反射型 XSS 可用于打管理员 Cookie 或结合 CSRF。",
                        ["xss"],
                    )
                )

    for url in urls:
        param = first_param(url)
        if not param:
            continue
        name = param[0].lower()
        if name not in LFI_PARAMS:
            continue
        payload_url = replace_param(url, param[0], "../../../../etc/passwd")
        probe = request(payload_url, timeout=min(timeout, 6.0), max_body=128 * 1024)
        if probe.status and re.search(r"(root:x:0:0|daemon:x:|www-data:x:)", probe.body):
            findings.append(
                _finding(
                    "疑似本地文件包含（LFI）",
                    "high",
                    "主动探测",
                    payload_url,
                    "读取 /etc/passwd 成功，响应包含系统账号",
                    "尝试读取源码、日志与 /proc/self/environ，或使用 php://filter 链。",
                    "LFI 可进一步通过日志投毒、php filter 链或 session 文件实现 RCE。",
                    ["lfi"],
                )
            )
            break
        win_url = replace_param(url, param[0], "..\\..\\..\\..\\windows\\win.ini")
        win_probe = request(win_url, timeout=min(timeout, 6.0), max_body=128 * 1024)
        if win_probe.status and "[extensions]" in win_probe.body.lower():
            findings.append(
                _finding(
                    "疑似本地文件包含（Windows）",
                    "high",
                    "主动探测",
                    win_url,
                    "读取 windows/win.ini 成功",
                    "尝试包含日志、配置或上传临时文件。",
                    "Windows 下可进一步包含日志或会话文件。",
                    ["lfi"],
                )
            )
            break

    for url in urls:
        param = first_param(url)
        if not param:
            continue
        name = param[0].lower()
        if name not in REDIRECT_PARAMS:
            continue
        payload_url = replace_param(url, param[0], "https://example.com/ctfscout")
        probe = request(payload_url, timeout=min(timeout, 6.0), max_body=64 * 1024, allow_redirects=False)
        location = header(probe.headers, "location")
        if "example.com" in location.lower():
            findings.append(
                _finding(
                    "疑似开放重定向",
                    "low",
                    "主动探测",
                    payload_url,
                    f"Location: {location}",
                    "限制跳转目标为站内白名单；可结合 OAuth 回调窃取 token。",
                    "开放重定向可用于钓鱼与 OAuth token 窃取。",
                    ["redirect"],
                )
            )
            break

    return findings
