"""Web 指纹、目录枚举与技术栈定向检查。"""

from __future__ import annotations

import json
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlsplit, urlunsplit

from ..http import header, normalize_text, parse_html, request
from ..models import Finding, WebTarget
from ..wordlists import PATHS, SNIPPET_PATHS


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


def _dir_url(web: WebTarget) -> str:
    parts = urlsplit(web.url)
    path = parts.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _origin(web: WebTarget) -> str:
    parts = urlsplit(web.url)
    return f"{parts.scheme}://{parts.netloc}"


def probe_web(url: str, scheme: str, host: str, port: int, timeout: float) -> WebTarget | None:
    """抓取首页并完成基础指纹。"""
    resp = request(url, timeout=timeout)
    if resp.status == 0:
        return None
    content_type = header(resp.headers, "content-type").lower()
    web = WebTarget(
        url=url,
        scheme=scheme,
        host=host,
        port=port,
        status=resp.status,
        final_url=resp.url,
        headers=resp.headers,
        cookies=[c.strip() for c in header(resp.headers, "set-cookie").split("\n") if c.strip()],
        body=resp.body,
        body_len=resp.raw_len,
    )
    if "html" in content_type or resp.body.lstrip().startswith("<"):
        parsed = parse_html(resp.body)
        web.title = parsed.title
        web.forms = parsed.forms
        web.links = parsed.links
        web.scripts = parsed.scripts
        web.comments = parsed.comments
        web.meta_generator = parsed.meta_generator
    web.technologies = detect_technologies(web)
    if "Elasticsearch" in web.technologies:
        web.skip_enum = True
    return web


def detect_technologies(web: WebTarget) -> list[str]:
    techs: list[str] = []

    def add(name: str) -> None:
        if name and name not in techs:
            techs.append(name)

    server = header(web.headers, "server").lower()
    powered = header(web.headers, "x-powered-by").lower()
    cookies = " ".join(web.cookies).lower()
    body = web.body.lower()
    title = web.title.lower()
    scripts = " ".join(web.scripts).lower()
    meta = " ".join(web.meta_generator).lower()

    for name in ("nginx", "openresty", "apache", "microsoft-iis", "caddy", "lighttpd", "python"):
        if name in server:
            add({"apache": "Apache", "microsoft-iis": "Microsoft-IIS", "python": "Python http.server"}.get(name, name))
    if "tomcat" in server or "coyote" in server:
        add("Tomcat")
    if "php" in powered or "phpsessid" in cookies:
        add("PHP")
    if "asp.net" in powered or "asp.net_sessionid" in cookies:
        add("ASP.NET")
    if "jsessionid" in cookies:
        add("Java")
    if "wp-content" in body or "wp-includes" in body or "wordpress" in meta:
        add("WordPress")
    if "thinkphp" in body:
        add("ThinkPHP")
    if "whitelabel error page" in body or "spring boot" in body or "springframework" in body:
        add("Spring Boot")
    if "swagger-ui" in body or "swagger-resources" in body or "swagger-ui" in title:
        add("Swagger UI")
    if "__next_data__" in body:
        add("Next.js")
    if "csrfmiddlewaretoken" in body:
        add("Django")
    if "laravel_session" in cookies or "laravel" in body:
        add("Laravel")
    if "ci_session" in cookies:
        add("CodeIgniter")
    if "connect.sid" in cookies:
        add("Express")
    if "__nuxt" in body:
        add("Nuxt")
    if "grafana" in body:
        add("Grafana")
    if "jenkins" in body or "jenkins" in title:
        add("Jenkins")
    if "gitlab" in body:
        add("GitLab")
    if "nacos" in body:
        add("Nacos")
    if "druid" in body:
        add("Druid")
    if "phpmyadmin" in body:
        add("phpMyAdmin")
    if '"cluster_name"' in body and '"number_of_nodes"' in body:
        add("Elasticsearch")
    if "kbn-name" in body or "kibana" in body:
        add("Kibana")
    if "jquery" in scripts:
        add("jQuery")
    if "react" in scripts:
        add("React")
    if "vue" in scripts or "__vue__" in body:
        add("Vue.js")
    if "bootstrap" in scripts:
        add("Bootstrap")
    return techs


def _is_soft_404(resp, baseline) -> bool:
    if baseline is None or baseline.status == 0:
        return False
    if resp.status != baseline.status:
        return False
    if resp.status in (401, 403):
        return True
    if resp.status == 200:
        if abs(resp.raw_len - baseline.raw_len) <= max(30, int(baseline.raw_len * 0.03)):
            return True
        ratio = SequenceMatcher(
            None,
            normalize_text(baseline.body)[:1500],
            normalize_text(resp.body)[:1500],
        ).ratio()
        return ratio > 0.85
    if resp.status in (301, 302, 307, 308):
        return resp.headers.get("location", "") == baseline.headers.get("location", "")
    return False


def enum_paths(
    web: WebTarget,
    timeout: float,
    workers: int = 8,
    progress=None,
) -> tuple[list[Finding], dict[str, PathHit], list[str]]:
    """探测常见敏感路径，返回发现、命中集合与 robots 路径。"""
    directory = _dir_url(web)
    random_path = f".ctf-scout-{uuid.uuid4().hex[:8]}"
    baseline = request(urljoin(directory, random_path), timeout=min(timeout, 6.0), max_body=64 * 1024)
    if baseline.status in (401, 403):
        # 整站要求认证时，逐路径探测没有意义，避免制造大量误报
        return [], {}, []

    def fetch(item: tuple[str, tuple[str, str, str]]):
        path, meta = item
        resp = request(urljoin(directory, path), timeout=min(timeout, 6.0), max_body=64 * 1024)
        return path, meta, resp

    findings: list[Finding] = []
    hits: dict[str, PathHit] = {}
    items = list(PATHS.items())
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for index, (path, meta, resp) in enumerate(pool.map(fetch, items), start=1):
            if progress and index % 20 == 0:
                progress(index, len(items))
            if resp.status == 0 or _is_soft_404(resp, baseline):
                continue
            if resp.status not in (200, 201, 204, 301, 302, 307, 308, 401, 403):
                continue

            severity, title, hint = meta
            status_note = ""
            url = urljoin(directory, path)
            body_lower = resp.body.lower()
            if resp.status == 200 and ("index of /" in body_lower or "directory listing for" in body_lower):
                severity = "medium"
                title = f"目录浏览开启: /{path.strip('/')}"
                hint = "关闭目录浏览；下载目录中的备份、源码或上传文件，优先寻找 flag。"
            elif resp.status in (401, 403):
                severity = "low" if severity in ("critical", "high") else "info"
                status_note = "（受保护）"
            elif resp.status in (301, 302, 307, 308):
                status_note = "（跳转）"
                location = resp.headers.get("location", "")
                if location and any(k in location.lower() for k in ("login", "signin", "auth")):
                    title = f"{title}，跳转登录页"

            content_type = header(resp.headers, "content-type")
            snippet = ""
            if path in SNIPPET_PATHS or resp.status == 200:
                snippet = normalize_text(resp.body)[:240]
            parsed_title = ""
            match = re.search(r"<title[^>]*>(.*?)</title>", resp.body, re.I | re.S)
            if match:
                parsed_title = " ".join(match.group(1).split())[:100]

            hit = PathHit(
                path=path,
                url=url,
                status=resp.status,
                length=resp.raw_len,
                content_type=content_type,
                title=parsed_title,
                snippet=snippet,
                body=resp.body,
                location=resp.headers.get("location", ""),
            )
            hits[path] = hit

            evidence_parts = [
                f"HTTP {resp.status}",
                content_type or "未知类型",
                f"{resp.raw_len} 字节",
                url,
            ]
            if parsed_title:
                evidence_parts.append(f"标题: {parsed_title}")
            if hit.location:
                evidence_parts.append(f"Location: {hit.location}")
            if snippet:
                evidence_parts.append(f"片段: {snippet[:200]}")
            tags = ["path", "exposure"]
            lower_path = path.lower()
            if any(k in lower_path for k in ("git", "svn", "env", "backup", "zip", "tar", "sql", "config", "www-data")):
                tags.append("source-leak")
            if lower_path in ("flag", "flag.txt", "flag.php"):
                tags.append("flag")
            if any(k in lower_path for k in ("admin", "manager", "console", "login")):
                tags.append("admin")
            if any(k in lower_path for k in ("swagger", "api-docs", "graphql")) or lower_path.startswith("actuator"):
                tags.append("api")
            if "upload" in lower_path:
                tags.append("upload")
            if "目录浏览开启" in title:
                tags.append("dirlisting")
            finding = Finding(
                title=f"{title}{status_note}",
                severity=severity,
                category="敏感路径",
                target=url,
                evidence=" | ".join(evidence_parts),
                suggestion=hint,
                ctf_hint=hint,
                tags=tags,
            )
            findings.append(finding)

    robots_paths = _parse_robots(hits.get("robots.txt"))
    return findings, hits, robots_paths


def _parse_robots(hit: PathHit | None) -> list[str]:
    if not hit or hit.status != 200:
        return []
    paths: list[str] = []
    for line in hit.body.splitlines():
        match = re.match(r"\s*(?:Disallow|Allow)\s*:\s*(\S+)", line, re.I)
        if not match:
            continue
        value = match.group(1).strip()
        if not value or value == "/" or value.startswith("*"):
            continue
        if not value.startswith("/"):
            value = "/" + value
        if value not in paths:
            paths.append(value)
    return paths[:20]


def tech_checks(web: WebTarget, hits: dict[str, PathHit], timeout: float) -> list[Finding]:
    """针对识别出的技术栈做定向检查。"""
    findings: list[Finding] = []
    techs = set(web.technologies)
    directory = _dir_url(web)
    origin = _origin(web)

    def add(title: str, severity: str, url: str, evidence: str, suggestion: str, hint: str, tags: list[str]) -> None:
        findings.append(
            Finding(
                title=title,
                severity=severity,
                category="技术栈定向检查",
                target=url,
                evidence=evidence,
                suggestion=suggestion,
                ctf_hint=hint,
                tags=tags,
            )
        )

    if "WordPress" in techs:
        login = request(urljoin(directory, "wp-login.php"), timeout=min(timeout, 6.0), max_body=32 * 1024)
        if login.status == 200 and "user_login" in login.body:
            add(
                "WordPress 登录页暴露",
                "low",
                login.url,
                "HTTP 200 | /wp-login.php 含 user_login 表单",
                "确认用户名后谨慎测试弱口令；优先寻找插件漏洞与 xmlrpc 利用面。",
                "wp-login 可用于枚举用户与密码喷洒。",
                ["wordpress", "admin"],
            )
        xmlrpc = request(urljoin(directory, "xmlrpc.php"), timeout=min(timeout, 6.0), max_body=16 * 1024)
        if xmlrpc.status in (200, 405):
            add(
                "WordPress XML-RPC 接口开启",
                "medium",
                xmlrpc.url,
                f"HTTP {xmlrpc.status} | /xmlrpc.php 可访问",
                "可使用 xmlrpc 做 pingback SSRF 或密码爆破；若不需要应在服务端关闭。",
                "xmlrpc.php 常被用于放大攻击与 SSRF。",
                ["wordpress", "xmlrpc"],
            )
        users = request(
            urljoin(directory, "wp-json/wp/v2/users"),
            timeout=min(timeout, 6.0),
            max_body=64 * 1024,
        )
        if users.status == 200 and '"slug"' in users.body:
            add(
                "WordPress REST API 用户枚举",
                "medium",
                users.url,
                f"HTTP 200 | 返回用户对象: {normalize_text(users.body)[:180]}",
                "收集管理员用户名，结合登录页做低频口令测试。",
                "WP REST API 常泄露作者账号。",
                ["wordpress", "user-enum"],
            )

    if "Spring Boot" in techs or any(p.startswith("actuator") for p in hits):
        if "actuator/heapdump" not in hits:
            heap = request(
                urljoin(directory, "actuator/heapdump"),
                method="HEAD",
                timeout=min(timeout, 6.0),
                max_body=1024,
            )
            if heap.status == 200:
                add(
                    "Spring Boot heapdump 可下载",
                    "critical",
                    heap.url,
                    "HTTP 200 | HEAD /actuator/heapdump 成功",
                    "下载堆转储并使用 JDumpSpider / MAT 提取明文口令、数据库连接串与 session。",
                    "heapdump 中常能直接翻到数据库密码甚至 flag。",
                    ["spring", "actuator", "unauth"],
                )
        if not any(path in hits for path in ("actuator/env", "env")):
            for env_path in ("actuator/env", "env"):
                env = request(urljoin(directory, env_path), timeout=min(timeout, 6.0), max_body=128 * 1024)
                if env.status == 200 and "propertySources" in env.body:
                    add(
                        "Spring Boot 环境配置暴露",
                        "high",
                        env.url,
                        f"HTTP 200 | {env_path} 返回 propertySources",
                        "检索 datasource、secret、password、token 等属性，寻找数据库与云服务凭据。",
                        "Actuator env 常直接泄露数据库口令。",
                        ["spring", "actuator", "secret"],
                    )
                    break
        if "actuator" not in hits:
            act = request(urljoin(directory, "actuator"), timeout=min(timeout, 6.0), max_body=32 * 1024)
            if act.status == 200 and "href" in act.body:
                add(
                    "Spring Boot Actuator 端点可访问",
                    "medium",
                    act.url,
                    "HTTP 200 | /actuator 返回端点列表",
                    "逐个检查 env、heapdump、mappings、configprops 等端点。",
                    "Actuator 端点未授权是 Spring 靶场常见入口。",
                    ["spring", "actuator"],
                )

    if "Swagger UI" in techs or any("api-docs" in p or "swagger" in p for p in hits):
        doc_url, doc_body = _find_api_docs(directory, timeout)
        if doc_url and doc_body:
            try:
                data = json.loads(doc_body)
            except json.JSONDecodeError:
                data = {}
            paths = data.get("paths") if isinstance(data, dict) else None
            if isinstance(paths, dict) and paths:
                sample = ", ".join(list(paths.keys())[:10])
                add(
                    "OpenAPI 接口文档暴露",
                    "medium",
                    doc_url,
                    f"共 {len(paths)} 个接口 | 示例: {sample}",
                    "按接口清单测试未授权访问、IDOR 与文件上传。",
                    "接口文档是 CTF Web 题的高价值入口，优先找 admin/upload/exec 类接口。",
                    ["swagger", "api"],
                )

    if "Jenkins" in techs:
        script = request(urljoin(directory, "script"), timeout=min(timeout, 6.0), max_body=32 * 1024)
        if script.status == 200:
            add(
                "Jenkins Script Console 可访问",
                "critical",
                script.url,
                "HTTP 200 | /script 无需认证即可访问",
                "Script Console 可直接执行 Groovy，属于高危未授权。请仅做只读验证。",
                "Jenkins /script 是经典 RCE 入口。",
                ["jenkins", "rce"],
            )
        elif script.status in (401, 403):
            add(
                "Jenkins Script Console 存在但需认证",
                "low",
                script.url,
                f"HTTP {script.status} | /script 受保护",
                "尝试默认口令或已知 CVE，确认版本。",
                "Jenkins 默认口令与历史 CVE 较多。",
                ["jenkins"],
            )

    if "Nacos" in techs or "nacos/" in hits:
        console = request(urljoin(directory, "nacos/"), timeout=min(timeout, 6.0), max_body=32 * 1024)
        if console.status == 200:
            add(
                "Nacos 控制台可访问",
                "medium",
                console.url,
                "HTTP 200 | /nacos/ 控制台可访问",
                "尝试 nacos/nacos 默认口令；登录后检查配置中心的数据库与云密钥。",
                "Nacos 默认口令与未授权配置接口是常见考点。",
                ["nacos", "admin"],
            )

    if "Elasticsearch" in techs:
        indices = request(urljoin(origin + "/", "_cat/indices?v"), timeout=min(timeout, 6.0), max_body=128 * 1024)
        if indices.status == 200 and ("health" in indices.body.lower() or "index" in indices.body.lower()):
            add(
                "Elasticsearch 未授权访问",
                "critical",
                indices.url,
                f"HTTP 200 | /_cat/indices 返回索引信息: {normalize_text(indices.body)[:200]}",
                "使用 _search 读取索引数据，重点查找用户、日志与 flag 索引。",
                "ES 未授权往往可直接读取全部业务数据。",
                ["elasticsearch", "unauth"],
            )

    if "Django" in techs and "debug" in web.body.lower():
        add(
            "Django DEBUG 模式疑似开启",
            "medium",
            web.url,
            "页面中出现 debug 相关关键字",
            "尝试触发异常获取完整 settings 与堆栈，确认 DEBUG 是否开启。",
            "Django DEBUG 页面会泄露密钥与 SQL。",
            ["django", "debug"],
        )

    return findings


def _find_api_docs(directory: str, timeout: float) -> tuple[str, str]:
    candidates = ("v3/api-docs", "v2/api-docs", "api-docs", "swagger-resources")
    for path in candidates:
        resp = request(urljoin(directory, path), timeout=min(timeout, 6.0), max_body=256 * 1024)
        if resp.status != 200:
            continue
        body = resp.body.strip()
        if path == "swagger-resources":
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                continue
            if isinstance(data, list) and data and isinstance(data[0], dict):
                location = data[0].get("location") or data[0].get("url")
                if location:
                    doc = request(urljoin(directory, str(location).lstrip("/")), timeout=min(timeout, 6.0), max_body=256 * 1024)
                    if doc.status == 200:
                        return doc.url, doc.body
            continue
        if '"paths"' in body:
            return resp.url, body
    return "", ""


def fetch_extra_paths(
    web: WebTarget,
    paths: list[str],
    timeout: float,
) -> list[Finding]:
    """跟进 robots.txt 中的路径。"""
    findings: list[Finding] = []
    directory = _dir_url(web)
    for path in paths[:15]:
        resp = request(urljoin(directory, path.lstrip("/")), timeout=min(timeout, 6.0), max_body=64 * 1024)
        if resp.status not in (200, 201, 301, 302, 401, 403):
            continue
        content_type = header(resp.headers, "content-type")
        findings.append(
            Finding(
                title=f"robots.txt 指向的路径可访问: {path}",
                severity="low" if resp.status == 200 else "info",
                category="隐藏路径",
                target=resp.url,
                evidence=f"HTTP {resp.status} | {content_type or '未知类型'} | {resp.raw_len} 字节",
                suggestion="手工访问该路径，确认是否为后台、备份或隐藏接口。",
                ctf_hint="robots.txt 的 Disallow 往往是出题人留下的隐藏入口。",
                tags=["robots", "hidden"],
            )
        )
    return findings
