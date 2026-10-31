"""侦察智能体：规划 -> 执行 -> 根据结果追加任务 -> 分析。"""

from __future__ import annotations

import time
from collections import deque
from typing import Callable

from .http import build_base_url
from .models import Context, WebTarget
from .scope import parse_ports
from .tools import checks, recon, services
from .tools import web as web_tools

TASK_LABELS = {
    "port_scan": "端口扫描",
    "service_probe": "服务识别",
    "http_probe": "Web 入口探测",
    "enum": "敏感路径枚举",
    "passive": "被动信息泄露检查",
    "tech": "技术栈定向检查",
    "robots": "跟进 robots.txt 路径",
    "active": "主动验证",
}


class Agent:
    """一个基于任务队列的轻量智能体。"""

    def __init__(
        self,
        ctx: Context,
        progress: Callable[[str], None] | None = None,
        max_steps: int = 1000,
    ) -> None:
        self.ctx = ctx
        self.progress = progress or (lambda _msg: None)
        self.max_steps = max_steps
        self.queue: deque[tuple[str, object]] = deque()
        self.seen: set[tuple[str, str]] = set()
        self.steps = 0
        self.web_by_url: dict[str, WebTarget] = {}
        self.hits_by_url: dict[str, dict] = {}
        self.robots_by_url: dict[str, list[str]] = {}
        self.open_port_total = 0

    def enqueue(self, kind: str, payload: object = None) -> None:
        key = (kind, str(payload))
        if key in self.seen:
            return
        self.seen.add(key)
        self.queue.append((kind, payload))

    def run(self) -> None:
        self.ctx.log("智能体启动")
        self.enqueue("port_scan")
        while self.queue and self.steps < self.max_steps:
            kind, payload = self.queue.popleft()
            handler = getattr(self, f"_task_{kind}", None)
            if handler is None:
                continue
            self.steps += 1
            self.progress(f"[{self.steps:02d}] {TASK_LABELS.get(kind, kind)}")
            try:
                handler(payload)
            except Exception as exc:  # noqa: BLE001 - 单任务失败不中断整体扫描
                self.ctx.log(f"任务 {kind} 失败: {exc}", "error")
                self.progress(f"  [!] {kind} 执行失败: {exc}")
        if self.queue:
            self.ctx.log("达到最大任务数，剩余任务被截断", "warn")
        self._finalize()

    # ---------- 任务实现 ----------

    def _task_port_scan(self, _payload: object) -> None:
        options = self.ctx.options
        if options.get("full"):
            ports = list(range(1, 65536))
        elif options.get("ports"):
            ports = parse_ports(str(options["ports"]))
        else:
            ports = list(recon.COMMON_PORTS)
        if self.ctx.target_port not in ports:
            ports.append(self.ctx.target_port)
        ports = sorted(set(ports))

        workers = int(options.get("threads", 200))
        connect_timeout = float(options.get("connect_timeout", 0.7))

        def on_progress(done: int, total: int, opened: list[int]) -> None:
            self.progress(f"    进度 {done}/{total}，开放 {len(opened)} 个")

        open_ports = recon.scan_ports(
            self.ctx.target_host,
            ports,
            timeout=connect_timeout,
            workers=workers,
            progress=on_progress,
        )
        self.open_port_total = len(open_ports)
        if not open_ports:
            self.ctx.log("未发现开放端口", "warn")
            self.progress("  [!] 未发现开放端口")
            return
        self.ctx.log(f"端口扫描完成，开放端口: {', '.join(map(str, open_ports))}")
        self.progress(f"  [+] 开放端口: {', '.join(map(str, open_ports))}")
        for port in open_ports:
            self.enqueue("service_probe", port)

    def _task_service_probe(self, payload: object) -> None:
        port = int(payload)
        info = recon.probe_service(self.ctx.target_host, port, timeout=1.2)
        self.ctx.open_ports[port] = info
        label = f"{port}/{info.service}"
        if info.product:
            label += f" ({info.product})"
        self.progress(f"  [+] {label}")
        if info.banner:
            self.ctx.log(f"{port} Banner: {info.banner[:160]}")

        if info.is_http or port in recon.HTTP_PORTS or port in recon.HTTPS_PORTS:
            scheme = info.scheme or ("https" if port in recon.HTTPS_PORTS else "http")
            self.enqueue("http_probe", (scheme, port))
        elif info.service == "unknown":
            # 未知端口可能是自定义端口上的 Web 应用，先尝试一次 HTTP 探测
            self.enqueue("http_probe", (info.scheme or "http", port))

    def _task_http_probe(self, payload: object) -> None:
        scheme, port = payload  # type: ignore[misc]
        path = self.ctx.base_path if port == self.ctx.target_port else "/"
        url = build_base_url(scheme, str(self.ctx.target_host), int(port), path)
        timeout = float(self.ctx.options.get("timeout", 8.0))
        web = web_tools.probe_web(url, scheme, str(self.ctx.target_host), int(port), timeout)

        if web is None:
            alt = "https" if scheme == "http" else "http"
            alt_url = build_base_url(alt, str(self.ctx.target_host), int(port), path)
            web = web_tools.probe_web(alt_url, alt, str(self.ctx.target_host), int(port), timeout)
            if web is not None:
                scheme = alt

        if web is None:
            self.progress(f"  [-] {port} 未响应 Web 探测")
            return

        if web.url in self.web_by_url:
            return
        self.web_by_url[web.url] = web
        self.ctx.web_targets.append(web)
        tech = ", ".join(web.technologies) or "未识别"
        self.progress(f"  [+] Web {web.url} -> HTTP {web.status} | {web.title or '无标题'} | {tech}")
        self.ctx.log(f"Web 入口 {web.url} | HTTP {web.status} | 指纹: {tech}")

        if not web.skip_enum:
            self.enqueue("enum", web.url)
        self.enqueue("passive", web.url)
        self.enqueue("tech", web.url)
        if self.ctx.options.get("active"):
            self.enqueue("active", web.url)

    def _task_enum(self, payload: object) -> None:
        web = self.web_by_url.get(str(payload))
        if not web:
            return
        timeout = float(self.ctx.options.get("timeout", 8.0))

        def on_progress(done: int, total: int) -> None:
            if done % 20 == 0:
                self.progress(f"    路径进度 {done}/{total}")

        findings, hits, robots = web_tools.enum_paths(web, timeout, workers=8, progress=on_progress)
        self.hits_by_url[web.url] = hits
        for finding in findings:
            self.ctx.add(finding)
        for hit in hits.values():
            self.ctx.discovered_paths[hit.url] = f"HTTP {hit.status}"
        self.progress(f"  [+] 路径命中 {len(hits)} 个")
        self.ctx.log(f"{web.url} 敏感路径命中 {len(hits)} 个")

        if robots:
            self.robots_by_url[web.url] = robots
            self.ctx.robots_paths = sorted(set(self.ctx.robots_paths + robots))
            self.ctx.log(f"robots.txt 发现 {len(robots)} 个路径，加入跟进队列")
            self.progress(f"  [+] robots.txt 路径: {', '.join(robots[:5])}")
            self.enqueue("robots", web.url)

    def _task_robots(self, payload: object) -> None:
        web = self.web_by_url.get(str(payload))
        paths = self.robots_by_url.get(str(payload), [])
        if not web or not paths:
            return
        timeout = float(self.ctx.options.get("timeout", 8.0))
        known = {hit.path.strip("/") for hit in self.hits_by_url.get(web.url, {}).values()}
        follow = [path for path in paths if path.strip("/") not in known]
        for finding in web_tools.fetch_extra_paths(web, follow, timeout):
            self.ctx.add(finding)
            self.progress(f"  [+] robots 路径可访问: {finding.target}")

    def _task_passive(self, payload: object) -> None:
        web = self.web_by_url.get(str(payload))
        if not web:
            return
        timeout = float(self.ctx.options.get("timeout", 8.0))
        for finding in checks.passive_checks(web, timeout):
            self.ctx.add(finding)

    def _task_tech(self, payload: object) -> None:
        web = self.web_by_url.get(str(payload))
        if not web:
            return
        timeout = float(self.ctx.options.get("timeout", 8.0))
        hits = self.hits_by_url.get(web.url, {})
        for finding in web_tools.tech_checks(web, hits, timeout):
            self.ctx.add(finding)
            self.progress(f"  [+] {finding.title}")

    def _task_active(self, payload: object) -> None:
        web = self.web_by_url.get(str(payload))
        if not web:
            return
        timeout = float(self.ctx.options.get("timeout", 8.0))
        self.progress("  正在做低风险主动验证（SQLi / XSS / LFI / 重定向 / CORS）")
        for finding in checks.active_checks(web, timeout):
            self.ctx.add(finding)
            self.progress(f"  [+] {finding.title}")

    # ---------- 分析与收尾 ----------

    def _finalize(self) -> None:
        self.ctx.log("进入分析与收尾阶段")
        self.progress("[*] 汇总服务风险与未授权访问")
        for finding in services.passive_service_findings(self.ctx):
            self.ctx.add(finding)
        if self.ctx.options.get("active"):
            for finding in services.active_service_checks(
                self.ctx, float(self.ctx.options.get("timeout", 8.0))
            ):
                if self.ctx.add(finding):
                    self.progress(f"  [+] {finding.title}")
        self._build_attack_paths()
        self._build_commands()
        self.ctx.finished_at = time.time()
        counts = self.ctx.severity_counts()
        self.ctx.log(
            "扫描完成，发现 "
            f"{len(self.ctx.findings)} 项（严重 {counts['critical']} / 高危 {counts['high']} / "
            f"中危 {counts['medium']} / 低危 {counts['low']} / 信息 {counts['info']}）"
        )
        self.progress(
            f"[*] 完成：{len(self.ctx.findings)} 项发现，风险评分 {self.ctx.risk_score()}/100"
        )

    def _build_attack_paths(self) -> None:
        tags: set[str] = set()
        for finding in self.ctx.findings:
            tags.update(finding.tags)
        paths: list[str] = []

        if "flag" in tags:
            paths.append("页面或路径中已出现 flag 格式内容，优先核对并提交。")
        if "source-leak" in tags:
            paths.append("源码/配置泄露：还原源码或读取 .env，审计硬编码凭据、历史提交与过滤逻辑。")
        if "unauth" in tags:
            paths.append("未授权服务/接口：只读确认数据范围，优先从 Redis、Docker、ES 或 Actuator 中提取数据。")
        if "sqli" in tags:
            paths.append("SQL 注入：使用 sqlmap 验证后提取数据，重点关注 flag、users 与配置表。")
        if "lfi" in tags:
            paths.append("文件包含：读取源码与日志，尝试 php://filter 链、日志投毒或会话文件包含。")
        if "admin" in tags:
            paths.append("后台入口：枚举管理员账号，测试默认口令、弱口令与后台文件上传。")
        if "api" in tags:
            paths.append("接口暴露：按文档或前端 JS 遍历未授权接口，测试 IDOR、参数篡改与文件上传。")
        if "dirlisting" in tags:
            paths.append("目录浏览：下载备份、源码与数据库导出，寻找 flag 与下一层入口。")
        if "upload" in tags:
            paths.append("上传点：测试扩展名、Content-Type、文件头与解析路径绕过。")
        if "xss" in tags:
            paths.append("反射型 XSS：确认上下文后尝试获取管理员会话或触发后台操作。")
        if "redirect" in tags:
            paths.append("开放重定向：结合 OAuth 回调或钓鱼流程窃取凭据。")
        if "cors" in tags:
            paths.append("CORS 配置不当：从恶意页面跨域读取登录态接口。")
        if not paths:
            paths.append("暂未发现明显突破口：检查前端 JS 中的隐藏接口、参数差异与 404 页面，并考虑非 Web 服务。")
        self.ctx.attack_paths = paths

    def _build_commands(self) -> None:
        ctx = self.ctx
        host = ctx.target_host
        commands: list[str] = []

        port_list = ",".join(str(p) for p in list(ctx.open_ports)[:20]) or str(ctx.target_port)
        commands.append(f"nmap -sV -p{port_list} {host}")

        def targets_with_tag(tag: str) -> list[str]:
            return [f.target for f in ctx.findings if tag in f.tags]

        git_targets = [t for t in targets_with_tag("source-leak") if ".git" in t]
        if git_targets:
            base = git_targets[0].rsplit("/", 1)[0]
            commands.append(f"git-dumper {base} ./loot_git")

        sqli_targets = targets_with_tag("sqli")
        if sqli_targets:
            commands.append(f'sqlmap -u "{sqli_targets[0]}" --batch --level 2 --risk 1')

        lfi_targets = targets_with_tag("lfi")
        if lfi_targets:
            commands.append(f'curl -s "{lfi_targets[0]}"')

        if "WordPress" in {t for w in ctx.web_targets for t in w.technologies}:
            web = next((w for w in ctx.web_targets if "WordPress" in w.technologies), None)
            if web:
                commands.append(f"wpscan --url {web.url} --enumerate vp,u --disable-tls-checks")

        for port, info in sorted(ctx.open_ports.items()):
            if info.service == "redis":
                commands.append(f"redis-cli -h {host} -p {port} info")
            elif info.service.startswith("docker"):
                scheme = "https" if port == 2376 else "http"
                commands.append(f"docker -H {scheme}://{host}:{port} ps")
            elif info.service == "elasticsearch":
                commands.append(f'curl -s "http://{host}:{port}/_cat/indices?v"')
            elif info.service == "ssh":
                commands.append(f"ssh-audit {host}")

        docs = [t for t in targets_with_tag("api") if "api-docs" in t]
        if docs:
            commands.append(f'curl -s "{docs[0]}"')

        primary = next(
            (w for w in ctx.web_targets if w.port == ctx.target_port and w.scheme == ctx.scheme),
            None,
        )
        if primary:
            commands.append(f"curl -i {primary.url}")
        elif ctx.web_targets:
            commands.append(f"curl -i {ctx.web_targets[0].url}")

        # 去重并限制数量
        seen: set[str] = set()
        result: list[str] = []
        for command in commands:
            if command in seen:
                continue
            seen.add(command)
            result.append(command)
        ctx.commands = result[:8]
