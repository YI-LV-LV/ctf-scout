"""非 Web 服务的指纹提示与未授权访问验证。"""

from __future__ import annotations

import ftplib
import json
import socket

from ..http import request
from ..models import Context, Finding

SERVICE_HINTS = {
    21: ("FTP 服务暴露", "info", "尝试匿名登录：ftp <host> <port>；或 nmap --script ftp-anon。"),
    22: ("SSH 服务暴露", "info", "使用 ssh-audit 检查加密套件；确认版本是否存在已知漏洞。"),
    23: ("Telnet 服务暴露", "medium", "Telnet 明文传输，尝试连接并观察登录提示与默认口令。"),
    25: ("SMTP 服务暴露", "info", "尝试 VRFY/EXPN 枚举用户，或 smtp-user-enum。"),
    139: ("NetBIOS 服务暴露", "info", "使用 enum4linux-ng 枚举共享、用户与域信息。"),
    445: ("SMB 服务暴露", "info", "使用 smbclient -L 与 enum4linux-ng 检查匿名共享与弱口令。"),
    1433: ("MSSQL 服务暴露", "info", "确认是否允许弱口令登录；检查 xp_cmdshell 是否开启。"),
    1521: ("Oracle 服务暴露", "info", "检查默认账号与 TNS 监听器信息泄露。"),
    3306: ("MySQL 服务暴露", "info", "尝试默认/弱口令登录；登录后检查 FILE 权限与 UDF。"),
    5432: ("PostgreSQL 服务暴露", "info", "尝试默认口令；检查 pg_read_file 等文件读取能力。"),
    5900: ("VNC 服务暴露", "low", "尝试无认证连接或弱口令，VNC 常直接暴露桌面。"),
    5984: ("CouchDB 服务暴露", "medium", "检查 /_all_dbs 是否未授权，可能直接读取全部数据库。"),
    6379: ("Redis 服务暴露", "medium", "确认是否未授权：redis-cli -h <host> -p <port> ping。"),
    7001: ("WebLogic 服务暴露", "medium", "确认版本并检索历史反序列化漏洞；优先检查 T3/IIOP。"),
    7002: ("WebLogic 服务暴露", "medium", "确认版本并检索历史反序列化漏洞。"),
    8161: ("ActiveMQ 服务暴露", "medium", "检查 /admin 默认口令与 CVE-2016-3088 文件写入。"),
    8848: ("Nacos 服务暴露", "medium", "尝试 nacos/nacos 默认口令与未授权配置接口。"),
    11211: ("Memcached 服务暴露", "medium", "使用 stats 命令确认是否未授权，可能泄露缓存数据。"),
    15672: ("RabbitMQ 管理端暴露", "info", "尝试 guest/guest 默认口令登录管理面板。"),
    2375: ("Docker API 端口开放", "high", "确认是否未授权：curl http://<host>:<port>/version。"),
    2376: ("Docker TLS API 端口开放", "medium", "检查客户端证书是否可绕过或存在默认证书。"),
    27017: ("MongoDB 服务暴露", "medium", "确认是否允许无认证连接，登录后导出全部集合。"),
    9200: ("Elasticsearch 服务暴露", "medium", "检查 /_cat/indices 是否未授权。"),
}


def passive_service_findings(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for port, info in sorted(ctx.open_ports.items()):
        if info.is_http:
            continue
        hint = SERVICE_HINTS.get(port)
        if not hint:
            continue
        title, severity, suggestion = hint
        evidence_bits = [info.service]
        if info.product:
            evidence_bits.append(info.product)
        if info.banner:
            evidence_bits.append(info.banner[:200])
        findings.append(
            Finding(
                title=title,
                severity=severity,
                category="服务暴露",
                target=f"{ctx.target_host}:{port}",
                evidence=" | ".join(evidence_bits),
                suggestion=suggestion,
                ctf_hint=suggestion,
                tags=["service", "port"],
            )
        )
    return findings


def active_service_checks(ctx: Context, timeout: float) -> list[Finding]:
    """只做读取类验证，不执行写入或破坏性命令。"""
    findings: list[Finding] = []
    host = ctx.target_host
    budget = min(timeout, 6.0)

    for port in ctx.open_ports:
        if port == 21:
            finding = _ftp_anonymous(host, port, budget)
            if finding:
                findings.append(finding)
        elif port == 6379:
            finding = _redis_unauth(host, port, budget)
            if finding:
                findings.append(finding)
        elif port == 11211:
            finding = _memcached_unauth(host, port, budget)
            if finding:
                findings.append(finding)
        elif port in (2375, 2376):
            finding = _docker_unauth(host, port, budget)
            if finding:
                findings.append(finding)
        elif port == 9200:
            finding = _elasticsearch_unauth(host, port, budget)
            if finding:
                findings.append(finding)
        elif port == 5984:
            finding = _couchdb_unauth(host, port, budget)
            if finding:
                findings.append(finding)

    return findings


def _ftp_anonymous(host: str, port: int, timeout: float) -> Finding | None:
    ftp = ftplib.FTP()
    try:
        ftp.connect(host, port, timeout=timeout)
        welcome = ftp.getwelcome()
        ftp.login("anonymous", "anonymous")
        ftp.voidcmd("NOOP")
    except Exception:  # noqa: BLE001 - 认证失败即视为不可匿名
        return None
    finally:
        try:
            ftp.close()
        except Exception:  # noqa: BLE001
            pass
    return Finding(
        title="FTP 匿名登录可用",
        severity="critical",
        category="未授权访问",
        target=f"{host}:{port}",
        evidence=f"匿名登录成功 | 欢迎信息: {welcome[:200]}",
        suggestion="列出目录并检查是否有源码、备份或 flag 文件。",
        ctf_hint="FTP 匿名访问常直接给出源码或备份。",
        tags=["ftp", "unauth"],
    )


def _redis_unauth(host: str, port: int, timeout: float) -> Finding | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(b"PING\r\n")
        data = sock.recv(256).decode("utf-8", errors="replace")
    except OSError:
        return None
    finally:
        sock.close()
    if "+PONG" not in data:
        return None
    return Finding(
        title="Redis 未授权访问",
        severity="critical",
        category="未授权访问",
        target=f"{host}:{port}",
        evidence=f"PING 返回: {data.strip()[:120]}",
        suggestion="使用 INFO / CONFIG GET 只读确认权限；不要写入 key，避免影响赛题状态。",
        ctf_hint="Redis 未授权常可通过写入 SSH key、crontab 或 webshell 获取权限。",
        tags=["redis", "unauth"],
    )


def _memcached_unauth(host: str, port: int, timeout: float) -> Finding | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(b"stats\r\n")
        chunks = []
        while len(b"".join(chunks)) < 4096:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"END\r\n" in data:
                break
    except OSError:
        return None
    finally:
        sock.close()
    text = b"".join(chunks).decode("utf-8", errors="replace")
    if "STAT " not in text:
        return None
    return Finding(
        title="Memcached 未授权访问",
        severity="high",
        category="未授权访问",
        target=f"{host}:{port}",
        evidence=f"stats 命令返回: {text[:160]}",
        suggestion="使用 stats items / get 读取缓存内容，注意不要 flush 或写入。",
        ctf_hint="Memcached 中可能缓存 session、凭据或 flag。",
        tags=["memcached", "unauth"],
    )


def _docker_unauth(host: str, port: int, timeout: float) -> Finding | None:
    scheme = "https" if port == 2376 else "http"
    resp = request(f"{scheme}://{host}:{port}/version", timeout=timeout, max_body=64 * 1024)
    if resp.status != 200:
        return None
    try:
        data = json.loads(resp.body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict) or "ApiVersion" not in data:
        return None
    return Finding(
        title="Docker API 未授权访问",
        severity="critical",
        category="未授权访问",
        target=resp.url,
        evidence=f"ApiVersion: {data.get('ApiVersion')} | Version: {data.get('Version')}",
        suggestion="只读列出容器与镜像，确认权限边界；不要创建或删除容器。",
        ctf_hint="Docker API 未授权可通过挂载宿主机目录获取 flag。",
        tags=["docker", "unauth"],
    )


def _elasticsearch_unauth(host: str, port: int, timeout: float) -> Finding | None:
    resp = request(f"http://{host}:{port}/_cat/indices?v", timeout=timeout, max_body=128 * 1024)
    if resp.status != 200 or "health" not in resp.body.lower():
        return None
    return Finding(
        title="Elasticsearch 未授权访问",
        severity="critical",
        category="未授权访问",
        target=resp.url,
        evidence=f"/_cat/indices 返回: {resp.body[:200]}",
        suggestion="使用 _search 只读查询索引，重点查找用户、日志与 flag。",
        ctf_hint="ES 未授权通常可直接读取全部索引数据。",
        tags=["elasticsearch", "unauth"],
    )


def _couchdb_unauth(host: str, port: int, timeout: float) -> Finding | None:
    resp = request(f"http://{host}:{port}/_all_dbs", timeout=timeout, max_body=64 * 1024)
    if resp.status != 200:
        return None
    try:
        data = json.loads(resp.body)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list):
        return None
    return Finding(
        title="CouchDB 未授权访问",
        severity="high",
        category="未授权访问",
        target=resp.url,
        evidence=f"/_all_dbs 返回 {len(data)} 个数据库: {', '.join(map(str, data[:5]))}",
        suggestion="只读查看数据库文档，寻找凭据与 flag。",
        ctf_hint="CouchDB 未授权可读取全部文档。",
        tags=["couchdb", "unauth"],
    )
