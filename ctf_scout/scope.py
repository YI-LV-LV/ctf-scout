"""目标解析与授权范围校验。

工具只允许扫描两类目标：
1. 本机 / 私网 / 链路本地地址；
2. 公网地址，但使用者必须显式通过 --authorized 确认已获得书面授权。
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443}


class ScopeError(ValueError):
    """目标或授权校验失败。"""


@dataclass
class Target:
    original: str
    scheme: str
    host: str
    port: int
    base_path: str
    resolved_ip: str
    is_private: bool


def parse_target(raw: str, default_scheme: str = "http") -> Target:
    """解析 URL、host:port 或裸主机名。"""
    text = (raw or "").strip()
    if not text:
        raise ScopeError("目标不能为空")
    if "[" in text or "]" in text:
        raise ScopeError("暂不支持 IPv6 目标")

    base_path = "/"
    if "://" in text:
        parts = urlsplit(text)
        if parts.scheme not in ("http", "https"):
            raise ScopeError(f"不支持的协议: {parts.scheme}")
        scheme = parts.scheme
        host = parts.hostname or ""
        try:
            port = parts.port or DEFAULT_PORTS[scheme]
        except ValueError as exc:
            raise ScopeError(f"端口不合法: {exc}") from exc
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        base_path = path if path.startswith("/") else "/" + path
    else:
        if "/" in text:
            text, rest = text.split("/", 1)
            base_path = "/" + rest
        scheme = default_scheme
        if text.count(":") == 1:
            host, port_text = text.rsplit(":", 1)
            if not port_text.isdigit():
                raise ScopeError(f"端口不合法: {port_text}")
            port = int(port_text)
        else:
            host = text
            port = DEFAULT_PORTS[scheme]

    host = host.strip()
    if not host:
        raise ScopeError("无法解析目标主机")
    if not 1 <= port <= 65535:
        raise ScopeError("端口必须位于 1-65535")

    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"目标域名解析失败: {host} ({exc})") from exc
    if not infos:
        raise ScopeError(f"目标域名无可用 IPv4 地址: {host}")

    ip_text = infos[0][4][0]
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError as exc:
        raise ScopeError(f"解析结果不是合法 IP: {ip_text}") from exc

    if ip.is_unspecified or ip.is_multicast:
        raise ScopeError(f"拒绝扫描特殊地址: {ip_text}")
    if ip == ipaddress.ip_address("255.255.255.255"):
        raise ScopeError("拒绝扫描广播地址")

    is_private = bool(ip.is_private or ip.is_loopback or ip.is_link_local)
    return Target(
        original=raw,
        scheme=scheme,
        host=host,
        port=port,
        base_path=base_path,
        resolved_ip=ip_text,
        is_private=is_private,
    )


def require_authorization(target: Target, authorized_flag: bool) -> None:
    """公网目标必须显式确认授权。"""
    if target.is_private:
        return
    if not authorized_flag:
        raise ScopeError(
            "目标解析为公网地址 "
            f"{target.resolved_ip}。请确认你已获得该目标的明确测试授权，"
            "然后重新运行并添加 --authorized 参数。"
        )


def parse_ports(spec: str) -> list[int]:
    """解析 '80,443,8000-8100' 形式的端口列表。"""
    ports: set[int] = set()
    for chunk in spec.split(","):
        part = chunk.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ScopeError(f"端口范围不合法: {part}")
            start, end = int(start_text), int(end_text)
            if start > end:
                start, end = end, start
            if not 1 <= start <= 65535 or not 1 <= end <= 65535:
                raise ScopeError(f"端口范围超出 1-65535: {part}")
            ports.update(range(start, end + 1))
        else:
            if not part.isdigit():
                raise ScopeError(f"端口不合法: {part}")
            value = int(part)
            if not 1 <= value <= 65535:
                raise ScopeError(f"端口超出范围: {part}")
            ports.add(value)
    if not ports:
        raise ScopeError("端口列表为空")
    return sorted(ports)
