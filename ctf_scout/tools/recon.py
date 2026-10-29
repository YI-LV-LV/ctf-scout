"""端口扫描与服务指纹。"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor

from ..models import ServiceInfo

PORT_SERVICES = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    81: "http",
    88: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3000: "http",
    3306: "mysql",
    3389: "rdp",
    5000: "http",
    5432: "postgresql",
    5601: "kibana",
    5672: "rabbitmq",
    5900: "vnc",
    5984: "couchdb",
    6379: "redis",
    7001: "weblogic",
    7002: "weblogic-ssl",
    8000: "http",
    8008: "http",
    8009: "ajp",
    8080: "http",
    8081: "http",
    8082: "http",
    8088: "http",
    8090: "http",
    8161: "activemq",
    8180: "http",
    8443: "https",
    8848: "nacos",
    8888: "http",
    9000: "http",
    9090: "http",
    9200: "elasticsearch",
    9300: "elasticsearch-transport",
    9443: "https",
    10000: "webmin",
    11211: "memcached",
    15672: "rabbitmq-mgmt",
    18080: "http",
    27017: "mongodb",
    4444: "unknown-http",
}

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 443, 445, 993,
    995, 1433, 1521, 2049, 2375, 2376, 3000, 3306, 3389, 4444, 5000, 5432,
    5601, 5672, 5900, 5984, 6379, 7001, 7002, 8000, 8008, 8080, 8081, 8082,
    8088, 8090, 8161, 8180, 8443, 8848, 8888, 9000, 9090, 9200, 9300, 9443,
    10000, 11211, 15672, 18080, 27017,
]

HTTP_PORTS = {
    80, 81, 88, 3000, 5000, 5601, 7001, 8000, 8008, 8080, 8081, 8082, 8088,
    8090, 8161, 8180, 8848, 8888, 9000, 9090, 9200, 10000, 15672, 18080, 4444,
}
HTTPS_PORTS = {443, 7002, 8443, 9443}

PRODUCT_PATTERNS = [
    (r"OpenSSH[_\s-]*([\w.]+)?", "OpenSSH"),
    (r"Apache/([\w.]+)", "Apache"),
    (r"nginx/([\w.]+)", "nginx"),
    (r"openresty/([\w.]+)", "OpenResty"),
    (r"Microsoft-IIS/([\w.]+)", "Microsoft-IIS"),
    (r"vsftpd[_\s-]*([\w.]+)?", "vsftpd"),
    (r"Pure-FTPd", "Pure-FTPd"),
    (r"ProFTPD[_\s-]*([\w.]+)?", "ProFTPD"),
    (r"MySQL[_\s-]*([\w.]+)?", "MySQL"),
    (r"MariaDB", "MariaDB"),
    (r"PostgreSQL", "PostgreSQL"),
    (r"Redis", "Redis"),
    (r"MongoDB", "MongoDB"),
    (r"Tomcat/([\w.]+)", "Tomcat"),
    (r"Jenkins", "Jenkins"),
    (r"WebLogic", "WebLogic"),
    (r"RabbitMQ", "RabbitMQ"),
]


def guess_service(port: int) -> str:
    return PORT_SERVICES.get(port, "unknown")


def scan_ports(
    host: str,
    ports: list[int],
    timeout: float = 0.7,
    workers: int = 200,
    progress=None,
) -> list[int]:
    """TCP connect 扫描。"""

    def probe(port: int) -> int | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((host, port)) == 0:
                return port
        finally:
            sock.close()
        return None

    open_ports: list[int] = []
    total = len(ports)
    workers = max(1, min(workers, 512))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for index, result in enumerate(pool.map(probe, ports), start=1):
            if result is not None:
                open_ports.append(result)
            if progress and (index % 2000 == 0 or index == total):
                progress(index, total, open_ports)
    return sorted(open_ports)


def _read_some(sock: socket.socket, limit: int = 8192, timeout: float = 0.9) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        try:
            data = sock.recv(1024)
        except socket.timeout:
            break
        except OSError:
            break
        if not data:
            break
        chunks.append(data)
        total += len(data)
    return b"".join(chunks)


def _identify_product(banner: str) -> str:
    for pattern, name in PRODUCT_PATTERNS:
        if re.search(pattern, banner, re.I):
            return name
    return ""


def probe_service(host: str, port: int, timeout: float = 1.2) -> ServiceInfo:
    """连接端口并抓取 Banner，判断是否为 HTTP 服务。"""
    service = guess_service(port)
    scheme = "https" if port in HTTPS_PORTS else "http"
    is_http = port in HTTP_PORTS or port in HTTPS_PORTS
    banner_text = ""
    product = ""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        if is_http:
            path = "/"
            payload = (
                f"HEAD {path} HTTP/1.0\r\nHost: {host}:{port}\r\n"
                "User-Agent: ctf-scout/0.1\r\nConnection: close\r\n\r\n"
            ).encode()
            sock.sendall(payload)
            raw = _read_some(sock, timeout=min(1.5, timeout))
        elif port == 6379:
            sock.sendall(b"PING\r\n")
            raw = _read_some(sock, timeout=min(1.2, timeout))
        elif port == 11211:
            sock.sendall(b"stats\r\n")
            raw = _read_some(sock, timeout=min(1.2, timeout))
        elif port == 3306 or port == 22:
            # MySQL / SSH 会主动发送握手 Banner
            raw = _read_some(sock, timeout=min(1.2, timeout))
        else:
            raw = _read_some(sock, timeout=min(0.8, timeout))
            if not raw:
                sock.sendall(b"\r\n")
                raw = _read_some(sock, timeout=min(0.8, timeout))
        banner_text = raw.decode("utf-8", errors="replace").replace("\x00", " ").strip()
        if banner_text.upper().startswith("HTTP/") and port not in HTTPS_PORTS:
            is_http = True
            if "https://" in banner_text.lower():
                scheme = "https"
        product = _identify_product(banner_text)
        if product == "OpenSSH":
            service = "ssh"
        elif product in ("MySQL", "MariaDB"):
            service = "mysql"
        elif product == "Redis":
            service = "redis"
    except OSError:
        pass
    finally:
        sock.close()

    banner_text = re.sub(r"\r", " ", banner_text)
    banner_text = re.sub(r"[ \t]+", " ", banner_text)[:400]
    return ServiceInfo(
        port=port,
        service=service,
        banner=banner_text,
        product=product,
        is_http=is_http,
        scheme=scheme,
    )
