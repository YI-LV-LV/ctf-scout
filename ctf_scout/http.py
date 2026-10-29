"""轻量 HTTP 客户端与 HTML 解析工具（仅依赖标准库）。"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 ctf-scout/0.1"
)

_SSL_CONTEXT = ssl.create_default_context()
_SSL_CONTEXT.check_hostname = False
_SSL_CONTEXT.verify_mode = ssl.CERT_NONE


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_len: int = 0
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status != 0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _headers_dict(headers) -> dict[str, str]:
    """把响应头转成小写字典，并保留多条 Set-Cookie。"""
    result: dict[str, str] = {}
    for key, value in headers.items():
        key = key.lower()
        if key == "set-cookie" and key in result:
            result[key] += "\n" + value
        else:
            result[key] = value
    return result


def request(
    url: str,
    method: str = "GET",
    timeout: float = 8.0,
    allow_redirects: bool = True,
    max_body: int = 512 * 1024,
    extra_headers: dict[str, str] | None = None,
) -> Response:
    """发起一次 HTTP 请求，手动处理有限次重定向。"""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)

    opener = urllib.request.build_opener(
        _NoRedirect(),
        urllib.request.HTTPSHandler(context=_SSL_CONTEXT),
    )
    current = url
    origin_host = (urlsplit(url).hostname or "").lower()
    redirects = 0
    while True:
        req = urllib.request.Request(current, headers=headers, method=method)
        try:
            resp = opener.open(req, timeout=timeout)
            status = getattr(resp, "status", 0) or resp.getcode()
            resp_headers = _headers_dict(resp.headers)
            raw = resp.read(max_body + 1)
            resp.close()
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = _headers_dict(exc.headers)
            try:
                raw = exc.read(max_body + 1)
            finally:
                exc.close()
        except Exception as exc:  # noqa: BLE001 - 网络异常统一降级
            reason = getattr(exc, "reason", exc)
            return Response(url=current, status=0, error=str(reason))

        body = _decode(raw, resp_headers)
        location = resp_headers.get("location", "")
        if (
            allow_redirects
            and status in (301, 302, 303, 307, 308)
            and location
            and redirects < 3
        ):
            target = urljoin(current, location)
            next_host = (urlsplit(target).hostname or "").lower()
            if (
                target.startswith(("http://", "https://"))
                and next_host == origin_host
            ):
                current = target
                redirects += 1
                if status == 303:
                    method = "GET"
                continue
        return Response(url=current, status=status, headers=resp_headers, body=body, raw_len=len(raw))


def _decode(raw: bytes, headers: dict[str, str]) -> str:
    charset = "utf-8"
    content_type = headers.get("content-type", "")
    match = re.search(r"charset=([^\s;]+)", content_type, re.I)
    if match:
        charset = match.group(1).strip("\"'")
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def header(headers: dict[str, str], name: str) -> str:
    return headers.get(name.lower(), "")


def build_base_url(scheme: str, host: str, port: int, path: str = "/") -> str:
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if default_port else f"{host}:{port}"
    if not path.startswith("/"):
        path = "/" + path
    return f"{scheme}://{netloc}{path}"


def same_host(url: str, host: str) -> bool:
    parsed = urlsplit(url)
    return (parsed.hostname or "").lower() == host.lower()


def query_urls(web: Any, limit: int = 6) -> list[str]:
    """从页面链接与 GET 表单中收集带参数的 URL。"""
    urls: list[str] = []
    seen: set[str] = set()

    def add(candidate: str) -> None:
        if len(urls) >= limit:
            return
        parsed = urlsplit(candidate)
        if parsed.scheme not in ("http", "https"):
            return
        if not parsed.netloc or not same_host(candidate, web.host):
            return
        if not parsed.query:
            return
        clean = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, parsed.query, ""))
        if clean in seen or len(clean) > 300:
            return
        seen.add(clean)
        urls.append(clean)

    for link in web.links:
        add(urljoin(web.url, link))

    for form in web.forms:
        if (form.get("method") or "GET").upper() != "GET":
            continue
        action = urljoin(web.url, form.get("action") or web.url)
        inputs = [i for i in form.get("inputs", []) if i.get("name")]
        if not inputs:
            continue
        pairs = []
        for item in inputs[:8]:
            name = item["name"]
            value = item.get("value") or "1"
            pairs.append((name, value))
        candidate = action.split("?", 1)[0] + "?" + urlencode(pairs)
        add(candidate)

    return urls


def first_param(url: str) -> tuple[str, str] | None:
    query = urlsplit(url).query
    for name, value in parse_qsl(query, keep_blank_values=True):
        return name, value
    return None


def replace_param(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    new_pairs = [(k, value if k == name else v) for k, v in pairs]
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urlencode(new_pairs), parsed.fragment)
    )


class PageParser(HTMLParser):
    """收集标题、表单、链接、脚本、meta 与注释。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.meta_generator: list[str] = []
        self.comments: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
        elif tag == "form":
            self._form = {
                "action": values.get("action", ""),
                "method": (values.get("method", "GET") or "GET").upper(),
                "inputs": [],
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            name = values.get("name", "")
            if name:
                self._form["inputs"].append(
                    {
                        "name": name,
                        "type": (values.get("type", "text") or "text").lower(),
                        "value": values.get("value", ""),
                    }
                )
        elif tag == "a" and values.get("href"):
            if len(self.links) < 200:
                self.links.append(values["href"])
        elif tag == "script" and values.get("src"):
            if len(self.scripts) < 100:
                self.scripts.append(values["src"])
        elif tag == "meta" and values.get("name", "").lower() == "generator":
            content = values.get("content", "")
            if content:
                self.meta_generator.append(content)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data

    def handle_comment(self, data: str) -> None:
        text = " ".join(data.split())
        if text and len(text) <= 500:
            self.comments.append(text)


def parse_html(body: str) -> PageParser:
    parser = PageParser()
    try:
        parser.feed(body)
    except Exception:  # noqa: BLE001 - 畸形 HTML 忽略
        pass
    parser.title = " ".join(parser.title.split())[:200]
    return parser


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip().lower()
