"""核心数据结构。"""

from __future__ import annotations

import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}
SEVERITY_WEIGHT = {"critical": 50, "high": 20, "medium": 8, "low": 2, "info": 0}


@dataclass
class Finding:
    """一条侦察发现。"""

    title: str
    severity: str
    category: str
    target: str
    evidence: str
    suggestion: str = ""
    ctf_hint: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ServiceInfo:
    """一个开放端口及其指纹。"""

    port: int
    service: str = "unknown"
    banner: str = ""
    product: str = ""
    is_http: bool = False
    scheme: str = ""


@dataclass
class WebTarget:
    """一个 Web 入口的探测结果。"""

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
    def base_url(self) -> str:
        return self.url


@dataclass
class Context:
    """一次扫描的全局上下文，智能体各阶段共享。"""

    input_target: str
    target_host: str
    target_port: int
    scheme: str
    base_path: str
    resolved_ip: str
    is_private: bool
    authorized: bool
    options: dict[str, Any] = field(default_factory=dict)
    open_ports: dict[int, ServiceInfo] = field(default_factory=dict)
    web_targets: list[WebTarget] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    discovered_paths: dict[str, str] = field(default_factory=dict)
    robots_paths: list[str] = field(default_factory=list)
    attack_paths: list[str] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    ai_analysis: str = ""
    logs: list[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0

    def log(self, message: str, level: str = "info") -> None:
        self.logs.append(f"[{time.strftime('%H:%M:%S')}] {level.upper()} {message}")

    def add(self, finding: Finding) -> bool:
        """按标题 + 目标去重；同标题同目标时合并更完整的证据。"""
        for existing in self.findings:
            if existing.title != finding.title or existing.target != finding.target:
                continue
            if SEVERITY_ORDER.get(finding.severity, 9) < SEVERITY_ORDER.get(existing.severity, 9):
                existing.severity = finding.severity
            evidence = re.sub(r"\s+", " ", finding.evidence).strip()
            if evidence and evidence not in existing.evidence and len(existing.evidence) < 700:
                existing.evidence = f"{existing.evidence} | {evidence}"[:800]
            if finding.suggestion and not existing.suggestion:
                existing.suggestion = finding.suggestion
            if finding.ctf_hint and not existing.ctf_hint:
                existing.ctf_hint = finding.ctf_hint
            existing.tags = sorted(set(existing.tags + finding.tags))
            return False
        self.findings.append(finding)
        return True

    def severity_counts(self) -> dict[str, int]:
        counts = {key: 0 for key in SEVERITY_ORDER}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def risk_score(self) -> int:
        score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in self.findings)
        return min(100, score)

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.title),
        )

    @property
    def elapsed(self) -> float:
        end = self.finished_at or time.time()
        return max(0.0, end - self.started_at)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["risk_score"] = self.risk_score()
        data["severity_counts"] = self.severity_counts()
        data["elapsed"] = round(self.elapsed, 2)
        return data
