"""控制台输出与 Markdown / JSON / HTML 报告。"""

from __future__ import annotations

import html
import json
import os
import re
import time
from typing import Any

from .models import SEVERITY_LABEL, Context

ANSI = {
    "critical": "91",
    "high": "93",
    "medium": "33",
    "low": "94",
    "info": "90",
    "accent": "92",
    "muted": "90",
    "bold": "1",
}


def _paint(text: str, code: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"\033[{code}m{text}\033[0m"


def _sev_label(severity: str) -> str:
    return SEVERITY_LABEL.get(severity, severity)


def _md(text: str, limit: int = 400) -> str:
    cleaned = re.sub(r"\s+", " ", str(text)).strip()
    if len(cleaned) > limit:
        cleaned = cleaned[:limit] + "..."
    return cleaned.replace("|", "\\|")


def _safe_name(host: str, port: int) -> str:
    prefix = re.sub(r"[^A-Za-z0-9._-]+", "_", host)[:60] or "target"
    return f"{prefix}_{port}_{time.strftime('%Y%m%d_%H%M%S')}"


def print_summary(ctx: Context, color: bool = True) -> None:
    counts = ctx.severity_counts()
    print()
    print(_paint("=" * 68, ANSI["accent"], color))
    print(_paint("  CTF SCOUT 侦察结果", ANSI["bold"], color))
    print(_paint("=" * 68, ANSI["accent"], color))
    print(f"  目标      : {ctx.input_target}")
    print(f"  解析地址  : {ctx.resolved_ip} ({'本机/私网' if ctx.is_private else '公网，已确认授权'})")
    print(f"  耗时      : {ctx.elapsed:.1f}s")
    print(f"  风险评分  : {ctx.risk_score()}/100")
    print(
        "  发现统计  : "
        + "  ".join(
            f"{_sev_label(sev)} {counts[sev]}" for sev in ("critical", "high", "medium", "low", "info")
        )
    )
    ports = ", ".join(str(p) for p in sorted(ctx.open_ports)) or "无"
    print(f"  开放端口  : {ports}")

    if ctx.findings:
        print()
        print(_paint("  发现清单（按严重度）", ANSI["bold"], color))
        for finding in ctx.sorted_findings()[:12]:
            tag = _paint(f"[{_sev_label(finding.severity)}]", ANSI.get(finding.severity, "0"), color)
            print(f"  {tag} {finding.title}")
            print(f"       目标: {finding.target}")
            evidence = re.sub(r"\s+", " ", finding.evidence)[:150]
            print(_paint(f"       证据: {evidence}", ANSI["muted"], color))
        if len(ctx.findings) > 12:
            print(_paint(f"       ... 其余 {len(ctx.findings) - 12} 项见完整报告", ANSI["muted"], color))

    if ctx.attack_paths:
        print()
        print(_paint("  推荐攻击路径", ANSI["bold"], color))
        for index, path in enumerate(ctx.attack_paths[:6], start=1):
            print(f"  {index}. {path}")

    if ctx.commands:
        print()
        print(_paint("  建议验证命令（仅手动执行）", ANSI["bold"], color))
        for command in ctx.commands:
            print(_paint(f"    {command}", ANSI["accent"], color))
    print()


def render_markdown(ctx: Context) -> str:
    counts = ctx.severity_counts()
    lines: list[str] = []
    lines.append("# CTF 侦察报告")
    lines.append("")
    lines.append("> 本报告由 ctf-scout 自动生成，仅用于已授权的 CTF / 靶场 / 自有资产。")
    lines.append("")
    lines.append("## 基本信息")
    lines.append("")
    lines.append(f"- 目标: `{ctx.input_target}`")
    lines.append(f"- 解析地址: `{ctx.resolved_ip}`（{'本机/私网' if ctx.is_private else '公网，用户已确认授权'}）")
    lines.append(f"- 扫描时间: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ctx.started_at))}")
    lines.append(f"- 耗时: {ctx.elapsed:.1f}s")
    lines.append(f"- 风险评分: **{ctx.risk_score()}/100**")
    lines.append(
        "- 发现统计: "
        + " / ".join(f"{_sev_label(sev)} {counts[sev]}" for sev in ("critical", "high", "medium", "low", "info"))
    )
    lines.append("")

    lines.append("## 资产概览")
    lines.append("")
    lines.append("### 开放端口")
    lines.append("")
    if ctx.open_ports:
        lines.append("| 端口 | 服务 | 产品 | Banner 摘要 |")
        lines.append("| --- | --- | --- | --- |")
        for port, info in sorted(ctx.open_ports.items()):
            banner = _md(info.banner, 90) if info.banner else "-"
            lines.append(f"| {port} | {info.service} | {info.product or '-'} | {banner} |")
    else:
        lines.append("未发现开放端口。")
    lines.append("")

    lines.append("### Web 入口")
    lines.append("")
    if ctx.web_targets:
        for web in ctx.web_targets:
            lines.append(f"- `{web.url}` → HTTP {web.status}，标题: {web.title or '无'}")
            lines.append(f"  - 指纹: {', '.join(web.technologies) or '未识别'}")
            if web.forms:
                lines.append(f"  - 表单: {len(web.forms)} 个")
    else:
        lines.append("未发现可识别的 Web 入口。")
    lines.append("")

    lines.append("## 漏洞与发现")
    lines.append("")
    if ctx.findings:
        for finding in ctx.sorted_findings():
            lines.append(f"### [{_sev_label(finding.severity)}] {finding.title}")
            lines.append("")
            lines.append(f"- 类别: {finding.category}")
            lines.append(f"- 目标: `{finding.target}`")
            lines.append(f"- 证据: {_md(finding.evidence, 500)}")
            if finding.suggestion:
                lines.append(f"- 建议: {_md(finding.suggestion, 400)}")
            if finding.ctf_hint and finding.ctf_hint != finding.suggestion:
                lines.append(f"- CTF 思路: {_md(finding.ctf_hint, 400)}")
            lines.append("")
    else:
        lines.append("未发现明显问题。建议检查前端 JS、参数差异与隐藏接口。")
        lines.append("")

    lines.append("## 推荐攻击路径")
    lines.append("")
    for index, path in enumerate(ctx.attack_paths, start=1):
        lines.append(f"{index}. {path}")
    lines.append("")

    lines.append("## 建议验证命令")
    lines.append("")
    lines.append("```bash")
    for command in ctx.commands:
        lines.append(command)
    lines.append("```")
    lines.append("")

    if ctx.ai_analysis:
        lines.append("## AI 辅助分析")
        lines.append("")
        lines.append(ctx.ai_analysis.strip())
        lines.append("")

    lines.append("## 已发现路径")
    lines.append("")
    if ctx.discovered_paths:
        lines.append("| URL | 状态 |")
        lines.append("| --- | --- |")
        for url, status in list(ctx.discovered_paths.items())[:80]:
            lines.append(f"| `{url}` | {status} |")
    else:
        lines.append("无。")
    lines.append("")

    lines.append("## 附：侦察日志")
    lines.append("")
    lines.append("```text")
    lines.extend(ctx.logs[-40:])
    lines.append("```")
    lines.append("")
    lines.append("> 报告可能包含账号、密钥、flag 等敏感信息，请勿公开分享。")
    lines.append("")
    return "\n".join(lines)


def _json_payload(ctx: Context) -> dict[str, Any]:
    return {
        "tool": "ctf-scout",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "target": {
            "input": ctx.input_target,
            "host": ctx.target_host,
            "port": ctx.target_port,
            "scheme": ctx.scheme,
            "base_path": ctx.base_path,
            "resolved_ip": ctx.resolved_ip,
            "is_private": ctx.is_private,
            "authorized": ctx.authorized,
        },
        "risk_score": ctx.risk_score(),
        "severity_counts": ctx.severity_counts(),
        "elapsed": round(ctx.elapsed, 2),
        "ports": [
            {
                "port": info.port,
                "service": info.service,
                "product": info.product,
                "banner": info.banner,
                "is_http": info.is_http,
                "scheme": info.scheme,
            }
            for info in sorted(ctx.open_ports.values(), key=lambda i: i.port)
        ],
        "web_targets": [
            {
                "url": web.url,
                "status": web.status,
                "title": web.title,
                "technologies": web.technologies,
                "forms": web.forms,
                "headers": web.headers,
            }
            for web in ctx.web_targets
        ],
        "findings": [finding.to_dict() for finding in ctx.sorted_findings()],
        "discovered_paths": ctx.discovered_paths,
        "attack_paths": ctx.attack_paths,
        "commands": ctx.commands,
        "ai_analysis": ctx.ai_analysis,
        "logs": ctx.logs,
    }


def render_json(ctx: Context) -> str:
    return json.dumps(_json_payload(ctx), ensure_ascii=False, indent=2)


def render_html(ctx: Context) -> str:
    counts = ctx.severity_counts()
    score = ctx.risk_score()
    findings_html = _render_findings_html(ctx)
    ports_html = _render_ports_html(ctx)
    web_html = _render_web_html(ctx)
    paths_html = _render_paths_html(ctx)
    paths_section = (
        f'<section class="panel"><h2>已发现路径</h2>{paths_html}</section>' if paths_html else ""
    )
    ai_section = (
        f'<section class="panel"><h2>AI 辅助分析</h2><div class="ai">{html.escape(ctx.ai_analysis)}</div></section>'
        if ctx.ai_analysis
        else ""
    )
    commands_html = "".join(
        f"<li><code>{html.escape(command)}</code></li>" for command in ctx.commands
    ) or "<li>无</li>"
    attack_html = "".join(f"<li>{html.escape(path)}</li>" for path in ctx.attack_paths) or "<li>无</li>"
    logs = html.escape("\n".join(ctx.logs[-50:]))
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    scope_text = "本机 / 私网目标" if ctx.is_private else "公网目标，用户已确认授权"
    target = html.escape(ctx.input_target)
    title = html.escape(ctx.target_host)
    tech_list = ", ".join({t for w in ctx.web_targets for t in w.technologies}) or "未识别"

    cards = ""
    for sev in ("critical", "high", "medium", "low", "info"):
        cards += (
            f'<div class="stat sev-{sev}"><span class="num">{counts[sev]}</span>'
            f'<span class="lbl">{_sev_label(sev)}</span></div>'
        )

    template = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CTF 侦察报告 - __TITLE__</title>
<style>
:root {
  --bg: #080c11; --panel: #0f161d; --panel2: #131d26; --line: #22303c;
  --text: #e7f0f6; --muted: #8da2b3; --accent: #35e0a1;
  --critical: #ff5d5d; --high: #ff9f43; --medium: #ffd166; --low: #6fb3ff; --info: #9aa7b1;
}
* { box-sizing: border-box; }
body {
  margin: 0; background: radial-gradient(circle at 15% 0%, #0f2027 0, var(--bg) 45%);
  color: var(--text); font-family: "Segoe UI", "PingFang SC", "Microsoft YaHei", system-ui, sans-serif;
  line-height: 1.65;
}
.wrap { max-width: 1080px; margin: 0 auto; padding: 44px 24px 70px; }
.kicker { color: var(--accent); letter-spacing: .28em; font-size: 12px; font-weight: 700; margin: 0 0 10px; }
h1 { font-size: 34px; margin: 0 0 14px; letter-spacing: -.02em; }
h2 { font-size: 20px; margin: 0 0 16px; border-left: 3px solid var(--accent); padding-left: 12px; }
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; color: var(--muted); font-size: 14px; }
.meta strong { color: var(--text); font-weight: 600; }
.scorebar { margin-top: 24px; padding: 18px 22px; background: linear-gradient(120deg, var(--panel2), var(--panel)); border: 1px solid var(--line); border-radius: 14px; display: flex; align-items: center; gap: 22px; flex-wrap: wrap; }
.score { font-size: 40px; font-weight: 800; color: var(--accent); line-height: 1; }
.score small { font-size: 14px; color: var(--muted); font-weight: 500; }
.bar { flex: 1; min-width: 220px; height: 10px; border-radius: 999px; background: #1c2933; overflow: hidden; }
.bar span { display: block; height: 100%; border-radius: inherit; background: linear-gradient(90deg, #35e0a1, #ffd166 55%, #ff5d5d); }
.stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 26px 0 8px; }
.stat { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 14px 16px; }
.stat .num { display: block; font-size: 26px; font-weight: 700; }
.stat .lbl { color: var(--muted); font-size: 12px; }
.sev-critical .num { color: var(--critical); } .sev-high .num { color: var(--high); }
.sev-medium .num { color: var(--medium); } .sev-low .num { color: var(--low); } .sev-info .num { color: var(--info); }
.panel { background: rgba(15, 22, 29, .86); border: 1px solid var(--line); border-radius: 16px; padding: 24px; margin-top: 24px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; font-size: 12px; letter-spacing: .04em; }
td code, .ai code { color: var(--accent); word-break: break-all; }
.mono { font-family: "Cascadia Code", Consolas, monospace; font-size: 12.5px; color: #b8c8d4; word-break: break-all; }
.finding { border: 1px solid var(--line); border-left-width: 4px; border-radius: 12px; padding: 16px 18px; margin: 14px 0; background: var(--panel2); }
.finding.sev-critical { border-left-color: var(--critical); } .finding.sev-high { border-left-color: var(--high); }
.finding.sev-medium { border-left-color: var(--medium); } .finding.sev-low { border-left-color: var(--low); }
.finding.sev-info { border-left-color: var(--info); }
.finding h3 { margin: 0 0 8px; font-size: 16px; }
.badge { display: inline-block; padding: 2px 9px; border-radius: 999px; font-size: 11px; font-weight: 700; margin-right: 8px; color: #08111a; background: var(--info); }
.badge.sev-critical { background: var(--critical); } .badge.sev-high { background: var(--high); }
.badge.sev-medium { background: var(--medium); } .badge.sev-low { background: var(--low); } .badge.sev-info { background: var(--info); }
.fmeta { color: var(--muted); font-size: 13px; margin: 4px 0; }
.fmeta b { color: var(--text); font-weight: 600; }
ul { margin: 0; padding-left: 22px; }
li { margin: 7px 0; }
code { font-family: "Cascadia Code", Consolas, monospace; font-size: 12.5px; background: #0a1218; border: 1px solid var(--line); padding: 2px 6px; border-radius: 5px; color: var(--accent); }
.logs { background: #070d12; border: 1px solid var(--line); border-radius: 10px; padding: 14px; overflow-x: auto; color: #9ab0be; font-family: Consolas, monospace; font-size: 12px; white-space: pre-wrap; }
.ai { white-space: pre-wrap; color: #cfe0ea; }
.footer { color: var(--muted); font-size: 12px; margin-top: 30px; text-align: center; }
@media (max-width: 640px) { .stats { grid-template-columns: repeat(3, 1fr); } h1 { font-size: 26px; } .wrap { padding-top: 28px; } }
</style>
</head>
<body>
<div class="wrap">
  <p class="kicker">CTF SCOUT / RECON REPORT</p>
  <h1>__TITLE__</h1>
  <div class="meta">
    <div>目标：<strong>__TARGET__</strong></div>
    <div>解析地址：<strong>__IP__</strong></div>
    <div>授权范围：<strong>__SCOPE__</strong></div>
    <div>扫描时间：<strong>__GENERATED__</strong></div>
    <div>耗时：<strong>__ELAPSED__s</strong></div>
    <div>Web 指纹：<strong>__TECH__</strong></div>
  </div>
  <div class="scorebar">
    <div class="score">__SCORE__<small>/100</small></div>
    <div class="bar"><span style="width: __SCORE__%"></span></div>
    <div class="muted">风险评分由发现严重度加权得出，仅用于排序参考。</div>
  </div>
  <div class="stats">__CARDS__</div>

  <section class="panel">
    <h2>资产概览</h2>
    <h3 style="font-size:14px;color:var(--muted);margin:4px 0 10px;">开放端口</h3>
    __PORTS__
    <h3 style="font-size:14px;color:var(--muted);margin:22px 0 10px;">Web 入口</h3>
    __WEB__
  </section>

  <section class="panel">
    <h2>漏洞与发现</h2>
    __FINDINGS__
  </section>

  <section class="panel">
    <h2>推荐攻击路径</h2>
    <ul>__ATTACK__</ul>
  </section>

  <section class="panel">
    <h2>建议验证命令（仅手动执行）</h2>
    <ul>__COMMANDS__</ul>
  </section>

  __PATHS__
  __AI__

  <section class="panel">
    <h2>侦察日志</h2>
    <div class="logs">__LOGS__</div>
  </section>

  <div class="footer">本报告由 ctf-scout 自动生成，仅用于已授权的 CTF / 靶场 / 自有资产。<br>
  报告可能包含账号、密钥或 flag 等敏感信息，请勿公开分享。</div>
</div>
</body>
</html>
"""
    return (
        template.replace("__TITLE__", title)
        .replace("__TARGET__", target)
        .replace("__IP__", html.escape(ctx.resolved_ip))
        .replace("__SCOPE__", scope_text)
        .replace("__GENERATED__", generated)
        .replace("__ELAPSED__", f"{ctx.elapsed:.1f}")
        .replace("__TECH__", html.escape(tech_list))
        .replace("__SCORE__", str(score))
        .replace("__CARDS__", cards)
        .replace("__PORTS__", ports_html)
        .replace("__WEB__", web_html)
        .replace("__FINDINGS__", findings_html)
        .replace("__ATTACK__", attack_html)
        .replace("__COMMANDS__", commands_html)
        .replace("__PATHS__", paths_section)
        .replace("__AI__", ai_section)
        .replace("__LOGS__", logs)
    )


def _render_findings_html(ctx: Context) -> str:
    if not ctx.findings:
        return '<p class="muted">未发现明显问题。建议检查前端 JS、参数差异与隐藏接口。</p>'
    blocks = []
    for finding in ctx.sorted_findings():
        blocks.append(
            f'<div class="finding sev-{finding.severity}">'
            f'<h3><span class="badge sev-{finding.severity}">{_sev_label(finding.severity)}</span>'
            f"{html.escape(finding.title)}</h3>"
            f'<div class="fmeta"><b>类别：</b>{html.escape(finding.category)}</div>'
            f'<div class="fmeta"><b>目标：</b><span class="mono">{html.escape(finding.target)}</span></div>'
            f'<div class="fmeta"><b>证据：</b>{html.escape(finding.evidence)}</div>'
            + (f'<div class="fmeta"><b>建议：</b>{html.escape(finding.suggestion)}</div>' if finding.suggestion else "")
            + (f'<div class="fmeta"><b>CTF 思路：</b>{html.escape(finding.ctf_hint)}</div>' if finding.ctf_hint and finding.ctf_hint != finding.suggestion else "")
            + "</div>"
        )
    return "".join(blocks)


def _render_ports_html(ctx: Context) -> str:
    if not ctx.open_ports:
        return '<p class="muted">未发现开放端口。</p>'
    rows = []
    for port, info in sorted(ctx.open_ports.items()):
        rows.append(
            f"<tr><td>{port}</td><td>{html.escape(info.service)}</td>"
            f"<td>{html.escape(info.product) or '-'}</td>"
            f'<td class="mono">{html.escape(info.banner[:180]) or "-"}</td></tr>'
        )
    return (
        "<table><thead><tr><th>端口</th><th>服务</th><th>产品</th><th>Banner</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _render_web_html(ctx: Context) -> str:
    if not ctx.web_targets:
        return '<p class="muted">未发现可识别的 Web 入口。</p>'
    rows = []
    for web in ctx.web_targets:
        rows.append(
            f"<tr><td class=\"mono\">{html.escape(web.url)}</td><td>HTTP {web.status}</td>"
            f"<td>{html.escape(web.title) or '-'}</td>"
            f"<td>{html.escape(', '.join(web.technologies) or '未识别')}</td></tr>"
        )
    return (
        "<table><thead><tr><th>URL</th><th>状态</th><th>标题</th><th>指纹</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _render_paths_html(ctx: Context) -> str:
    items = list(ctx.discovered_paths.items())[:80]
    if not items:
        return ""
    rows = "".join(
        f'<tr><td class="mono">{html.escape(url)}</td><td>{html.escape(status)}</td></tr>'
        for url, status in items
    )
    return (
        "<table><thead><tr><th>URL</th><th>状态</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def write_reports(ctx: Context, output_dir: str, formats: str) -> dict[str, str]:
    """按格式写出报告，返回 格式 -> 文件路径。"""
    os.makedirs(output_dir, exist_ok=True)
    name = _safe_name(ctx.target_host, ctx.target_port)
    selected = ["md", "json", "html"] if formats == "all" else [formats]
    written: dict[str, str] = {}
    if "md" in selected:
        path = os.path.join(output_dir, f"{name}.md")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(render_markdown(ctx))
        written["md"] = os.path.abspath(path)
    if "json" in selected:
        path = os.path.join(output_dir, f"{name}.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(render_json(ctx))
        written["json"] = os.path.abspath(path)
    if "html" in selected:
        path = os.path.join(output_dir, f"{name}.html")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(render_html(ctx))
        written["html"] = os.path.abspath(path)
    return written
