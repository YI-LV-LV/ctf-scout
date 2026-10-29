"""命令行入口。"""

from __future__ import annotations

import argparse
import os
import sys
import time
import traceback

from . import __version__
from .agent import Agent
from .models import Context
from .report import print_summary, write_reports
from .scope import ScopeError, parse_ports, parse_target, require_authorization

BANNER = r"""
  ___ _____ _____    ___  ___ _____ ___ _   _ _____
 / __|_   _| __\ \  / __|/ __|  _  | _ \ | | |_   _|
| (__  | | | _| \ \/ / (__| (__| | | |   / |_| | | |
 \___| |_| |_|   \__/ \___|\___|_| |_|_|_\___/  |_|
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf-scout",
        description="面向授权 CTF / 靶场的自动化漏洞侦察智能体。",
    )
    parser.add_argument("--version", action="version", version=f"ctf-scout {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="扫描一个授权目标")
    scan.add_argument("target", help="目标，例如 10.10.10.5、10.10.10.5:8080、http://ctf.example/")
    scan.add_argument("--ports", help="自定义端口，例如 80,443,8000-9000（默认扫常见端口）")
    scan.add_argument("--full", action="store_true", help="扫描 1-65535 全端口（较慢）")
    scan.add_argument("--timeout", type=float, default=8.0, help="HTTP 请求超时秒数（默认 8）")
    scan.add_argument("--connect-timeout", type=float, default=0.7, help="TCP 连接超时秒数（默认 0.7）")
    scan.add_argument("--threads", type=int, default=200, help="端口扫描并发数（默认 200）")
    scan.add_argument("--active", action="store_true", help="启用低风险主动验证（SQLi/XSS/LFI/未授权服务）")
    scan.add_argument("--authorized", action="store_true", help="确认已获得公网目标的测试授权")
    scan.add_argument("--llm", action="store_true", help="调用 OpenAI 兼容接口生成 AI 辅助分析")
    scan.add_argument("--format", default="all", choices=["all", "md", "json", "html", "none"], help="报告格式")
    scan.add_argument("--output", default="reports", help="报告输出目录（默认 ./reports）")
    scan.add_argument("--no-color", action="store_true", help="禁用彩色输出")
    scan.add_argument("--quiet", action="store_true", help="只输出最终摘要")
    scan.add_argument("--max-steps", type=int, default=1000, help="智能体最大任务步数")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 1
    return run_scan(args)


def run_scan(args: argparse.Namespace) -> int:
    color = not args.no_color and os.getenv("NO_COLOR") is None
    if color and os.name == "nt":
        os.system("")

    def paint(text: str, code: str) -> str:
        if not color:
            return text
        return f"\033[{code}m{text}\033[0m"

    if not args.quiet:
        print(paint(BANNER, "92"))
        print(paint(f"ctf-scout {__version__} | 授权 CTF 侦察智能体", "1"))
        print("仅限你拥有明确授权的 CTF 比赛、靶场或自有资产。\n")

    if args.ports and args.full:
        print(paint("[!] --ports 与 --full 不能同时使用", "91"))
        return 2
    if args.timeout <= 0 or args.connect_timeout <= 0 or args.threads <= 0:
        print(paint("[!] timeout、connect-timeout 与 threads 必须为正数", "91"))
        return 2
    if args.ports:
        try:
            parse_ports(args.ports)
        except ScopeError as exc:
            print(paint(f"[!] {exc}", "91"))
            return 2

    try:
        target = parse_target(args.target)
        require_authorization(target, args.authorized)
    except ScopeError as exc:
        print(paint(f"[!] {exc}", "91"))
        return 2

    ctx = Context(
        input_target=args.target,
        target_host=target.host,
        target_port=target.port,
        scheme=target.scheme,
        base_path=target.base_path,
        resolved_ip=target.resolved_ip,
        is_private=target.is_private,
        authorized=target.is_private or args.authorized,
        options={
            "full": args.full,
            "ports": args.ports,
            "timeout": args.timeout,
            "connect_timeout": args.connect_timeout,
            "threads": args.threads,
            "active": args.active,
        },
    )

    if not args.quiet:
        scope_note = "本机 / 私网" if target.is_private else "公网，已确认授权"
        print(f"目标: {paint(args.target, '96')}  ->  {target.resolved_ip} ({scope_note})")
        print(f"扫描: {'全端口' if args.full else (args.ports or '常见端口')} | "
              f"主动验证: {'开启' if args.active else '关闭'} | "
              f"报告: {args.format} -> {args.output}\n")
        if args.active:
            print(paint("[!] 主动验证会发送少量测试请求，请确保目标状态允许。", "93"))
            print()

    def progress(message: str) -> None:
        if args.quiet:
            return
        if message.strip().startswith("[+]"):
            print(paint(message, "92"))
        elif message.strip().startswith("[!]"):
            print(paint(message, "93"))
        elif message.strip().startswith("[*]"):
            print(paint(message, "96"))
        elif message.strip().startswith("["):
            print(paint(message, "1"))
        else:
            print(message)

    agent = Agent(ctx, progress=progress, max_steps=args.max_steps)
    try:
        agent.run()
    except KeyboardInterrupt:
        print(paint("\n[!] 已中断扫描", "93"))
        return 130
    except Exception as exc:  # noqa: BLE001
        print(paint(f"\n[!] 扫描失败: {exc}", "91"))
        if os.getenv("CTF_SCOUT_DEBUG"):
            traceback.print_exc()
        return 1

    if args.llm:
        from . import llm

        if not args.quiet:
            print(paint("\n[*] 调用 LLM 生成辅助分析（将发送侦察摘要到配置的服务）", "96"))
        try:
            ctx.ai_analysis = llm.review(ctx)
            if not args.quiet:
                print(paint("[+] AI 分析完成", "92"))
        except Exception as exc:  # noqa: BLE001
            print(paint(f"[!] AI 分析失败，已跳过: {exc}", "93"))

    written: dict[str, str] = {}
    if args.format != "none":
        try:
            written = write_reports(ctx, args.output, args.format)
        except OSError as exc:
            print(paint(f"[!] 报告写入失败: {exc}", "91"))

    print_summary(ctx, color=color)

    if written:
        print(paint("  报告文件:", "1"))
        for fmt, path in written.items():
            print(f"    {fmt.upper():<5} {path}")
        print()
    return 0
