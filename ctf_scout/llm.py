"""可选的 LLM 辅助分析（OpenAI 兼容接口，无第三方依赖）。"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .models import Context

SYSTEM_PROMPT = """你是一名资深 CTF 安全分析师，负责基于侦察结果给出下一步验证思路。
约束：
1. 目标处于用户已确认授权的 CTF 比赛、靶场或自有资产。
2. 只建议只读、低风险的验证请求；不要给出破坏性、拒绝服务或影响赛题状态的操作。
3. 不要编造侦察结果中不存在的漏洞；无法确认时明确写出“需要验证”。
4. 输出中文 Markdown，控制在 600 字以内，结构为：
   - 核心判断（2-3 条）
   - 优先验证顺序（按可能性与收益排序）
   - 具体请求示例（curl / sqlmap 等，标注仅手动执行）
   - 风险与误报提示
"""


def review(ctx: Context) -> str:
    api_key = os.getenv("CTF_SCOUT_LLM_API_KEY") or os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "未找到 LLM API Key。请设置 CTF_SCOUT_LLM_API_KEY 或 OPENAI_API_KEY 后重试。"
        )
    base_url = os.getenv("CTF_SCOUT_LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.getenv("CTF_SCOUT_LLM_MODEL", "gpt-4o-mini")

    summary = {
        "target": ctx.input_target,
        "resolved_ip": ctx.resolved_ip,
        "ports": [
            {"port": info.port, "service": info.service, "product": info.product, "banner": info.banner[:120]}
            for info in sorted(ctx.open_ports.values(), key=lambda i: i.port)
        ],
        "web": [
            {
                "url": web.url,
                "status": web.status,
                "title": web.title,
                "technologies": web.technologies,
                "forms": web.forms[:5],
            }
            for web in ctx.web_targets
        ],
        "findings": [
            {
                "title": finding.title,
                "severity": finding.severity,
                "category": finding.category,
                "target": finding.target,
                "evidence": finding.evidence[:300],
                "tags": finding.tags,
            }
            for finding in ctx.sorted_findings()[:30]
        ],
        "attack_paths": ctx.attack_paths,
        "existing_commands": ctx.commands,
    }

    payload = {
        "model": model,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "以下是自动侦察结果，请给出下一步人工验证建议：\n"
                + json.dumps(summary, ensure_ascii=False, indent=2),
            },
        ],
    }
    req = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"LLM 接口返回 HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"LLM 接口连接失败: {exc.reason}") from exc

    try:
        return str(data["choices"][0]["message"]["content"]).strip()
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"LLM 响应格式不符合预期: {str(data)[:200]}") from exc
