#!/usr/bin/env python3
# 合并 ocr 各文件的**原生 JSON**（ocr-part-*.json），产出三样：
#   1) ocr.sarif        —— 极简 SARIF，仅供 GitHub 安全页（节点⑤上传）
#   2) ocr-generic.json —— DefectDojo「Generic Findings Import」，带 mitigation(修复建议)+
#                          steps_to_reproduce(复现/触发路径)+severity(严重度)
#   3) .ocr_count       —— security 类发现数，供门禁（节点⑦）
#
# 为什么改这个（part3 修复）：
#   ocr 原生 comment 本就带 suggestion_code(具体改法代码)、severity、thinking(触发路径分析)，
#   但旧版先转 SARIF 再入库，SARIF 只有 message+location、且没有 mitigation/复现字段，
#   于是 DefectDojo 这两个字段永远空。改从原生 JSON 直接产 Generic，把信息落到专用字段。
#   注意：ocr 现在用 `--format json` 输出（不再是 sarif），故本脚本读 ocr-part-*.json。
import json, glob, re

SEV_MAP = {  # ocr severity -> DefectDojo 五档
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info", "informational": "Info", "warning": "Low",
}

comments = []
for p in sorted(glob.glob("ocr-part-*.json")):
    try:
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        continue
    for c in (d.get("comments") or []):
        if (c.get("category") or "").lower() == "security":
            comments.append(c)


def title_of(content):
    m = re.match(r"\s*\*\*(.+?)\*\*", content or "")   # 取开头的 **加粗前缀** 作标题
    if m:
        return m.group(1).strip().rstrip(":：")
    t = re.sub(r"\s+", " ", (content or "").strip())
    return (t[:80] + "…") if len(t) > 80 else (t or "OCR security finding")


def as_line(v):
    try:
        return int(v)
    except Exception:
        return 1


sarif_results, generic = [], []
for c in comments:
    content = (c.get("content") or "").strip()
    sug = (c.get("suggestion_code") or "").strip()
    old = (c.get("existing_code") or "").strip()
    think = (c.get("thinking") or "").strip()
    path = c.get("path") or ""
    line = as_line(c.get("start_line") or c.get("end_line") or 1)
    sev = SEV_MAP.get((c.get("severity") or "").lower(), "High")
    title = title_of(content)

    # --- 极简 SARIF（安全页用；无 tool.driver.rules，避免 DefectDojo 解析 500 的老坑）---
    sarif_results.append({
        "ruleId": "security",
        "level": "error",
        "message": {"text": ((title + " — " + content) if content else title)[:1000]},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": path},
            "region": {"startLine": line},
        }}],
    })

    # --- DefectDojo Generic（带修复建议/复现步骤）---
    desc = content or title
    if old:
        desc += "\n\n**存在问题的代码：**\n```\n" + old + "\n```"
    mitigation = ("**推荐改法（AI 生成，需人工确认）：**\n```\n" + sug + "\n```") if sug \
        else "见描述中的整改说明。"
    steps = ("**AI 分析的触发路径：**\n" + think) if think else "见描述中的利用示例。"
    generic.append({
        "title": title,
        "description": desc,
        "severity": sev,
        "mitigation": mitigation,
        "steps_to_reproduce": steps,
        "file_path": path,
        "line": line,
        "unique_id_from_tool": (path + ":" + str(line) + ":" + title)[:200],
        "static_finding": True,
        "dynamic_finding": False,
    })

json.dump({
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{"tool": {"driver": {"name": "open-code-review"}}, "results": sarif_results}],
}, open("ocr.sarif", "w", encoding="utf-8"))

json.dump({"findings": generic}, open("ocr-generic.json", "w", encoding="utf-8"), ensure_ascii=False)

open(".ocr_count", "w").write(str(len(generic)))
print("%d security findings -> ocr.sarif + ocr-generic.json" % len(generic))
