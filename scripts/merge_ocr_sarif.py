#!/usr/bin/env python3
# 合并各 .py 文件的 ocr SARIF（ocr-part-*.sarif），只保留 security 类结果，并**归一化** -> ocr.sarif
#
# 两个已实测的坑：
# 1) ocr 的 SARIF 用 ruleId 表示类别（security/bug/performance/...），严重度不在 SARIF 里；
#    安全门禁与台账只关心 security 类，故在此过滤。同时写 .ocr_count 供门禁计数。
# 2) DefectDojo 的 SARIF 解析器遇到 ocr 原始的 tool.driver.rules 会 HTTP 500（reimport 失败）。
#    故这里剥掉 tool.driver.rules，只保留极简 tool + 每条 result 的 ruleId/level/message/locations——
#    实测这样 DefectDojo 能正常 import，GitHub 安全页也接受。
import json, glob, os

security = []
for p in sorted(glob.glob("ocr-part-*.sarif")):
    try:
        if os.path.getsize(p) == 0:
            continue
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        continue
    for r in d.get("runs", []):
        security += [x for x in r.get("results", []) if x.get("ruleId") == "security"]

clean = []
for x in security:
    r = {
        "ruleId": "security",
        "level": x.get("level", "error"),
        "message": {"text": (x.get("message") or {}).get("text", "")},
    }
    if x.get("locations"):
        r["locations"] = x["locations"]
    clean.append(r)

merged = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{"tool": {"driver": {"name": "open-code-review"}}, "results": clean}],
}
json.dump(merged, open("ocr.sarif", "w", encoding="utf-8"))
open(".ocr_count", "w").write(str(len(clean)))
print("%d security findings -> ocr.sarif" % len(clean))
