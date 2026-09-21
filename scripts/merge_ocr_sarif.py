#!/usr/bin/env python3
# 合并各 .py 文件的 ocr SARIF（ocr-part-*.sarif），仅保留 security 类结果 -> ocr.sarif
# ocr 的 SARIF 用 ruleId 表示类别（security/bug/performance/...），严重度不在 SARIF 里；
# 安全门禁与台账只关心 security 类，故在此过滤。同时写 .ocr_count 供门禁计数。
import json, glob, os

results = []
tool = None
for p in sorted(glob.glob("ocr-part-*.sarif")):
    try:
        if os.path.getsize(p) == 0:
            continue
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        continue
    for r in d.get("runs", []):
        tool = tool or r.get("tool")
        results += [x for x in r.get("results", []) if x.get("ruleId") == "security"]

merged = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [{"tool": tool or {"driver": {"name": "open-code-review"}}, "results": results}],
}
json.dump(merged, open("ocr.sarif", "w", encoding="utf-8"))
open(".ocr_count", "w").write(str(len(results)))
print("%d security findings -> ocr.sarif" % len(results))
