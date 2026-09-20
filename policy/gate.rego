package aisdlc.gate

# AI-SDLC 安全门禁——策略即代码（OPA/Rego）。
# 输入(gate-input.json)：
#   { "ocr_high": <int>, "gitleaks": <int>, "semgrep_error": <int>,
#     "trivy": <int>, "asset_criticality": "critical"|"high"|"medium"|"low" }
# 输出：data.aisdlc.gate.decision = "block" | "warn" | "pass"
#       data.aisdlc.gate.reasons = [原因...]

import future.keywords.if
import future.keywords.contains
import future.keywords.in

default decision := "pass"

# —— 硬阻断条件 ——
block if input.ocr_high > 0            # AI 评审报出严重/高危(越权/注入/密钥)
block if input.gitleaks > 0            # 硬编码密钥，任一即拦
block if input.semgrep_error > 0       # 静态 SAST error 级

# —— 资产分级：关键资产上，依赖 CVE 也阻断；普通资产则仅告警 ——
block if {
	input.asset_criticality == "critical"
	input.trivy > 0
}

decision := "block" if block

decision := "warn" if {
	not block
	input.trivy > 0
}

# —— 阻断原因（供门禁输出）——
reasons contains sprintf("ocr严重/高危=%v", [input.ocr_high]) if input.ocr_high > 0
reasons contains sprintf("Gitleaks密钥=%v", [input.gitleaks]) if input.gitleaks > 0
reasons contains sprintf("Semgrep-error=%v", [input.semgrep_error]) if input.semgrep_error > 0
reasons contains sprintf("Trivy依赖CVE=%v(关键资产阻断)", [input.trivy]) if {
	input.asset_criticality == "critical"
	input.trivy > 0
}
reasons contains sprintf("Trivy依赖CVE=%v(报告态)", [input.trivy]) if {
	input.asset_criticality != "critical"
	input.trivy > 0
}
