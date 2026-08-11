package render

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Reporting (reporting_renderer.py)
// ---------------------------------------------------------------------------

func renderVulnerabilityReport(args map[string]any, result any) string {
	resultMap, _ := result.(map[string]any)
	var b strings.Builder
	b.WriteString("🐞 " + Bold(ReportHdr).Render("漏洞报告"))

	field := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label+": ") + value)
		}
	}
	title := StringValue(args["title"])
	field("标题", title)

	if sev := StringValue(resultMap["severity"]); sev != "" {
		b.WriteString("\n\n" + Bold(Field).Render("严重性: ") +
			lipgloss.NewStyle().Bold(true).Foreground(SeverityColor(sev)).Render(SeverityLabelZH(sev)))
	}
	if score, ok := NumericValue(resultMap["cvss_score"]); ok {
		b.WriteString("\n\n" + Bold(Field).Render("CVSS 分数: ") +
			lipgloss.NewStyle().Bold(true).Foreground(CVSSColor(score)).Render(StringValue(resultMap["cvss_score"])))
	}
	field("目标", StringValue(args["target"]))
	field("接口", StringValue(args["endpoint"]))
	field("方法", StringValue(args["method"]))
	field("CVE", StringValue(args["cve"]))
	field("CWE", StringValue(args["cwe"]))

	if bd, ok := args["cvss_breakdown"].(map[string]any); ok && len(bd) > 0 {
		parts := CVSSVectorParts(bd)
		if len(parts) > 0 {
			b.WriteString("\n\n" + Bold(Field).Render("CVSS 向量: ") + Dim().Render(strings.Join(parts, "/")))
		}
	}

	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label) + "\n" + value)
		}
	}
	section("漏洞描述", StringValue(args["description"]))
	section("影响", StringValue(args["impact"]))
	section("技术分析", StringValue(args["technical_analysis"]))
	renderCodeLocations(&b, args["code_locations"])
	section("概念验证说明", StringValue(args["poc_description"]))
	if poc := StringValue(args["poc_script_code"]); poc != "" {
		b.WriteString("\n\n" + Bold(Field).Render("概念验证代码") + "\n" + Col(Text).Render(poc))
	}
	section("修复建议", StringValue(args["remediation_steps"]))

	if title == "" {
		b.WriteString("\n  " + Dim().Render("正在创建漏洞报告..."))
	}
	return "\n\n" + b.String() + "\n\n"
}

var cvssKeys = [][2]string{
	{"attack_vector", "AV"}, {"attack_complexity", "AC"}, {"privileges_required", "PR"},
	{"user_interaction", "UI"}, {"scope", "S"}, {"confidentiality", "C"},
	{"integrity", "I"}, {"availability", "A"},
}

func CVSSVectorParts(bd map[string]any) []string {
	var parts []string
	for _, kp := range cvssKeys {
		if v := StringValue(bd[kp[0]]); v != "" {
			parts = append(parts, kp[1]+":"+v)
		}
	}
	return parts
}

func renderCodeLocations(b *strings.Builder, raw any) {
	locs, ok := raw.([]any)
	if !ok || len(locs) == 0 {
		return
	}
	b.WriteString("\n\n" + Bold(Field).Render("代码位置"))
	for i, l := range locs {
		loc, ok := l.(map[string]any)
		if !ok {
			continue
		}
		b.WriteString("\n\n" + Dim().Render(fmt.Sprintf("  位置 %d: ", i+1)))
		file := StringValue(loc["file"])
		if file == "" {
			file = "unknown"
		}
		b.WriteString(Bold(InfoBlue).Render(file))
		if start, ok := NumericValue(loc["start_line"]); ok {
			if end, ok := NumericValue(loc["end_line"]); ok && end != start {
				b.WriteString(Col(LineNum).Render(fmt.Sprintf(":%d-%d", int(start), int(end))))
			} else {
				b.WriteString(Col(LineNum).Render(fmt.Sprintf(":%d", int(start))))
			}
		}
		if label := StringValue(loc["label"]); label != "" {
			b.WriteString(lipgloss.NewStyle().Italic(true).Foreground(Label).Render("\n  " + label))
		}
		if snip := StringValue(loc["snippet"]); snip != "" {
			b.WriteString("\n  " + Col(Snippet).Render(snip))
		}
		before, after := StringValue(loc["fix_before"]), StringValue(loc["fix_after"])
		if before != "" || after != "" {
			b.WriteString("\n  " + Dim().Render("建议修复:"))
			if before != "" {
				b.WriteString("\n  " + Col(Red).Render("- ") + Col(Red).Render(before))
			}
			if after != "" {
				b.WriteString("\n  " + Col(Green).Render("+ ") + Col(Green).Render(after))
			}
		}
	}
}
