package render

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func renderDependencyReport(args map[string]any, result any) string {
	resultMap, _ := result.(map[string]any)
	// Unsuccessful / not-persisted variants.
	if resultMap != nil {
		success, hasSuccess := resultMap["success"].(bool)
		warning := StringValue(resultMap["warning"])
		if (hasSuccess && !success) || warning != "" {
			return renderDependencyUnsuccessful(args, resultMap)
		}
	}
	var b strings.Builder
	b.WriteString("📦 " + Bold(ReportHdr).Render("依赖漏洞报告"))
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
	if score, ok := NumericValue(args["advisory_cvss"]); ok {
		b.WriteString("\n\n" + Bold(Field).Render("公告 CVSS: ") +
			lipgloss.NewStyle().Bold(true).Foreground(CVSSColor(score)).Render(StringValue(args["advisory_cvss"])))
	}
	field("CVE", StringValue(args["cve"]))
	field("CWE", StringValue(args["cwe"]))
	if pkg := StringValue(args["package_name"]); pkg != "" {
		b.WriteString("\n\n" + Bold(Field).Render("组件: ") + Bold(InfoBlue).Render(pkg))
		if eco := StringValue(args["package_ecosystem"]); eco != "" {
			b.WriteString(Dim().Render(" (" + eco + ")"))
		}
	}
	if inst := StringValue(args["installed_version"]); inst != "" {
		b.WriteString("\n\n" + Bold(Field).Render("当前版本: ") + Col(Red).Render(inst))
		if fixed := StringValue(args["fixed_version"]); fixed != "" {
			b.WriteString(Dim().Render("  →  ") + Bold(Field).Render("修复版本: ") + Col(Green).Render(fixed))
		}
	}
	field("修复成本", StringValue(args["fix_effort"]))
	field("目标", StringValue(args["target"]))
	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label) + "\n" + value)
		}
	}
	section("漏洞描述", StringValue(args["description"]))
	section("影响", StringValue(args["impact"]))
	section("技术分析", StringValue(args["technical_analysis"]))
	if reach := StringValue(args["reachability"]); reach != "" && reach != "unknown" {
		b.WriteString("\n\n" + Bold(Field).Render("可达性级别: ") + reach)
		if ev := StringValue(args["reachability_evidence"]); ev != "" {
			b.WriteString("\n" + ev)
		}
	}
	section("前提假设", StringValue(args["assumptions"]))
	section("修复建议", StringValue(args["remediation_steps"]))
	if title == "" {
		b.WriteString("\n  " + Dim().Render("正在创建依赖漏洞报告..."))
	}
	return "\n\n" + b.String() + "\n\n"
}

func renderDependencyUnsuccessful(args, result map[string]any) string {
	var b strings.Builder
	b.WriteString("📦 " + Bold(ReportHdr).Render("依赖漏洞报告"))
	if title := StringValue(args["title"]); title != "" {
		b.WriteString("\n\n" + Bold(Field).Render("标题: ") + title)
	}
	success, hasSuccess := result["success"].(bool)
	var label, detail string
	var style lipgloss.Style
	if hasSuccess && !success {
		detail = StringValue(result["error"])
		if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
			var parts []string
			for _, e := range errs {
				parts = append(parts, StringValue(e))
			}
			detail = strings.Join(parts, "; ")
		}
		label, style = "✗ 未创建: ", Bold(SevCrit)
		if detail == "" {
			detail = "报告未创建。"
		}
	} else {
		detail = StringValue(result["warning"])
		label, style = "⚠ 未落盘: ", Bold(SevMed)
		if detail == "" {
			detail = "报告未能落盘。"
		}
	}
	b.WriteString("\n\n" + style.Render(label) + detail)
	return "\n\n" + b.String() + "\n\n"
}
