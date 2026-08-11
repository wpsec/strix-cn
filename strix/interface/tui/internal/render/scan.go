package render

import (
	"strings"
)

// ---------------------------------------------------------------------------
// Finish scan (finish_renderer.py)
// ---------------------------------------------------------------------------

func renderFinishScan(args map[string]any) string {
	var b strings.Builder
	b.WriteString(Col(Green).Render("◆ ") + Bold(Green).Render("渗透测试已完成"))
	section := func(label, value string) {
		if value != "" {
			b.WriteString("\n\n" + Bold(Field).Render(label) + "\n" + value)
		}
	}
	es := StringValue(args["executive_summary"])
	me := StringValue(args["methodology"])
	ta := StringValue(args["technical_analysis"])
	re := StringValue(args["recommendations"])
	section("执行摘要", es)
	section("测试方法", me)
	section("技术分析", ta)
	section("修复建议", re)
	if es == "" && me == "" && ta == "" && re == "" {
		b.WriteString("\n  " + Dim().Render("正在生成最终报告..."))
	}
	return "\n\n" + b.String() + "\n\n"
}
