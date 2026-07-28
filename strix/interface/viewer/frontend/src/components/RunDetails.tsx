import { useState } from "react";
import { ChevronDown, ChevronUp, Info } from "lucide-react";
import { formatNumber } from "@/lib/display-number";
import { formatRunStatusLabel, formatScanModeLabel, formatScopeModeLabel, humanizeLabel } from "@/lib/utils";

/**
 * "Run details" card for the Overview tab: the launch configuration the run was
 * started with (targets, instruction, scope, mode) and its LLM usage + cost.
 * Everything is read defensively from the raw run.json record, which may be
 * partial while a scan is still live.
 */

type Rec = Record<string, unknown>;

function rec(v: unknown): Rec {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Rec) : {};
}
function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : [];
}
function str(v: unknown): string | null {
  return typeof v === "string" && v.trim() ? v : null;
}
function num(v: unknown): number | null {
  return typeof v === "number" && Number.isFinite(v) ? v : null;
}
function fmtDuration(seconds: number | null): string {
  if (seconds == null || seconds < 0) return "暂无";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h) return `${h} 小时 ${m} 分 ${s} 秒`;
  if (m) return `${m} 分 ${s} 秒`;
  return `${s} 秒`;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[7rem_1fr] gap-3 items-baseline">
      <dt className="text-[11px] uppercase tracking-wide text-[#666]">{label}</dt>
      <dd className="min-w-0 break-words text-sm text-[#ddd]">{children}</dd>
    </div>
  );
}

export function RunDetails({
  raw,
  durationSeconds,
}: {
  raw: Rec;
  durationSeconds: number | null;
}) {
  const [open, setOpen] = useState(true);

  // Configuration (launch inputs)
  const targets = arr(raw.targets_info).map((t) => {
    const o = rec(t);
    const display = str(o.original) ?? str(rec(o.details).target_url) ?? "未知目标";
    const type = str(o.type);
    return { display, type: type ? humanizeLabel(type) : null };
  });
  const instruction = str(raw.instruction);
  const scanMode = formatScanModeLabel(str(raw.scan_mode));
  const scopeMode = str(raw.scope_mode);
  const diff = rec(raw.diff_scope);
  const diffActive = diff.active === true;
  const diffMode = str(diff.mode);
  const diffBase = str(raw.diff_base);
  const nonInteractive = raw.non_interactive === true;
  const localSources = arr(raw.local_sources)
    .map((x) => {
      if (typeof x === "string") return x;
      const o = rec(x);
      return str(o.source_path) ?? str(o.target_path) ?? "";
    })
    .filter(Boolean);
  const status = formatRunStatusLabel(str(raw.status));

  let scope = formatScopeModeLabel(scopeMode) ?? "自动";
  if (diffActive) {
    scope += `（差异${diffMode ? `：${humanizeLabel(diffMode)}` : ""}${diffBase ? `，对比 ${diffBase}` : ""}）`;
  }

  // Usage & cost
  const usage = rec(raw.llm_usage);
  const hasUsage = Object.keys(usage).length > 0;
  const agents = arr(usage.agents).map(rec);
  const models = Array.from(
    new Set(agents.map((a) => str(a.model)).filter((m): m is string => !!m))
  );
  const requests = num(usage.requests);
  const inputTokens = num(usage.input_tokens);
  const cached = num(rec(arr(usage.input_tokens_details)[0]).cached_tokens);
  const outputTokens = num(usage.output_tokens);
  const reasoning = num(rec(arr(usage.output_tokens_details)[0]).reasoning_tokens);
  const totalTokens = num(usage.total_tokens);
  const cost = num(usage.cost);
  const subscription = str(raw.auth_mode) === "subscription";

  const sub = (n: number, word: string) => (
    <span className="text-[#666]">（{formatNumber(n)} {word}）</span>
  );

  return (
    <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full cursor-pointer items-center gap-2 text-left"
      >
        <Info className="h-4 w-4 text-[#888]" aria-hidden="true" />
        <h2 className="text-sm font-semibold text-white">运行详情</h2>
        {open ? (
          <ChevronUp className="ml-auto h-4 w-4 text-[#666]" aria-hidden="true" />
        ) : (
          <ChevronDown className="ml-auto h-4 w-4 text-[#666]" aria-hidden="true" />
        )}
      </button>

      {open && (
      <div className="mt-4 grid grid-cols-1 gap-x-8 gap-y-6 md:grid-cols-2">
        <section>
          <h3 className="mb-3 text-[11px] font-semibold uppercase tracking-wide text-[#555]">
            运行配置
          </h3>
          <dl className="space-y-2.5">
            {targets.length > 0 && (
              <Field label="目标">
                <div className="space-y-1">
                  {targets.map((t, i) => (
                    <div key={i} className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-[#ddd]">{t.display}</span>
                      {t.type && (
                        <span className="rounded-full border border-[#2a2a2a] px-1.5 py-0.5 text-[10px] text-[#888]">
                          {t.type}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              </Field>
            )}
            <Field label="测试指令">
              {instruction ? (
                <span className="whitespace-pre-wrap">{instruction}</span>
              ) : (
                <span className="text-[#666]">无</span>
              )}
            </Field>
            {scanMode && <Field label="测试模式">{scanMode}</Field>}
            <Field label="范围">{scope}</Field>
            <Field label="交互模式">{nonInteractive ? "非交互式" : "交互式"}</Field>
            {localSources.length > 0 && (
              <Field label="本地来源">
                <div className="space-y-0.5 font-mono text-[#ddd]">
                  {localSources.map((s, i) => (
                    <div key={i}>{s}</div>
                  ))}
                </div>
              </Field>
            )}
            {status && <Field label="状态">{status}</Field>}
          </dl>
        </section>

        <section>
          <h3 className="mb-3 text-[11px] font-semibold uppercase tracking-wide text-[#555]">
            用量与费用
          </h3>
          {hasUsage ? (
            <dl className="space-y-2.5 tabular-nums">
              <Field label="模型">{models.length ? models.join(", ") : "暂无"}</Field>
              {subscription && (
                <Field label="提供方">
                  <span className="inline-flex items-center gap-1.5">
                    <span className="rounded-full border border-[#22c55e]/40 bg-[#22c55e]/10 px-2 py-0.5 text-[11px] text-[#22c55e]">
                      ChatGPT 订阅
                    </span>
                  </span>
                </Field>
              )}
              <Field label="运行时长">{fmtDuration(durationSeconds)}</Field>
              {requests != null && <Field label="请求数">{formatNumber(requests)}</Field>}
              {inputTokens != null && (
                <Field label="输入 Token">
                  {formatNumber(inputTokens)}
                  {cached != null && sub(cached, "缓存")}
                </Field>
              )}
              {outputTokens != null && (
                <Field label="输出 Token">
                  {formatNumber(outputTokens)}
                  {reasoning != null && sub(reasoning, "推理")}
                </Field>
              )}
              {totalTokens != null && <Field label="总 Token">{formatNumber(totalTokens)}</Field>}
              {subscription ? (
                <Field label="费用">
                  <span className="text-[#22c55e]">$0.00</span>
                  <span className="text-[#666]">（订阅内）</span>
                </Field>
              ) : (
                cost != null && <Field label="费用">${cost.toFixed(2)}</Field>
              )}
              {agents.length > 0 && <Field label="代理数">{formatNumber(agents.length)}</Field>}
            </dl>
          ) : (
            <p className="text-sm text-[#666]">暂不可用。</p>
          )}
        </section>
      </div>
      )}
    </div>
  );
}

export default RunDetails;
