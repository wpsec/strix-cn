import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowLeft,
  AlertCircle,
  Bot,
  Mail,
  ChevronDown,
  Radar,
  Rocket,
  ArrowUpRight,
  History,
} from "lucide-react";
import type { Vulnerability, VulnerabilitySeverity } from "@/types/issues";
import { SEVERITY_COLORS, SEVERITY_LABELS } from "@/types/issues";
import { getSeverityDot } from "@/lib/vulnerability-utils";
import VulnerabilityDetail from "@/components/vulnerability/VulnerabilityDetail";
import { ContentSection } from "@/components/vulnerability/ContentSection";
import { IssueSeveritySummary } from "@/components/IssueSeveritySummary";
import AgentGraph from "@/components/live/AgentGraph";
import { buildGraphAgents } from "@/components/live/AgentTranscript";
import AgentDetailModal from "@/components/live/AgentDetailModal";
import { ScanPromptComposer } from "@/components/live/ScanPromptComposer";
import { severityCounts, type ParsedRunSummary } from "@/lib/local-run-parser";
import {
  fetchAll,
  fetchAuthStatus,
  fetchCapabilities,
  fetchRunSummary,
  fetchRuns,
  fetchTranscript,
  fetchVulnerabilities,
  forgetAuth,
  type AuthStatus,
  type LoadedRun,
  type RunsPayload,
} from "@/data/serverSource";
import { SIGNUP_URL, ctaUrl, trackCta } from "@/lib/cta";
import { runTitle } from "@/lib/target-utils";
import Sidebar from "@/components/Sidebar";
import PastRunsView from "@/components/PastRunsView";
import EmailReportView from "@/components/EmailReportView";
import { RunDetails } from "@/components/RunDetails";
import { TrustToast } from "@/components/TrustToast";
import FeedbackView from "@/components/FeedbackView";
import { ProInlineCta } from "@/components/ProCta";
import { formatRunStatusLabel, formatScanModeLabel } from "@/lib/utils";

export type View = "overview" | "issues" | "agents" | "history" | "email" | "feedback";

const TRUST_BANNER =
  "你的扫描结果始终保留在本机。这里的内容仅在浏览器本地渲染，不会被 Strix 上传或存储。";

const SEVERITY_ORDER: VulnerabilitySeverity[] = ["critical", "high", "medium", "low"];
const POLL_MS = 500;

export default function App() {
  const [activeRun, setActiveRun] = useState<string | null>(null);
  const [run, setRun] = useState<LoadedRun | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [view, setView] = useState<View>("overview");
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [runs, setRuns] = useState<RunsPayload | null>(null);
  const [emailPurpose, setEmailPurpose] = useState<"report" | "verify">("report");
  const [emailSkipDisclosure, setEmailSkipDisclosure] = useState(false);
  // Whether this viewer can steer a live scan (true only inside the in-TUI
  // launcher that shares the running scan's coordinator + event loop).
  const [canSteer, setCanSteer] = useState(false);

  const refreshAuth = useCallback(async () => {
    try {
      setAuth(await fetchAuthStatus());
    } catch {
      /* auth status is best-effort; the launched run stays viewable */
    }
  }, []);

  const refreshRuns = useCallback(async () => {
    try {
      setRuns(await fetchRuns());
    } catch {
      /* history list is best-effort */
    }
  }, []);

  useEffect(() => {
    void refreshAuth();
    void refreshRuns();
    // Capabilities never change over a session, so fetch once on mount.
    fetchCapabilities()
      .then((caps) => setCanSteer(caps.can_steer))
      .catch(() => {
        /* absence of steering is the safe default */
      });
  }, [refreshAuth, refreshRuns]);

  // Live polling, scoped to the active run. Re-runs when the active run changes
  // so switching to a past run (?run=<name>) reloads its data; a finished run
  // does a single full fetch and stops.
  const finishedRef = useRef(false);
  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    finishedRef.current = false;

    const schedule = () => {
      timer = setTimeout(tick, POLL_MS);
    };

    const tick = async () => {
      if (cancelled) return;
      try {
        const { summary, raw, finished } = await fetchRunSummary(activeRun);
        if (cancelled) return;
        if (finished && !finishedRef.current) {
          finishedRef.current = true;
          const full = await fetchAll(activeRun);
          if (!cancelled) setRun(full);
          return; // stop polling
        }
        const [transcript, vulnerabilities] = await Promise.all([
          fetchTranscript(activeRun).catch(() => ({ agents: [], events: [] })),
          fetchVulnerabilities(summary.runId, activeRun).catch(() => [] as Vulnerability[]),
        ]);
        if (cancelled) return;
        setRun((prev) => ({
          summary,
          raw,
          finished,
          transcript,
          vulnerabilities,
          reportMarkdown: prev?.reportMarkdown ?? null,
        }));
        schedule();
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "无法加载运行数据。");
        schedule();
      }
    };

    (async () => {
      try {
        const full = await fetchAll(activeRun);
        if (cancelled) return;
        setRun(full);
        if (full.finished) {
          finishedRef.current = true;
        } else {
          schedule();
        }
      } catch (e) {
        if (cancelled) return;
        setError(e instanceof Error ? e.message : "无法加载运行数据。");
        schedule();
      }
    })();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [activeRun]);

  const counts = useMemo(
    () => (run ? severityCounts(run.vulnerabilities) : null),
    [run]
  );
  const selected = run?.vulnerabilities.find((v) => v.id === selectedId) ?? null;
  const agentCount = run?.transcript.agents.length ?? 0;
  const verified = auth?.verified === true;

  // Per-run guard for the default view: land on Agents while a scan is live,
  // Overview once it finishes. Applied at most once per run and never once the
  // user has navigated manually (userSetView flips the guard).
  const initialViewAppliedRef = useRef(false);

  // Reset the guard whenever the active run changes so the newly selected run
  // gets its own default.
  useEffect(() => {
    initialViewAppliedRef.current = false;
  }, [activeRun]);

  useEffect(() => {
    if (initialViewAppliedRef.current || !run) return;
    if (run.finished) {
      initialViewAppliedRef.current = true;
      setView("overview");
    } else if (agentCount > 0) {
      // Live and agents have appeared: default to the agent graph. If it is
      // live but no agents exist yet, wait (do not apply, do not set the flag).
      initialViewAppliedRef.current = true;
      setView("agents");
    }
  }, [run, agentCount]);

  // User-initiated navigation: mark the default guard applied so the per-run
  // default effect never yanks the user off the view they chose.
  const userSetView = useCallback((v: View) => {
    initialViewAppliedRef.current = true;
    setView(v);
  }, []);

  const selectRun = useCallback((name: string) => {
    setActiveRun(name);
    setSelectedId(null);
    setRun(null);
    setError(null);
    // Reset the guard so the per-run default applies to the newly selected run.
    initialViewAppliedRef.current = false;
  }, []);

  const goEmail = useCallback((skipDisclosure: boolean, surface: string) => {
    trackCta("email_report", surface);
    setEmailPurpose("report");
    setEmailSkipDisclosure(skipDisclosure);
    userSetView("email");
  }, [userSetView]);

  // Sidebar entry keeps the disclosure (first place those users see it);
  const openEmail = useCallback(() => goEmail(false, "sidebar"), [goEmail]);
  // the Overview CTA already states the tradeoff, so it starts the flow directly.
  const openEmailFromOverview = useCallback(() => goEmail(true, "overview"), [goEmail]);

  const openHistory = useCallback(() => {
    void refreshRuns();
    userSetView("history");
  }, [refreshRuns, userSetView]);

  const onPastRunsVerified = useCallback(async () => {
    await refreshAuth();
    await refreshRuns();
  }, [refreshAuth, refreshRuns]);

  const onForget = useCallback(async () => {
    await forgetAuth();
    await refreshAuth();
    await refreshRuns();
  }, [refreshAuth, refreshRuns]);

  return (
    <div className="min-h-screen bg-black text-white flex">
      <Sidebar
        view={view}
        onSelectView={(v) => {
          // Clicking a sidebar view always lands on that section's top level,
          // so leaving a specific issue's detail view and clicking "Issues"
          // returns to the full findings list.
          setSelectedId(null);
          if (v === "history") openHistory();
          else userSetView(v);
        }}
        issuesCount={run?.vulnerabilities.length ?? 0}
        agentCount={agentCount}
        runCount={runs?.count ?? 0}
        finished={run?.finished ?? false}
        verified={verified}
        email={auth?.email ?? null}
        onOpenEmail={openEmail}
        onOpenHistory={openHistory}
        onForget={() => void onForget()}
      />

      <div className="flex-1 min-w-0">
        {/* Top bar */}
        <div className="border-b border-[#222]">
          <div className="max-w-[88rem] mx-auto px-3 sm:px-6 py-4 flex items-center gap-1.5">
            <a
              href={ctaUrl("https://app.strix.ai", "logo")}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => trackCta("logo", "topbar")}
              className="flex items-center gap-1.5 opacity-90 transition-opacity hover:opacity-100 lg:hidden"
              title="打开 Strix Cloud"
            >
              <img src="./logo.png" alt="Strix" className="w-10 h-8 object-cover" />
              <div className="text-base text-white font-medium tracking-tight">Strix</div>
            </a>
            {run && <LiveIndicator finished={run.finished} />}
            <div className="ml-auto flex items-center gap-3">
              {verified && runs && !runs.locked && runs.runs.length > 0 && (
                <RunSwitcher
                  runs={runs}
                  activeRun={activeRun}
                  launchedName={runTitle(run?.summary.targets[0] ?? null, run?.summary.runName ?? run?.summary.runId ?? "当前运行")}
                  onSelect={selectRun}
                />
              )}
              <a
                href={ctaUrl(SIGNUP_URL, "run_in_cloud")}
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => trackCta("run_in_cloud", "topbar")}
                className="inline-flex items-center gap-1 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-black transition-opacity hover:opacity-90"
              >
                在云端运行
                <ArrowUpRight className="w-3 h-3" aria-hidden="true" />
              </a>
            </div>
          </div>
        </div>

        <div className="max-w-[88rem] mx-auto px-3 sm:px-6 py-8 sm:py-12 space-y-6">
          {error && !run && view !== "history" && view !== "email" && (
            <div className="rounded-lg px-4 py-3 flex gap-3 items-start border border-red-500/30 bg-red-500/5">
              <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5 text-red-400" aria-hidden="true" />
              <p className="text-sm text-red-300">{error}</p>
            </div>
          )}

          {/* Keyed wrapper: re-mounts on every view / finding / run change so the
              page-in transition replays. */}
          <div
            key={`${activeRun ?? "launched"}:${view}:${selectedId ?? ""}`}
            className="animate-page-in space-y-6"
          >
          {view === "email" ? (
            <EmailReportView
              activeRun={activeRun}
              auth={auth}
              purpose={emailPurpose}
              skipDisclosure={emailSkipDisclosure}
              onAuthChanged={() => {
                void refreshAuth();
                void refreshRuns();
              }}
              onExit={(dest) => setView(dest === "history" ? "history" : "overview")}
            />
          ) : view === "feedback" ? (
            <FeedbackView
              defaultEmail={auth?.email ?? null}
              onExit={(dest) => setView(dest)}
            />
          ) : view === "history" ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <History className="w-5 h-5 text-[#888]" aria-hidden="true" />
                <h1 className="text-2xl font-semibold text-white">历史运行</h1>
              </div>
              <PastRunsView
                runs={runs}
                activeRun={activeRun}
                onSelectRun={selectRun}
                onVerified={() => void onPastRunsVerified()}
              />
            </div>
          ) : !run && !error ? (
            <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-10 text-center">
              <div className="w-6 h-6 mx-auto mb-3 rounded-full border-2 border-[#333] border-t-white animate-spin" />
              <p className="text-sm text-[#888]">正在加载运行数据…</p>
            </div>
          ) : run && counts ? (
            <>
              <SummaryHeader summary={run.summary} />

              {/* Tab strip: shown on small screens where the sidebar is hidden. */}
              <div className="flex gap-5 border-b border-[#2a2a2a] lg:hidden">
                <TabButton active={view === "overview"} onClick={() => userSetView("overview")}>
                  测试总览
                </TabButton>
                <TabButton active={view === "issues"} onClick={() => userSetView("issues")}>
                  问题{run.vulnerabilities.length > 0 ? ` (${run.vulnerabilities.length})` : ""}
                </TabButton>
                {agentCount > 0 && (
                  <TabButton active={view === "agents"} onClick={() => userSetView("agents")}>
                    代理 ({agentCount})
                  </TabButton>
                )}
              </div>

              {view === "overview" ? (
                <OverviewTab
                  summary={run.summary}
                  counts={counts}
                  total={run.vulnerabilities.length}
                  reportMarkdown={run.reportMarkdown}
                  raw={run.raw}
                  finished={run.finished}
                  onOpenEmail={openEmailFromOverview}
                />
              ) : view === "agents" && agentCount > 0 ? (
                <AgentsTab run={run} canSteer={canSteer} />
              ) : selected ? (
                <div className="space-y-4">
                  <button
                    onClick={() => setSelectedId(null)}
                    className="cursor-pointer inline-flex items-center gap-1.5 text-sm text-[#888] hover:text-white transition-colors"
                  >
                    <ArrowLeft className="w-4 h-4" /> 返回全部问题
                  </button>
                  <VulnerabilityDetail vulnerability={selected} />
                </div>
              ) : (
                <FindingsList
                  vulnerabilities={run.vulnerabilities}
                  finished={run.finished}
                  onSelect={(id) => setSelectedId(id)}
                />
              )}
            </>
          ) : null}
          </div>
        </div>
      </div>
      <TrustToast message={TRUST_BANNER} />
    </div>
  );
}

function RunSwitcher({
  runs,
  activeRun,
  launchedName,
  onSelect,
}: {
  runs: RunsPayload;
  activeRun: string | null;
  launchedName: string;
  onSelect: (name: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const activeEntry = runs.runs.find((r) => r.name === activeRun);
  const current = activeEntry ? runTitle(activeEntry.target, activeEntry.name) : launchedName;
  return (
    <div className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        aria-label="切换测试"
        className="flex items-center gap-2 rounded-lg border border-[#3a3a3a] bg-[rgba(255,255,255,0.05)] px-3 py-2 text-sm text-white transition-colors hover:border-[#555] hover:bg-[rgba(255,255,255,0.09)]"
      >
        <History className="h-4 w-4 flex-shrink-0 text-[#888]" aria-hidden="true" />
        <span className="flex-shrink-0 text-[#888]">测试</span>
        <span className="max-w-[260px] truncate font-medium">{current}</span>
        <ChevronDown className="h-4 w-4 flex-shrink-0 text-[#aaa]" aria-hidden="true" />
      </button>
      {open && (
        <div
          className="absolute right-0 z-50 mt-2 max-h-96 w-96 overflow-y-auto rounded-xl py-1.5 shadow-2xl"
          style={{ border: "1px solid #3a3a3a", background: "#0a0a0a" }}
        >
          <div className="border-b border-[#222] px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-[#666]">
            切换测试
          </div>
          {runs.runs.map((r) => {
            const active = r.name === activeRun;
            return (
              <button
                key={r.name}
                onMouseDown={() => onSelect(r.name)}
                className={`flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm transition-colors hover:bg-[rgba(255,255,255,0.06)] ${
                  active ? "bg-[rgba(255,255,255,0.04)] text-white" : "text-[#aaa]"
                }`}
              >
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-medium">{runTitle(r.target, r.name)}</span>
                  {r.target && <span className="block truncate font-mono text-xs text-[#666]">{r.target}</span>}
                </span>
                {active && <span className="h-2 w-2 flex-shrink-0 rounded-full bg-emerald-400" />}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

function LiveIndicator({ finished }: { finished: boolean }) {
  if (finished) {
    return (
      <span className="ml-3 inline-flex items-center gap-1.5 text-xs text-[#888]">
        <span className="w-1.5 h-1.5 rounded-full bg-[#555]" />
        已完成
      </span>
    );
  }
  return (
    <span className="ml-3 inline-flex items-center gap-1.5 text-xs text-emerald-400">
      <span className="relative flex h-1.5 w-1.5">
        <span className="absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75 animate-ping" />
        <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-emerald-400" />
      </span>
      进行中
    </span>
  );
}

function formatDuration(seconds: number | null): string | null {
  if (seconds == null) return null;
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

function SummaryHeader({ summary }: { summary: ParsedRunSummary }) {
  const duration = formatDuration(summary.durationSeconds);
  return (
    <div>
      <h1 className="text-2xl font-semibold text-white">
        {runTitle(summary.targets[0] ?? null, summary.runName ?? summary.runId ?? "渗透测试结果")}
      </h1>
      <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-[#888]">
        {summary.targets.length > 0 && (
          <span className="font-mono text-[#aaa]">{summary.targets.join(", ")}</span>
        )}
        {summary.scanMode && <Meta label={formatScanModeLabel(summary.scanMode) ?? summary.scanMode} />}
        {duration && <Meta label={duration} />}
        {summary.status && <Meta label={formatRunStatusLabel(summary.status) ?? summary.status} />}
      </div>
    </div>
  );
}

function Meta({ label }: { label: string }) {
  return (
    <>
      <span className="text-[#333]">·</span>
      <span className="capitalize">{label}</span>
    </>
  );
}

function FindingsList({
  vulnerabilities,
  finished,
  onSelect,
}: {
  vulnerabilities: Vulnerability[];
  finished: boolean;
  onSelect: (id: string) => void;
}) {
  const sorted = [...vulnerabilities].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  if (sorted.length === 0) {
    return (
      <div className="space-y-4">
        <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-8 text-center text-sm text-[#888]">
          {finished ? "本次运行没有发现问题。" : "暂未发现问题，测试仍在进行中…"}
        </div>
        {finished && (
          <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
            <p className="text-sm font-medium text-white">提前发现新的暴露面</p>
            <p className="mt-0.5 mb-3 text-xs text-[#666]">
              持续监控攻击面，及时发现组织新增暴露点。
            </p>
            <ProInlineCta
              label="攻击面监控"
              desc="为整个组织提供持续覆盖。"
              slug="asm"
              surface="empty_state"
              icon={Radar}
            />
          </div>
        )}
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {sorted.map((v) => (
        <button
          key={v.id}
          onClick={() => onSelect(v.id)}
          className="animate-card-in cursor-pointer w-full text-left rounded-lg border border-[#222] hover:border-[#444] bg-[rgba(255,255,255,0.02)] px-4 py-3 transition-colors flex items-center gap-3"
        >
          <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${getSeverityDot(v.severity)}`} aria-hidden="true" />
          <span className="flex-1 min-w-0">
            <span className="block text-sm font-medium text-white truncate">{v.title}</span>
            {v.target && (
              <span className="block text-xs text-[#666] font-mono truncate">{v.target}</span>
            )}
          </span>
          <span
            className={`text-xs font-semibold px-2 py-0.5 rounded-full border capitalize ${SEVERITY_COLORS[v.severity]}`}
          >
            {SEVERITY_LABELS[v.severity]}
          </span>
        </button>
      ))}
    </div>
  );
}

/** Strip a single leading markdown heading (report sections embed their own). */
function stripLeadingHeading(md: string): string {
  return md.replace(/^\s*#{1,6}[ \t]+.*(?:\r?\n)+/, "").trimStart();
}

function dedupeHeadings(md: string): string {
  const out: string[] = [];
  let lastHeading: string | null = null;
  for (const line of md.split("\n")) {
    const m = line.match(/^#{1,6}\s+(.*)$/);
    if (m) {
      const norm = m[1].trim().toLowerCase();
      if (norm === lastHeading) continue;
      lastHeading = norm;
    } else if (line.trim() !== "") {
      lastHeading = null;
    }
    out.push(line);
  }
  return out.join("\n");
}

/** Primary local CTA: email an encrypted PDF. Verify-email affordance, no lock. */
function EmailReportCta({ onOpenEmail }: { onOpenEmail: () => void }) {
  return (
    <button
      onClick={onOpenEmail}
      className="group w-full cursor-pointer rounded-xl border border-emerald-500/25 bg-emerald-500/[0.06] p-4 text-left transition-colors hover:border-emerald-500/40"
    >
      <div className="flex items-center gap-3">
        <div
          className="flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg"
          style={{ border: "1px solid rgba(16,185,129,0.3)", background: "rgba(16,185,129,0.08)" }}
        >
          <Mail className="h-4 w-4 text-emerald-400" aria-hidden="true" />
        </div>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-white">将本次运行的加密 PDF 报告发送到邮箱</p>
          <p className="mt-0.5 text-xs text-[#888]">
            报告会使用仅你可见的密码加密，发送前需通过一次性验证码验证邮箱。
          </p>
        </div>
        <span className="flex-shrink-0 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-black transition-opacity group-hover:opacity-90">
          导出 PDF 报告
        </span>
      </div>
    </button>
  );
}

function OverviewTab({
  summary,
  counts,
  total,
  reportMarkdown,
  raw,
  finished,
  onOpenEmail,
}: {
  summary: ParsedRunSummary;
  counts: Record<VulnerabilitySeverity, number>;
  total: number;
  reportMarkdown: string | null;
  raw: Record<string, unknown>;
  finished: boolean;
  onOpenEmail: () => void;
}) {
  const sections = (
    [
      ["执行摘要", summary.executiveSummary],
      ["技术分析", summary.technicalAnalysis],
      ["测试方法", summary.methodology],
      ["修复建议", summary.recommendations],
    ] as const
  )
    .filter(([, content]) => !!content)
    .map(([title, content]) => ({ title, content: stripLeadingHeading(content as string) }));

  return (
    <div className="space-y-6">
      <div className="animate-card-in">
        <RunDetails raw={raw} durationSeconds={summary.durationSeconds} />
      </div>

      {total > 0 && (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
          <IssueSeveritySummary findings={{ total, ...counts }} />
        </div>
      )}

      {/* Primary CTA: the one primary on Overview. Hidden until the run is
          finished, since a live scan would only email a partial report. */}
      {finished && (
        <div className="animate-card-in">
          <EmailReportCta onOpenEmail={onOpenEmail} />
        </div>
      )}

      {sections.length > 0 ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5 space-y-8">
          {sections.map((s) => (
            <ContentSection key={s.title} title={s.title} content={s.content} />
          ))}
        </div>
      ) : reportMarkdown ? (
        <div className="animate-card-in rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
          <ContentSection content={dedupeHeadings(reportMarkdown)} />
        </div>
      ) : (
        total === 0 && (
          <p className="text-sm text-[#888]">当前运行暂未生成摘要。</p>
        )
      )}

    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`cursor-pointer relative pb-2.5 text-sm font-semibold transition-colors ${
        active ? "text-white" : "text-[#666] hover:text-white"
      }`}
    >
      {children}
      {active && <span className="absolute bottom-0 inset-x-0 h-0.5 bg-white rounded-full" />}
    </button>
  );
}

function AgentsTab({ run, canSteer }: { run: LoadedRun; canSteer: boolean }) {
  const { agents, events } = run.transcript;
  const graphAgents = useMemo(() => buildGraphAgents(agents, events), [agents, events]);
  // Clicking a graph node opens the agent's transcript in a modal; no node selected means no modal.
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedAgent = selectedId ? (agents.find((a) => a.id === selectedId) ?? null) : null;

  // Live steering is only possible in-process (canSteer) while the scan runs.
  const steerable = canSteer && !run.finished;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
        <div className="flex items-center gap-2">
          <Bot className="w-4 h-4 text-[#888]" aria-hidden="true" />
          <h2 className="text-sm font-semibold text-white">代理关系图</h2>
          <span className="text-xs text-[#666]">
            {agents.length} 个代理
          </span>
        </div>
        <p className="mt-1 mb-4 text-xs text-[#666]">
          点击代理可查看完整对话记录。
        </p>
        <div className="h-[480px] rounded-lg border border-[#1a1a1a] overflow-hidden">
          <AgentGraph
            agents={graphAgents}
            selectedAgentId={selectedId}
            onSelectAgent={(id) => setSelectedId(id)}
            eventsLoaded
            eventsEmpty={graphAgents.size === 0}
            scanCompleted={run.finished}
          />
        </div>
      </div>

      {/* Live steering: only in-process while the scan runs. Otherwise omitted. */}
      {steerable && <ScanPromptComposer agents={agents} />}

      {/* Re-run always routes to Strix Cloud. */}
      <div className="rounded-xl border border-[#222] bg-[rgba(255,255,255,0.02)] p-5">
        <p className="text-sm font-semibold text-white">使用更深入的方式重新运行本次测试</p>
        <p className="mt-0.5 text-xs text-[#666]">在云端托管基础设施上重新执行这次渗透测试。</p>
        <div className="mt-3 flex flex-wrap gap-2.5">
          <ProInlineCta
            label="在 Strix Pro 中深入复测"
            desc="在托管基础设施上更深入地运行这次渗透测试。"
            slug="live_scan"
            surface="agents"
            icon={Rocket}
          />
        </div>
      </div>

      <AgentDetailModal
        open={selectedAgent !== null}
        agent={selectedAgent}
        events={events}
        steerable={steerable}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}
