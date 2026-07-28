import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { ArrowUp, ChevronDown, ChevronUp, Loader2, Sparkles } from "lucide-react";
import { steerAgent, type TranscriptAgent } from "@/data/serverSource";
import { track } from "@/lib/cta";
import { cn } from "@/lib/utils";

const ROOT_TARGET_VALUE = "__root__";

interface ScanPromptComposerProps {
  /** All agents in the run; used to resolve the root and running children. */
  agents: TranscriptAgent[];
  /**
   * Single-agent (modal) mode: pins the composer to one agent and shows a
   * static "Target: <name>" pill instead of the dropdown. Omit for the
   * multi-agent graph variant.
   */
  fixedAgentId?: string;
  className?: string;
}

/**
 * Faithful port of the pro app's ScanPromptComposer for the local viewer.
 * Collapsed by default into a "Guide the agent" pill; expands into a card with
 * an auto-resizing textarea and a target control. The viewer's steering is
 * immediate (no Enterprise lock, no bridge-connecting state), so this is only
 * rendered by callers when steering is available. Sends via steerAgent, which
 * requires a concrete agent id, so "Root agent" resolves to the root agent's id.
 */
export function ScanPromptComposer({
  agents,
  fixedAgentId,
  className,
}: ScanPromptComposerProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [expanded, setExpanded] = useState(false);
  const [focused, setFocused] = useState(false);
  const [value, setValue] = useState("");
  const [sending, setSending] = useState(false);
  const [feedback, setFeedback] = useState<string | null>(null);

  const isModal = fixedAgentId != null;

  // Root = the agent with no parent; fall back to the first agent.
  const rootAgent = useMemo(
    () => agents.find((a) => !a.parent_id) ?? agents[0] ?? null,
    [agents]
  );

  // Multi-agent dropdown options: running child agents plus Root (added in JSX).
  const targetOptions = useMemo(
    () => agents.filter((a) => a.parent_id && a.status === "running"),
    [agents]
  );

  // Selected target for the multi-agent variant. ROOT sentinel by default.
  const [selectedTarget, setSelectedTarget] = useState<string>(ROOT_TARGET_VALUE);
  const [menuOpen, setMenuOpen] = useState(false);

  // If the selected child target disappears (finished), fall back to Root.
  useEffect(() => {
    if (
      selectedTarget !== ROOT_TARGET_VALUE &&
      !targetOptions.some((a) => a.id === selectedTarget)
    ) {
      setSelectedTarget(ROOT_TARGET_VALUE);
    }
  }, [selectedTarget, targetOptions]);

  // Resolve the concrete agent id + display name for the current target.
  const { targetId, targetName } = useMemo(() => {
    if (isModal) {
      const agent = agents.find((a) => a.id === fixedAgentId) ?? null;
      return {
        targetId: fixedAgentId ?? null,
        targetName: agent?.name ?? "当前代理",
      };
    }
    if (selectedTarget === ROOT_TARGET_VALUE) {
      return {
        targetId: rootAgent?.id ?? null,
        targetName: "根代理",
      };
    }
    const agent = agents.find((a) => a.id === selectedTarget) ?? null;
    return {
      targetId: agent?.id ?? rootAgent?.id ?? null,
      targetName: agent?.name ?? "根代理",
    };
  }, [agents, fixedAgentId, isModal, rootAgent, selectedTarget]);

  const empty = value.trim().length === 0;

  // Grow the textarea with its content, capped by max-h via CSS.
  useLayoutEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${el.scrollHeight}px`;
  }, [value]);

  const handleExpand = useCallback(() => {
    setExpanded(true);
    requestAnimationFrame(() => textareaRef.current?.focus());
  }, []);

  const handleCollapse = useCallback(() => {
    setExpanded(false);
    setFocused(false);
    setMenuOpen(false);
  }, []);

  const handleSend = useCallback(async () => {
    if (sending) return;
    const message = value.trim();
    if (!message || !targetId) return;

    setSending(true);
    setFeedback(null);
    const name = targetName;
    const res = await steerAgent(targetId, message);
    setSending(false);
    if (res.ok) {
      setValue("");
      setFeedback(`已发送给 ${name}`);
      track("agent_steered");
    } else if (res.error === "not_delivered") {
      setFeedback("无法联系该代理，它可能已经结束。");
    } else {
      setFeedback("消息发送失败，请重试。");
    }
  }, [sending, value, targetId, targetName]);

  if (!expanded) {
    return (
      <button
        type="button"
        onClick={handleExpand}
        className={cn(
          "mt-4 flex w-full items-center justify-between gap-3 rounded-2xl border border-white/[0.08] bg-[#050505] px-5 py-3 text-left transition-colors duration-300 hover:border-white/[0.12] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/20",
          className
        )}
        aria-expanded={false}
        aria-label="展开实时提示面板"
      >
        <div className="flex min-w-0 items-center gap-2">
          <Sparkles className="h-4 w-4 shrink-0 text-[#666]" />
          <span className="truncate text-sm font-medium text-white">指导代理</span>
        </div>
        <ChevronUp className="h-4 w-4 shrink-0 text-[#777]" />
      </button>
    );
  }

  return (
    <div
      className={cn(
        "mt-4 rounded-2xl border border-white/[0.08] bg-[#050505] overflow-hidden transition-colors duration-300",
        focused ? "border-white/[0.18]" : "hover:border-white/[0.12]",
        className
      )}
    >
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-5 py-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-[#666]" />
            <p className="text-sm font-medium text-white">实时提示</p>
          </div>
          <p className="mt-0.5 text-xs text-[#777]">已连接</p>
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {isModal ? (
            <div className="rounded-full border border-white/[0.08] bg-white/[0.03] px-3 py-1 text-xs text-[#aaa]">
              目标：<span className="text-white">{targetName}</span>
            </div>
          ) : (
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-[#aaa]">目标：</span>
              <div className="relative">
                <button
                  type="button"
                  onClick={() => setMenuOpen((o) => !o)}
                  onBlur={() => requestAnimationFrame(() => setMenuOpen(false))}
                  className="inline-flex h-7 items-center gap-1 rounded-full border border-white/[0.08] bg-white/[0.03] px-3 text-xs text-white transition-colors hover:border-white/[0.16] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/20"
                  aria-haspopup="listbox"
                  aria-expanded={menuOpen}
                >
                  <span className="max-w-[140px] truncate">{targetName}</span>
                  <ChevronDown className="h-3.5 w-3.5 text-[#999]" />
                </button>
                {menuOpen && (
                  <div
                    className="absolute right-0 z-10 mt-1 min-w-[160px] overflow-hidden rounded-lg border border-[#333] bg-[#0a0a0a] py-1 shadow-xl"
                    role="listbox"
                  >
                    <TargetMenuItem
                      label="根代理"
                      active={selectedTarget === ROOT_TARGET_VALUE}
                      onSelect={() => {
                        setSelectedTarget(ROOT_TARGET_VALUE);
                        setMenuOpen(false);
                      }}
                    />
                    {targetOptions.map((option) => (
                      <TargetMenuItem
                        key={option.id}
                        label={option.name}
                        active={selectedTarget === option.id}
                        onSelect={() => {
                          setSelectedTarget(option.id);
                          setMenuOpen(false);
                        }}
                      />
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
          <button
            type="button"
            onClick={handleCollapse}
            className="inline-flex h-7 w-7 items-center justify-center rounded-full text-[#777] transition-colors hover:bg-white/[0.06] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/20"
            aria-label="收起实时提示面板"
          >
            <ChevronDown className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="px-5 pt-4 pb-3">
        <textarea
          ref={textareaRef}
          rows={1}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              void handleSend();
            }
          }}
          placeholder="向正在运行的测试发送实时提示…"
          maxLength={4000}
          disabled={sending}
          className="block w-full resize-none border-0 bg-transparent p-0 text-[15px] leading-6 text-white placeholder:text-[#444] focus:outline-none disabled:opacity-60 max-h-[160px] overflow-y-auto"
        />
      </div>

      <div className="flex items-center justify-between gap-3 px-4 pb-4">
        <div className="text-xs text-[#666]">{feedback ?? "按 Enter 发送。"}</div>
        <button
          type="button"
          onClick={(event) => {
            event.stopPropagation();
            void handleSend();
          }}
          disabled={sending || empty}
          className={cn(
            "inline-flex h-10 min-w-[112px] items-center justify-center gap-2 rounded-full px-4 text-sm font-medium transition-colors",
            sending || empty
              ? "bg-white/[0.08] text-[#666]"
              : "bg-white text-black hover:bg-neutral-200"
          )}
        >
          {sending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <ArrowUp className="h-4 w-4" strokeWidth={2.5} />
          )}
          <span>发送提示</span>
        </button>
      </div>
    </div>
  );
}

function TargetMenuItem({
  label,
  active,
  onSelect,
}: {
  label: string;
  active: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      role="option"
      aria-selected={active}
      // onMouseDown so the click lands before the trigger's onBlur closes the menu.
      onMouseDown={(e) => {
        e.preventDefault();
        onSelect();
      }}
      className={cn(
        "block w-full truncate px-3 py-1.5 text-left text-xs transition-colors hover:bg-white/[0.06]",
        active ? "text-white" : "text-[#aaa]"
      )}
    >
      {label}
    </button>
  );
}

export default ScanPromptComposer;
