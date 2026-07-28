import { useState } from "react";
import { ArrowLeft, AlertCircle, CheckCircle2 } from "lucide-react";
import { IoChatbubblesOutline } from "react-icons/io5";
import { submitFeedback } from "@/data/serverSource";
import type { View } from "@/App";

const MAX_MESSAGE = 5000;

const ERROR_COPY: Record<string, string> = {
  invalid_email: "邮箱格式看起来不正确。",
  invalid_message: "请再补充一点内容。",
  unavailable: "暂时无法发送，请稍后再试。",
};

/**
 * Feedback & support form. Collects a message plus a work email (no
 * verification — the email is taken as-is) and relays it to Strix via the local
 * server. Mirrors EmailReportView's centered-card styling and palette.
 */
export default function FeedbackView({
  defaultEmail,
  onExit,
}: {
  defaultEmail: string | null;
  onExit: (dest: View) => void;
}) {
  const [message, setMessage] = useState("");
  const [email, setEmail] = useState(defaultEmail ?? "");
  const [step, setStep] = useState<"form" | "sending" | "sent">("form");
  const [error, setError] = useState<string | null>(null);

  const canSend = message.trim().length > 0 && email.trim().length > 0 && step !== "sending";

  const send = async () => {
    if (!canSend) return;
    setStep("sending");
    setError(null);
    const result = await submitFeedback(message.trim(), email.trim());
    if (result.ok) {
      setStep("sent");
      return;
    }
    setStep("form");
    setError(ERROR_COPY[result.error] ?? ERROR_COPY.unavailable);
  };

  return (
    <div className="mx-auto max-w-xl space-y-4">
      <button
        onClick={() => onExit("overview")}
        className="cursor-pointer inline-flex items-center gap-1.5 text-sm text-[#888] transition-colors hover:text-white"
      >
        <ArrowLeft className="h-4 w-4" />
        返回结果页
      </button>

      <div className="flex items-center gap-2">
        <IoChatbubblesOutline className="h-5 w-5 text-[#888]" aria-hidden="true" />
        <h1 className="text-2xl font-semibold text-white">反馈与支持</h1>
      </div>

      <div
        className="w-full rounded-2xl bg-[rgba(255,255,255,0.02)] p-6"
        style={{ border: "1px solid #2a2a2a" }}
      >
        {step === "sent" ? (
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 h-5 w-5 flex-shrink-0 text-emerald-400" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-white">已收到你的反馈。</p>
              <p className="mt-1 text-xs text-[#888]">
                我们会阅读每一条反馈；如果需要回复，会通过你填写的邮箱联系你。
              </p>
              <button
                onClick={() => {
                  setMessage("");
                  setStep("form");
                }}
                className="mt-4 cursor-pointer text-xs text-[#888] transition-colors hover:text-white"
              >
                继续反馈
              </button>
            </div>
          </div>
        ) : (
          <>
            <p className="mb-4 text-xs text-[#666]">
              Bug、功能建议，或任何使用问题，都可以直接告诉我们。
            </p>

            {error && (
              <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2">
                <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" aria-hidden="true" />
                <p className="text-xs text-red-300">{error}</p>
              </div>
            )}

            <label className="block">
              <span className="mb-1.5 block text-xs text-[#888]">反馈内容</span>
              <textarea
                autoFocus
                value={message}
                maxLength={MAX_MESSAGE}
                onChange={(e) => setMessage(e.target.value)}
                rows={5}
                placeholder="哪些地方好用，哪些地方不好用，或者你希望看到什么改进…"
                className="w-full resize-y rounded-lg border border-[#2a2a2a] bg-black px-3 py-2.5 text-sm text-white outline-none transition-colors focus:border-white/50 focus:ring-2 focus:ring-white/10"
              />
            </label>

            <label className="mt-4 block">
              <span className="mb-1.5 block text-xs text-[#888]">工作邮箱</span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="w-full rounded-lg border border-[#2a2a2a] bg-black px-3 py-2.5 text-sm text-white outline-none transition-colors focus:border-white/50 focus:ring-2 focus:ring-white/10"
              />
            </label>

            <button
              onClick={() => void send()}
              disabled={!canSend}
              className="mt-4 flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              {step === "sending" ? "发送中…" : "发送反馈"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
