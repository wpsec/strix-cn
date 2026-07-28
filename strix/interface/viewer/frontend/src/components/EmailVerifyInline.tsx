import { useState } from "react";
import { Loader2, AlertCircle } from "lucide-react";
import { otpStart, otpVerify } from "@/data/serverSource";
import { track } from "@/lib/cta";

/**
 * Compact inline email -> 6-digit-code verify flow. Unlike EmailReportView this
 * has no page chrome, no report send, and no password panel: it just confirms
 * the email so the past-runs list can unlock in place. On success it calls
 * `onVerified` (the parent refreshes auth + runs).
 */

const OTP_START_ERRORS: Record<string, string> = {
  work_email_required: "请使用工作邮箱，不要使用个人邮箱。",
  rate_limited: "请求过于频繁，请稍后再试。",
  invalid_email: "邮箱格式不正确，请检查后重试。",
  unavailable: "邮件服务暂时不可用，请稍后再试。",
};

// A small set of common personal providers for instant client-side feedback.
// The relay is authoritative (it checks the full free-email-domains list).
const COMMON_FREE_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
  "hotmail.com", "live.com", "icloud.com", "me.com", "aol.com", "proton.me",
  "protonmail.com", "gmx.com", "mail.com",
]);

export default function EmailVerifyInline({ onVerified }: { onVerified: () => void }) {
  const [step, setStep] = useState<"email" | "code">("email");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const submitEmail = async () => {
    const value = email.trim();
    if (!value) {
      setError("请输入邮箱后继续。");
      return;
    }
    const domain = value.slice(value.lastIndexOf("@") + 1).toLowerCase();
    if (COMMON_FREE_DOMAINS.has(domain)) {
      track("work_email_required");
      setError(OTP_START_ERRORS.work_email_required);
      return;
    }
    setBusy(true);
    setError(null);
    const result = await otpStart(value);
    setBusy(false);
    if (result.ok) {
      track("email_submitted", { purpose: "verify" });
      setNotice(`6 位验证码已发送到 ${value}。`);
      setStep("code");
    } else {
      if (result.error === "work_email_required") track("work_email_required");
      setError(OTP_START_ERRORS[result.error] ?? "无法发送验证码，请稍后再试。");
    }
  };

  const submitCode = async () => {
    const value = code.trim();
    if (value.length < 4) {
      setError("请输入邮件中的 6 位验证码。");
      return;
    }
    setBusy(true);
    setError(null);
    const result = await otpVerify(email.trim(), value);
    setBusy(false);
    if (!result.verified) {
      setError("验证码不正确，请检查后重试。");
      return;
    }
    track("email_verified", { purpose: "verify" });
    onVerified();
  };

  return (
    <div className="mx-auto mt-5 max-w-sm text-left">
      {error && (
        <div className="mb-3 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2">
          <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" aria-hidden="true" />
          <p className="text-xs text-red-300">{error}</p>
        </div>
      )}
      {notice && !error && <p className="mb-3 text-xs text-[#888]">{notice}</p>}

      {step === "email" ? (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submitEmail();
          }}
        >
          <label className="block">
            <span className="mb-1.5 block text-xs text-[#888]">工作邮箱</span>
            <input
              type="email"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
              className="w-full rounded-lg bg-black px-3 py-2.5 text-sm text-white outline-none transition-colors focus:border-[#444]"
              style={{ border: "1px solid #2a2a2a" }}
            />
            <span className="mt-1.5 block text-[11px] text-[#666]">请使用工作邮箱。</span>
          </label>
          <button
            type="submit"
            disabled={busy}
            className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-60"
          >
            {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            发送验证码
          </button>
        </form>
      ) : (
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submitCode();
          }}
        >
          <label className="block">
            <span className="mb-1.5 block text-xs text-[#888]">6 位验证码</span>
            <input
              inputMode="numeric"
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
              placeholder="123456"
              className="w-full rounded-lg bg-black px-3 py-2.5 text-center text-lg font-mono tracking-[0.4em] text-white outline-none transition-colors focus:border-[#444]"
              style={{ border: "1px solid #2a2a2a" }}
            />
          </label>
          <button
            type="submit"
            disabled={busy}
            className="flex w-full cursor-pointer items-center justify-center gap-2 rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-black transition-opacity hover:opacity-90 disabled:opacity-60"
          >
            {busy && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
            验证
          </button>
          <button
            type="button"
            onClick={() => {
              setStep("email");
              setError(null);
              setNotice(null);
            }}
            className="w-full cursor-pointer text-center text-xs text-[#666] transition-colors hover:text-[#aaa]"
          >
            使用其他邮箱
          </button>
        </form>
      )}
    </div>
  );
}
