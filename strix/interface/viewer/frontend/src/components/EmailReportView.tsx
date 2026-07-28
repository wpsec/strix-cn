import { useEffect, useRef, useState } from "react";
import { Mail, ShieldCheck, Lock, Copy, Check, Loader2, AlertCircle, ArrowLeft } from "lucide-react";
import {
  otpStart,
  otpVerify,
  sendReport,
  type AuthStatus,
} from "@/data/serverSource";
import { track } from "@/lib/cta";

/**
 * The email-report / email-verification flow rendered as its own page (not a
 * modal, so it never floats over another surface). Report mode ends in the
 * one-time password panel; verify mode just confirms the email and returns to
 * the caller. The page unmounts when you navigate away, so state resets each
 * time it is opened.
 */

type Step = "disclosure" | "email" | "code" | "sending" | "password";

interface EmailReportViewProps {
  activeRun: string | null;
  auth: AuthStatus | null;
  purpose: "report" | "verify";
  /**
   * Skip the report disclosure and start the flow directly (used by the
   * Overview CTA, which already states the tradeoff). Unverified users land on
   * the email step; already-verified users send immediately.
   */
  skipDisclosure?: boolean;
  /** Refresh auth + runs after a successful verify (lifts state to App). */
  onAuthChanged: () => void;
  /** Leave this page (report "Done" -> overview; verify success -> history). */
  onExit: (dest: "overview" | "history") => void;
}

const OTP_START_ERRORS: Record<string, string> = {
  work_email_required: "请使用工作邮箱，不要使用个人邮箱。",
  rate_limited: "请求过于频繁，请稍后再试。",
  invalid_email: "邮箱格式不正确，请检查后重试。",
  unavailable: "邮件服务暂时不可用，请稍后再试。",
};

const SEND_ERRORS: Record<string, string> = {
  forbidden: "该邮箱已取消订阅 Strix 邮件，当前无法发送。",
  too_large: "报告体积过大，无法通过邮件发送，请尝试更小的运行记录。",
  unavailable: "邮件服务暂时不可用，请稍后再试。",
};

// A small set of common personal providers for instant client-side feedback.
// The relay is authoritative (it checks the full free-email-domains list).
const COMMON_FREE_DOMAINS = new Set([
  "gmail.com", "googlemail.com", "yahoo.com", "ymail.com", "outlook.com",
  "hotmail.com", "live.com", "icloud.com", "me.com", "aol.com", "proton.me",
  "protonmail.com", "gmx.com", "mail.com",
]);

export default function EmailReportView({
  activeRun,
  auth,
  purpose,
  skipDisclosure = false,
  onAuthChanged,
  onExit,
}: EmailReportViewProps) {
  const verified = auth?.verified === true;
  const verifyOnly = purpose === "verify";
  // Verify mode (and the Overview CTA, which skips the disclosure) start on the
  // email step; a verified user who skips the disclosure sends immediately.
  const [step, setStep] = useState<Step>(() => {
    if (verifyOnly) return "email";
    if (skipDisclosure) return verified ? "sending" : "email";
    return "disclosure";
  });
  const [email, setEmail] = useState(auth?.email ?? "");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [filename, setFilename] = useState("");
  const [copied, setCopied] = useState(false);
  const [sentTo, setSentTo] = useState("");
  const autoSentRef = useRef(false);

  const doSend = async () => {
    setStep("sending");
    setError(null);
    const result = await sendReport(activeRun);
    if (result.ok) {
      track("report_sent");
      setPassword(result.password);
      setFilename(result.filename);
      setStep("password");
      return;
    }
    if (result.error === "reverify" || result.error === "unverified") {
      setNotice("当前验证已过期，请重新输入邮箱完成验证。");
      setStep("email");
      return;
    }
    setError(SEND_ERRORS[result.error] ?? "无法发送报告，请稍后重试。");
    setStep("disclosure");
  };

  const startFlow = () => {
    setError(null);
    setNotice(null);
    if (verified) void doSend();
    else setStep("email");
  };

  // A verified user who skipped the disclosure (Overview CTA) sends on arrival.
  useEffect(() => {
    if (!verifyOnly && skipDisclosure && verified && !autoSentRef.current) {
      autoSentRef.current = true;
      void doSend();
    }
    // Run once on mount; the page remounts fresh each time it is opened.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

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
      track("email_submitted", { purpose });
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
    track("email_verified", { purpose });
    setSentTo(result.email);
    onAuthChanged();
    if (verifyOnly) onExit("history");
    else void doSend();
  };

  const copyPassword = async () => {
    try {
      await navigator.clipboard.writeText(password);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable; the password is visible to copy manually */
    }
  };

  const confirmationEmail = sentTo || auth?.email || email.trim();

  return (
    <div className="mx-auto max-w-xl space-y-4">
      <button
        onClick={() => onExit(verifyOnly ? "history" : "overview")}
        className="cursor-pointer inline-flex items-center gap-1.5 text-sm text-[#888] transition-colors hover:text-white"
      >
        <ArrowLeft className="h-4 w-4" />
        {verifyOnly ? "返回历史运行" : "返回结果页"}
      </button>

      <div className="flex items-center gap-2">
        <Mail className="h-5 w-5 text-[#888]" aria-hidden="true" />
        <h1 className="text-2xl font-semibold text-white">
          {verifyOnly ? "验证邮箱" : "导出 PDF 报告"}
        </h1>
      </div>

      <div
        className="w-full rounded-2xl bg-[rgba(255,255,255,0.02)] p-6"
        style={{ border: "1px solid #2a2a2a" }}
      >
        <p className="mb-4 text-xs text-[#666]">
          {verifyOnly
            ? "我们会向你的邮箱发送一次性验证码，用于确认是你本人操作。"
            : "发送前需要通过邮箱中的一次性验证码完成验证"}
        </p>

        {error && (
          <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-2">
            <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" aria-hidden="true" />
            <p className="text-xs text-red-300">{error}</p>
          </div>
        )}
        {notice && !error && step !== "password" && (
          <p className="mb-4 text-xs text-[#888]">{notice}</p>
        )}

        {step === "disclosure" && (
          <div className="space-y-4">
            <div
              className="space-y-2.5 rounded-lg p-3.5"
              style={{ border: "1px solid #222", background: "rgba(255,255,255,0.02)" }}
            >
              <div className="flex items-start gap-2.5">
                <ShieldCheck className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-400" aria-hidden="true" />
                <p className="text-xs leading-relaxed text-[#aaa]">
                  我们发送的是<span className="text-white">加密 PDF</span>，除此之外不会有任何额外数据离开你的机器。
                </p>
              </div>
              <div className="flex items-start gap-2.5">
                <Lock className="mt-0.5 h-4 w-4 flex-shrink-0 text-[#888]" aria-hidden="true" />
                <p className="text-xs leading-relaxed text-[#aaa]">
                  密码只会展示给你，Strix 无法读取该报告内容。
                </p>
              </div>
            </div>
            <button
              onClick={startFlow}
              className="w-full cursor-pointer rounded-lg bg-white px-4 py-2.5 text-sm font-semibold text-black transition-opacity hover:opacity-90"
            >
              导出报告
            </button>
            {verified && auth?.email && (
              <p className="text-center text-xs text-[#666]">将发送到 {auth.email}</p>
            )}
          </div>
        )}

        {step === "email" && (
          <form
            className="space-y-4"
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
        )}

        {step === "code" && (
          <form
            className="space-y-4"
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
              {verifyOnly ? "验证" : "验证并发送"}
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

        {step === "sending" && (
          <div className="flex flex-col items-center gap-3 py-8">
            <Loader2 className="h-6 w-6 animate-spin text-white" aria-hidden="true" />
            <p className="text-sm text-[#aaa]">正在本地生成并加密报告…</p>
          </div>
        )}

        {step === "password" && (
          <div className="space-y-4">
            <div className="flex items-start gap-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-3 py-2.5">
              <Check className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-400" aria-hidden="true" />
              <p className="text-xs text-emerald-200">
                报告已发送到 {confirmationEmail}。请使用以下密码打开附件中的 PDF。
              </p>
            </div>
            <div>
              <span className="mb-1.5 block text-xs text-[#888]">本次一次性密码</span>
              <div
                className="flex items-center gap-2 rounded-lg bg-black p-3"
                style={{ border: "1px solid #2a2a2a" }}
              >
                <code className="flex-1 break-all font-mono text-base text-white">{password}</code>
                <button
                  onClick={copyPassword}
                  className="flex cursor-pointer items-center gap-1 rounded-md px-2 py-1 text-xs text-[#aaa] transition-colors hover:bg-[rgba(255,255,255,0.06)] hover:text-white"
                  style={{ border: "1px solid #2a2a2a" }}
                >
                  {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                  {copied ? "已复制" : "复制"}
                </button>
              </div>
              <p className="mt-2 text-xs text-[#666]">
                请立即保存。Strix 不会存储该密码，之后也无法再次展示。文件名：
                <span className="font-mono text-[#888]">{filename}</span>
              </p>
            </div>
            <button
              onClick={() => onExit("overview")}
              className="w-full cursor-pointer rounded-lg px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[rgba(255,255,255,0.06)]"
              style={{ border: "1px solid #2a2a2a" }}
            >
              完成
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
