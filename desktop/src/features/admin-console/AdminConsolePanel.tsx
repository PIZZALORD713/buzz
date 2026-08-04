/**
 * Main admin console panel — renders when probe state is `nip98Authorized`.
 *
 * Shows two tabs: Reports (deployment-wide moderation reports) and Feedback
 * (product feedback with optional image attachments).
 *
 * All query/UI state is keyed by `(origin)`, which is already scoped to the
 * active pubkey by the settings card (pubkey changed → different origin stored).
 * In-flight requests are cancelled on origin change via useEffect cleanup.
 */

import { useEffect, useRef, useState } from "react";
import {
  AlertCircle,
  ChevronLeft,
  Download,
  LoaderCircle,
  MessageSquare,
  ShieldAlert,
} from "lucide-react";
import { Button } from "@/shared/ui/button";
import { cn } from "@/shared/lib/cn";
import {
  fetchAdminAttachmentBlobUrl,
  getAdminFeedback,
  getAdminReport,
  listAdminFeedback,
  listAdminReports,
  type AdminAttachmentErrorCode,
} from "./api";

// ── Generic async state ───────────────────────────────────────────────────

type AsyncState<T> =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ok"; data: T }
  | { status: "error"; message: string };

function useAsyncLoad<T>(
  load: (signal: AbortSignal) => Promise<T>,
  deps: unknown[],
): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ status: "idle" });

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: "loading" });
    load(controller.signal).then(
      (data) => {
        if (!controller.signal.aborted) setState({ status: "ok", data });
      },
      (e: unknown) => {
        if (!controller.signal.aborted) {
          setState({
            status: "error",
            message: e instanceof Error ? e.message : String(e),
          });
        }
      },
    );
    return () => controller.abort();
    // biome-ignore lint/correctness/useExhaustiveDependencies: deps array is passed from the call site as the explicit trigger list; adding `load` would cause infinite re-runs since it's created inline
  }, deps);

  return state;
}

// ── Reports tab ───────────────────────────────────────────────────────────

function ReportsTab({ origin }: { origin: string }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const listState = useAsyncLoad(() => listAdminReports(origin), [origin]);

  if (selectedId) {
    return (
      <ReportDetail
        origin={origin}
        reportId={selectedId}
        onBack={() => setSelectedId(null)}
      />
    );
  }

  if (listState.status === "loading") {
    return <LoadingSpinner />;
  }
  if (listState.status === "error") {
    return <ErrorMessage message={listState.message} />;
  }
  if (listState.status !== "ok") return null;

  const reports = listState.data as Array<Record<string, unknown>>;
  if (!Array.isArray(reports) || reports.length === 0) {
    return <p className="text-sm text-muted-foreground">No reports found.</p>;
  }

  return (
    <ul className="space-y-1">
      {reports.map((report) => {
        const id = String(report.id ?? report.reportId ?? "");
        const summary =
          String(report.summary ?? report.report_type ?? "") || "Report";
        const status = String(report.status ?? "");
        return (
          <li key={id || summary}>
            <button
              className="w-full rounded-md border border-border/60 px-3 py-2.5 text-left text-sm hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => setSelectedId(id)}
              type="button"
            >
              <span className="block font-medium">{summary}</span>
              {status && (
                <span className="text-xs text-muted-foreground">{status}</span>
              )}
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function ReportDetail({
  origin,
  reportId,
  onBack,
}: {
  origin: string;
  reportId: string;
  onBack: () => void;
}) {
  const detailState = useAsyncLoad(
    () => getAdminReport(origin, reportId),
    [origin, reportId],
  );

  return (
    <div>
      <button
        className="mb-3 flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        onClick={onBack}
        type="button"
      >
        <ChevronLeft className="h-3.5 w-3.5" />
        Back to reports
      </button>
      {detailState.status === "loading" && <LoadingSpinner />}
      {detailState.status === "error" && (
        <ErrorMessage message={detailState.message} />
      )}
      {detailState.status === "ok" && (
        <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
          {JSON.stringify(detailState.data, null, 2)}
        </pre>
      )}
    </div>
  );
}

// ── Feedback tab ──────────────────────────────────────────────────────────

function FeedbackTab({ origin }: { origin: string }) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const listState = useAsyncLoad(() => listAdminFeedback(origin), [origin]);

  if (selectedId) {
    return (
      <FeedbackDetail
        feedbackId={selectedId}
        onBack={() => setSelectedId(null)}
        origin={origin}
      />
    );
  }

  if (listState.status === "loading") return <LoadingSpinner />;
  if (listState.status === "error") {
    return <ErrorMessage message={listState.message} />;
  }
  if (listState.status !== "ok") return null;

  const items = listState.data as Array<Record<string, unknown>>;
  if (!Array.isArray(items) || items.length === 0) {
    return <p className="text-sm text-muted-foreground">No feedback found.</p>;
  }

  return (
    <ul className="space-y-1">
      {items.map((item) => {
        const id = String(item.id ?? item.feedbackId ?? "");
        const text = String(
          item.feedback ?? item.message ?? item.content ?? "",
        ).slice(0, 120);
        const createdAt = String(item.created_at ?? item.createdAt ?? "");
        return (
          <li key={id || text}>
            <button
              className="w-full rounded-md border border-border/60 px-3 py-2.5 text-left text-sm hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              onClick={() => setSelectedId(id)}
              type="button"
            >
              <span className="block font-medium line-clamp-2">{text}</span>
              {createdAt && (
                <span className="text-xs text-muted-foreground">
                  {new Date(Number(createdAt) * 1000).toLocaleString()}
                </span>
              )}
            </button>
          </li>
        );
      })}
    </ul>
  );
}

// ── Attachment viewer ─────────────────────────────────────────────────────

type AttachmentMeta = {
  sha256: string;
  mime: string;
  size: number;
};

function AttachmentViewer({
  origin,
  feedbackId,
  attachment,
}: {
  origin: string;
  feedbackId: string;
  attachment: AttachmentMeta;
}) {
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState<AdminAttachmentErrorCode | null>(null);
  const [loading, setLoading] = useState(false);
  const blobUrlRef = useRef<string | null>(null);

  // Revoke blob URL on unmount.
  useEffect(() => {
    return () => {
      if (blobUrlRef.current) URL.revokeObjectURL(blobUrlRef.current);
    };
  }, []);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const url = await fetchAdminAttachmentBlobUrl(
        origin,
        feedbackId,
        attachment.sha256,
        attachment.mime,
        attachment.size,
      );
      // Revoke any previous blob before replacing.
      if (blobUrlRef.current) URL.revokeObjectURL(blobUrlRef.current);
      blobUrlRef.current = url;
      setBlobUrl(url);
    } catch (e) {
      setError(
        typeof e === "string" ? (e as AdminAttachmentErrorCode) : String(e),
      );
    } finally {
      setLoading(false);
    }
  }

  if (error) {
    const friendlyError: Record<string, string> = {
      admin_attachment_too_large: "Attachment exceeds the 10 MiB desktop cap.",
      admin_attachment_mime_mismatch:
        "Attachment MIME type does not match the imeta record.",
      admin_attachment_size_mismatch:
        "Attachment byte count does not match the imeta record.",
      admin_attachment_network_error: "Network error fetching attachment.",
    };
    return (
      <div className="flex items-center gap-1.5 text-xs text-destructive">
        <AlertCircle className="h-3.5 w-3.5" />
        {friendlyError[error] ?? `Error: ${error}`}
      </div>
    );
  }

  if (!blobUrl) {
    return (
      <Button
        className="gap-1.5"
        disabled={loading}
        onClick={() => void load()}
        size="sm"
        type="button"
        variant="outline"
      >
        {loading ? (
          <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
        ) : (
          <Download className="h-3.5 w-3.5" />
        )}
        {loading ? "Loading…" : `View attachment (${attachment.mime})`}
      </Button>
    );
  }

  if (attachment.mime.startsWith("image/")) {
    return (
      <img
        alt="Feedback attachment"
        className="max-h-96 max-w-full rounded-md border border-border/60 object-contain"
        src={blobUrl}
      />
    );
  }

  return (
    <a
      className="flex items-center gap-1.5 text-xs text-primary underline"
      download={`attachment-${attachment.sha256.slice(0, 8)}`}
      href={blobUrl}
    >
      <Download className="h-3.5 w-3.5" />
      Download attachment ({attachment.mime})
    </a>
  );
}

function FeedbackDetail({
  origin,
  feedbackId,
  onBack,
}: {
  origin: string;
  feedbackId: string;
  onBack: () => void;
}) {
  const detailState = useAsyncLoad(
    () => getAdminFeedback(origin, feedbackId),
    [origin, feedbackId],
  );

  // Extract imeta attachment metadata from the detail.
  const attachments: AttachmentMeta[] = [];
  if (detailState.status === "ok") {
    const detail = detailState.data as Record<string, unknown>;
    const rawAttachments = detail.attachments;
    if (Array.isArray(rawAttachments)) {
      for (const a of rawAttachments as Array<Record<string, unknown>>) {
        const sha256 = String(a.sha256 ?? a.hash ?? "");
        const mime = String(a.mime ?? a.m ?? a.content_type ?? "");
        const size = Number(a.size ?? a.content_length ?? 0);
        if (sha256.length === 64 && mime && size > 0) {
          attachments.push({ sha256, mime, size });
        }
      }
    }
  }

  return (
    <div className="space-y-4">
      <button
        className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        onClick={onBack}
        type="button"
      >
        <ChevronLeft className="h-3.5 w-3.5" />
        Back to feedback
      </button>
      {detailState.status === "loading" && <LoadingSpinner />}
      {detailState.status === "error" && (
        <ErrorMessage message={detailState.message} />
      )}
      {detailState.status === "ok" && (
        <>
          <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
            {JSON.stringify(detailState.data, null, 2)}
          </pre>
          {attachments.length > 0 && (
            <div className="space-y-3">
              <h4 className="text-sm font-medium">Attachments</h4>
              {attachments.map((a) => (
                <AttachmentViewer
                  attachment={a}
                  feedbackId={feedbackId}
                  key={a.sha256}
                  origin={origin}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── Tab bar ───────────────────────────────────────────────────────────────

type Tab = "reports" | "feedback";

function TabBar({
  activeTab,
  onSelect,
}: {
  activeTab: Tab;
  onSelect: (tab: Tab) => void;
}) {
  return (
    <div className="mb-4 flex gap-1 border-b border-border/60">
      {(
        [
          { value: "reports" as const, label: "Reports", Icon: ShieldAlert },
          {
            value: "feedback" as const,
            label: "Feedback",
            Icon: MessageSquare,
          },
        ] as const
      ).map(({ value, label, Icon }) => (
        <button
          className={cn(
            "flex items-center gap-1.5 border-b-2 px-3 pb-2 pt-1 text-sm font-medium transition-colors",
            activeTab === value
              ? "border-primary text-foreground"
              : "border-transparent text-muted-foreground hover:text-foreground",
          )}
          data-testid={`admin-tab-${value}`}
          key={value}
          onClick={() => onSelect(value)}
          type="button"
        >
          <Icon className="h-3.5 w-3.5" />
          {label}
        </button>
      ))}
    </div>
  );
}

// ── Shared helpers ────────────────────────────────────────────────────────

function LoadingSpinner() {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <LoaderCircle className="h-4 w-4 animate-spin" />
      Loading…
    </div>
  );
}

function ErrorMessage({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-1.5 text-sm text-destructive">
      <AlertCircle className="h-4 w-4" />
      {message}
    </div>
  );
}

// ── Panel root ────────────────────────────────────────────────────────────

export function AdminConsolePanel({ origin }: { origin: string }) {
  const [activeTab, setActiveTab] = useState<Tab>("reports");

  return (
    <div
      className="flex min-h-0 flex-1 flex-col"
      data-testid="admin-console-panel"
    >
      <TabBar activeTab={activeTab} onSelect={setActiveTab} />
      {activeTab === "reports" && <ReportsTab origin={origin} />}
      {activeTab === "feedback" && <FeedbackTab origin={origin} />}
    </div>
  );
}
