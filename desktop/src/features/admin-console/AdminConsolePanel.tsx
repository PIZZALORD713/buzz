/**
 * Main admin console panel — renders when probe state is `nip98Authorized` or
 * `disabled`.
 *
 * Shows three tabs: Reports (deployment-wide moderation reports), Feedback
 * (product feedback with optional image attachments), and Staffing (Operator-
 * only operator management).
 *
 * All query/UI state is keyed by `(pubkey, origin)`. In-flight native requests
 * are fenced by an effect-local `active` flag that is set to `false` in the
 * effect cleanup, ensuring stale results are discarded on arrival.
 *
 * Tauri invoke is not cancellable at the native layer, but the active-flag
 * pattern ensures stale results never update visible state or create
 * unreachable blob URLs.
 *
 * Sub-components live in adjacent files:
 *   - AdminConsolePanelHelpers.tsx  — AsyncState, useAsyncLoad, formatTimestamp,
 *                                     DetailRow, LoadingSpinner, ErrorMessage,
 *                                     AttachmentMeta, parseImetaAttachments
 *   - AdminConsoleFeedbackTab.tsx   — FeedbackTab, FeedbackDetail
 *   - AdminConsoleStaffingTab.tsx   — StaffingTab
 */

import { useEffect, useRef, useState } from "react";
import {
  ChevronLeft,
  LoaderCircle,
  MessageSquare,
  Shield,
  ShieldAlert,
  Users,
} from "lucide-react";
import { Button } from "@/shared/ui/button";
import { Badge } from "@/shared/ui/badge";
import { cn } from "@/shared/lib/cn";
import {
  getAdminReport,
  listAdminReports,
  resolveAdminReport,
  type AdminPrincipalRole,
  type AdminPrincipalSource,
  type AdminReportAction,
  type AdminReportDetailDto,
  type AdminReportDto,
} from "./api";
import {
  DetailRow,
  ErrorMessage,
  LoadingSpinner,
  formatTimestamp,
  useAsyncLoad,
} from "./AdminConsolePanelHelpers";
import { FeedbackTab } from "./AdminConsoleFeedbackTab";
import { StaffingTab } from "./AdminConsoleStaffingTab";

export {
  parseImetaAttachments,
  type AttachmentMeta,
} from "./AdminConsolePanelHelpers";

// ── Status variant helper ─────────────────────────────────────────────────

function statusVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status) {
    case "open":
      return "default";
    case "resolved":
      return "secondary";
    case "dismissed":
      return "outline";
    case "escalated":
      return "secondary";
    case "processing":
      return "secondary";
    case "pending":
      return "secondary";
    case "enforcing":
      return "secondary";
    case "succeeded":
      return "secondary";
    case "failed":
      return "destructive";
    case "cancelled":
      return "outline";
    default:
      return "outline";
  }
}

// ── Action matrix helpers ─────────────────────────────────────────────────

/**
 * Return the allowed actions for a given target kind per the v4 frozen matrix.
 * event:  delete | kick | ban | timeout | dismiss | escalate
 * pubkey: ban | timeout | dismiss | escalate
 * blob:   dismiss | escalate
 */
function allowedActionsForTargetKind(targetKind: string): AdminReportAction[] {
  switch (targetKind.toLowerCase()) {
    case "event":
      return ["delete", "kick", "ban", "timeout", "dismiss", "escalate"];
    case "pubkey":
      return ["ban", "timeout", "dismiss", "escalate"];
    case "blob":
      return ["dismiss", "escalate"];
    default:
      return ["dismiss", "escalate"];
  }
}

/** Label for each action. */
function actionLabel(action: AdminReportAction): string {
  switch (action) {
    case "delete":
      return "Delete";
    case "kick":
      return "Kick";
    case "ban":
      return "Ban";
    case "timeout":
      return "Timeout";
    case "dismiss":
      return "Dismiss";
    case "escalate":
      return "Escalate";
  }
}

/** Variant for each action button. */
function actionVariant(
  action: AdminReportAction,
): "destructive" | "outline" | "secondary" {
  switch (action) {
    case "delete":
    case "ban":
      return "destructive";
    case "kick":
    case "timeout":
      return "outline";
    default:
      return "secondary";
  }
}

// ── Enforcement state block ───────────────────────────────────────────────

/**
 * Inline enforcement-state block shown on `processing` reports and after a
 * failed enforcement action. Shows the action record's state and offers
 * retry/cancel where appropriate.
 *
 * Cancel is only offered when the server permits it (pre-mutation failures).
 * A rejected cancel is treated as authoritative — the server knows whether
 * the mutation has landed.
 */
function EnforcementStateBlock({
  activeAction,
  origin,
  reportId,
  onActionComplete,
}: {
  activeAction: NonNullable<AdminReportDto["activeAction"]>;
  origin: string;
  reportId: string;
  onActionComplete: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const [isWorking, setIsWorking] = useState(false);

  const actionStatus = activeAction.status;

  // User-facing copy for each action state.
  const stateLabel: Record<string, string> = {
    pending: "Enforcement pending…",
    enforcing: "Enforcing…",
    succeeded: "Enforcement succeeded",
    failed: "Enforcement failed",
    cancelled: "Enforcement cancelled",
  };

  const handleRetry = async () => {
    setError(null);
    setIsWorking(true);
    try {
      // Retry reuses the same requestId so the server returns the existing
      // action record rather than creating a new claim.
      await resolveAdminReport(origin, reportId, {
        action: activeAction.action,
        requestId: activeAction.requestId,
        expirationSecs: activeAction.expirationSecs ?? undefined,
        reason: activeAction.reason ?? undefined,
      });
      onActionComplete();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsWorking(false);
    }
  };

  const handleCancel = async () => {
    setError(null);
    setIsWorking(true);
    try {
      // Cancel via the same resolve endpoint with action="dismiss".
      // The server rejects cancel if mutation has already landed.
      await resolveAdminReport(origin, reportId, {
        action: "dismiss",
        requestId: crypto.randomUUID(),
        reason: "cancelled",
      });
      onActionComplete();
    } catch (e) {
      // A rejected cancel is authoritative — the enforcement may have landed.
      // Surface the error but do not retry.
      setError(
        `Cancel rejected: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      setIsWorking(false);
    }
  };

  return (
    <div
      className="rounded-md border border-border/60 px-3 py-2.5 space-y-2"
      data-testid="enforcement-state-block"
    >
      <div className="flex items-center gap-2 text-sm">
        {(actionStatus === "pending" || actionStatus === "enforcing") && (
          <LoaderCircle className="h-4 w-4 animate-spin text-muted-foreground" />
        )}
        <Badge variant={statusVariant(actionStatus)}>
          {stateLabel[actionStatus] ?? actionStatus}
        </Badge>
        <span className="text-xs text-muted-foreground font-mono">
          {activeAction.action}
        </span>
      </div>
      {actionStatus === "failed" && (
        <div className="flex gap-2">
          <Button
            data-testid="enforcement-retry-btn"
            disabled={isWorking}
            onClick={() => void handleRetry()}
            size="sm"
            type="button"
            variant="outline"
          >
            {isWorking ? (
              <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
            ) : (
              "Retry"
            )}
          </Button>
          <Button
            data-testid="enforcement-cancel-btn"
            disabled={isWorking}
            onClick={() => void handleCancel()}
            size="sm"
            type="button"
            variant="ghost"
          >
            Cancel
          </Button>
        </div>
      )}
      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}

// ── Resolve report form ───────────────────────────────────────────────────

/**
 * Resolution form — shown on open reports (not `processing`). Presents the
 * action matrix for the report's target_kind, collects optional reason and
 * (for timeout) expiration_secs, then calls the resolve endpoint.
 *
 * The form generates a `requestId` per submission attempt. On retry after a
 * lost response, the caller should reuse the same `requestId` — this is
 * handled by the retry path in `EnforcementStateBlock`.
 */
function ResolveReportForm({
  report,
  origin,
  onResolved,
}: {
  report: AdminReportDto;
  origin: string;
  onResolved: () => void;
}) {
  const [selectedAction, setSelectedAction] =
    useState<AdminReportAction | null>(null);
  const [reason, setReason] = useState("");
  const [expirationSecs, setExpirationSecs] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // Stable requestId per submission; regenerated on each new submit attempt.
  const requestIdRef = useRef<string | null>(null);

  const allowedActions = allowedActionsForTargetKind(report.targetKind ?? "");

  const handleSubmit = async () => {
    if (!selectedAction) return;
    setError(null);
    setIsSubmitting(true);

    // Generate a fresh requestId for this submission attempt (v4 amendment 2).
    if (!requestIdRef.current) {
      requestIdRef.current = crypto.randomUUID();
    }

    try {
      await resolveAdminReport(origin, report.id, {
        action: selectedAction,
        requestId: requestIdRef.current,
        expirationSecs:
          selectedAction === "timeout" && expirationSecs
            ? Number(expirationSecs)
            : undefined,
        reason: reason.trim() || undefined,
      });
      onResolved();
    } catch (e) {
      // On error, reset requestId so the next submit generates a new one.
      // But: if the error suggests a 409 (report already processing), the
      // server has a claim — don't reset, let the parent handle it.
      const msg = e instanceof Error ? e.message : String(e);
      if (!msg.includes("409") && !msg.includes("processing")) {
        requestIdRef.current = null;
      }
      setError(msg);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div
      className="rounded-md border border-border/60 px-3 py-2.5 space-y-3"
      data-testid="resolve-report-form"
    >
      <p className="text-xs font-medium text-muted-foreground">
        Resolve report
      </p>
      <div className="flex flex-wrap gap-1.5">
        {allowedActions.map((action) => (
          <Button
            className={cn(
              "text-xs",
              selectedAction === action && "ring-2 ring-ring ring-offset-1",
            )}
            data-testid={`action-btn-${action}`}
            key={action}
            onClick={() =>
              setSelectedAction(action === selectedAction ? null : action)
            }
            size="sm"
            type="button"
            variant={actionVariant(action)}
          >
            {actionLabel(action)}
          </Button>
        ))}
      </div>

      {selectedAction === "timeout" && (
        <div className="flex items-center gap-2">
          <label
            className="text-xs text-muted-foreground shrink-0"
            htmlFor="timeout-duration-input"
          >
            Duration (seconds)
          </label>
          <input
            className="flex-1 rounded-md border border-border/60 bg-background px-2 py-1 text-xs font-mono"
            data-testid="timeout-duration-input"
            id="timeout-duration-input"
            min="1"
            onChange={(e) => setExpirationSecs(e.target.value)}
            placeholder="e.g. 3600"
            type="number"
            value={expirationSecs}
          />
        </div>
      )}

      <div>
        <input
          className="w-full rounded-md border border-border/60 bg-background px-2 py-1 text-xs"
          data-testid="resolve-reason-input"
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason (optional)"
          type="text"
          value={reason}
        />
      </div>

      {selectedAction && (
        <Button
          data-testid="resolve-submit-btn"
          disabled={
            isSubmitting || (selectedAction === "timeout" && !expirationSecs)
          }
          onClick={() => void handleSubmit()}
          size="sm"
          type="button"
        >
          {isSubmitting ? (
            <LoaderCircle className="h-3.5 w-3.5 animate-spin" />
          ) : (
            `Confirm: ${actionLabel(selectedAction)}`
          )}
        </Button>
      )}

      {error && <p className="text-xs text-destructive">{error}</p>}
    </div>
  );
}

// ── Reports tab ───────────────────────────────────────────────────────────

function ReportsTab({
  origin,
  pubkey,
  generation,
}: {
  origin: string;
  pubkey: string;
  generation: number;
}) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const listState = useAsyncLoad(
    () => listAdminReports(origin),
    [origin, pubkey],
    generation,
  );

  if (selectedId) {
    return (
      <ReportDetail
        origin={origin}
        pubkey={pubkey}
        generation={generation}
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

  const reports = listState.data;
  if (!Array.isArray(reports) || reports.length === 0) {
    return <p className="text-sm text-muted-foreground">No reports found.</p>;
  }

  return (
    <ul className="space-y-1">
      {reports.map((report: AdminReportDto) => {
        const id = report.id;
        const summary = report.reportType || "Report";
        const status = report.status;
        const isProcessing = status === "processing";
        return (
          <li key={id}>
            <button
              className={cn(
                "w-full rounded-md border border-border/60 px-3 py-2.5 text-left text-sm hover:bg-muted/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
                isProcessing && "opacity-60 cursor-default",
              )}
              disabled={isProcessing}
              onClick={() => {
                if (!isProcessing) setSelectedId(id);
              }}
              type="button"
            >
              <span className="block font-medium">{summary}</span>
              {status && (
                <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  {status}
                  {isProcessing && (
                    <LoaderCircle className="h-3 w-3 animate-spin" />
                  )}
                </span>
              )}
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function ReportFields({ data }: { data: AdminReportDetailDto }) {
  const status = data.status ?? "";
  return (
    <div
      className="space-y-1.5 rounded-md border border-border/60 px-3 py-2.5"
      data-testid="report-detail-fields"
    >
      <div className="mb-2 flex flex-wrap items-center gap-2">
        {status && <Badge variant={statusVariant(status)}>{status}</Badge>}
        {data.reportType && <Badge variant="outline">{data.reportType}</Badge>}
      </div>
      <DetailRow label="ID" value={data.id} mono />
      <DetailRow label="Community" value={data.communityId} mono />
      <DetailRow label="Host" value={data.communityHost} />
      <DetailRow label="Event ID" value={data.reportEventId} mono />
      <DetailRow label="Reporter" value={data.reporterPubkey} mono />
      <DetailRow label="Target kind" value={data.targetKind} />
      <DetailRow label="Target" value={data.target} mono />
      <DetailRow label="Channel" value={data.channelId ?? null} mono />
      <DetailRow label="Note" value={data.note ?? null} />
      <DetailRow label="Resolved by" value={data.resolvedBy ?? null} mono />
      <DetailRow label="Resolved at" value={formatTimestamp(data.resolvedAt)} />
      <DetailRow label="Action ID" value={data.actionId ?? null} mono />
      <DetailRow label="Created" value={formatTimestamp(data.createdAt)} />
      {data.message != null && (
        <div className="mt-3 space-y-1.5 rounded-md border border-border/40 px-3 py-2.5">
          <p className="mb-1 text-xs font-semibold text-muted-foreground">
            Reported message
            {data.message.deletedAt != null && (
              <span className="ml-1.5 text-destructive">(deleted)</span>
            )}
          </p>
          <DetailRow label="Author" value={data.message.authorPubkey} mono />
          <DetailRow label="Content" value={data.message.content} />
          <DetailRow
            label="Msg created"
            value={formatTimestamp(data.message.createdAt)}
          />
        </div>
      )}
    </div>
  );
}

function ReportDetail({
  origin,
  pubkey,
  generation,
  reportId,
  onBack,
}: {
  origin: string;
  pubkey: string;
  generation: number;
  reportId: string;
  onBack: () => void;
}) {
  // Resolution generation: bump to reload detail after an action completes.
  const [resolveGen, setResolveGen] = useState(0);

  const detailState = useAsyncLoad(
    () => getAdminReport(origin, reportId),
    [origin, pubkey, reportId],
    generation + resolveGen,
  );

  const data = detailState.status === "ok" ? detailState.data : null;
  const isProcessing = data?.status === "processing";
  const isOpen = data?.status === "open";
  const activeAction = data?.activeAction ?? null;

  return (
    <div className="space-y-4">
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
        <>
          <ReportFields data={detailState.data} />
          {/* Enforcement state: present on processing reports or failed actions */}
          {activeAction &&
            (isProcessing ||
              activeAction.status === "failed" ||
              activeAction.status === "pending" ||
              activeAction.status === "enforcing") && (
              <EnforcementStateBlock
                activeAction={activeAction}
                origin={origin}
                reportId={reportId}
                onActionComplete={() => setResolveGen((g) => g + 1)}
              />
            )}
          {/* Resolve form: only for open (non-processing) reports */}
          {isOpen && !activeAction && (
            <ResolveReportForm
              report={detailState.data}
              origin={origin}
              onResolved={() => setResolveGen((g) => g + 1)}
            />
          )}
        </>
      )}
    </div>
  );
}

// ── Tab bar ───────────────────────────────────────────────────────────────

type Tab = "reports" | "feedback" | "staffing";

function TabBar({
  activeTab,
  onSelect,
  showStaffing,
}: {
  activeTab: Tab;
  onSelect: (tab: Tab) => void;
  showStaffing: boolean;
}) {
  const allTabs: Array<{
    value: Tab;
    label: string;
    Icon: React.ComponentType<{ className?: string }>;
  }> = [
    { value: "reports", label: "Reports", Icon: ShieldAlert },
    { value: "feedback", label: "Feedback", Icon: MessageSquare },
    ...(showStaffing
      ? [{ value: "staffing" as const, label: "Staffing", Icon: Users }]
      : []),
  ];
  return (
    <div className="mb-4 flex gap-1 border-b border-border/60">
      {allTabs.map(({ value, label, Icon }) => (
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

// ── Panel root ────────────────────────────────────────────────────────────

export function AdminConsolePanel({
  origin,
  pubkey,
  role,
  source,
}: {
  origin: string;
  /** Active identity pubkey — all state is keyed on (pubkey, origin). */
  pubkey: string;
  /** Principal role from probe — `"operator"` | `"moderator"` | undefined */
  role?: AdminPrincipalRole | null;
  /** Source from probe — `"config"` | `"owner_fallback"` | `"db"` | undefined */
  source?: AdminPrincipalSource | null;
}) {
  const isOperator = role === "operator";
  const [activeTab, setActiveTab] = useState<Tab>("reports");
  // Increment whenever the (pubkey, origin) context changes to invalidate all
  // in-flight useAsyncLoad effects via their effect-local `active` flags.
  const generationRef = useRef(0);
  const [generation, setGeneration] = useState(0);

  // biome-ignore lint/correctness/useExhaustiveDependencies: pubkey and origin are reactive props — effect fires when either changes to bump the generation fence
  useEffect(() => {
    generationRef.current += 1;
    setGeneration(generationRef.current);
  }, [pubkey, origin]);

  return (
    <div
      className="flex min-h-0 flex-1 flex-col"
      data-testid="admin-console-panel"
    >
      {role && (
        <div className="mb-3 flex items-center gap-2 text-xs">
          <Shield className="h-3.5 w-3.5 text-muted-foreground" />
          <Badge variant="secondary">{role}</Badge>
          {source && (
            <Badge variant="outline">{source.replace("_", " ")}</Badge>
          )}
        </div>
      )}
      <TabBar
        activeTab={activeTab}
        onSelect={setActiveTab}
        showStaffing={isOperator}
      />
      {activeTab === "reports" && (
        <ReportsTab origin={origin} pubkey={pubkey} generation={generation} />
      )}
      {activeTab === "feedback" && (
        <FeedbackTab origin={origin} pubkey={pubkey} generation={generation} />
      )}
      {activeTab === "staffing" && isOperator && (
        <StaffingTab origin={origin} pubkey={pubkey} generation={generation} />
      )}
    </div>
  );
}
