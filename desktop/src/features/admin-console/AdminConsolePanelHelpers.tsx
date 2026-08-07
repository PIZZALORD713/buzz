/**
 * Shared helpers for the admin console panel sub-components.
 *
 * Exported from here to avoid duplication across AdminConsolePanel.tsx,
 * AdminConsoleFeedbackTab.tsx, and AdminConsoleStaffingTab.tsx.
 */

import { useEffect, useRef, useState } from "react";
import { AlertCircle, LoaderCircle } from "lucide-react";
import { formatRelativeTime } from "../forum/lib/time";

// ── Generic async state ───────────────────────────────────────────────────

export type AsyncState<T> =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ok"; data: T }
  | { status: "error"; message: string };

/**
 * Async load hook with effect-local active-flag cancellation.
 *
 * Each effect invocation sets `active = true` and flips it to `false` in the
 * cleanup function. Completions check `active` before calling setState, so a
 * result that arrives after the deps changed (or the component unmounted) is
 * silently discarded.
 *
 * `load` is stored in a ref so it is not a dependency of the effect — callers
 * create it inline and `deps` + `generation` are the explicit trigger list.
 */
export function useAsyncLoad<T>(
  load: () => Promise<T>,
  deps: unknown[],
  generation: number,
): AsyncState<T> {
  const [state, setState] = useState<AsyncState<T>>({ status: "idle" });
  const loadRef = useRef(load);
  loadRef.current = load;

  // biome-ignore lint/correctness/useExhaustiveDependencies: loadRef is a stable ref; deps and generation are the intentional trigger set
  useEffect(() => {
    let active = true;
    setState({ status: "loading" });
    loadRef.current().then(
      (data) => {
        if (!active) return;
        setState({ status: "ok", data });
      },
      (e: unknown) => {
        if (!active) return;
        setState({
          status: "error",
          message: e instanceof Error ? e.message : String(e),
        });
      },
    );
    return () => {
      active = false;
    };
  }, [...deps, generation]);

  return state;
}

// ── Shared UI helpers ─────────────────────────────────────────────────────

export function LoadingSpinner() {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <LoaderCircle className="h-4 w-4 animate-spin" />
      Loading…
    </div>
  );
}

export function ErrorMessage({ message }: { message: string }) {
  return (
    <div className="flex items-center gap-1.5 text-sm text-destructive">
      <AlertCircle className="h-4 w-4" />
      {message}
    </div>
  );
}

// ── Timestamp formatter ───────────────────────────────────────────────────

export function formatTimestamp(raw: string | null | undefined): string {
  if (!raw) return "—";
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return raw;
  const absolute = date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
  const rel = formatRelativeTime(Math.floor(date.getTime() / 1000));
  // Render relative label with the absolute value inline in parentheses.
  return `${rel} (${absolute})`;
}

// ── Structured detail row ─────────────────────────────────────────────────

export function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string | null | undefined;
  mono?: boolean;
}) {
  return (
    <div className="flex gap-2 text-xs">
      <span className="w-28 shrink-0 text-muted-foreground">{label}</span>
      <span className={mono ? "font-mono break-all" : "break-words"}>
        {value ?? "—"}
      </span>
    </div>
  );
}

// ── Attachment meta ───────────────────────────────────────────────────────

export type AttachmentMeta = {
  /** Lowercase 64-hex SHA-256 as stored/returned by the relay. */
  sha256: string;
  /** MIME type from the `m` imeta field. */
  mime: string;
  /** Byte size from the `size` imeta field. */
  size: number;
};

/**
 * Parse imeta attachment metadata from the relay's `tags: string[][]` wire
 * format. Matches the reference SPA implementation in `admin-web/src/App.tsx`.
 *
 * Each `imeta` tag looks like:
 *   `["imeta", "url https://...", "m image/png", "x <sha256>", "size 12345"]`
 * Each entry after `"imeta"` is a singleton `"key value"` string.
 *
 * Rejected: missing x/m/size, non-lowercase-hex x, non-positive size.
 */
export function parseImetaAttachments(tags: unknown): AttachmentMeta[] {
  if (!Array.isArray(tags)) return [];
  const result: AttachmentMeta[] = [];
  for (const tag of tags) {
    if (!Array.isArray(tag) || tag[0] !== "imeta") continue;
    const values = new Map<string, string>();
    for (const entry of (tag as string[]).slice(1)) {
      const sep = typeof entry === "string" ? entry.indexOf(" ") : -1;
      if (sep > 0) {
        values.set(entry.slice(0, sep), entry.slice(sep + 1));
      }
    }
    const sha256 = values.get("x") ?? "";
    const mime = values.get("m") ?? "";
    const rawSize = values.get("size") ?? "";
    const size = Number(rawSize);
    // Require exactly 64 lowercase hex chars for the hash (relay stores lowercase;
    // uppercase returns 404). Require a non-empty MIME type and a positive size.
    if (
      sha256.length !== 64 ||
      !/^[0-9a-f]{64}$/.test(sha256) ||
      !mime ||
      !Number.isFinite(size) ||
      size <= 0
    ) {
      continue;
    }
    result.push({ sha256, mime, size });
  }
  return result;
}
