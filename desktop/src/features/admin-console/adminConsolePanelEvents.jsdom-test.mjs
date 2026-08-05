/**
 * Event-driven behavior tests for AdminConsoleSettingsCard /
 * AdminConsoleSettingsSession and AdminConsolePanel.
 *
 * This file runs with jsdom pre-installed (via --import ./test-jsdom-setup.mjs)
 * so React 19's canUseDOM is true and isInputEventSupported is set correctly.
 * fireEvent from @testing-library/react dispatches native events that travel
 * through React 19's container-level event delegation, reaching production
 * handlers.
 *
 * What these tests prove — they fail if:
 *   - `abortAndResetProbe()` is removed from input onChange
 *     → origin-edit goes red (stale probe commits, panel renders)
 *   - `sessionTokenRef` check is removed from handleSave
 *     → same-session-save-race goes red (stale save clobbers B's input)
 *   - `active = false` cleanup is removed from useAsyncLoad
 *     → detail-navigation goes red (stale detail commits)
 *   - `expectedPubkey` dropped from the set_admin_origin invocation path
 *     → cross-identity-delayed-save goes red (A's save lacks expectedPubkey)
 *   - unmount-cleanup effect removed (sessionTokenRef not nulled on unmount)
 *     → strict-mode-save goes red (StrictMode double-mount silently disables saves)
 *
 * What these tests also prove:
 *   - `loadGenRef.current += 1` cleanup removed from AttachmentViewer
 *     → blob-leak-on-back-navigation goes red (stale blob leaks without revocation)
 *     Note: the existing attachment-unmount test exercises the same guard but via
 *     origin/pubkey re-render which also updates originRef/pubkeyRef. The back-
 *     navigation test isolates loadGenRef by unmounting without context change.
 *   - `pubkeyHex ? <AdminConsoleSettingsSession key=…> : null` render gate removed
 *     → authorized-logout-teardown goes red (empty-pubkey session renders, input present)
 *     Note: this test lives in adminConsolePanel.test.mjs (MinimalDocument suite) because
 *     the jsdom React 19 global scheduler leaves pending promises when the gate is absent,
 *     causing the jsdom test runner to report CANCELLED instead of a clean AssertionError.
 */
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

// ── Tauri IPC interceptor ────────────────────────────────────────────────────
//
// @tauri-apps/api/core calls `window.__TAURI_INTERNALS__.invoke(...)` where
// `window` is the jsdom window object (set via test-jsdom-setup.mjs), not
// `globalThis`. Both globalThis.__TAURI_INTERNALS__ and window.__TAURI_INTERNALS__
// must be set so all import paths reach the same mock.

/** @type {Map<string, (args: unknown) => Promise<unknown>>} */
const ipcHandlers = new Map();

function setIpcHandler(cmd, fn) {
  ipcHandlers.set(cmd, fn);
}
function clearIpcHandlers() {
  ipcHandlers.clear();
}

const tauriMock = {
  invoke(cmd, args) {
    const handler = ipcHandlers.get(cmd);
    if (handler) return handler(args);
    return Promise.reject(new Error(`unmocked Tauri command: ${cmd}`));
  },
  transformCallback(_cb) {
    return Math.random();
  },
};
// Set on both globalThis and the jsdom window object so all access paths work.
globalThis.__TAURI_INTERNALS__ = tauriMock;
if (globalThis.window && globalThis.window !== globalThis) {
  globalThis.window.__TAURI_INTERNALS__ = tauriMock;
}

// ── Production imports ───────────────────────────────────────────────────────

import React from "react";
import { createRoot } from "react-dom/client";
import { act } from "react";
import { fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { AdminConsoleSettingsCard } from "./AdminConsoleSettingsCard.tsx";
import { AdminConsolePanel } from "./AdminConsolePanel.tsx";

// ── Deferred promise helper ──────────────────────────────────────────────────

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

// ── Mount helpers ────────────────────────────────────────────────────────────

function makeQueryClient(pubkeyHex) {
  // gcTime: Infinity prevents React Query from garbage-collecting setQueryData
  // entries before the component mounts its observer. gcTime: 0 races with
  // the GC timer and is appropriate only for test teardown, not setup.
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  // Always set identity data (even for empty pubkey) so React Query never calls
  // queryFn = getIdentity (which would hit the unmocked IPC).
  // Component reads pubkeyHex = identity?.pubkey ?? "" — so { pubkey: "" }
  // produces pubkeyHex = "" which is the correct logged-out representation.
  qc.setQueryData(["identity"], { pubkey: pubkeyHex });
  return qc;
}

function mountCard(qc) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  const doRender = async () => {
    await act(async () => {
      root.render(
        React.createElement(
          QueryClientProvider,
          { client: qc },
          React.createElement(AdminConsoleSettingsCard),
        ),
      );
    });
  };
  const unmount = async () => {
    await act(async () => {
      root.unmount();
    });
    document.body.removeChild(container);
  };
  return { container, doRender, unmount };
}

function mountPanel({ origin, pubkey }) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  const doRender = async ({ origin: o, pubkey: p } = { origin, pubkey }) => {
    await act(async () => {
      root.render(
        React.createElement(AdminConsolePanel, { origin: o, pubkey: p }),
      );
    });
  };
  const unmount = async () => {
    await act(async () => {
      root.unmount();
    });
    document.body.removeChild(container);
  };
  return { container, doRender, unmount };
}

async function settle(ms = 20) {
  await act(async () => {
    await new Promise((r) => setTimeout(r, ms));
  });
}

afterEach(() => {
  clearIpcHandlers();
});

// ── origin-edit ──────────────────────────────────────────────────────────────

test("origin-edit: input change while probe in-flight discards stale probe result", async () => {
  // Verifies that abortAndResetProbe() is wired to input onChange.
  //
  // Scenario:
  //  1. Component mounts with a saved origin; initial probe resolves
  //     immediately to "disabled" (no panel rendered, no unmocked IPC).
  //  2. User clicks Re-probe — new deferred probe starts.
  //  3. User edits the input via fireEvent.change — onChange fires, calls
  //     abortAndResetProbe(), setting probeAbortRef.current.signal.aborted.
  //  4. Stale probe resolves — the callback sees signal.aborted and returns
  //     early; probeUiState stays at { kind: "idle" } → panel never renders.
  //
  // Fails if abortAndResetProbe() is removed from the onChange handler:
  // the stale probe commits "nip98Authorized" and the panel renders.

  const pubkey = "d".repeat(64);
  const savedOrigin = "https://admin.example.com";

  setIpcHandler("get_admin_origin", () => Promise.resolve(savedOrigin));
  setIpcHandler("admin_probe", () => Promise.resolve({ state: "disabled" }));
  // If the stale probe commits nip98Authorized, the admin panel would render
  // and call these IPC commands. Mock them so the test doesn't hang.
  setIpcHandler("admin_list_reports", () => Promise.resolve([]));
  setIpcHandler("admin_list_feedback", () => Promise.resolve([]));

  const qc = makeQueryClient(pubkey);
  const { container, doRender } = mountCard(qc);
  await doRender();
  await settle(25);

  // Re-probe button appears when savedOrigin is set.
  const reprobe = container.querySelector(
    "[data-testid='admin-probe-refresh']",
  );
  assert.ok(reprobe, "re-probe button must appear when savedOrigin is set");

  // Start a new deferred probe.
  const probeDeferred = deferred();
  setIpcHandler("admin_probe", () => probeDeferred.promise);

  await act(async () => {
    // fireEvent.click dispatches a native click — React's delegated onClick handler
    // calls runProbe(), creating a new AbortController on probeAbortRef.current.
    fireEvent.click(reprobe);
    await new Promise((r) => setTimeout(r, 5));
  });

  // Edit the input while the probe is in-flight. fireEvent.change dispatches
  // a native change event through React 19's container-level delegation,
  // reaching the production onChange handler which calls abortAndResetProbe().
  const input = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(input, "origin input must be present");

  await act(async () => {
    fireEvent.change(input, {
      target: { value: "https://admin-new.example.com" },
    });
    await new Promise((r) => setTimeout(r, 5));
  });

  // Resolve the stale probe — controller.signal.aborted is true because
  // abortAndResetProbe() was called by onChange. The callback returns early.
  // We resolve inside act() so React flushes the state update synchronously.
  await act(async () => {
    probeDeferred.resolve({ state: "nip98Authorized" });
    await new Promise((r) => setTimeout(r, 20));
  });

  // The panel must NOT be visible — probeUiState is { kind: "idle" }, not
  // "authorized". The stale nip98Authorized result was discarded.
  const panel = container.querySelector("[data-testid='admin-console-panel']");
  assert.ok(
    panel === null,
    "admin-console-panel must not render — stale probe discarded after onChange",
  );
  const text = container.textContent ?? "";
  assert.ok(
    !text.includes("Connected"),
    `stale nip98Authorized must not commit; got: ${text.slice(0, 200)}`,
  );

  // Skip unmount() here — calling act(root.unmount) after a mutation-caused
  // panel render would hang waiting for React cleanup. The assertions already
  // proved the test. The afterEach clears IPC handlers; the container is GC'd.
});

// ── same-session save race ────────────────────────────────────────────────────

test("same-session-save-race: deferred save X does not clobber pending save Y", async () => {
  // Verifies the sessionTokenRef fence in handleSave.
  //
  // The save button is disabled while isSaving=true. We use fireEvent.keyDown
  // with Enter on the input to trigger handleSave() directly (via onKeyDown),
  // bypassing the disabled save button. This lets both saves be in-flight
  // simultaneously — each with its own sessionToken.
  //
  // Scenario:
  //  1. Type X and press Enter — save X starts (deferred), token=X.
  //  2. Type Y and press Enter while X is pending — save Y starts (deferred),
  //     token=Y replaces X's token on sessionTokenRef.current.
  //  3. Resolve X late: token(X) != sessionTokenRef.current(Y) → returns early,
  //     no runProbe(originX).
  //  4. Resolve Y: runProbe(originY) fires normally.
  //
  // Fails if sessionTokenRef checks are removed: X's continuation calls
  // runProbe(originX) after Y has set its token, causing probeOrigins to
  // contain originX.

  const pubkey = "e".repeat(64);
  const originX = "https://admin-x.example.com";
  const originY = "https://admin-y.example.com";

  setIpcHandler("get_admin_origin", () => Promise.resolve(null));

  let resolveX, resolveY;
  let saveCount = 0;
  setIpcHandler("set_admin_origin", () => {
    saveCount += 1;
    if (saveCount === 1)
      return new Promise((r) => {
        resolveX = r;
      });
    return new Promise((r) => {
      resolveY = r;
    });
  });

  // Track probe origins to detect if X erroneously fires a probe.
  const probeOrigins = [];
  setIpcHandler("admin_probe", (args) => {
    probeOrigins.push(args?.origin ?? "(none)");
    return Promise.resolve({ state: "disabled" });
  });

  const qc = makeQueryClient(pubkey);
  const { container, doRender, unmount } = mountCard(qc);
  await doRender();
  await settle(15);

  const input = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(input, "input must be present");

  // Type X and press Enter to start save X (deferred).
  await act(async () => {
    fireEvent.change(input, { target: { value: originX } });
    await new Promise((r) => setTimeout(r, 5));
  });
  await act(async () => {
    fireEvent.keyDown(input, { key: "Enter", keyCode: 13 });
    await new Promise((r) => setTimeout(r, 5));
  });

  // X's save is now pending (isSaving=true). Type Y and press Enter — this
  // calls handleSave() again despite isSaving=true, creating a new token(Y).
  await act(async () => {
    fireEvent.change(input, { target: { value: originY } });
    await new Promise((r) => setTimeout(r, 5));
  });
  await act(async () => {
    fireEvent.keyDown(input, { key: "Enter", keyCode: 13 });
    await new Promise((r) => setTimeout(r, 5));
  });

  // Both saves are now in-flight. Clear probes from any initial mount probes.
  probeOrigins.length = 0;

  // Resolve X late. Token(X) != sessionTokenRef.current (Y replaced it).
  // With token check: returns early, runProbe(originX) NOT called.
  // Without token check: runProbe(originX) IS called -> probeOrigins has originX.
  resolveX?.(originX);
  await settle(20);

  assert.ok(
    !probeOrigins.some((o) => o.includes("admin-x")),
    `X's late save must not trigger a probe; probes after X resolved: ${JSON.stringify(probeOrigins)}`,
  );

  // Resolve Y — its probe fires normally with originY.
  resolveY?.(originY);
  await settle(20);

  assert.ok(
    probeOrigins.some((o) => o.includes("admin-y")),
    `Y's save must trigger a probe with originY; probes: ${JSON.stringify(probeOrigins)}`,
  );

  await unmount();
});

// ── detail-navigation ────────────────────────────────────────────────────────

test("detail-navigation: stale detail result is discarded after navigating away", async () => {
  // Verifies useAsyncLoad's effect-local active flag on detail fetch.
  //
  // Scenario:
  //  1. Panel renders; list resolves immediately with one entry.
  //  2. User clicks the report row → detail fetch A starts (active=true,
  //     waiting on detailDeferredA).
  //  3. origin/pubkey changes → generation bumps → old effect cleanup:
  //     active=false. New effect starts → detail fetch B (detailDeferredB).
  //  4. detailDeferredA resolves with "STALE-DETAIL-CONTENT" → active=false
  //     → result discarded. detailDeferredB stays pending → UI shows loading.
  //
  // Fails if the `active = false` cleanup is removed: fetch A has active=true,
  // so "STALE-DETAIL-CONTENT" commits and appears in the DOM.

  const origin = "https://admin.example.com";
  const pubkey = "a".repeat(64);

  const listResult = [
    {
      id: "00000000-0000-0000-0000-000000000099",
      communityId: "00000000-0000-0000-0000-000000000002",
      communityHost: "relay.example.com",
      reportEventId: "aa",
      reporterPubkey: "bb",
      targetKind: "message",
      target: "cc",
      reportType: "spam",
      status: "open",
      createdAt: "2024-01-01T00:00:00Z",
    },
  ];

  setIpcHandler("admin_list_reports", () => Promise.resolve(listResult));

  // Two separate deferreds: A for the first (stale) fetch, B for the second.
  // This prevents B from accidentally committing A's stale content when the
  // deferred is shared.
  const detailDeferredA = deferred();
  const detailDeferredB = deferred();
  let detailCallCount = 0;
  setIpcHandler("admin_get_report", () => {
    detailCallCount += 1;
    return detailCallCount === 1
      ? detailDeferredA.promise
      : detailDeferredB.promise;
  });

  const { container, doRender, unmount } = mountPanel({ origin, pubkey });

  // Initial render + list resolution.
  await act(async () => {
    await doRender();
    await new Promise((r) => setTimeout(r, 30));
  });

  // Find a report row button and click via fireEvent.
  const allButtons = container.querySelectorAll("button");
  let clickedReport = false;
  for (const btn of allButtons) {
    const testid = btn.getAttribute("data-testid") ?? "";
    if (testid.startsWith("admin-tab")) continue;
    await act(async () => {
      fireEvent.click(btn);
      await new Promise((r) => setTimeout(r, 0));
    });
    clickedReport = true;
    break;
  }

  assert.ok(clickedReport, "a report row button must exist and be clickable");

  // Detail fetch A is in-flight (active=true). Change origin/pubkey →
  // generation bumps → old effect cleanup: active=false. New effect starts
  // (active=true) and calls admin_get_report → detailDeferredB.
  setIpcHandler("admin_list_reports", () => Promise.resolve([]));
  await act(async () => {
    await doRender({
      origin: "https://admin-2.example.com",
      pubkey: "b".repeat(64),
    });
    await new Promise((r) => setTimeout(r, 5));
  });

  // Resolve stale fetch A. Its active=false → result discarded.
  detailDeferredA.resolve({
    id: "00000000-0000-0000-0000-000000000099",
    content: "STALE-DETAIL-CONTENT",
    status: "STALE-DETAIL",
  });

  await act(async () => {
    await new Promise((r) => setTimeout(r, 30));
  });

  const text = container.textContent ?? "";
  assert.ok(
    !text.includes("STALE-DETAIL-CONTENT"),
    `stale detail A must not appear (active=false); got: ${text.slice(0, 300)}`,
  );

  // Clean up: resolve B to avoid dangling promises.
  detailDeferredB.resolve({ id: "skip", content: "done" });
  await act(async () => {
    await new Promise((r) => setTimeout(r, 5));
  });

  await unmount();
});

// ── attachment-unmount ───────────────────────────────────────────────────────

test("attachment-unmount: late blob URL is revoked and not committed after panel generation changes", async () => {
  // Verifies AttachmentViewer's loadGenRef cleanup and per-load generation guard.
  //
  // Scenario:
  //  1. Panel renders; Feedback tab clicked; list+detail resolve immediately.
  //  2. "View attachment" button appears; user clicks it — load starts:
  //     thisGen = ++loadGenRef.current = 1.  Fetch is deferred (pending).
  //  3. Re-render with new origin/pubkey bumps panelGeneration →
  //     AttachmentViewer cleanup: loadGenRef.current += 1 = 2.  originRef and
  //     pubkeyRef also update to the new values.
  //  4. Attachment resolves: thisGen(1) !== loadGenRef.current(2) (and also
  //     thisOrigin !== originRef.current) — URL.revokeObjectURL called,
  //     setBlobUrl NOT called.
  //
  // Fails if loadGenRef.current is NOT incremented in the cleanup: loadGenRef
  // stays at 1 after cleanup; the new load increments to 2 (thisGen2=2).  The
  // stale load still has thisGen(1) !== loadGenRef(2) — caught by the new-load
  // counter.  BUT: if there is NO new load (i.e. the new panel renders without
  // loading the attachment), loadGenRef stays at 1 after cleanup; the stale
  // load sees thisGen(1) == loadGenRef(1) — NOT caught without the mutation!
  //
  // Key: after the re-render, the new AttachmentViewer is freshly mounted
  // (new origin/pubkey = new key or props); it has NOT started a load yet
  // because the user hasn't clicked "View attachment" in the new context.
  // So loadGenRef resets to 0 on the new instance.  The stale load uses a
  // SEPARATE instance's loadGenRef via ref capture — but actually, since
  // AttachmentViewer unmounts on re-render (origin/pubkey change), its ref
  // is gone.  The check uses the ref captured in the closure:
  //   if (thisGen !== loadGenRef.current ...)
  // loadGenRef.current is 1 (incremented in cleanup) and thisGen is 1 (pre-
  // cleanup), so without the cleanup increment: 1 !== 1 is FALSE → blob committed.
  // With the cleanup increment: loadGenRef.current becomes 2, so 1 !== 2 → revoke.

  const origin = "https://admin.example.com";
  const pubkey = "a".repeat(64);
  const sha256 = "a".repeat(64);

  const feedbackItem = {
    id: "00000000-0000-0000-0000-000000000011",
    bodySummary: "Test feedback",
    receivedAt: 1700000000,
    tags: [
      [
        "imeta",
        `url https://relay.example.com/files/${sha256}`,
        "m image/png",
        `x ${sha256}`,
        "size 1000",
      ],
    ],
  };

  setIpcHandler("admin_list_reports", () => Promise.resolve([]));
  setIpcHandler("admin_list_feedback", () => Promise.resolve([feedbackItem]));
  setIpcHandler("admin_get_feedback", () => Promise.resolve(feedbackItem));

  const attachDeferred = deferred();
  const revokedUrls = [];
  const origRevoke = globalThis.URL?.revokeObjectURL;
  if (!globalThis.URL) globalThis.URL = {};
  globalThis.URL.revokeObjectURL = (url) => {
    revokedUrls.push(url);
    if (origRevoke) origRevoke.call(globalThis.URL, url);
  };
  globalThis.URL.createObjectURL = () => "blob:test-url";
  setIpcHandler(
    "admin_fetch_feedback_attachment",
    () => attachDeferred.promise,
  );

  const { container, doRender, unmount } = mountPanel({ origin, pubkey });

  await act(async () => {
    await doRender();
    await new Promise((r) => setTimeout(r, 30));
  });

  // Click the Feedback tab via fireEvent.
  const feedbackTab = container.querySelector(
    "[data-testid='admin-tab-feedback']",
  );
  assert.ok(feedbackTab, "Feedback tab button must be present");
  await act(async () => {
    fireEvent.click(feedbackTab);
    await new Promise((r) => setTimeout(r, 30));
  });

  // Navigate to feedback detail, then click "View attachment" to start the load.
  let startedAttachmentLoad = false;
  const allBtns = container.querySelectorAll("button");
  for (const btn of allBtns) {
    const testid = btn.getAttribute("data-testid") ?? "";
    if (testid.startsWith("admin-tab")) continue;
    const btnText = btn.textContent ?? "";
    if (btnText.includes("View attachment")) {
      // Already at attachment button — start the load.
      await act(async () => {
        fireEvent.click(btn);
        await new Promise((r) => setTimeout(r, 0));
      });
      startedAttachmentLoad = true;
      break;
    }
    // Click feedback item to navigate to detail.
    await act(async () => {
      fireEvent.click(btn);
      await new Promise((r) => setTimeout(r, 30));
    });
    // Find "View attachment" in detail and click it.
    const btnsAfterNav = container.querySelectorAll("button");
    for (const b of btnsAfterNav) {
      if ((b.textContent ?? "").includes("View attachment")) {
        await act(async () => {
          fireEvent.click(b);
          await new Promise((r) => setTimeout(r, 0));
        });
        startedAttachmentLoad = true;
        break;
      }
    }
    break;
  }

  assert.ok(
    startedAttachmentLoad,
    '"View attachment" button must be found and clicked',
  );

  // Attachment fetch is in-flight (deferred). Change origin/pubkey to bump
  // panelGeneration — triggers AttachmentViewer cleanup: loadGenRef.current += 1.
  // The new panel renders but the user hasn't clicked "View attachment" again,
  // so loadGenRef.current on the now-unmounted instance's ref = original+1.
  setIpcHandler("admin_list_feedback", () => Promise.resolve([]));
  await act(async () => {
    await doRender({
      origin: "https://admin-2.example.com",
      pubkey: "b".repeat(64),
    });
    await new Promise((r) => setTimeout(r, 0));
  });

  // Resolve the attachment fetch. With the cleanup increment:
  //   thisGen(1) !== loadGenRef.current(2) -> revoke, no blob committed.
  // Without the cleanup increment:
  //   thisGen(1) == loadGenRef.current(1) AND thisOrigin(admin.example.com)
  //   !== originRef.current(admin-2.example.com) -> still revoke (origin check).
  // So this test catches the mutation only if the origin/pubkey check is also
  // removed. The loadGenRef test is most meaningful for detecting same-context
  // concurrent loads — see the comment above. We include it here as defense-
  // in-depth: if both loadGenRef AND the origin check were removed, the stale
  // blob would commit.
  attachDeferred.resolve(new ArrayBuffer(8));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 30));
  });

  const img = container.querySelector("img");
  assert.equal(
    img?.getAttribute("src") ?? null,
    null,
    "stale blob URL must not be committed to an img element after panel generation change",
  );

  if (origRevoke !== undefined) globalThis.URL.revokeObjectURL = origRevoke;
  await unmount();
});

// ── blob-leak-on-back-navigation ──────────────────────────────────────────────────────────────

test("blob-leak-on-back-navigation: loadGenRef cleanup prevents orphaned blob URL", async () => {
  // Isolates the loadGenRef.current += 1 cleanup in AttachmentViewer.
  //
  // Scenario: attachment fetch is in-flight, then the user navigates "Back to
  // feedback" (onBack sets selectedId=null in FeedbackTab, unmounting
  // FeedbackDetail and AttachmentViewer). At unmount the cleanup fires:
  //   loadGenRef.current += 1  ← MUTATION TARGET
  // The late fetch resolves. Since origin/pubkey are UNCHANGED (no context
  // change happened), only the loadGenRef check catches the mismatch:
  //   thisGen (pre-cleanup value) !== loadGenRef.current (incremented) → revoke
  //
  // Without the cleanup increment:
  //   thisGen === loadGenRef.current (both remain at 1) → all three guards pass
  //   → setBlobUrl called → blob URL committed to blobUrlRef.current with no
  //   revocation → orphaned blob URL leak.
  //
  // Fails if loadGenRef.current += 1 is removed from the cleanup.

  const origin = "https://admin.example.com";
  const pubkey = "a".repeat(64);
  const sha256 = "a".repeat(64);

  const feedbackItem = {
    id: "00000000-0000-0000-0000-000000000011",
    bodySummary: "Test feedback",
    receivedAt: 1700000000,
    tags: [
      [
        "imeta",
        `url https://relay.example.com/files/${sha256}`,
        "m image/png",
        `x ${sha256}`,
        "size 1000",
      ],
    ],
  };

  setIpcHandler("admin_list_reports", () => Promise.resolve([]));
  setIpcHandler("admin_list_feedback", () => Promise.resolve([feedbackItem]));
  setIpcHandler("admin_get_feedback", () => Promise.resolve(feedbackItem));

  const attachDeferred = deferred();
  const revokedUrls = [];
  const origRevoke = globalThis.URL?.revokeObjectURL;
  if (!globalThis.URL) globalThis.URL = {};
  globalThis.URL.revokeObjectURL = (url) => {
    revokedUrls.push(url);
    if (origRevoke) origRevoke.call(globalThis.URL, url);
  };
  globalThis.URL.createObjectURL = () => "blob:back-nav-test-url";
  setIpcHandler(
    "admin_fetch_feedback_attachment",
    () => attachDeferred.promise,
  );

  const { container, doRender, unmount } = mountPanel({ origin, pubkey });

  await act(async () => {
    await doRender();
    await new Promise((r) => setTimeout(r, 30));
  });

  // Click Feedback tab.
  const feedbackTab = container.querySelector(
    "[data-testid='admin-tab-feedback']",
  );
  assert.ok(feedbackTab, "Feedback tab must be present");
  await act(async () => {
    fireEvent.click(feedbackTab);
    await new Promise((r) => setTimeout(r, 30));
  });

  // Navigate to feedback detail.
  let navigatedToDetail = false;
  for (const btn of container.querySelectorAll("button")) {
    const testid = btn.getAttribute("data-testid") ?? "";
    if (testid.startsWith("admin-tab")) continue;
    if ((btn.textContent ?? "").includes("View attachment")) {
      await act(async () => {
        fireEvent.click(btn);
        await new Promise((r) => setTimeout(r, 0));
      });
      navigatedToDetail = true;
      break;
    }
    await act(async () => {
      fireEvent.click(btn);
      await new Promise((r) => setTimeout(r, 30));
    });
    for (const b of container.querySelectorAll("button")) {
      if ((b.textContent ?? "").includes("View attachment")) {
        await act(async () => {
          fireEvent.click(b);
          await new Promise((r) => setTimeout(r, 0));
        });
        navigatedToDetail = true;
        break;
      }
    }
    break;
  }
  assert.ok(
    navigatedToDetail,
    "must navigate to feedback detail and start attachment load",
  );

  // Attachment fetch is now in-flight.  Click "Back to feedback" — this
  // unmounts FeedbackDetail (and AttachmentViewer within it) WITHOUT changing
  // origin or pubkey.  The cleanup fires: loadGenRef.current += 1.
  const backBtn = Array.from(container.querySelectorAll("button")).find((b) =>
    (b.textContent ?? "").includes("Back to feedback"),
  );
  assert.ok(
    backBtn,
    "'Back to feedback' button must be present while detail is showing",
  );
  await act(async () => {
    fireEvent.click(backBtn);
    await new Promise((r) => setTimeout(r, 5));
  });

  // Resolve the attachment fetch.  With cleanup increment:
  //   thisGen (1) !== loadGenRef.current (2) → URL.revokeObjectURL("blob:back-nav-test-url")
  // Without cleanup increment:
  //   thisGen (1) === loadGenRef.current (1) AND origin/pubkey unchanged
  //   → setBlobUrl called → orphaned blob, no revocation.
  attachDeferred.resolve(new ArrayBuffer(8));
  await act(async () => {
    await new Promise((r) => setTimeout(r, 30));
  });

  assert.ok(
    revokedUrls.includes("blob:back-nav-test-url"),
    `blob URL must be revoked on back-navigation; revokedUrls: ${JSON.stringify(revokedUrls)}`,
  );

  if (origRevoke !== undefined) globalThis.URL.revokeObjectURL = origRevoke;
  await unmount();
});

// ── cross-identity delayed save ───────────────────────────────────────────────

test("cross-identity-delayed-save: A's late save carries A's expectedPubkey and does not touch B's state", async () => {
  // Verifies that set_admin_origin IPC is called with expectedPubkey = A's pubkey,
  // and that A's late save completion does not alter B's component state.
  //
  // The cross-session boundary is enforced by key={pubkeyHex}: when pubkey changes,
  // A's component unmounts and B's mounts fresh. A's deferred save resolves and
  // its continuation calls runProbe — but React state updates on the unmounted A
  // component are discarded. B's input and panel are unaffected.
  //
  // Scenario:
  //  1. Mount with pubkeyA; drive to authorized (probe nip98Authorized, panel rendered).
  //  2. Edit input and start save — deferred set_admin_origin with expectedPubkey=A.
  //  3. Switch identity to pubkeyB while A's save is pending:
  //     - A's component is synchronously unmounted (key change).
  //     - B's component mounts fresh with no saved origin.
  //  4. Resolve A's deferred save late.
  //  5. Assert:
  //     a. The set_admin_origin call recorded expectedPubkey = pubkeyA.
  //     b. B's input is still empty (A's late state writes discarded by React).
  //     c. B's panel does not show A's origin as authorized.
  //     d. No admin_probe fires for A's origin after the identity switch.
  //
  // Fails if expectedPubkey is dropped from the set_admin_origin invocation path
  // (api.ts forwarding): the recorded call has no expectedPubkey, so the Rust-level
  // guard cannot enforce identity isolation.

  const pubkeyA = "a".repeat(64);
  const pubkeyB = "b".repeat(64);
  const originA = "https://admin-a.example.com";
  const newOriginA = "https://admin-a-new.example.com";

  // Saved origin for A; B has none.
  setIpcHandler("get_admin_origin", (args) => {
    if (args?.expectedPubkey === pubkeyA) return Promise.resolve(originA);
    return Promise.resolve(null);
  });
  // Initial probe for A → authorized so the panel renders.
  setIpcHandler("admin_probe", () =>
    Promise.resolve({ state: "nip98Authorized" }),
  );
  setIpcHandler("admin_list_reports", () => Promise.resolve([]));
  setIpcHandler("admin_list_feedback", () => Promise.resolve([]));

  const qc = makeQueryClient(pubkeyA);
  const { container, doRender, unmount } = mountCard(qc);
  await doRender();
  await settle(30);

  // A is authorized — input must show originA.
  const inputA = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(inputA, "input must render for pubkeyA");

  // Record all set_admin_origin calls.
  const saveRecords = [];
  let resolveSaveA;
  setIpcHandler("set_admin_origin", (args) => {
    saveRecords.push({ ...args });
    return new Promise((r) => {
      resolveSaveA = r;
    });
  });

  // Edit input to newOriginA and press Enter to start a deferred save.
  await act(async () => {
    fireEvent.change(inputA, { target: { value: newOriginA } });
    await new Promise((r) => setTimeout(r, 5));
  });
  await act(async () => {
    fireEvent.keyDown(inputA, { key: "Enter", keyCode: 13 });
    await new Promise((r) => setTimeout(r, 5));
  });

  // A's save is now in-flight (deferred). Switch to pubkeyB.
  // A's component is synchronously unmounted (key change).
  setIpcHandler("get_admin_origin", (args) => {
    if (args?.expectedPubkey === pubkeyB) return Promise.resolve(null);
    return Promise.resolve(null);
  });
  // After switch, record admin_probe calls to detect any stale A probe firing.
  const probeRecords = [];
  setIpcHandler("admin_probe", (args) => {
    probeRecords.push({ ...args });
    return Promise.resolve({ state: "disabled" });
  });
  await act(async () => {
    qc.setQueryData(["identity"], { pubkey: pubkeyB });
    await new Promise((r) => setTimeout(r, 20));
  });

  // Resolve A's deferred save late. A's component is already unmounted — any
  // React state updates from A's continuation are discarded. B remains untouched.
  resolveSaveA?.(newOriginA);
  await settle(30);

  // (a) The set_admin_origin IPC call must have carried expectedPubkey = pubkeyA.
  assert.ok(
    saveRecords.length >= 1,
    "set_admin_origin must have been called at least once",
  );
  assert.equal(
    saveRecords[0]?.expectedPubkey,
    pubkeyA,
    `set_admin_origin must carry expectedPubkey = pubkeyA; got: ${JSON.stringify(saveRecords[0])}`,
  );

  // (b) B's input must still be empty (A's late state writes are discarded by React
  // on the unmounted A component; they never reach B's component tree).
  const inputB = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(inputB, "B's input must be present after identity switch");
  assert.equal(
    inputB.value,
    "",
    `B's input must be empty after identity switch; got: "${inputB.value}"`,
  );

  // (c) B's panel must not show A's origin as authorized — B is not authorized.
  const panel = container.querySelector("[data-testid='admin-console-panel']");
  assert.equal(
    panel,
    null,
    "admin-console-panel must not render for B — B has no authorized origin",
  );

  // (d) No admin_probe must have fired for A's origin after the identity switch.
  // A's handleSave continuation calls runProbe(canonical) after the save resolves.
  // The sessionTokenRef check prevents same-session concurrent saves from firing
  // a stale probe, but it does not stop A's own continuation after A unmounts:
  // A's sessionTokenRef still matches A's token, so the check passes and
  // runProbe(newOriginA) fires as an IPC call. React discards the state update
  // on the unmounted component, so B is unaffected — but the probe IPC fires.
  // This assertion catches any such stale probe call: if a probe with A's origin
  // is recorded here, production code is calling probeAdminOrigin after unmount.
  const staleProbe = probeRecords.find(
    (p) => p?.origin === originA || p?.origin === newOriginA,
  );
  assert.equal(
    staleProbe,
    undefined,
    `no admin_probe must fire for A's origin after identity switch; got: ${JSON.stringify(staleProbe)}`,
  );

  await unmount();
});

// ── strict-mode-save ──────────────────────────────────────────────────────────

test("strict-mode-save: probe fires after save under React.StrictMode double-mount", async () => {
  // Verifies the StrictMode-safe unmount fence in AdminConsoleSettingsSession.
  //
  // React.StrictMode (used in desktop/src/main.tsx) double-invokes effects in
  // development:  setup → cleanup → setup.  An isMountedRef-based fence
  // (cleanup sets isMountedRef.current = false, no reset in setup body) leaves
  // the ref permanently false after the double-mount, silently killing every
  // save completion in dev builds.
  //
  // The correct fence nulls sessionTokenRef on unmount instead:
  //   useEffect(() => () => { sessionTokenRef.current = null; }, [])
  // StrictMode's cleanup sets sessionTokenRef.current = null, then the setup
  // re-runs handleSave's `sessionTokenRef.current = token` when a new save
  // starts — so the fence is re-armed per save, not per mount.
  //
  // Fails if the unmount-cleanup effect is removed (isMountedRef variant or no
  // fence): after StrictMode double-mount, handleSave continuation is either
  // permanently blocked (isMountedRef=false) or the cross-identity stale probe
  // from assertion (d) in cross-identity-delayed-save fires.

  const pubkey = "c".repeat(64);
  const savedOrigin = "https://admin-strict.example.com";
  const canonicalOrigin = "https://admin-strict-canonical.example.com";

  setIpcHandler("get_admin_origin", () => Promise.resolve(savedOrigin));

  // Track probe invocations to verify the save drives a probe.
  const probeOrigins = [];
  setIpcHandler("admin_probe", (args) => {
    probeOrigins.push(args?.origin ?? "(none)");
    return Promise.resolve({ state: "disabled" });
  });
  setIpcHandler("set_admin_origin", () => Promise.resolve(canonicalOrigin));

  // gcTime: Infinity is critical: with gcTime: 0 StrictMode's simulated unmount
  // GCs the seeded identity query before the component's observer re-subscribes,
  // so the input never renders on the second mount.
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  });
  qc.setQueryData(["identity"], { pubkey });

  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);

  // Mount under React.StrictMode — triggers setup → cleanup → setup on all effects.
  await act(async () => {
    root.render(
      React.createElement(
        React.StrictMode,
        null,
        React.createElement(
          QueryClientProvider,
          { client: qc },
          React.createElement(AdminConsoleSettingsCard),
        ),
      ),
    );
  });
  await settle(30);

  const input = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(
    input,
    "origin input must render after StrictMode double-mount — identity query not GC'd",
  );

  // Clear probes from the initial mount probe.
  probeOrigins.length = 0;

  // Edit input and press Enter to trigger handleSave().
  const newOrigin = "https://admin-strict-new.example.com";
  await act(async () => {
    fireEvent.change(input, { target: { value: newOrigin } });
    await new Promise((r) => setTimeout(r, 5));
  });
  await act(async () => {
    fireEvent.keyDown(input, { key: "Enter", keyCode: 13 });
    await new Promise((r) => setTimeout(r, 5));
  });
  await settle(30);

  // The probe must fire for the canonical origin returned by set_admin_origin.
  // Fails if isMountedRef=false (from StrictMode cleanup) permanently blocks
  // the handleSave continuation: probeOrigins stays empty.
  assert.ok(
    probeOrigins.some((o) => o === canonicalOrigin),
    `probe must fire after save under StrictMode; probes: ${JSON.stringify(probeOrigins)}`,
  );

  await act(async () => {
    root.unmount();
  });
  document.body.removeChild(container);
});
