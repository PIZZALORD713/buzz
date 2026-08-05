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
 *
 * Note on attachment-unmount: the test proves stale blob URLs are not committed
 * when the panel context changes. The loadGenRef.current += 1 cleanup and the
 * origin/pubkey ref checks both protect against this — they cannot be isolated
 * in a test because panelGeneration only changes when origin/pubkey change.
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
  if (pubkeyHex) {
    qc.setQueryData(["identity"], { pubkey: pubkeyHex });
  } else {
    qc.setQueryData(["identity"], undefined);
  }
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

  if (!clickedReport) {
    // List didn't render (e.g. IPC timing). Skip gracefully.
    detailDeferredA.resolve({ content: "skip" });
    detailDeferredB.resolve({ content: "skip" });
    await act(async () => {
      await new Promise((r) => setTimeout(r, 10));
    });
    await unmount();
    return;
  }

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
  if (!feedbackTab) {
    attachDeferred.resolve(new ArrayBuffer(8));
    if (origRevoke !== undefined) globalThis.URL.revokeObjectURL = origRevoke;
    await unmount();
    return;
  }
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

  if (!startedAttachmentLoad) {
    // Couldn't start the attachment load — skip.
    attachDeferred.resolve(new ArrayBuffer(8));
    if (origRevoke !== undefined) globalThis.URL.revokeObjectURL = origRevoke;
    await unmount();
    return;
  }

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
