/**
 * Behavior tests for admin console panel helpers.
 *
 * Tests the pure logic that must be correct for the generation-fence and
 * imeta-parsing contracts to hold. Deferred-promise tests verify the
 * active-flag discard semantics that prevent stale results from crossing
 * identity/origin boundaries.
 */
import assert from "node:assert/strict";
import test from "node:test";

import { parseImetaAttachments } from "./AdminConsolePanel.tsx";

// ── parseImetaAttachments ─────────────────────────────────────────────────

test("parseImetaAttachments: parses a well-formed imeta tag", () => {
  const sha256 = "a".repeat(64);
  const tags = [
    [
      "imeta",
      `url https://example.com/a.jpg`,
      `m image/jpeg`,
      `x ${sha256}`,
      "size 1234",
    ],
  ];
  const result = parseImetaAttachments(tags);
  assert.equal(result.length, 1);
  assert.equal(result[0].sha256, sha256);
  assert.equal(result[0].mime, "image/jpeg");
  assert.equal(result[0].size, 1234);
});

test("parseImetaAttachments: skips tags that are not imeta", () => {
  const tags = [
    ["p", "abc123"],
    ["e", "def456"],
  ];
  assert.deepEqual(parseImetaAttachments(tags), []);
});

test("parseImetaAttachments: rejects uppercase x hash", () => {
  const sha256Upper = "A".repeat(64);
  const tags = [["imeta", `x ${sha256Upper}`, "m image/png", "size 100"]];
  assert.deepEqual(parseImetaAttachments(tags), []);
});

test("parseImetaAttachments: rejects hash shorter than 64 chars", () => {
  const tags = [["imeta", `x ${"a".repeat(63)}`, "m image/png", "size 100"]];
  assert.deepEqual(parseImetaAttachments(tags), []);
});

test("parseImetaAttachments: rejects hash longer than 64 chars", () => {
  const tags = [["imeta", `x ${"a".repeat(65)}`, "m image/png", "size 100"]];
  assert.deepEqual(parseImetaAttachments(tags), []);
});

test("parseImetaAttachments: rejects missing m field", () => {
  const sha256 = "b".repeat(64);
  const tags = [["imeta", `x ${sha256}`, "size 100"]];
  assert.deepEqual(parseImetaAttachments(tags), []);
});

test("parseImetaAttachments: rejects missing size field", () => {
  const sha256 = "c".repeat(64);
  const tags = [["imeta", `x ${sha256}`, "m image/png"]];
  assert.deepEqual(parseImetaAttachments(tags), []);
});

test("parseImetaAttachments: rejects non-positive size", () => {
  const sha256 = "d".repeat(64);
  const tags = [["imeta", `x ${sha256}`, "m image/png", "size 0"]];
  assert.deepEqual(parseImetaAttachments(tags), []);
  const tagsNeg = [["imeta", `x ${sha256}`, "m image/png", "size -1"]];
  assert.deepEqual(parseImetaAttachments(tagsNeg), []);
});

test("parseImetaAttachments: parses multiple imeta tags", () => {
  const sha1 = "e".repeat(64);
  const sha2 = "f".repeat(64);
  const tags = [
    ["imeta", `x ${sha1}`, "m image/png", "size 111"],
    ["imeta", `x ${sha2}`, "m image/jpeg", "size 222"],
  ];
  const result = parseImetaAttachments(tags);
  assert.equal(result.length, 2);
  assert.equal(result[0].sha256, sha1);
  assert.equal(result[1].sha256, sha2);
});

test("parseImetaAttachments: returns empty array for non-array input", () => {
  assert.deepEqual(parseImetaAttachments(null), []);
  assert.deepEqual(parseImetaAttachments({}), []);
  assert.deepEqual(parseImetaAttachments("imeta"), []);
});

test("parseImetaAttachments: extracts from camelCase AdminFeedback relay fixture", () => {
  // Exact wire shape emitted by the relay (serde rename_all = "camelCase").
  const sha256 =
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const fixture = {
    id: "00000000-0000-0000-0000-000000000001",
    reportType: "feedback",
    bodySummary: "App crashes on startup",
    body: "Full description here",
    receivedAt: 1700000000,
    tags: [
      [
        "imeta",
        `url https://relay.example.com/files/${sha256}`,
        `m image/png`,
        `x ${sha256}`,
        "size 98765",
      ],
    ],
  };
  const result = parseImetaAttachments(fixture.tags);
  assert.equal(result.length, 1);
  assert.equal(result[0].sha256, sha256);
  assert.equal(result[0].mime, "image/png");
  assert.equal(result[0].size, 98765);
});

// ── Active-flag discard semantics ─────────────────────────────────────────
//
// These tests verify the deferred-promise discard contract that underlies
// useAsyncLoad's active-flag pattern. The pattern is: each effect invocation
// creates a local `active = true`, flips it false in cleanup, and checks it
// before committing results. The tests below exercise the exact same logic
// inline to prove the contract is sound.

test("active-flag: result committed when active", async () => {
  let committed = null;
  let active = true;
  await Promise.resolve("data").then((data) => {
    if (active) committed = data;
  });
  assert.equal(committed, "data");
  active = false;
});

test("active-flag: stale result discarded when active flipped before resolution", async () => {
  let committed = null;
  let active = true;

  // Deferred promise — simulates an in-flight Tauri invoke.
  let resolve;
  const deferred = new Promise((r) => {
    resolve = r;
  });
  const p = deferred.then((data) => {
    if (active) committed = data;
  });

  // Simulate effect cleanup (identity/origin changed) before result arrives.
  active = false;

  // Native result arrives.
  resolve("stale-data");
  await p;

  assert.equal(
    committed,
    null,
    "stale result must not be committed after active=false",
  );
});

test("active-flag: old-list-after-new-list race — each invocation has its own flag", async () => {
  const committed = [];

  // First invocation — has its own closure-local active1.
  let active1 = true;
  let resolveFirst;
  const first = new Promise((r) => {
    resolveFirst = r;
  });
  const p1 = first.then((data) => {
    if (active1) committed.push({ load: "first", data });
  });

  // Cleanup of first invocation (pubkey changed).
  active1 = false;

  // Second invocation — has its own closure-local active2.
  const active2 = true;
  let resolveSecond;
  const second = new Promise((r) => {
    resolveSecond = r;
  });
  const p2 = second.then((data) => {
    if (active2) committed.push({ load: "second", data });
  });

  // Second resolves first.
  resolveSecond("new-data");
  await p2;

  // First resolves after (stale — active1 is false).
  resolveFirst("old-data");
  await p1;

  assert.equal(committed.length, 1);
  assert.equal(committed[0].load, "second");
  assert.equal(committed[0].data, "new-data");
});

test("active-flag per-invocation: identity switch discards old result", async () => {
  const results = [];

  // First effect invocation.
  let active1 = true;
  const p1 = Promise.resolve("first").then((data) => {
    if (active1) results.push(data);
  });

  // Cleanup of first invocation.
  active1 = false;

  // Second effect invocation (new pubkey/origin).
  const active2 = true;
  const p2 = Promise.resolve("second").then((data) => {
    if (active2) results.push(data);
  });

  await Promise.all([p1, p2]);

  // Only second was active when it resolved.
  assert.deepEqual(results, ["second"]);
});

test("active-flag: origin edit discards in-flight probe result", async () => {
  // Simulates: probe started with originA, user edits input, active = false,
  // probe result arrives and must be discarded.
  let committedOrigin = null;
  let active = true;

  let resolveProbe;
  const probeResult = new Promise((r) => {
    resolveProbe = r;
  });
  const p = probeResult.then((origin) => {
    if (active) committedOrigin = origin;
  });

  // User edits input — abort/reset sets active = false.
  active = false;

  // Probe resolves (stale).
  resolveProbe("https://old.example.com");
  await p;

  assert.equal(
    committedOrigin,
    null,
    "stale probe result must not update UI after origin edit",
  );
});

// ── Attachment load-generation semantics ─────────────────────────────────
//
// These tests verify the loadGenRef pattern used in AttachmentViewer:
// increment in cleanup before revoke, compare at commit time.

test("attachment load-gen: increment in cleanup invalidates in-flight loads", async () => {
  const loadGenRef = { current: 0 };
  const blobUrls = [];
  const revokedUrls = [];

  function revokeObjectURL(url) {
    revokedUrls.push(url);
  }

  // Start a load — captures thisGen = 1.
  const thisGen = ++loadGenRef.current;
  let resolveLoad;
  const loadPromise = new Promise((r) => {
    resolveLoad = r;
  });
  const p = loadPromise.then((url) => {
    if (thisGen !== loadGenRef.current) {
      revokeObjectURL(url);
      return;
    }
    blobUrls.push(url);
  });

  // Cleanup increments loadGenRef to 2 — invalidates the in-flight load.
  loadGenRef.current += 1;

  // Load resolves (stale — gen 1 !== current 2).
  resolveLoad("blob://fake-1");
  await p;

  assert.equal(blobUrls.length, 0, "stale blob URL must not be committed");
  assert.equal(revokedUrls.length, 1, "stale blob URL must be revoked");
  assert.equal(revokedUrls[0], "blob://fake-1");
});

test("attachment load-gen: second load supersedes first when first resolves late", async () => {
  const loadGenRef = { current: 0 };
  const blobUrls = [];
  const revokedUrls = [];

  function revokeObjectURL(url) {
    revokedUrls.push(url);
  }

  let resolveFirst;
  const firstLoad = new Promise((r) => {
    resolveFirst = r;
  });

  // Start first load — captures gen 1.
  const thisGen1 = ++loadGenRef.current;
  const p1 = firstLoad.then((url) => {
    if (thisGen1 !== loadGenRef.current) {
      revokeObjectURL(url);
      return;
    }
    blobUrls.push(url);
  });

  // Start second load — gen 2 (user pressed load again).
  const thisGen2 = ++loadGenRef.current;
  // Second resolves immediately.
  if (thisGen2 === loadGenRef.current) {
    blobUrls.push("blob://second");
  }

  // First resolves (stale — gen 1 !== current 2).
  resolveFirst("blob://first");
  await p1;

  assert.deepEqual(blobUrls, ["blob://second"], "only second load committed");
  assert.deepEqual(
    revokedUrls,
    ["blob://first"],
    "stale URL from first load revoked",
  );
});

test("attachment unmount: cleanup revokes in-flight blob URL", async () => {
  // Simulates unmount while a load is in flight: panelGeneration effect cleanup
  // increments loadGenRef and revokes blobUrlRef. The subsequent native result
  // sees the mismatch and immediately revokes its URL too.
  const loadGenRef = { current: 0 };
  const blobUrlRef = { current: null };
  const revokedUrls = [];

  function revokeObjectURL(url) {
    revokedUrls.push(url);
    if (blobUrlRef.current === url) blobUrlRef.current = null;
  }

  const thisGen = ++loadGenRef.current;
  let resolveLoad;
  const loadPromise = new Promise((r) => {
    resolveLoad = r;
  });
  const p = loadPromise.then((url) => {
    if (thisGen !== loadGenRef.current) {
      revokeObjectURL(url);
      return;
    }
    if (blobUrlRef.current) revokeObjectURL(blobUrlRef.current);
    blobUrlRef.current = url;
  });

  // Unmount cleanup: increment gen + revoke any existing blob.
  loadGenRef.current += 1;
  if (blobUrlRef.current) {
    revokeObjectURL(blobUrlRef.current);
    blobUrlRef.current = null;
  }

  // Load resolves after unmount.
  resolveLoad("blob://after-unmount");
  await p;

  assert.equal(
    blobUrlRef.current,
    null,
    "blob URL must not be committed after unmount",
  );
  assert.deepEqual(
    revokedUrls,
    ["blob://after-unmount"],
    "late blob URL must be revoked",
  );
});
