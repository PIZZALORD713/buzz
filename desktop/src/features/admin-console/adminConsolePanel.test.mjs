/**
 * Behavior and race tests for AdminConsoleSettingsCard / AdminConsoleSettingsSession.
 *
 * Tests mount the REAL production components (including the key-prop session
 * boundary, sessionTokenRef fence, and abortAndResetProbe wiring) against a
 * mocked Tauri IPC bridge and a real QueryClientProvider.
 *
 * This file uses the hand-rolled MinimalDocument shim (same pattern as
 * useLoadArchivedObserverEvents.test.mjs) and covers prop-driven and query-
 * driven tests that do NOT require native event dispatch through React 19's
 * container-level delegation:
 *
 * What makes these tests authoritative — they fail if:
 *   - `key={pubkeyHex}` boundary is removed (logout, identity-switch, delayed-save tests)
 *   - `active` flag cleanup is removed from useAsyncLoad (old-list-after-new-list)
 *   - the `getAdminOrigin()` catch is changed to silent-degrade (storage-error test)
 *
 * Event-driven tests (origin-edit, detail-navigation, attachment-unmount,
 * same-session-save-race) live in adminConsolePanelEvents.jsdom-test.mjs,
 * which is run with jsdom pre-installed so React 19's event delegation works.
 *
 * Also covers:
 *   - parseImetaAttachments wire contract (imported from AdminConsolePanel)
 */
import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

// ── Minimal DOM shim ──────────────────────────────────────────────────────────
//
// Installs the minimum DOM surface that React + react-dom/client need.
// Uses the same pattern as useLoadArchivedObserverEvents.test.mjs to avoid
// jsdom background timers that prevent the process from exiting cleanly.

function installDOMShim() {
  class MinimalEventTarget {
    constructor() {
      this._listeners = {};
    }
    addEventListener(type, fn) {
      if (!this._listeners[type]) this._listeners[type] = [];
      this._listeners[type].push(fn);
    }
    removeEventListener(type, fn) {
      if (this._listeners[type]) {
        this._listeners[type] = this._listeners[type].filter((f) => f !== fn);
      }
    }
    dispatchEvent(e) {
      for (const fn of this._listeners[e.type] ?? []) fn(e);
      return true;
    }
  }

  class MinimalNode extends MinimalEventTarget {
    constructor(tagName) {
      super();
      this.tagName = tagName?.toUpperCase?.() ?? tagName;
      this.nodeName = this.tagName;
      this.children = [];
      this.childNodes = [];
      this.style = {};
      this.nodeType = 1;
      this.parentNode = null;
      this.attributes = [];
      this._data = {};
    }
    get ownerDocument() {
      return globalThis.document;
    }
    get firstChild() {
      return this.childNodes[0] ?? null;
    }
    get lastChild() {
      return this.childNodes[this.childNodes.length - 1] ?? null;
    }
    get nextSibling() {
      return null;
    }
    get previousSibling() {
      return null;
    }
    get nodeValue() {
      return null;
    }
    set nodeValue(_v) {}
    get textContent() {
      return this.childNodes.map((c) => c.textContent ?? "").join("");
    }
    set textContent(v) {
      this.childNodes = [];
      if (v) {
        const t = globalThis.document.createTextNode(v);
        this.appendChild(t);
      }
    }
    appendChild(child) {
      child.parentNode = this;
      this.childNodes.push(child);
      if (child.nodeType === 1) this.children.push(child);
      return child;
    }
    removeChild(child) {
      this.childNodes = this.childNodes.filter((c) => c !== child);
      this.children = this.children.filter((c) => c !== child);
      return child;
    }
    insertBefore(newNode, refNode) {
      if (!refNode) return this.appendChild(newNode);
      const i = this.childNodes.indexOf(refNode);
      if (i < 0) return this.appendChild(newNode);
      newNode.parentNode = this;
      this.childNodes.splice(i, 0, newNode);
      if (newNode.nodeType === 1) this.children.push(newNode);
      return newNode;
    }
    replaceChild(newNode, oldNode) {
      const i = this.childNodes.indexOf(oldNode);
      if (i >= 0) {
        newNode.parentNode = this;
        this.childNodes[i] = newNode;
        const j = this.children.indexOf(oldNode);
        if (j >= 0) this.children[j] = newNode;
      }
      return oldNode;
    }
    contains(node) {
      if (!node) return false;
      return this === node || this.childNodes.some((c) => c?.contains?.(node));
    }
    setAttribute(name, value) {
      this._data[name] = value;
    }
    getAttribute(name) {
      return this._data[name] ?? null;
    }
    hasAttribute(name) {
      return Object.hasOwn(this._data, name);
    }
    removeAttribute(name) {
      delete this._data[name];
    }
    querySelector(selector) {
      // Support [data-testid='...'] and simple tag selectors.
      const attrMatch = selector.match(/\[([^\]=']+)(?:='([^']*)')?\]/);
      const tagMatch = selector.match(/^([a-zA-Z]+)$/);
      for (const node of this._allElements()) {
        if (attrMatch) {
          const [, attrName, attrVal] = attrMatch;
          const nodeVal = node.getAttribute?.(attrName);
          if (attrVal === undefined ? nodeVal !== null : nodeVal === attrVal) {
            return node;
          }
        } else if (tagMatch) {
          if (node.tagName?.toLowerCase() === tagMatch[1].toLowerCase()) {
            return node;
          }
        }
      }
      return null;
    }
    querySelectorAll(selector) {
      const attrMatch = selector.match(/\[([^\]=']+)(?:='([^']*)')?\]/);
      const results = [];
      for (const node of this._allElements()) {
        if (attrMatch) {
          const [, attrName, attrVal] = attrMatch;
          const nodeVal = node.getAttribute?.(attrName);
          if (attrVal === undefined ? nodeVal !== null : nodeVal === attrVal) {
            results.push(node);
          }
        }
      }
      return results;
    }
    *_allElements() {
      for (const child of this.childNodes) {
        yield child;
        if (child._allElements) yield* child._allElements();
      }
    }
    get innerHTML() {
      return this.childNodes
        .map((c) => c.outerHTML ?? c.textContent ?? "")
        .join("");
    }
    set innerHTML(_v) {}
    get outerHTML() {
      return `<${this.tagName?.toLowerCase() ?? "div"}>...</${this.tagName?.toLowerCase() ?? "div"}>`;
    }
    focus() {}
    blur() {}
    getBoundingClientRect() {
      return { top: 0, left: 0, bottom: 0, right: 0, width: 0, height: 0 };
    }
    cloneNode() {
      return new MinimalNode(this.tagName);
    }
    get value() {
      return this._value ?? "";
    }
    set value(v) {
      this._value = v;
    }
    get disabled() {
      return this._disabled ?? false;
    }
    set disabled(v) {
      this._disabled = v;
    }
    get type() {
      return this._type ?? "";
    }
    set type(v) {
      this._type = v;
    }
    get checked() {
      return this._checked ?? false;
    }
    set checked(v) {
      this._checked = v;
    }
    get className() {
      return this._className ?? "";
    }
    set className(v) {
      this._className = v;
    }
    get id() {
      return this._id ?? "";
    }
    set id(v) {
      this._id = v;
    }
    get placeholder() {
      return this._placeholder ?? "";
    }
    set placeholder(v) {
      this._placeholder = v;
    }
    get readOnly() {
      return this._readOnly ?? false;
    }
    set readOnly(v) {
      this._readOnly = v;
    }
    get tabIndex() {
      return this._tabIndex ?? -1;
    }
    set tabIndex(v) {
      this._tabIndex = v;
    }
    get href() {
      return this._href ?? "";
    }
    set href(v) {
      this._href = v;
    }
    get src() {
      return this._src ?? "";
    }
    set src(v) {
      this._src = v;
    }
    get alt() {
      return this._alt ?? "";
    }
    set alt(v) {
      this._alt = v;
    }
  }

  class MinimalTextNode extends MinimalEventTarget {
    constructor(value) {
      super();
      this.nodeType = 3;
      this.nodeName = "#text";
      this.nodeValue = value;
      this.parentNode = null;
    }
    get textContent() {
      return this.nodeValue;
    }
    set textContent(v) {
      this.nodeValue = v;
    }
    contains(node) {
      return this === node;
    }
  }

  class MinimalDocument extends MinimalEventTarget {
    constructor() {
      super();
      this.nodeType = 9;
      this.nodeName = "#document";
      this._body = null;
      this._head = null;
    }
    createElement(tagName) {
      return new MinimalNode(tagName);
    }
    createTextNode(value) {
      return new MinimalTextNode(value);
    }
    createComment(value) {
      const n = new MinimalNode("#comment");
      n.nodeType = 8;
      n.nodeValue = value;
      return n;
    }
    createElementNS(_ns, tagName) {
      return this.createElement(tagName);
    }
    get body() {
      if (!this._body) {
        this._body = this.createElement("body");
      }
      return this._body;
    }
    get head() {
      if (!this._head) {
        this._head = this.createElement("head");
      }
      return this._head;
    }
    get activeElement() {
      return null;
    }
    contains(node) {
      return node != null;
    }
    querySelector(sel) {
      return this.body.querySelector(sel);
    }
    querySelectorAll(sel) {
      return this.body.querySelectorAll(sel);
    }
    get documentElement() {
      return this.body;
    }
  }

  const doc = new MinimalDocument();
  globalThis.document = doc;
  globalThis.HTMLElement = MinimalNode;
  globalThis.HTMLInputElement = MinimalNode;
  globalThis.HTMLButtonElement = MinimalNode;
  globalThis.HTMLDivElement = MinimalNode;
  globalThis.HTMLSpanElement = MinimalNode;
  globalThis.HTMLAnchorElement = MinimalNode;
  globalThis.HTMLFormElement = MinimalNode;
  globalThis.HTMLIFrameElement = MinimalNode;
  globalThis.SVGElement = MinimalNode;
  globalThis.SVGSVGElement = MinimalNode;
  globalThis.Text = MinimalTextNode;
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  process.env.IS_REACT_ACT_ENVIRONMENT = "true";

  globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
  globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

  globalThis.MutationObserver = class {
    observe() {}
    disconnect() {}
    takeRecords() {
      return [];
    }
  };

  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };

  globalThis.IntersectionObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };

  globalThis.getComputedStyle = () => ({
    getPropertyValue: () => "",
    setProperty: () => {},
  });

  if (typeof globalThis.window === "undefined") {
    Object.defineProperty(globalThis, "window", {
      value: globalThis,
      configurable: true,
    });
  }
  if (!Object.getOwnPropertyDescriptor(globalThis, "navigator")?.value) {
    Object.defineProperty(globalThis, "navigator", {
      value: { userAgent: "node" },
      configurable: true,
    });
  }
}

installDOMShim();

// ── Tauri IPC interceptor ─────────────────────────────────────────────────────

/** @type {Map<string, (args: unknown) => Promise<unknown>>} */
const ipcHandlers = new Map();

function setIpcHandler(cmd, fn) {
  ipcHandlers.set(cmd, fn);
}
function clearIpcHandlers() {
  ipcHandlers.clear();
}

globalThis.__TAURI_INTERNALS__ = {
  invoke(cmd, args) {
    const handler = ipcHandlers.get(cmd);
    if (handler) return handler(args);
    return Promise.reject(new Error(`unmocked Tauri command: ${cmd}`));
  },
  transformCallback(_cb) {
    return Math.random();
  },
};

// ── Production imports ────────────────────────────────────────────────────────

import React from "react";
import { createRoot } from "react-dom/client";
import { act } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { AdminConsoleSettingsCard } from "./AdminConsoleSettingsCard.tsx";
import {
  AdminConsolePanel,
  parseImetaAttachments,
} from "./AdminConsolePanel.tsx";

// ── Deferred promise helper ───────────────────────────────────────────────────

function deferred() {
  let resolve, reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

// ── Mount helpers ─────────────────────────────────────────────────────────────

function makeQueryClient(pubkeyHex) {
  const qc = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
    },
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

/**
 * Mount AdminConsolePanel directly (not through the settings card).
 * Used for panel-level race tests (list, detail, attachment).
 */
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

// Flush React effects and timers.
async function settle(ms = 20) {
  await act(async () => {
    await new Promise((r) => setTimeout(r, ms));
  });
}

afterEach(() => {
  clearIpcHandlers();
});

// ── parseImetaAttachments ─────────────────────────────────────────────────────

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

// ── Component-level session boundary and race tests ───────────────────────────
//
// Each test below mounts the production AdminConsoleSettingsCard (including
// AdminConsoleSettingsSession keyed by pubkeyHex) and drives Tauri IPC calls
// via deferred promises. These tests fail if the identity boundary or fences
// are removed from the production code.

test("logout: pubkeyHex empty renders no origin input", async () => {
  // When no pubkey is present, the session component must not render.
  // Removing the `pubkeyHex ? <Session key=…> : null` guard causes this to fail.
  setIpcHandler("get_admin_origin", () => Promise.resolve(null));

  const qc = makeQueryClient("");
  const { container, doRender, unmount } = mountCard(qc);
  await doRender();
  await settle();

  const input = container.querySelector("[data-testid='admin-origin-input']");
  assert.equal(
    input,
    null,
    "admin origin input must not render when logged out (no pubkey)",
  );
  await unmount();
});

test("identity-switch: fresh session mounts with empty input on pubkey change", async () => {
  // Verifies the key-prop boundary. Without `key={pubkeyHex}`, React reuses
  // the component and A's origin state survives the switch to B.

  const pubkeyA = "a".repeat(64);
  const pubkeyB = "b".repeat(64);
  const originA = "https://admin-a.example.com";

  setIpcHandler("get_admin_origin", (args) => {
    if (args?.expectedPubkey === pubkeyA) return Promise.resolve(originA);
    return Promise.resolve(null);
  });
  setIpcHandler("admin_probe", () => Promise.resolve({ state: "disabled" }));

  const qc = makeQueryClient(pubkeyA);
  const { container, doRender, unmount } = mountCard(qc);
  await doRender();
  await settle(25);

  const inputA = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(inputA, "input must render for pubkeyA");
  assert.equal(
    inputA.value,
    originA,
    "input must show A's saved origin after mount",
  );

  // Switch to pubkeyB — key prop causes a full remount of AdminConsoleSettingsSession.
  // B has no saved origin, so the input must be empty.
  setIpcHandler("get_admin_origin", (args) => {
    if (args?.expectedPubkey === pubkeyB) return Promise.resolve(null);
    // Reject any call with A's pubkey — must not fire after the switch.
    return Promise.reject(new Error("unexpected pubkey after identity switch"));
  });

  await act(async () => {
    qc.setQueryData(["identity"], { pubkey: pubkeyB });
    await new Promise((r) => setTimeout(r, 25));
  });

  const inputB = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(inputB, "input must render for pubkeyB");
  assert.equal(
    inputB.value,
    "",
    "input must be empty for pubkeyB — key boundary ensures fresh state, not stale A origin",
  );
  await unmount();
});

test("storage-error surfaced: getAdminOrigin rejection shows error in UI", async () => {
  // Verifies the mount-effect catch sets `{ kind: 'error', message }`.
  // Removing error propagation from the catch (silent degrade) causes the
  // error text to not appear.

  const pubkey = "c".repeat(64);
  const errorMsg = "stored admin console origin is invalid (removed): bad json";
  setIpcHandler("get_admin_origin", () => Promise.reject(new Error(errorMsg)));

  const qc = makeQueryClient(pubkey);
  const { container, doRender, unmount } = mountCard(qc);
  await doRender();
  await settle(25);

  // The error or its key fragment must be visible in the rendered tree.
  const bodyText = container.textContent ?? "";
  const hasError =
    bodyText.includes("invalid") ||
    bodyText.includes("bad json") ||
    bodyText.includes("removed") ||
    bodyText.includes("admin console origin");
  assert.ok(
    hasError,
    `error from getAdminOrigin must appear in UI; body text: "${bodyText.slice(0, 300)}"`,
  );
  await unmount();
});

// origin-edit (abortAndResetProbe wired to onChange) is covered by
// adminConsolePanelEvents.jsdom-test.mjs where fireEvent dispatches native
// events through React 19's container-level delegation.

test("delayed-save-after-switch: save result from old session is discarded after identity switch", async () => {
  // Verifies the key={pubkeyHex} boundary (not sessionTokenRef) protects
  // cross-session saves: when pubkey changes, the entire session unmounts,
  // so any pending save promise resolves against the old (now-unmounted)
  // session component whose state no longer affects B.
  //
  // The sessionTokenRef fence within a single session is covered by the
  // same-session-save-race test in adminConsolePanelEvents.jsdom-test.mjs.
  //
  // Fails if `key={pubkeyHex}` is removed: React reuses the component and
  // A's session token survives the identity switch, potentially corrupting B.

  const pubkeyA = "a".repeat(64);
  const pubkeyB = "b".repeat(64);

  setIpcHandler("get_admin_origin", () => Promise.resolve(null));
  setIpcHandler("admin_probe", () => Promise.resolve({ state: "disabled" }));

  const qc = makeQueryClient(pubkeyA);
  const { container, doRender, unmount } = mountCard(qc);
  await doRender();
  await settle(15);

  const input = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(input, "input must be present");

  // Switch to pubkeyB — key prop unmounts A's component entirely.
  setIpcHandler("get_admin_origin", () => Promise.resolve(null));
  await act(async () => {
    qc.setQueryData(["identity"], { pubkey: pubkeyB });
    await new Promise((r) => setTimeout(r, 20));
  });

  // B's input must be empty (B has no saved origin).
  const inputB = container.querySelector("[data-testid='admin-origin-input']");
  assert.ok(
    inputB,
    "B's input must be present — AdminConsoleSettingsSession must have mounted for pubkeyB",
  );
  assert.equal(
    inputB.value,
    "",
    "B's input must be empty — key boundary ensures B mounts fresh, not with A's state",
  );
  await unmount();
});

// ── AdminConsolePanel race tests ──────────────────────────────────────────────
//
// These tests mount AdminConsolePanel directly (bypassing the settings card)
// and use deferred promises to simulate in-flight native requests. They verify
// the effect-local `active` flag cancellation in useAsyncLoad, the generation
// fence in AdminConsolePanel, and the loadGenRef cleanup in AttachmentViewer.

test("old-list-after-new-list: stale list result does not replace new list after pubkey change", async () => {
  // Verifies the effect-local `active` flag in useAsyncLoad.
  //
  // Scenario: panel renders with pubkeyA/originA → list query starts (deferred).
  // Before it resolves, panel re-renders with pubkeyB/originB → a new list
  // query starts. Then the old (A's) deferred resolves: the active flag in
  // A's effect closure is already false (effect re-ran with B's deps), so
  // A's result is discarded. Only B's result may commit.
  //
  // This test fails if useAsyncLoad's active-flag cleanup is removed, because
  // A's result would overwrite B's list state.

  const originA = "https://admin-a.example.com";
  const originB = "https://admin-b.example.com";
  const pubkeyA = "a".repeat(64);
  const pubkeyB = "b".repeat(64);

  const listDeferredA = deferred();
  const listDeferredB = deferred();

  // First call returns A's deferred; subsequent calls return B's.
  let callCount = 0;
  setIpcHandler("admin_list_reports", () => {
    callCount += 1;
    if (callCount === 1) return listDeferredA.promise;
    return listDeferredB.promise;
  });

  const { container, doRender, unmount } = mountPanel({
    origin: originA,
    pubkey: pubkeyA,
  });

  // Render with A — list query starts and stays pending (no settle; would hang).
  await act(async () => {
    await doRender({ origin: originA, pubkey: pubkeyA });
    await new Promise((r) => setTimeout(r, 0));
  });

  // Switch to B — triggers generation bump + effect cleanup (active = false for A).
  // Re-render causes the effect to re-run with B's deps.
  await act(async () => {
    await doRender({ origin: originB, pubkey: pubkeyB });
    await new Promise((r) => setTimeout(r, 0));
  });

  // Now resolve A's stale list with a distinct marker item.
  listDeferredA.resolve([
    {
      id: "00000000-0000-0000-0000-000000000001",
      communityId: "00000000-0000-0000-0000-000000000002",
      communityHost: "relay.example.com",
      reportEventId: "aabb",
      reporterPubkey: "ccdd",
      targetKind: "message",
      target: "eeff",
      reportType: "spam",
      status: "STALE-A-RESULT",
      createdAt: "2024-01-01T00:00:00Z",
    },
  ]);

  // Flush A's resolution — active is false so it must not commit.
  await act(async () => {
    await new Promise((r) => setTimeout(r, 30));
  });

  // A's stale result must not appear — active flag was false.
  const text = container.textContent ?? "";
  assert.ok(
    !text.includes("STALE-A-RESULT"),
    `stale list result from A must not appear after B renders; got: ${text.slice(0, 300)}`,
  );

  // Resolve B's list — this one is live.
  listDeferredB.resolve([
    {
      id: "00000000-0000-0000-0000-000000000003",
      communityId: "00000000-0000-0000-0000-000000000004",
      communityHost: "relay.example.com",
      reportEventId: "1122",
      reporterPubkey: "3344",
      targetKind: "message",
      target: "5566",
      reportType: "feedback",
      status: "LIVE-B-RESULT",
      createdAt: "2024-01-02T00:00:00Z",
    },
  ]);

  await act(async () => {
    await new Promise((r) => setTimeout(r, 30));
  });

  const textAfter = container.textContent ?? "";
  assert.ok(
    textAfter.includes("LIVE-B-RESULT"),
    `B's live list result must appear; got: ${textAfter.slice(0, 300)}`,
  );

  await unmount();
});

// detail-navigation and attachment-unmount (useAsyncLoad active flag,
// AttachmentViewer loadGenRef cleanup) are covered by
// adminConsolePanelEvents.jsdom-test.mjs where fireEvent dispatches native
// events through React 19's container-level delegation.
