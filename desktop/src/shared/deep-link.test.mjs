import assert from "node:assert/strict";
import { afterEach, test } from "node:test";

const ipcHandlers = new Map();
let nextCallbackId = 1;
const callbacks = new Map();

const tauriInternals = {
  invoke: (cmd, args) => {
    const handler = ipcHandlers.get(cmd);
    if (handler) return Promise.resolve(handler(args));
    return Promise.reject(new Error(`unmocked Tauri command: ${cmd}`));
  },
  transformCallback: (callback) => {
    const id = nextCallbackId++;
    callbacks.set(id, callback);
    return id;
  },
};
globalThis.window = {
  __TAURI_INTERNALS__: tauriInternals,
  __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener: () => {} },
};
globalThis.__TAURI_INTERNALS__ = tauriInternals;

const { listenForNavigationDeepLinks } = await import("@/shared/deep-link.ts");

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function settle() {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

afterEach(() => {
  ipcHandlers.clear();
  callbacks.clear();
});

test("listener teardown leaves an unaccepted FIFO item for the next mount", async () => {
  const queue = [
    {
      id: "first",
      kind: "channel",
      channelId: "channel-1",
      messageId: null,
      threadRootId: null,
    },
    {
      id: "second",
      kind: "message",
      channelId: "channel-2",
      messageId: "message-2",
      threadRootId: "root-2",
    },
  ];
  const firstAcknowledge = deferred();
  const acknowledged = [];
  let unlistenCount = 0;

  ipcHandlers.set("plugin:event|listen", () => nextCallbackId);
  ipcHandlers.set("plugin:event|unlisten", () => {
    unlistenCount += 1;
  });
  ipcHandlers.set("take_pending_navigation_deep_link", () => queue[0] ?? null);
  ipcHandlers.set(
    "acknowledge_pending_navigation_deep_link",
    async ({ id }) => {
      if (id === "first") await firstAcknowledge.promise;
      assert.equal(queue[0]?.id, id);
      acknowledged.push(id);
      queue.shift();
      return true;
    },
  );

  let firstMountActive = true;
  const firstOpened = [];
  const firstUnlisten = await listenForNavigationDeepLinks(
    (payload) => {
      if (!firstMountActive) return false;
      firstOpened.push(payload.channelId);
      return true;
    },
    (payload) => {
      if (!firstMountActive) return false;
      firstOpened.push(payload.messageId);
      return true;
    },
  );
  await settle();
  assert.deepEqual(firstOpened, ["channel-1"]);

  firstMountActive = false;
  firstUnlisten();
  firstAcknowledge.resolve();
  await settle();

  assert.deepEqual(acknowledged, ["first"]);
  assert.equal(queue[0]?.id, "second");

  const secondOpened = [];
  const secondUnlisten = await listenForNavigationDeepLinks(
    (payload) => {
      secondOpened.push(payload.channelId);
      return true;
    },
    (payload) => {
      secondOpened.push(payload.messageId);
      return true;
    },
  );
  await settle();

  assert.deepEqual(secondOpened, ["message-2"]);
  assert.deepEqual(acknowledged, ["first", "second"]);
  assert.equal(queue.length, 0);
  secondUnlisten();
  assert.equal(unlistenCount, 4);
});
