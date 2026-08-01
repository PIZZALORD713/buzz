# Phase 3 — macOS Manual Offline Desktop E2E

This is the final **GUI-only** acceptance script for the desktop-owned local
relay. Run it on a macOS machine with an interactive Desktop session after
`local-mode/phase-3` has been rebased onto the **accepted** Phase 2 tip.

Do not treat a successful build, an `/info` response, or a relay-level restart
as a substitute for these rows. Those are headless checks; this document proves
the user-visible fresh-install path.

## Preconditions and handoff

Record these values in the test evidence before beginning:

- Phase 2 accepted commit: `<SHA>`
- Phase 3 rebased commit: `<SHA>` (`git rev-parse HEAD`)
- macOS version, CPU architecture, and tester
- date/time and whether the machine was offline
- deterministic local managed-agent/harness name and its expected response

The managed agent must already be locally usable and able to return a known,
short response with **no network access**. Do not use a cloud provider or an
agent that might silently succeed through an existing network connection.

Turn off network access before opening the app (for example, disable Wi-Fi and
unplug Ethernet). Keep it off for every row marked **Offline required**.

## Build and artifact preparation

From the repository root, on the rebased Phase 3 commit:

```sh
cd desktop
pnpm tauri build
```

Expected macOS artifacts for the currently configured version/Apple Silicon
build are:

```text
App: desktop/src-tauri/target/release/bundle/macos/Buzz.app
DMG: desktop/src-tauri/target/release/bundle/dmg/Buzz_0.5.2_aarch64.dmg
```

If building on another architecture or after a version change, use the actual
DMG emitted in `desktop/src-tauri/target/release/bundle/dmg/`; do not rename it
as evidence. Validate that the bundled sidecar is executable before handing off
an artifact:

```sh
APP=desktop/src-tauri/target/release/bundle/macos/Buzz.app
"$APP/Contents/MacOS/buzz-relay" --help >/dev/null
ls -l "$APP/Contents/MacOS/buzz-relay"
```

For the install under test, open the DMG and copy **Buzz.app** to
`/Applications`. Start `/Applications/Buzz.app`; do not run the app directly
from the build directory or mounted DMG.

## Fresh-install reset and evidence layout

> **Destructive:** the cleanup below removes this app's local desktop state.
> Confirm that the tester does not need existing Buzz data first.

Quit Buzz fully. Use Activity Monitor, or run the following and verify it shows
no remaining Buzz or `buzz-relay` process before cleanup:

```sh
pgrep -alf 'Buzz|buzz-relay' || true
```

The release app identifier is `xyz.block.buzz.app`. Its expected app-data root
is:

```text
~/Library/Application Support/xyz.block.buzz.app
```

Move—not delete—the prior root so the test starts clean and prior state remains
recoverable:

```sh
APP_DATA="$HOME/Library/Application Support/xyz.block.buzz.app"
STAMP="$(date +%Y%m%d-%H%M%S)"
[ ! -e "$APP_DATA" ] || mv "$APP_DATA" "${APP_DATA}.before-phase3-${STAMP}"
mkdir -p "$HOME/Desktop/phase3-evidence-$STAMP"
```

Use that Desktop evidence folder for screenshots and a plain-text results log.
Name images `01-first-run.png`, `02-local-workspace.png`, and so on. For each
capture, include the macOS menu bar clock if possible. Do not place secret keys,
tokens, or full private messages in the evidence folder.

After choosing the local workspace, capture the owner directory name without
publishing the owner pubkey outside the approved test evidence:

```sh
find "$APP_DATA/local-relay" -mindepth 1 -maxdepth 1 -type d -print
find "$APP_DATA/local-relay" -mindepth 2 -maxdepth 2 \
  \( -name relay.sqlite3 -o -name media \) -print
```

Expected shape (where `<owner-pubkey>` is the desktop identity):

```text
~/Library/Application Support/xyz.block.buzz.app/local-relay/<owner-pubkey>/relay.sqlite3
~/Library/Application Support/xyz.block.buzz.app/local-relay/<owner-pubkey>/media/
```

The UI persists `buzz-local://on-this-device`; the app resolves it at runtime
to a dynamic `ws://127.0.0.1:<port>` endpoint. Do not expect a fixed port or
try to connect another device to it.

## Acceptance rows

Mark every row **Pass**, **Fail**, or **Blocked**. A Blocked GUI row is not a
Pass. Include the observed result and the listed evidence filenames/commands in
the results log.

| ID | Scenario | Steps | Expected result | Evidence |
| --- | --- | --- | --- | --- |
| WP-B-1 | Fresh local onboarding (**Offline required**) | With the clean app-data root and network off, launch `/Applications/Buzz.app`. At “Join or create a community,” click **Use this device** (`community-choice-local`). Wait up to 15 seconds. | Onboarding completes without joining/creating a remote community. The workspace is labelled **On this device** and is usable; no network or sign-in requirement appears. | `01-first-run.png`; `02-local-workspace.png`; app-data directory listing showing one `<owner-pubkey>` nest, `relay.sqlite3`, and `media/`. |
| WP-B-2 | Local sidecar ownership and bootstrap (**Offline required**) | With the workspace open, run `pgrep -alf buzz-relay` in Terminal. Inspect the directory shape above. Keep the app open while inspecting. | A bundled `buzz-relay` child is present while Buzz is open. The owner-scoped SQLite file and media directory exist. The local workspace is connected/usable, establishing that owner bootstrap and relay readiness completed. | Terminal output saved as `02-sidecar.txt`; `03-local-relay-data.png` or redacted listing. |
| WP-B-3 | Offline managed-agent creation and chat (**Offline required**) | Open the **Agents** area. Create/select the preconfigured local managed agent/harness. Send the fixed prompt, for example `PHASE3_OFFLINE_PROBE`, in the local workspace and wait for its predetermined response. | The agent starts/uses the current local workspace and returns the expected deterministic response while the machine is offline. The conversation visibly contains both prompt and reply. | `04-agent-created.png`; `05-offline-agent-reply.png`; record prompt and exact expected/actual response in results log. |
| WP-B-4 | Workspace switch causes local sidecar shutdown | While the local workspace and sidecar are running, add/select a pre-existing non-local test community through the community switcher (`community-switcher`). Do not need that remote community to connect. After switching away, run `pgrep -alf buzz-relay`. Then select **On this device** again and wait for it to become usable. | Switching away stops the local relay child. Selecting **On this device** starts a new local sidecar and restores the local workspace. Remote connection failure, if offline, must be clearly distinct from local state. | `06-switch-away.png`; `06-no-sidecar.txt`; `07-switch-back.png`; `07-sidecar-restarted.txt`. |
| WP-B-5 | App shutdown and restart persistence (**Offline required**) | In the local workspace, make a unique note/message such as `phase3-persist-<timestamp>` and attach a small non-sensitive file if attachments are available. Quit Buzz normally. Confirm `pgrep -alf buzz-relay` shows no child. Relaunch `/Applications/Buzz.app` with network still off, select **On this device** if necessary, and locate the unique message (and attachment, if used). | The relay exits with the app. On restart, the local workspace, agent conversation, unique message, and any tested attachment persist and are visible offline. The relay restarts and uses the same owner-scoped directory. | `08-before-quit.png`; `08-no-sidecar-after-quit.txt`; `09-after-restart.png`; before/after `ls -l` or `stat` of `relay.sqlite3` and `media/`. |
| WP-B-6 | Identity-scoped storage isolation | Preserve the first identity's local-relay directory path in the results log. Use the supported desktop identity change/import flow to activate a second test identity. Select **Use this device** for that identity, then inspect `$APP_DATA/local-relay`. Do not delete either identity's directory. Switch back to the first identity using the supported flow and verify its marker remains; switch again to the second identity and verify the first marker is absent there. | Two different owner-pubkey directories exist. Each identity sees only its own local workspace data; no messages, media, or membership state leaks between nests. | Redacted `10-two-identities.txt` listing (two distinct directory names); `10-identity-A.png`; `11-identity-B.png`; results log states which unique marker belongs to each identity. |

## Completion criteria and reporting

The manual GUI gate passes only when **WP-B-1 through WP-B-6 pass** on the
rebased build. Preserve the app and DMG used, the commit SHAs, results log, and
all screenshot/terminal evidence in the handoff folder.

Report failures with the row ID, exact observed behavior, the commit SHA, and
the evidence filenames. Do not erase the app-data root after a failure; it is
the primary reproduction artifact. If an identity transition cannot be completed
because the available build has no supported identity change/import UI, mark
**WP-B-6 Blocked** and route it for product/test-environment direction rather
than simulating isolation by moving database directories.

## Headless checks that complement—but do not replace—this script

After rebasing onto the accepted Phase 2 tip, rerun the applicable headless
checks from the Phase 3 handoff: frontend suite, `local_relay` Rust tests,
`cargo check -p buzz-relay`, `pnpm tauri build`, bundle sidecar layout,
relay-level `/info` startup/restart persistence, and two identity-scoped relay
data-directory checks. Record their commands and output alongside this GUI
evidence. They validate packaging and the relay contract; only the rows above
validate the actual desktop interaction.
