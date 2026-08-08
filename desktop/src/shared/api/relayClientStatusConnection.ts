import { type Channel, invoke } from "@tauri-apps/api/core";
import { createAuthEvent } from "@/shared/api/tauri";
import type { RelayEvent } from "@/shared/api/types";
import {
  clearCurrentProjection,
  createCurrentProjectionChannel,
  type CurrentProjection,
} from "@/features/binding-status/currentProjectionStore";

type NativeSocketBinding = Readonly<{
  id: number;
  relayUrl: string;
}>;

const CLIENT_BINDING_SCOPE_TAG = "buzz_client_binding_scope";
const CANONICAL_UUID_V4 =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
let currentProjectionOwner: symbol | null = null;

function connectionEpochFromAuthEvent(event: RelayEvent): string | null {
  const matching = event.tags.filter(
    (tag) => tag[0] === CLIENT_BINDING_SCOPE_TAG,
  );
  if (matching.length !== 1) return null;
  const tag = matching[0];
  const epoch = tag?.[2];
  return tag?.length === 4 &&
    tag[1] === "1" &&
    typeof epoch === "string" &&
    CANONICAL_UUID_V4.test(epoch)
    ? epoch
    : null;
}

export class RelayClientStatusConnection {
  readonly projectionChannel: Channel<CurrentProjection | null>;
  private readonly nativeSocketBinding: Promise<NativeSocketBinding | null>;
  private resolveNativeSocketBinding!: (
    binding: NativeSocketBinding | null,
  ) => void;
  private nativeSocketId: number | null = null;
  private connectionEpoch: string | null = null;
  private readonly projectionOwner = Symbol("relay-client-status-connection");
  private settled = false;
  private readonly isActive: (nativeSocketId: number) => boolean;
  private readonly isAuthActive: (nativeSocketId: number) => boolean;
  private readonly setPendingEventId: (eventId: string) => void;
  private readonly sendAuth: (event: RelayEvent) => Promise<void>;

  constructor(
    isActive: (nativeSocketId: number) => boolean,
    isAuthActive: (nativeSocketId: number) => boolean,
    setPendingEventId: (eventId: string) => void,
    sendAuth: (event: RelayEvent) => Promise<void>,
  ) {
    this.isActive = isActive;
    this.isAuthActive = isAuthActive;
    this.setPendingEventId = setPendingEventId;
    this.sendAuth = sendAuth;
    this.nativeSocketBinding = new Promise((resolve) => {
      this.resolveNativeSocketBinding = resolve;
    });
    currentProjectionOwner = this.projectionOwner;
    this.projectionChannel = createCurrentProjectionChannel(
      () =>
        currentProjectionOwner === this.projectionOwner &&
        this.nativeSocketId !== null &&
        this.isActive(this.nativeSocketId),
      () => this.connectionEpoch,
    );
    clearCurrentProjection();
  }

  async connect(
    relayUrl: string,
    onMessage: Channel<unknown>,
  ): Promise<number> {
    return invoke<number>("plugin:websocket|connect_with_status", {
      url: relayUrl,
      onMessage,
      onProjection: this.projectionChannel,
      config: {},
    });
  }

  bind(id: number, relayUrl: string) {
    this.nativeSocketId = id;
    this.settle({ id, relayUrl });
  }

  retire() {
    this.settle(null);
    this.nativeSocketId = null;
    this.connectionEpoch = null;
    if (currentProjectionOwner === this.projectionOwner) {
      currentProjectionOwner = null;
      clearCurrentProjection();
    }
  }

  async handleAuthChallenge(challenge: string) {
    const binding = await this.nativeSocketBinding;
    if (!binding) return;
    const event = await createAuthEvent({
      challenge,
      nativeWebsocketId: binding.id,
      relayUrl: binding.relayUrl,
    });
    if (!this.isAuthActive(binding.id)) return;
    const connectionEpoch = connectionEpochFromAuthEvent(event);
    if (connectionEpoch === null) {
      // Status is optional. Retire only presentation ownership while still
      // sending the ordinary NIP-42 event so authentication can succeed.
      this.retire();
    } else {
      this.connectionEpoch = connectionEpoch;
    }
    this.setPendingEventId(event.id);
    await this.sendAuth(event);
  }

  private settle(binding: NativeSocketBinding | null) {
    if (this.settled) return;
    this.settled = true;
    this.resolveNativeSocketBinding(binding);
  }
}
