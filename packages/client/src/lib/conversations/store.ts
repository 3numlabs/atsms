/**
 * Persistence for a DCGKA conversation (sdk-shape.md Part A; atsms-integration §2).
 *
 * The durable state of a `@atsms/dcgka` session IS its signed frame log — the
 * engine is a pure fold over it, restored by replay (`Session.fromFrames`). So a
 * conversation persists two things: the **bootstrap material** needed to
 * reconstruct the local member (device, signing key, leaf prekey secret), and the
 * ordered **frame log** (its own + ingested frames).
 *
 * A focused interface, deliberately separate from the app-facing `StorageAdapter`
 * (messages/conversations): the crypto-engine's frame log is a distinct layer.
 * The `ATSMS.create` wiring backs it with the real database; tests use the
 * in-memory impl below.
 *
 * SECURITY: `bootstrap` holds private key material and the frame log gates
 * forward secrecy — a persistent backing MUST encrypt at rest and verify key
 * deletion (integration §6).
 */

import type { DeviceID } from "@atsms/dcgka";

/** What's needed to rebuild the local member of a conversation on restore. */
export interface ConversationBootstrap {
  groupId: string; // lowercase hex (= the create op MessageID)
  device: DeviceID;
  signingSk: Uint8Array;
  leafPk: Uint8Array;
  leafSk: Uint8Array;
}

export interface StoredConversation {
  bootstrap: ConversationBootstrap;
  /** Ordered signed-frame log; `frames[0]` is the `create`. Deduplicated. */
  frames: Uint8Array[];
}

export interface DcgkaSessionStore {
  /** Record a new conversation's bootstrap material (idempotent per groupId). */
  createConversation(bootstrap: ConversationBootstrap): Promise<void>;
  /** Append frames to a conversation's log; already-present frames are ignored. */
  appendFrames(groupId: string, frames: Uint8Array[]): Promise<void>;
  /** Load a conversation's bootstrap + full frame log, or null if unknown. */
  load(groupId: string): Promise<StoredConversation | null>;
  /** All known conversation groupIds. */
  list(): Promise<string[]>;
  /** Forget a conversation (key deletion — FS depends on the backing honoring it). */
  delete(groupId: string): Promise<void>;
}

/** In-memory reference/test implementation. */
export class InMemoryDcgkaSessionStore implements DcgkaSessionStore {
  private readonly convos = new Map<
    string,
    { bootstrap: ConversationBootstrap; frames: Uint8Array[]; seen: Set<string> }
  >();

  async createConversation(bootstrap: ConversationBootstrap): Promise<void> {
    if (!this.convos.has(bootstrap.groupId)) {
      this.convos.set(bootstrap.groupId, { bootstrap, frames: [], seen: new Set() });
    }
  }

  async appendFrames(groupId: string, frames: Uint8Array[]): Promise<void> {
    const c = this.convos.get(groupId);
    if (!c) throw new Error(`unknown conversation ${groupId}`);
    for (const f of frames) {
      const key = frameKey(f);
      if (c.seen.has(key)) continue;
      c.seen.add(key);
      c.frames.push(f);
    }
  }

  async load(groupId: string): Promise<StoredConversation | null> {
    const c = this.convos.get(groupId);
    if (!c) return null;
    return { bootstrap: c.bootstrap, frames: c.frames.map((f) => f.slice()) };
  }

  async list(): Promise<string[]> {
    return [...this.convos.keys()];
  }

  async delete(groupId: string): Promise<void> {
    this.convos.delete(groupId);
  }
}

/** Dedup key for a raw frame (its bytes). */
function frameKey(raw: Uint8Array): string {
  let s = "";
  for (const b of raw) s += b.toString(16).padStart(2, "0");
  return s;
}
