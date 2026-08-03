/**
 * `atsms.peers` — the local peer directory (sdk-shape.md Part A, third noun).
 *
 * A **peer** is the technical entity we communicate with — the bits that make
 * it up: DID, devices (certs + prekeys), inbox endpoints, capability.
 * ("Contact" is the user-facing notion an operator builds on top.) The
 * directory keeps a persistent, observable snapshot per DID so operations
 * (open / addMember / route / reachability / one-shot send) read locally and
 * the network happens on the directory's schedule, not the user's critical
 * path (`atsms-dcgka/spec/add-member-flow.md` §7 has the fetch accounting
 * that motivated this).
 *
 * Trust note: nothing cached here changes what is *trusted* — certs and
 * prekeys re-verify against the cert identity key on refresh, and staleness
 * fails loudly and refetchably (admission failure → refresh prekeys; delivery
 * failure → refresh inbox). Snapshots persist in the device-state KV
 * (`peer:<did>`), so every storage adapter works unchanged and the directory
 * inherits encryption-at-rest when that lands.
 */

import { resolveInbox, type PdsClient } from "@atsms/dcgka";
import { Observable, Subject } from "rxjs";

import type { StorageAdapter } from "../storage/interface.js";
import { resolveDeviceCapabilities } from "./capability.js";

/** One device of a peer, as last verified. Key material is base64 (storable). */
export interface PeerDevice {
  fingerprint: string;
  certificatePEM: string;
  capable: boolean;
  /** Why not capable (e.g. "not-found", "expired") — absent when capable. */
  reason?: string;
  /** Verified admission material — present iff `capable`. */
  signedPrekeyB64?: string;
  signingPkB64?: string;
  prekeyExpiresAt?: number;
}

export interface PeerSnapshot {
  did: string;
  devices: PeerDevice[];
  /** `at.atsms.inbox` endpoint URIs in published preference order. */
  inboxEndpoints: string[];
  reachability: "conversation" | "one-shot" | "unreachable";
  /** When this snapshot was fetched — staleness is surfaced, never hidden. */
  refreshedAt: number;
}

/** Operations read through the directory with this default freshness. */
const PEER_MAX_AGE_MS = 15 * 60 * 1000;

const KEY_PREFIX = "peer:";

const toB64 = (u: Uint8Array): string => btoa(String.fromCharCode(...u));
export const peerKeyBytes = (b64: string): Uint8Array => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

export class ATSMSPeers {
  private readonly updates = new Subject<PeerSnapshot>();
  /** Single-flight per DID — concurrent read-throughs share one refresh. */
  private readonly inflight = new Map<string, Promise<PeerSnapshot>>();

  constructor(
    private readonly pds: PdsClient,
    private readonly storage: StorageAdapter,
    private readonly onEvent: (kind: string, detail: string) => void,
    private readonly maxAgeMs: number = PEER_MAX_AGE_MS,
  ) {}

  /** The locally-held snapshot — zero network. Null when never fetched. */
  async get(did: string): Promise<PeerSnapshot | null> {
    const bytes = await this.storage.loadDeviceState(KEY_PREFIX + did);
    if (bytes === null) return null;
    try {
      return JSON.parse(new TextDecoder().decode(bytes)) as PeerSnapshot;
    } catch {
      return null; // unreadable snapshot — treat as never fetched
    }
  }

  /** Snapshot changes for `did` (emits on every refresh). UX binds capability
   *  badges / disabled-add affordances to this. */
  observe(did: string): Observable<PeerSnapshot> {
    return new Observable((subscriber) => {
      void this.get(did).then((s) => {
        if (s !== null) subscriber.next(s);
      });
      const sub = this.updates.subscribe((s) => {
        if (s.did === did) subscriber.next(s);
      });
      return () => sub.unsubscribe();
    });
  }

  /** Fetch, verify, persist, and emit a fresh snapshot (single-flighted). */
  refresh(did: string): Promise<PeerSnapshot> {
    const running = this.inflight.get(did);
    if (running !== undefined) return running;
    const p = this.doRefresh(did).finally(() => this.inflight.delete(did));
    this.inflight.set(did, p);
    return p;
  }

  /**
   * Operation read-through: the local snapshot when fresh enough, else
   * refresh. On refresh failure a stale snapshot is still returned (loudly) —
   * an operation that might succeed on cached material is never blocked by a
   * flaky directory fetch; one that can't will fail with a refetchable error.
   */
  async ensureFresh(did: string, maxAgeMs: number = this.maxAgeMs): Promise<PeerSnapshot> {
    const cached = await this.get(did);
    if (cached !== null && Date.now() - cached.refreshedAt < maxAgeMs) return cached;
    try {
      return await this.refresh(did);
    } catch (err) {
      if (cached !== null) {
        this.onEvent("peer-stale-used", `${did} (refresh failed: ${err instanceof Error ? err.message : String(err)})`);
        return cached;
      }
      throw err;
    }
  }

  /** Drop the snapshot's claim to freshness (delivery/admission failure) —
   *  the next read-through refetches. */
  async invalidate(did: string): Promise<void> {
    const cached = await this.get(did);
    if (cached === null) return;
    await this.persist({ ...cached, refreshedAt: 0 });
  }

  /** The peer's preferred POST-able inbox ingress from the local snapshot —
   *  the first non-mailto endpoint in published preference order (https in
   *  production; whatever scheme the transport's ingress uses generally). */
  async inboxUrl(did: string, maxAgeMs?: number): Promise<string | null> {
    const snap = await this.ensureFresh(did, maxAgeMs);
    return snap.inboxEndpoints.find((u) => !u.startsWith("mailto:")) ?? null;
  }

  private async doRefresh(did: string): Promise<PeerSnapshot> {
    // The two record families are independent — fetch concurrently. Device
    // evaluation inside resolveDeviceCapabilities is itself parallel.
    const [caps, inbox] = await Promise.all([
      resolveDeviceCapabilities(this.pds, did),
      resolveInbox(this.pds, did).catch(() => ({ ok: false as const, reason: "unreachable" })),
    ]);
    const devices: PeerDevice[] = caps.map((c) => ({
      fingerprint: c.fingerprint,
      certificatePEM: c.certificatePEM,
      capable: c.capable,
      ...(c.reason !== undefined ? { reason: c.reason } : {}),
      ...(c.prekey !== undefined
        ? {
            signedPrekeyB64: toB64(c.prekey.signedPrekey),
            signingPkB64: toB64(c.prekey.signingPk),
            prekeyExpiresAt: Date.parse(c.prekey.expiresAt),
          }
        : {}),
    }));
    const snapshot: PeerSnapshot = {
      did,
      devices,
      inboxEndpoints: inbox.ok ? inbox.record.endpoints.map((e) => e.uri) : [],
      reachability: devices.some((d) => d.capable) ? "conversation" : devices.length > 0 ? "one-shot" : "unreachable",
      refreshedAt: Date.now(),
    };
    await this.persist(snapshot);
    this.onEvent("peer-refreshed", `${did} devices=${devices.length} reach=${snapshot.reachability}`);
    return snapshot;
  }

  private async persist(snapshot: PeerSnapshot): Promise<void> {
    await this.storage.saveDeviceState(KEY_PREFIX + snapshot.did, new TextEncoder().encode(JSON.stringify(snapshot)));
    this.updates.next(snapshot);
  }
}

/** The admission material of a snapshot's capable devices (open/addMember). */
export function capableFromSnapshot(
  snap: PeerSnapshot,
): Array<{ fingerprint: string; leafPk: Uint8Array; signingPk: Uint8Array }> {
  return snap.devices
    .filter((d) => d.capable && d.signedPrekeyB64 !== undefined && d.signingPkB64 !== undefined)
    .map((d) => ({
      fingerprint: d.fingerprint,
      leafPk: peerKeyBytes(d.signedPrekeyB64!),
      signingPk: peerKeyBytes(d.signingPkB64!),
    }));
}
