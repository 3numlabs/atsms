/**
 * `ATSMSDeviceIdentity` — this device, assembled from its endpoint cert
 * (identity-devices §4): the DeviceID (DID + fingerprint), the identity signing
 * scalar, and the prekey ring (`PrekeyManager`, persisted as an opaque
 * device-state blob in the one StorageAdapter). This is what the ATSMS client holds
 * to found/join conversations and to keep the device's `at.atsms.prekey` and
 * `at.atsms.inbox` records published.
 */

import {
  type Csprng,
  type DeviceID,
  hexToBytes,
  type InboxEndpoint,
  type PdsClient,
  PrekeyManager,
  type PrekeyRecord,
  publishInboxEndpoints,
  publishPrekey,
} from "@atsms/dcgka";

import { loadEndpointCertificate } from "../certificates/index.js";
import type { LocalKeys, MemberDescriptor } from "../conversations/index.js";
import type { StorageAdapter } from "../storage/interface.js";
import { deviceFingerprintFromCert, identityScalarFromKey } from "./cert-key.js";

const PREKEY_RING_KEY = "prekey-ring";
const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

export interface DeviceIdentityConfig {
  did: string;
  certificatePEM: string;
  privateKeyPEM: string;
  storage: StorageAdapter;
  rng: Csprng;
  /** Signed-prekey lifetime (one rotation period; parameters.md). */
  prekeyTtlMs?: number;
}

export class ATSMSDeviceIdentity {
  private constructor(
    readonly did: string,
    readonly device: DeviceID,
    /** Lowercase-hex fingerprint — the at.atsms.{x509,prekey} rkey. */
    readonly fingerprint: string,
    /** The worker-inbox key (pre-§8.5 the inboxes are still serial-keyed). */
    readonly certSerial: string,
    readonly certificatePEM: string,
    readonly privateKeyPEM: string,
    private readonly prekeys: PrekeyManager,
    private readonly storage: StorageAdapter,
    private readonly ttlMs: number,
  ) {}

  static async load(config: DeviceIdentityConfig): Promise<ATSMSDeviceIdentity> {
    const fingerprint = await deviceFingerprintFromCert(config.certificatePEM);
    const certSerial = loadEndpointCertificate(config.certificatePEM).serialNumber;
    const identitySk = await identityScalarFromKey(config.privateKeyPEM);
    const ttlMs = config.prekeyTtlMs ?? WEEK_MS;

    const blob = await config.storage.loadDeviceState(PREKEY_RING_KEY);
    const prekeys =
      blob === null
        ? new PrekeyManager(identitySk, config.rng, ttlMs)
        : PrekeyManager.restore(blob, { identitySk, rng: config.rng, ttlMs });

    return new ATSMSDeviceIdentity(
      config.did,
      { did: config.did, fingerprint: hexToBytes(fingerprint) },
      fingerprint,
      certSerial,
      config.certificatePEM,
      config.privateKeyPEM,
      prekeys,
      config.storage,
      ttlMs,
    );
  }

  /** Rotate the prekey ring if due and publish the record (rkey = fingerprint);
   *  persists the ring. Returns the current record either way. */
  async ensurePrekeyPublished(pds: PdsClient, now: number = Date.now()): Promise<PrekeyRecord> {
    if (this.prekeys.needsRotation(now)) {
      const record = this.prekeys.rotate(now);
      await publishPrekey(pds, this.fingerprint, record);
      await this.storage.saveDeviceState(PREKEY_RING_KEY, this.prekeys.serialize());
      return record;
    }
    return this.prekeys.currentRecord()!;
  }

  /** Publish the per-DID `at.atsms.inbox` singleton (ordered by preference;
   *  a mailto: fallback is mandatory, inbound-delivery §3). */
  publishInbox(pds: PdsClient, endpoints: InboxEndpoint[]): Promise<unknown> {
    return publishInboxEndpoints(pds, endpoints);
  }

  /** The live signed-prekey secrets (current + grace) — sealed-asym opening. */
  get prekeySecrets(): Uint8Array[] {
    return this.prekeys.liveSecrets();
  }

  /** The live initial-signing keypairs (current + grace) — admission matching. */
  get signingKeys(): Array<{ sk: Uint8Array; pk: Uint8Array }> {
    return this.prekeys.liveSigningKeys();
  }

  /** This device's current key material for FOUNDING a conversation. */
  get localKeys(): LocalKeys {
    const record = this.prekeys.currentRecord();
    const [signing] = this.prekeys.liveSigningKeys();
    const [leafSk] = this.prekeys.liveSecrets();
    if (record === null || signing === undefined || leafSk === undefined) {
      throw new Error("no prekey generation yet — call ensurePrekeyPublished first");
    }
    return { signingSk: signing.sk, signingPk: signing.pk, leafPk: record.signedPrekey, leafSk };
  }

  /** This device as a founding-member descriptor (current generation). */
  get descriptor(): MemberDescriptor {
    const keys = this.localKeys;
    return { device: this.device, leafPk: keys.leafPk, signingPk: keys.signingPk };
  }
}

/** The `mailto:` fallback address for a DID (inbound-delivery §3; the worker's
 *  encoded-DID local part: `:` → `!`, `.` → `#`). */
export function didMailtoUri(did: string, emailDomain: string): string {
  return `mailto:${did.replace(/:/g, "!").replace(/\./g, "#")}@${emailDomain}`;
}
