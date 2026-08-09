/**
 * Capability discovery (atsms-integration.md §3): is a peer reachable over the
 * advanced (DCGKA) tier, or only the X509 baseline?
 *
 * A recipient **device** is DCGKA-capable iff its `at.atsms.prekey/<fingerprint>`
 * record resolves and verifies against the device's identity key (from its
 * `at.atsms.x509` endpoint cert). A recipient **DID** is capable iff ≥ 1 of its
 * devices is. Path selection is per-conversation, never per-message.
 *
 * Verification returns the prekey bundles too — group creation seals welcomes to
 * these `signedPrekey`s (the BeeKEM admission leaf keys).
 */

import { type PdsClient, type PrekeyRecord,resolvePrekey } from "@atsms/dcgka";

import { deviceFingerprintFromCert, identityPublicKeyFromCert } from "./cert-key.js";

const COLLECTION_X509 = "at.atsms.x509";

export interface DeviceCapability {
  /** Device fingerprint (the prekey rkey). */
  fingerprint: string;
  capable: boolean;
  /** The verified prekey bundle — present iff `capable`. `signedPrekey` is the admission leaf key. */
  prekey?: PrekeyRecord;
  /** Why the device is not capable (e.g. "not-found", "bad-signature", "expired", "unparseable-cert"). */
  reason?: string;
  /** The device's endpoint-certificate PEM (the x509 record body) — kept so
   *  callers (the peer directory, one-shot cert selection) need no second
   *  listRecords pass. */
  certificatePEM: string;
}

/**
 * Evaluate every device of `did`: resolve its cert, derive the identity key +
 * fingerprint, and verify its prekey. `now` (ms) drives the prekey expiry check
 * (defaults to the host clock — the host owns time, §2).
 */
export async function resolveDeviceCapabilities(
  pds: PdsClient,
  did: string,
  now: number = Date.now(),
): Promise<DeviceCapability[]> {
  const certRecords = await pds.listRecords(did, COLLECTION_X509);
  // Devices are independent — evaluate them concurrently (one prekey fetch
  // each; the sequential form made an N-device DID cost N round trips).
  const results = await Promise.all(
    certRecords.map(async (rec): Promise<DeviceCapability | null> => {
      const pem = (rec.value as { certificate?: unknown }).certificate;
      if (typeof pem !== "string") return null;

      let fingerprint: string;
      let identityPub: Uint8Array;
      try {
        identityPub = await identityPublicKeyFromCert(pem);
        fingerprint = await deviceFingerprintFromCert(pem);
      } catch {
        return null; // unparseable cert — not a routable device
      }

      const r = await resolvePrekey(pds, did, fingerprint, identityPub, now);
      return r.ok
        ? { fingerprint, capable: true, prekey: r.record, certificatePEM: pem }
        : { fingerprint, capable: false, reason: r.reason, certificatePEM: pem };
    }),
  );
  return results.filter((d): d is DeviceCapability => d !== null);
}

/** True iff at least one of `did`'s devices is DCGKA-capable. */
export async function isDcgkaCapable(
  pds: PdsClient,
  did: string,
  now: number = Date.now(),
): Promise<boolean> {
  const caps = await resolveDeviceCapabilities(pds, did, now);
  return caps.some((d) => d.capable);
}

/** The capable devices of `did` — `{ fingerprint, prekey }` — the seal targets for group creation/add. */
export async function capableDevices(
  pds: PdsClient,
  did: string,
  now: number = Date.now(),
): Promise<Array<{ fingerprint: string; prekey: PrekeyRecord }>> {
  const caps = await resolveDeviceCapabilities(pds, did, now);
  return caps
    .filter((d): d is DeviceCapability & { prekey: PrekeyRecord } => d.capable && d.prekey !== undefined)
    .map((d) => ({ fingerprint: d.fingerprint, prekey: d.prekey }));
}

/**
 * Group-level path selection (§3): a set of DIDs can form a DCGKA group iff
 * **all** of them are capable. Returns the incapable ones so the client can
 * surface who holds it back (no silent downgrade).
 */
export async function selectGroupPath(
  pds: PdsClient,
  dids: string[],
  now: number = Date.now(),
): Promise<{ protocol: "dcgka" | "x509"; incapable: string[] }> {
  const incapable: string[] = [];
  for (const did of dids) {
    if (!(await isDcgkaCapable(pds, did, now))) incapable.push(did);
  }
  return { protocol: incapable.length === 0 ? "dcgka" : "x509", incapable };
}
