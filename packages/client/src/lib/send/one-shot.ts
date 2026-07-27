/**
 * The stateless one-shot path (sdk-shape.md Part A: `atsms.send()`) — the
 * **X509 baseline**: sign-then-encrypt to every recipient device's endpoint
 * cert, no session, no persisted crypto state. This is what reaches recipients
 * who are not DCGKA-capable, and what carries first contact.
 *
 * One-shots travel the SAME delivery contract as sealed envelopes — opaque
 * bytes into a DID's public inbox (inbound-delivery.md §1: the contract is
 * payload-agnostic). The receiving client tells them apart by content: sealed
 * envelopes are strict-CBOR arrays; a one-shot is a DER CMS blob.
 *
 * Trust: the CMS signature is verified against the embedded signer cert, and
 * then the signer cert must RESOLVE in the claimed sender's `at.atsms.x509`
 * collection at its fingerprint rkey — an unpublished (or mismatched) signer
 * is dropped. `convoId` for one-shots is deterministic over the participant
 * set, so a sender cannot inject into an arbitrary thread.
 */

import { loadEndpointCertificate, type ATSMSEndpointCertificate } from "../certificates/index.js";
import { cryptoProvider } from "../crypto-provider.js";
import { decryptAndVerifyMessageSignature } from "../crypto.js";
import { prepareMessageForSending } from "../messages.js";
import type { PdsClient } from "@atsms/dcgka";
import type { ATSMSMessagePayload } from "../types.js";

const COLLECTION_X509 = "at.atsms.x509";

/** Deterministic conversation id for a one-shot: SHA-256 over the sorted,
 *  deduped participant DIDs (the 2-party case equals `generateDMConvoId`). */
export async function oneShotConvoId(participants: string[]): Promise<string> {
  const sorted = [...new Set(participants)].sort().join(",");
  const digest = await cryptoProvider.subtle.digest("SHA-256", new TextEncoder().encode(sorted));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** A DID's valid endpoint certs (its devices), from its `at.atsms.x509` records. */
export async function resolveRecipientCerts(
  pds: PdsClient,
  did: string,
): Promise<ATSMSEndpointCertificate[]> {
  const records = await pds.listRecords(did, COLLECTION_X509);
  const certs: ATSMSEndpointCertificate[] = [];
  for (const rec of records) {
    const pem = (rec.value as { certificate?: unknown }).certificate;
    if (typeof pem !== "string") continue;
    try {
      const cert = loadEndpointCertificate(pem);
      if (cert.isValid()) certs.push(cert);
    } catch {
      // unparseable record — not a device
    }
  }
  return certs;
}

/** Sign (PKCS#7) then encrypt (CMS EnvelopedData) a payload to every recipient
 *  device cert. Returns the opaque DER bytes the delivery contract carries. */
export function sealOneShot(
  payload: ATSMSMessagePayload,
  senderCert: ATSMSEndpointCertificate,
  recipientCerts: ATSMSEndpointCertificate[],
): Promise<Uint8Array> {
  return prepareMessageForSending(payload, senderCert, recipientCerts);
}

export interface OpenedOneShot {
  payload: ATSMSMessagePayload;
  signer: ATSMSEndpointCertificate;
}

/**
 * Decrypt with this device's cert, verify the CMS signature, and parse the
 * payload. Throws when the blob is not addressed to this device or the
 * signature/shape is invalid. Sender AUTHENTICITY (signer published under the
 * claimed DID) is the caller's next step — it needs PDS access.
 */
export async function openOneShot(
  bytes: Uint8Array,
  myCert: ATSMSEndpointCertificate,
): Promise<OpenedOneShot> {
  const { messageSigner, decryptedContent } = await decryptAndVerifyMessageSignature(bytes, myCert);
  const payload = JSON.parse(new TextDecoder().decode(decryptedContent)) as ATSMSMessagePayload;
  if (
    typeof payload.id !== "string" ||
    typeof payload.senderId !== "string" ||
    typeof payload.convoId !== "string" ||
    typeof payload.content !== "string" ||
    typeof payload.contentType !== "string" ||
    !Array.isArray(payload.recipientIds)
  ) {
    throw new Error("one-shot payload has the wrong shape");
  }
  return { payload, signer: messageSigner };
}

/**
 * Sender authenticity (the fingerprint-keyed check, integration §8.5): the
 * signer cert must carry the claimed sender DID, and a record for the signer's
 * fingerprint must exist in that DID's `at.atsms.x509` collection with the
 * same public key. Returns null when authentic, else the reason to drop.
 */
export async function oneShotSenderProblem(
  pds: PdsClient,
  opened: OpenedOneShot,
): Promise<string | null> {
  const claimed = opened.payload.senderId;
  if (opened.signer.did !== claimed) return `signer cert DID ${opened.signer.did} ≠ payload sender ${claimed}`;
  const fingerprint = await opened.signer.getDeviceFingerprint();
  const rec = await pds.getRecord(claimed, COLLECTION_X509, fingerprint);
  if (rec === null) return `signer ${fingerprint.slice(0, 12)}… not published under ${claimed}`;
  const pem = (rec.value as { certificate?: unknown }).certificate;
  if (typeof pem !== "string") return "published record has no certificate";
  try {
    const published = loadEndpointCertificate(pem);
    if ((await published.getDeviceFingerprint()) !== fingerprint) {
      return "published record's key does not match its rkey";
    }
  } catch {
    return "published record's certificate is unparseable";
  }
  return null;
}
